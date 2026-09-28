'use strict';

// ---------------------------------------------------------------------------
// Luau beautifier.
//
// Obfuscator output usually arrives as one enormous line. This re-formats such
// source with a single guarantee: the token stream does not change. Tokens are
// never reordered, added, removed or rewritten - only whitespace and line
// breaks are produced - and a spacing pass makes sure two neighbours can never
// merge into a different token (`a - -b` must not become `a--b`, `x[ [1] ]`
// must not become `x[[1]]`).
//
// Invariant covered by tests: tokenize(input) === tokenize(beautify(input)).
// ---------------------------------------------------------------------------

const KEYWORDS = new Set([
  'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 'function', 'if', 'in',
  'local', 'nil', 'not', 'or', 'repeat', 'return', 'then', 'true', 'until', 'while', 'continue',
]);

const MULTI = ['..=', '//=', '+=', '-=', '*=', '/=', '%=', '^=', '==', '~=', '<=', '>=', '//', '..', '::', '->'];
const PUNCT = '()[]{},;:.#+-*/%^=<>?&|~';

const isDigit = c => c >= '0' && c <= '9';
const isNameStart = c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_';
const isNameChar = c => isNameStart(c) || isDigit(c);

// '[', '='*, '[' ... matching ']', '='*, ']'
function longBracketEnd(src, i) {
  if (src[i] !== '[') return -1;
  let j = i + 1;
  while (src[j] === '=') j++;
  if (src[j] !== '[') return -1;
  const close = ']' + '='.repeat(j - i - 1) + ']';
  const at = src.indexOf(close, j + 1);
  return at === -1 ? src.length : at + close.length;
}

function tokenize(src) {
  const tokens = [];
  const n = src.length;
  let i = 0;

  while (i < n) {
    const c = src[i];

    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v') { i++; continue; }

    // comments
    if (c === '-' && src[i + 1] === '-') {
      if (src[i + 2] === '[') {
        const end = longBracketEnd(src, i + 2);
        if (end !== -1) {
          tokens.push({ type: 'comment', text: src.slice(i, end) });
          i = end;
          continue;
        }
      }
      let j = i;
      while (j < n && src[j] !== '\n') j++;
      tokens.push({ type: 'comment', text: src.slice(i, j) });
      i = j;
      continue;
    }

    // long strings
    if (c === '[') {
      const end = longBracketEnd(src, i);
      if (end !== -1) {
        tokens.push({ type: 'string', text: src.slice(i, end) });
        i = end;
        continue;
      }
    }

    // quoted / interpolated strings
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      let j = i + 1;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === quote) { j++; break; }
        if (src[j] === '\n' && quote !== '`') break;
        j++;
      }
      tokens.push({ type: 'string', text: src.slice(i, j) });
      i = j;
      continue;
    }

    // numbers: 0x / 0b / decimal / exponent / Luau suffixes
    if (isDigit(c) || (c === '.' && isDigit(src[i + 1]))) {
      let j = i;
      // Luau allows `_` separators anywhere in a number, including between the
      // base marker and its digits: 0_xB, 0B1_011_, 0b_1_0_01
      const base = (() => {
        if (src[j] !== '0') return null;
        let k = j + 1;
        while (src[k] === '_') k++;
        if (src[k] === 'x' || src[k] === 'X') return { ch: 'x', at: k };
        if (src[k] === 'b' || src[k] === 'B') return { ch: 'b', at: k };
        return null;
      })();
      if (base && base.ch === 'x') {
        j = base.at + 1;
        while (j < n && /[0-9a-fA-F_]/.test(src[j])) j++;
      } else if (base && base.ch === 'b') {
        j = base.at + 1;
        while (j < n && /[01_]/.test(src[j])) j++;
      } else {
        while (j < n && /[0-9_]/.test(src[j])) j++;
        if (src[j] === '.' && src[j + 1] !== '.') {
          j++;
          while (j < n && /[0-9_]/.test(src[j])) j++;
        }
        if (src[j] === 'e' || src[j] === 'E') {
          let k = j + 1;
          if (src[k] === '+' || src[k] === '-') k++;
          if (isDigit(src[k])) {
            j = k;
            while (j < n && /[0-9_]/.test(src[j])) j++;
          }
        }
      }
      while (j < n && /[uUlLiI]/.test(src[j]) && !isNameChar(src[j + 1] || '')) j++;
      tokens.push({ type: 'number', text: src.slice(i, j) });
      i = j;
      continue;
    }

    if (isNameStart(c)) {
      let j = i;
      while (j < n && isNameChar(src[j])) j++;
      const text = src.slice(i, j);
      tokens.push({ type: KEYWORDS.has(text) ? 'keyword' : 'name', text });
      i = j;
      continue;
    }

    if (src.startsWith('...', i)) { tokens.push({ type: 'punct', text: '...' }); i += 3; continue; }

    const op = MULTI.find(o => src.startsWith(o, i));
    if (op) { tokens.push({ type: 'punct', text: op }); i += op.length; continue; }

    if (PUNCT.includes(c)) { tokens.push({ type: 'punct', text: c }); i++; continue; }

    tokens.push({ type: 'other', text: c });
    i++;
  }

  return tokens;
}

// Two adjacent tokens must not be written without a separator if that would
// change how they lex.
function wouldMerge(a, b) {
  const lc = a.text[a.text.length - 1];
  const fc = b.text[0];
  if (lc === '-' && fc === '-') return true;
  if (lc === '[' && fc === '[') return true;
  if (lc === '.' && fc === '.') return true;
  if (lc === ':' && fc === ':') return true;
  if (lc === '=' && fc === '=') return true;
  if (lc === '~' && fc === '=') return true;
  if (lc === '<' && fc === '=') return true;
  if (lc === '>' && fc === '=') return true;
  if (lc === '/' && (fc === '/' || fc === '*')) return true;
  if (isNameChar(lc) && isNameStart(fc)) return true;
  if (a.type === 'number' && (isDigit(fc) || fc === '.' || isNameStart(fc))) return true;
  return false;
}

function endsExpression(t) {
  if (!t) return false;
  if (t.type === 'name' || t.type === 'number' || t.type === 'string') return true;
  if (t.type === 'keyword') return t.text === 'true' || t.text === 'false' || t.text === 'nil' || t.text === 'end';
  if (t.type === 'punct') return t.text === ')' || t.text === ']' || t.text === '}' || t.text === '...';
  return false;
}

function startsStatement(t) {
  if (!t || t.type !== 'keyword') return false;
  return ['local', 'if', 'for', 'while', 'repeat', 'return', 'break', 'continue', 'do', 'function'].includes(t.text);
}

const NO_SPACE_BEFORE = new Set([')', ']', '}', ',', ';', '.', ':']);
const NO_SPACE_AFTER = new Set(['(', '[', '.', ':', '#']);
const SPACED_OPERATORS = new Set([
  '+', '-', '*', '/', '//', '%', '^', '..', '==', '~=', '<', '>', '<=', '>=', '&', '|',
  '=', '+=', '-=', '*=', '/=', '%=', '^=', '..=', '//=',
]);
const SPACED_KEYWORDS = new Set(['and', 'or', 'not', 'in', 'then', 'do', 'else', 'elseif', 'until']);

// Beatify with statement-per-line layout and block indentation.
function beautify(source, options = {}) {
  const indentUnit = typeof options.indent === 'string' ? options.indent : '\t';
  const tokens = tokenize(source);
  if (!tokens.length) return source;

  const lines = [];
  let line = '';
  let indent = 0;
  let depthParen = 0;

  const flush = () => {
    const text = line.replace(/\s+$/, '');
    lines.push(text ? indentUnit.repeat(Math.max(indent, 0)) + text : '');
    line = '';
  };

  // Is the `function` at i a statement (declaration) rather than an expression?
  function functionIsStatement(i) {
    const prev = tokens[i - 1];
    if (!prev) return true;
    if (prev.type === 'keyword') return prev.text === 'local' || prev.text === 'return' ? prev.text === 'local' : false;
    if (prev.type === 'punct') return !['=', '(', '{', ',', '..', '+', '-', '*', '/', '%', '^', 'then', 'do', 'return'].includes(prev.text);
    return false;
  }

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const prev = tokens[i - 1];
    const next = tokens[i + 1];

    if (t.type === 'comment') {
      flush();
      lines.push(indentUnit.repeat(Math.max(indent, 0)) + t.text.trim());
      continue;
    }

    if (t.type === 'punct') {
      if (t.text === '(' || t.text === '[' || t.text === '{') depthParen++;
      else if (t.text === ')' || t.text === ']' || t.text === '}') depthParen = Math.max(0, depthParen - 1);
    }

    // --- block structure ---------------------------------------------------
    // Inside `( ... )` / `{ ... }` nothing is a block keyword: `end` there
    // closes an anonymous function that is part of an expression.
    if (t.type === 'keyword' && depthParen === 0) {
      if (t.text === 'end' || t.text === 'until') {
        if (line.trim()) flush();
        indent = Math.max(0, indent - 1);
        if (t.text === 'until') {
          // `until <cond>` keeps its condition on the same line
          line = 'until';
          const sep = next ? spaceFor(next, t) : '';
          line += sep + (next ? next.text : '');
          if (next) i++;
          flush();
          continue;
        }
        // `end` may close a statement, or continue an expression (a = f() end?)
        line = 'end';
        const after = tokens[i + 1];
        if (after && (after.type === 'punct' && [')', ']', '}', ',', ';'].includes(after.text))) {
          line += spaceFor(after, { type: 'keyword', text: 'end' }) + after.text;
          i++;
        }
        flush();
        continue;
      }

      if (t.text === 'else') {
        flush();
        indent = Math.max(0, indent - 1);
        lines.push(indentUnit.repeat(Math.max(indent, 0)) + 'else');
        indent++;
        continue;
      }

      if (t.text === 'elseif') {
        flush();
        indent = Math.max(0, indent - 1);
        line = 'elseif';
        const sep = next ? spaceFor(next, t) : '';
        if (next) { line += sep + next.text; i++; }
        continue;
      }

      if (t.text === 'then' || t.text === 'do') {
        line += spaceFor(t, prev) + t.text;
        flush();
        indent++;
        continue;
      }

      if (t.text === 'repeat') {
        if (line.trim()) flush();
        lines.push(indentUnit.repeat(Math.max(indent, 0)) + 'repeat');
        indent++;
        continue;
      }

      if (t.text === 'function' && functionIsStatement(i)) {
        if (line.trim() && !/^(local|return)$/.test(line.trim())) flush();
        line += spaceFor(t, prev) + t.text;
        continue;
      }

      // statement keywords close the previous statement when it can be finished
      if (startsStatement(t) && line.trim() && prev) {
        const prevEndsExpression = endsExpression(prev);
        const prevIsBlockEdge = prev.type === 'keyword' && ['then', 'do', 'else', 'repeat', 'return'].includes(prev.text);
        if (prevEndsExpression || (prev.type === 'punct' && ['}', ')'].includes(prev.text))) flush();
        else if (prevIsBlockEdge) flush();
      }
    }

    // --- spacing -----------------------------------------------------------
    if (line && t.type !== 'punct' === false) { /* noop, spacing handled below */ }
    const sep = line ? spaceFor(t, prev) : '';
    line += sep + t.text;

    // a `;` ends the statement it terminates
    if (t.type === 'punct' && t.text === ';') flush();
  }

  flush();

  // collapse runs of blank lines
  const text = lines.filter((l, idx) => !(l === '' && lines[idx - 1] === '')).join('\n');

  return (text.trimEnd() || '') + '\n';
}

function spaceFor(t, prev) {
  if (!prev) return '';
  if (wouldMerge(prev, t)) return ' ';

  if (t.type === 'punct' && NO_SPACE_BEFORE.has(t.text)) return '';
  if (prev.type === 'punct' && NO_SPACE_AFTER.has(prev.text)) return '';
  if (t.type === 'punct' && (t.text === '(' || t.text === '[')) {
    // calling / indexing: no space, unless the previous token is a keyword
    return prev.type === 'keyword' ? ' ' : '';
  }
  if (t.type === 'punct' && t.text === '{') return ' ';
  if (prev.type === 'punct' && prev.text === ',') return ' ';
  if (prev.type === 'punct' && prev.text === '{') return ' ';
  if (t.type === 'punct' && SPACED_OPERATORS.has(t.text)) {
    if ((t.text === '-' || t.text === '+') && !endsExpression(prev)) return '';
    return ' ';
  }
  if (prev.type === 'punct' && SPACED_OPERATORS.has(prev.text)) return ' ';
  if (t.type === 'keyword' && SPACED_KEYWORDS.has(t.text)) return ' ';
  if (prev.type === 'keyword' && SPACED_KEYWORDS.has(prev.text)) return ' ';
  if (prev.type === 'keyword') return ' ';
  return ' ';
}

function looksLikeSource(text) {
  if (!text || text.length > 16 * 1024 * 1024) return false;
  const printable = (text.match(/[\x09\x0a\x0d\x20-\x7e]/g) || []).length / text.length;
  return printable > 0.92;
}

module.exports = { beautify, tokenize, looksLikeSource, longBracketEnd, wouldMerge };
