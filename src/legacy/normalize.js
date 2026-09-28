'use strict';

// ---------------------------------------------------------------------------
// Static normalizer for legacy (pre-v15) Luraph builds and their inner chunks.
//
// Those scripts are plain Luau dressed up: library calls hide behind generated
// aliases (`local ili1... = assert`), state numbers hide behind folded
// arithmetic (`((1052 - 60) - 14)`), and whole VMs arrive as one function whose
// 50-odd parameters are the libraries, passed at the bottom of the file. This
// undoes the dressing without changing what the code does:
//
//   * aliases resolve to what they stand for, transitively
//     (`local x = y.char` with `y` = `string` becomes `string.char`);
//   * `(integer +|-|* integer)` folds to its value;
//   * the result goes through the token-preserving beautifier.
//
// Safety rules (each is covered by a differential test that runs the original
// and the normalized snippet under stock Luau and compares the behaviour):
//
//   * a name is rewritten only when declared exactly once, never re-assigned,
//     and every genuine use sits inside its declaration's scope, at or after
//     the declaration (uses elsewhere would bind to a different variable);
//   * declaration sites, binders (params, loop variables), assignment targets,
//     and table-record keys are never rewritten;
//   * values are literals, immutable global reads, or single top-level reads
//     fixed before the alias — never calls, varargs, constructors, or
//     shadowable names; multi-token values substitute parenthesized;
//   * prefix/call positions (`a[i]`, `a.b`, `a:b()`, `a()`, `a{}`) only accept
//     name/path (or parenthesized) values, since `nil()` etc. do not parse;
//   * values spanning lines are skipped, and every line break stays exactly
//     where it was: some loaders probe their own error-line numbers and
//     sabotage (or hang) when reflowed, so the output is line-identical to
//     the input. Only intra-line spacing is normalized. Pass { beautify: ... }
//     for a reflowed copy, meant for human reading, not execution.
// ---------------------------------------------------------------------------

const { tokenize, beautify, wouldMerge } = require('../util/beautify');

// A value simple enough to inline: a literal, or a dotted global path.
function parseValue(tokens, at) {
  let i = at;
  const t = tokens[i];
  if (!t) return null;
  if (t.type === 'number' || t.type === 'string') return { end: i + 1, text: t.text };
  if (t.type === 'keyword' && (t.text === 'true' || t.text === 'false' || t.text === 'nil')) {
    return { end: i + 1, text: t.text };
  }
  if (t.type === 'punct' && t.text === '-' && tokens[i + 1] && tokens[i + 1].type === 'number') {
    return { end: i + 2, text: '-' + tokens[i + 1].text };
  }
  if (t.type === 'name') {
    let text = t.text;
    i++;
    while (tokens[i] && tokens[i].text === '.' && tokens[i + 1] && tokens[i + 1].type === 'name') {
      text += '.' + tokens[i + 1].text;
      i += 2;
    }
    return { end: i, text };
  }
  return null;
}

function isProperty(tokens, at) {
  const prev = tokens[at - 1];
  return !!prev && prev.type === 'punct' && (prev.text === '.' || prev.text === ':');
}

// Count declarations and assignments per name across the whole file.
function usageOf(tokens) {
  const decls = new Map();    // name -> local declarations (local, for-vars, params, loop vars)
  const assigns = new Map();  // name -> assignments outside its declaration
  const bump = (map, k) => map.set(k, (map.get(k) || 0) + 1);

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type === 'keyword' && t.text === 'local') {
      let j = i + 1;
      if (tokens[j] && tokens[j].text === 'function' && tokens[j + 1] && tokens[j + 1].type === 'name') {
        bump(decls, tokens[j + 1].text);
        continue;
      }
      while (tokens[j] && tokens[j].type === 'name') {
        bump(decls, tokens[j].text);
        j++;
        if (tokens[j] && tokens[j].text === ',') j++;
        else break;
      }
      continue;
    }
    if (t.type === 'keyword' && t.text === 'function') {
      // named function expression `function foo.bar:baz(...)` declares nothing new,
      // but its parameter list does
      let j = i + 1;
      while (tokens[j] && !(tokens[j].type === 'punct' && tokens[j].text === '(')) j++;
      if (tokens[j] && tokens[j].text === '(') {
        j++;
        let depth = 1;
        while (j < tokens.length && depth > 0) {
          if (tokens[j].type === 'punct' && tokens[j].text === '(') depth++;
          if (tokens[j].type === 'punct' && tokens[j].text === ')') depth--;
          if (depth === 1 && tokens[j].type === 'name') bump(decls, tokens[j].text);
          j++;
        }
      }
      continue;
    }
    if (t.type === 'keyword' && t.text === 'for') {
      let j = i + 1;
      while (tokens[j] && tokens[j].type === 'name') {
        bump(decls, tokens[j].text);
        j++;
        if (tokens[j] && tokens[j].text === ',') j++;
        else break;
      }
      continue;
    }
    // assignments: plain, compound, and multi-assign targets
    // (but not `==`, not properties, not table-record keys, and not the
    // declaration's own `=` — `assigns` counts RE-assignments only)
    if (t.type === 'name' && !isProperty(tokens, i) && isAssignTarget(tokens, i) &&
        !isLocalDeclAssign(tokens, i)) {
      bump(assigns, t.text);
    }
  }
  return { decls, assigns };
}

// Block-structure scan. Returns an Int32Array mapping each token index to the
// innermost enclosing block opener (`function`/`do`/`then`/`elseif`/`else`/
// `repeat`), or -1 at top level. `elseif`/`else` close the previous section:
// a local declared in one section is NOT visible in the next.
function innermostOpeners(tokens) {
  const out = new Int32Array(tokens.length).fill(-1);
  const stack = [];
  const top = () => tokens[stack[stack.length - 1]].text;
  for (let j = 0; j < tokens.length; j++) {
    const t = tokens[j];
    if (t.type === 'keyword') {
      if (t.text === 'function' || t.text === 'do' || t.text === 'then' || t.text === 'repeat') {
        stack.push(j);
      } else if (t.text === 'elseif' || t.text === 'else') {
        if (stack.length && (top() === 'then' || top() === 'elseif' || top() === 'else')) stack.pop();
        stack.push(j);
      } else if (t.text === 'end') {
        if (stack.length) stack.pop();
      } else if (t.text === 'until') {
        if (stack.length && top() === 'repeat') stack.pop();
      }
    }
    out[j] = stack.length ? stack[stack.length - 1] : -1;
  }
  return out;
}

// Index of the token closing the block opened at openerIdx (`end`/`until`/
// `elseif`/`else` for sections), or tokens.length when top-level/unmatched.
function blockEnd(tokens, openerIdx) {
  if (openerIdx < 0) return tokens.length;
  const stack = [tokens[openerIdx].text];
  for (let j = openerIdx + 1; j < tokens.length; j++) {
    const t = tokens[j];
    if (t.type !== 'keyword') continue;
    if (t.text === 'function' || t.text === 'do' || t.text === 'then' || t.text === 'repeat') {
      stack.push(t.text);
    } else if (t.text === 'elseif' || t.text === 'else') {
      if (stack[stack.length - 1] === 'then' || stack[stack.length - 1] === 'elseif' ||
          stack[stack.length - 1] === 'else') stack.pop();
      else { stack.push(t.text); continue; }
      if (!stack.length) return j;
      stack.push(t.text);
    } else if (t.text === 'end') {
      stack.pop();
      if (!stack.length) return j;
    } else if (t.text === 'until') {
      if (stack[stack.length - 1] === 'repeat') {
        stack.pop();
        if (!stack.length) return j;
      }
    }
  }
  return tokens.length;
}

// Names declared by top-level `local` statements: Map name -> `local` index.
// Only these are visible everywhere below their declaration.
function topLevelLocals(tokens, inner) {
  const out = new Map();
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].type === 'keyword' && tokens[i].text === 'local' && inner[i] === -1) {
      let j = i + 1;
      if (tokens[j] && tokens[j].text === 'function' && tokens[j + 1] && tokens[j + 1].type === 'name') {
        if (!out.has(tokens[j + 1].text)) out.set(tokens[j + 1].text, i);
        continue;
      }
      while (tokens[j] && tokens[j].type === 'name') {
        if (!out.has(tokens[j].text)) out.set(tokens[j].text, i);
        j++;
        if (tokens[j] && tokens[j].text === ',') j++;
        else break;
      }
    }
  }
  return out;
}

// True when `name` is genuinely USED (read) outside [lo, hi]. Declaration
// sites, binders, table keys, and properties are not uses.
function useOutsideRange(tokens, name, lo, hi) {
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type !== 'name' || t.text !== name) continue;
    if (isProperty(tokens, i)) continue;
    if (isTableKey(tokens, i)) continue;
    if (inLocalNameList(tokens, i)) continue;
    if (isBinder(tokens, i)) continue;
    if (isAssignTarget(tokens, i)) continue;  // targets are covered by assigns==0
    if (i < lo || i > hi) return true;
  }
  return false;
}

// `local a, b = V1, V2` -> [[name, value]...]; null when any value is too rich.
function parseLocalDecl(tokens, at) {
  // at -> `local`
  let j = at + 1;
  if (!tokens[j] || tokens[j].type !== 'name') return null;
  const names = [];
  while (tokens[j] && tokens[j].type === 'name') {
    names.push(tokens[j].text);
    j++;
    if (tokens[j] && tokens[j].text === ',') j++;
    else break;
  }
  if (!tokens[j] || tokens[j].text !== '=') {
    // `local a, b` without values: nothing to inline
    return names.map(n => [n, null]);
  }
  j++;
  const values = [];
  for (let k = 0; k < names.length; k++) {
    if (k > 0) {
      if (!tokens[j] || tokens[j].text !== ',') {
        // fewer values than names: sound `nil` padding ONLY at a statement
        // boundary. Anything else (a call's `(`, an operator, ...) means the
        // value list did not parse as single values — bail on the whole decl.
        // (`local a, b = f()` binds real results, never nil.)
        if (!isStmtBoundary(tokens, j)) return null;
        break;
      }
      j++;
    }
    const v = parseValue(tokens, j);
    if (!v) return null;   // something computed: leave the whole declaration alone
    // the value must be COMPLETE here: `local a = 1 + 2` does not bind 1,
    // and `local a = f()` does not bind f. A boundary means fewer values
    // than names (the rest pad with nil); anything else must be the next `,`.
    if (k === names.length - 1) {
      if (!isStmtBoundary(tokens, v.end)) return null;
    } else if (tokens[v.end] && tokens[v.end].text === ',') {
      // more values follow; the loop consumes the comma
    } else if (isStmtBoundary(tokens, v.end)) {
      values.push(v.text);
      j = v.end;
      break;
    } else {
      return null;
    }
    values.push(v.text);
    j = v.end;
  }
  while (values.length < names.length) values.push('nil');
  return names.map((n, k) => [n, values[k]]);
}

// Statement boundary after a complete expression. Two expressions can never
// abut, so a fresh name/number/`)`/`]`/`}` (or `;`/EOF/a non-operator keyword)
// ends the value; anything that can continue it (`(`, `[`, `{`, operators,
// `.`, `:`, `,`, strings, `...`, `and`/`or`/`not`) does not.
function isStmtBoundary(tokens, j) {
  const t = tokens[j];
  if (!t) return true;
  if (t.text === ';' || t.text === ')' || t.text === ']' || t.text === '}') return true;
  if (t.type === 'name' || t.type === 'number') return true;
  if (t.type === 'keyword' && t.text !== 'and' && t.text !== 'or' && t.text !== 'not') return true;
  return false;
}

// Can `value` (an alias right-hand side) be re-read at `useIdx` and mean the
// same thing it meant at the declaration? Literals always can; a name can only
// when it denotes the same immutable binding at both sites: either a global
// that is never assigned, or the single top-level declaration preceding the
// alias declaration, itself never re-assigned. Anything else (calls, varargs,
// constructors, shadowable names) is unsafe.
function valueSafe(tokens, usage, topLevel, value, declIdx) {
  const vt = tokenize(value);
  for (let k = 0; k < vt.length; k++) {
    const t = vt[k];
    if (t.text === '...') return false;
    if (t.type === 'keyword' && t.text === 'function') return false;
    if (t.text === '{' || t.text === '}') return false;
    // calls: `(` after a value, or string-arg sugar after a value
    if (t.text === '(') {
      const p = vt[k - 1];
      if (p && (p.type === 'name' || p.type === 'string' || p.text === ')' || p.text === ']')) return false;
    }
    if (t.type === 'string') {
      const p = vt[k - 1];
      if (p && (p.type === 'name' || p.text === ')')) return false;
    }
    if (t.type !== 'name') continue;
    const p = vt[k - 1];
    if (p && (p.text === '.' || p.text === ':')) continue;  // property, not a binding
    const decls = usage.decls.get(t.text) || 0;
    const assigns = usage.assigns.get(t.text) || 0;
    if (decls === 0) {
      if (assigns !== 0) return false;   // mutated global: value may differ
    } else if (decls === 1 && topLevel.has(t.text) && topLevel.get(t.text) < declIdx && assigns === 0) {
      // the one visible-everywhere binding, fixed before this declaration
    } else {
      return false;
    }
  }
  return true;
}

function collectAliases(tokens, usage, inner, topLevel) {
  const aliases = new Map();
  const endCache = new Map();
  const endOf = (op) => {
    if (!endCache.has(op)) endCache.set(op, blockEnd(tokens, op));
    return endCache.get(op);
  };
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].type === 'keyword' && tokens[i].text === 'local') {
      const decl = parseLocalDecl(tokens, i);
      if (!decl) continue;
      const hi = endOf(inner[i]);
      for (const [name, value] of decl) {
        if (value == null) continue;
        if (name === '_' || name === '...') continue;
        if ((usage.decls.get(name) || 0) !== 1) continue;
        if ((usage.assigns.get(name) || 0) !== 0) continue;
        if (!valueSafe(tokens, usage, topLevel, value, i)) continue;
        // every genuine use must sit inside the declaration's scope,
        // at or after the declaration (earlier uses bind to a global)
        if (useOutsideRange(tokens, name, i, hi)) continue;
        aliases.set(name, value);
      }
    }
  }
  // resolve chains transitively: `x = y.char`, `y = string` -> `x = string.char`
  for (let round = 0; round < 10; round++) {
    let changed = false;
    for (const [name, value] of aliases) {
      const head = /^([A-Za-z_][A-Za-z0-9_]*)(.*)$/.exec(value);
      if (head && aliases.has(head[1]) && head[1] !== name) {
        const resolved = aliases.get(head[1]) + head[2];
        if (resolved !== value) {
          aliases.set(name, resolved);
          changed = true;
        }
      }
    }
    if (!changed) break;
  }
  return aliases;
}

// `return ( function ( p1, p2, ... ) body end ) ( v1, v2, ... )`:
// map parameters to their actual values when the counts line up exactly.
// Returns { aliases, fnIdx, bodyEnd }: substitution is only valid inside the body.
function collectParamAliases(tokens) {
  const none = { aliases: new Map(), fnIdx: -1, bodyEnd: -1 };
  const out = new Map();
  if (tokens.length < 8) return none;
  let i = 0;
  while (tokens[i] && tokens[i].type === 'comment') i++;
  if (!tokens[i] || tokens[i].text !== 'return') return none;
  i++;
  if (tokens[i] && tokens[i].text === '(') i++;
  if (!tokens[i] || tokens[i].text !== 'function') return none;
  const fnIdx = i;
  i++;
  if (!tokens[i] || tokens[i].text !== '(') return none;
  i++;
  const params = [];
  while (tokens[i] && tokens[i].text !== ')') {
    if (tokens[i].type === 'name') params.push(tokens[i].text);
    else if (tokens[i].text !== ',') return none;   // `...` or anything else: bail
    i++;
  }
  if (!params.length) return none;
  // the outer function's closing `end`, followed by `) (`
  let close = -1;
  for (let n = 0; n < tokens.length - 3; n++) {
    if (tokens[n].text === 'end' && tokens[n + 1].text === ')' && tokens[n + 2].text === '(') close = n;
  }
  if (close === -1) return none;
  // split the actuals at depth-1 commas
  const slices = [];
  let s = close + 3;
  let depth = 1;
  for (let m = close + 3; m < tokens.length && depth > 0; m++) {
    const tx = tokens[m].text;
    if (tx === '(' || tx === '[' || tx === '{') depth++;
    else if (tx === ')' || tx === ']' || tx === '}') {
      depth--;
      if (depth === 0) { slices.push([s, m]); break; }
    } else if (tx === ',' && depth === 1) {
      slices.push([s, m]);
      s = m + 1;
    }
  }
  if (slices.length !== params.length) return none;
  for (let k = 0; k < params.length; k++) {
    const [a, b] = slices[k];
    const v = parseValue(tokens, a);
    // only single values, no calls or tables
    if (v && v.end === b) out.set(params[k], tokens.slice(a, b).map(x => x.text).join(''));
  }
  return { aliases: out, fnIdx, bodyEnd: close };
}

function parseInteger(text) {
  const clean = text.replace(/_/g, '');
  if (/^0[xX][0-9a-fA-F]+$/.test(clean)) return parseInt(clean, 16);
  if (/^0[bB][01]+$/.test(clean)) return parseInt(clean.slice(2), 2);
  if (/^[0-9]+$/.test(clean)) return parseInt(clean, 10);
  return null;
}

// Fold the inside of `( <int> <op> <int> )` for +,-,* to a fixpoint.
// The parens are KEPT: they may be call parens (`f(1+2)`), and keeping them
// is always precedence-safe. Returns folds applied.
function foldConstants(tokens) {
  let folds = 0;
  for (;;) {
    let changed = false;
    for (let i = 0; i + 4 < tokens.length; i++) {
      if (tokens[i].text !== '(' || tokens[i + 4].text !== ')') continue;
      const a = tokens[i + 1].type === 'number' ? parseInteger(tokens[i + 1].text) : null;
      const op = tokens[i + 2].text;
      const b = tokens[i + 3].type === 'number' ? parseInteger(tokens[i + 3].text) : null;
      if (a == null || b == null || !['+', '-', '*'].includes(op)) continue;
      const v = op === '+' ? a + b : op === '-' ? a - b : a * b;
      if (!Number.isSafeInteger(v)) continue;
      const swallowed = (tokens[i + 1].nlBefore || 0) + (tokens[i + 2].nlBefore || 0) +
        (tokens[i + 3].nlBefore || 0);
      tokens.splice(i + 1, 3, { type: 'number', text: String(v), nlBefore: swallowed });
      folds++;
      changed = true;
      break;   // restart the scan: indices shifted
    }
    if (!changed) break;
  }
  return folds;
}

// Is this `name =` occurrence a table-record key (`{ key = v, ... }`)?
// Walks back at bracket depth: a `{` (or a `,`-separated pair chain after one)
// means key; any statement boundary means assignment target.
function isTableKey(tokens, at) {
  const nx = tokens[at + 1];
  if (!nx || nx.text !== '=') return false;
  let j = at - 1, depth = 0;
  for (;;) {
    const t = tokens[j];
    if (!t) return false;
    if (t.text === ')' || t.text === ']') { depth++; j--; continue; }
    if (t.text === '(' || t.text === '[') {
      if (depth > 0) { depth--; j--; continue; }
      return false;
    }
    if (t.text === '}') { depth++; j--; continue; }
    if (t.text === '{') {
      if (depth > 0) { depth--; j--; continue; }
      return true;
    }
    if (depth === 0) {
      if (t.text === ',') { j--; continue; }
      if (t.text === '=') { j -= 2; continue; }  // skip previous `key =` pair's key
      if (t.type === 'keyword' || t.text === ';') return false;
      j--;
      continue;
    }
    j--;
  }
}

const COMPOUND = ['+=', '-=', '*=', '/=', '%=', '^=', '..=', '//='];

// Is this name an assignment target (`x = ...`, `x += ...`, `a, b = ...`)?
// Table-record keys are NOT targets.
function isAssignTarget(tokens, at) {
  const nx = tokens[at + 1];
  if (!nx) return false;
  if (nx.text === '=') return !isTableKey(tokens, at);
  if (nx.type === 'punct' && COMPOUND.includes(nx.text)) return true;
  if (nx.text !== ',') return false;
  // comma: could be multi-assign targets, call args, table items, return list...
  // scan forward: a depth-0 `=` means targets; any boundary means not
  let j = at + 1, depth = 0;
  for (;;) {
    const t = tokens[j];
    if (!t) return false;
    if (t.text === '(' || t.text === '[' || t.text === '{') { depth++; j++; continue; }
    if (t.text === ')' || t.text === ']' || t.text === '}') {
      if (depth > 0) { depth--; j++; continue; }
      return false;
    }
    if (depth === 0) {
      if (t.text === '=') return true;
      if (t.type === 'keyword' || t.text === ';') return false;
    }
    j++;
  }
}

// Is this name's `=` (or `,`-chain leading to `=`) the `local` declaration's own?
function isLocalDeclAssign(tokens, at) {
  if (!inLocalNameList(tokens, at)) return false;
  let j = at + 1;
  for (;;) {
    const t = tokens[j];
    if (!t) return false;
    if (t.text === ',') {
      j++;
      if (tokens[j] && tokens[j].type === 'name') { j++; continue; }
      return false;
    }
    if (t.text === '=') return true;
    return false;
  }
}

// Is this name part of a `local a, b, c` name list (any position)?
function inLocalNameList(tokens, at) {
  let j = at - 1;
  for (;;) {
    const t = tokens[j];
    if (!t) return false;
    if (t.type === 'keyword' && t.text === 'local') return true;
    if (t.type === 'name' || t.text === ',') { j--; continue; }
    return false;
  }
}

// Is this name a function parameter or for-loop variable?
function isBinder(tokens, at) {
  // `for a, b in` / `for i =`
  let j = at - 1;
  if (tokens[j] && tokens[j].text === 'for') return true;
  while (tokens[j] && (tokens[j].type === 'name' || tokens[j].text === ',')) j--;
  if (tokens[j] && tokens[j].text === 'for') return true;
  // `function f(a, b` or `function(a, b`: scan back to the opening paren
  j = at - 1;
  let depth = 0;
  while (j >= 0) {
    const t = tokens[j];
    if (t.text === ')') depth++;
    else if (t.text === '(') {
      if (depth === 0) {
        // `(` preceded by `function` (maybe with a name/table path between)
        let k = j - 1;
        while (tokens[k] && (tokens[k].type === 'name' || tokens[k].text === '.' || tokens[k].text === ':')) k--;
        return !!(tokens[k] && tokens[k].text === 'function');
      }
      depth--;
    } else if (depth === 0 && t.type !== 'name' && t.text !== ',') return false;
    j--;
  }
  return false;
}

function substitute(tokens, aliases) {
  let count = 0;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type !== 'name' || !aliases.has(t.text) || isProperty(tokens, i)) continue;
    const valueText = aliases.get(t.text);
    // a value spanning lines would shift every line below the use site
    if (/[\r\n]/.test(valueText)) continue;
    // never rewrite the declaration site itself, at any position
    if (inLocalNameList(tokens, i)) continue;
    if (isBinder(tokens, i)) continue;
    // never rewrite assignment targets or table-record keys
    if (isAssignTarget(tokens, i)) continue;
    if (isTableKey(tokens, i)) continue;
    // Prefix position (indexed, method-called, or called): `nil[..]`, `59.x`,
    // `"s":m()`, `nil()` do not parse. Only a name/path value — or a
    // multi-token one, which is parenthesized below — may go here.
    const nx = tokens[i + 1];
    if (nx && (nx.text === '.' || nx.text === ':' || nx.text === '[' || nx.text === '(' ||
               nx.text === '{' || nx.type === 'string')) {
      const vt = tokenize(aliases.get(t.text));
      const isPath = vt.length > 0 && vt.every(x => x.type === 'name' || x.text === '.');
      if (vt.length <= 1 && !isPath) continue;
    }
    let expansion = tokenize(valueText);
    expansion.forEach(x => { x.nlBefore = 0; });
    expansion[0].nlBefore = t.nlBefore || 0;
    // a multi-token value must keep its grouping: `p * 2` with p -> `1 + 2`
    // has to become `(1 + 2) * 2`. Pure paths (`a.b.c`) are atoms already.
    const isPath = expansion.length > 0 &&
      expansion.every((x, k) => (k % 2 === 0 ? x.type === 'name' : x.text === '.'));
    if (expansion.length > 1 && !isPath) {
      expansion = [{ type: 'punct', text: '(' }, ...expansion, { type: 'punct', text: ')' }];
    }
    tokens.splice(i, 1, ...expansion);
    i += expansion.length - 1;
    count++;
  }
  return count;
}

// Record the line breaks preceding each token (`nlBefore`) by aligning the
// token stream to the source. Token texts are verbatim in-order source slices
// and gaps hold whitespace only, so the first occurrence at/after the cursor
// is always the token itself. Loaders can be line-sensitive (anti-beautify
// probes compare error-line numbers), so the normalizer keeps every line
// break exactly where it was; only intra-line spacing is normalized.
function markNewlines(source, tokens) {
  const countBreaks = (gap) => (gap.match(/\r\n|\r|\n/g) || []).length;
  let cursor = 0;
  let prevEnd = 0;
  for (const t of tokens) {
    if (t.nlBefore !== undefined) {   // synthesized token: gap already assigned
      cursor += 0;
      continue;
    }
    const at = source.indexOf(t.text, cursor);
    if (at === -1) { t.nlBefore = 0; continue; }
    t.nlBefore = countBreaks(source.slice(prevEnd, at));
    cursor = at + t.text.length;
    prevEnd = cursor;
  }
  tokens.trailingNl = countBreaks(source.slice(prevEnd));
}

function serialize(tokens) {
  let out = '';
  let prev = null;
  for (const t of tokens) {
    const nl = t.nlBefore || 0;
    if (!prev) {
      if (nl > 0) out += '\n'.repeat(nl);
    } else if (nl > 0) {
      out += '\n'.repeat(nl);
    } else if (prev.type === 'comment' && !/^--\[/.test(prev.text)) {
      out += '\n';   // defensive: a line comment must end its line
    } else if (wouldMerge(prev, t)) {
      out += ' ';
    } else if (t.type !== 'punct' || ![',', ';', ')', ']', '}'].includes(t.text)) {
      out += ' ';
    }
    out += t.text;
    prev = t;
  }
  if (tokens.trailingNl > 0) out += '\n'.repeat(tokens.trailingNl);
  return out;
}

function normalize(source, opts = {}) {
  const tokens = tokenize(source);
  markNewlines(source, tokens);
  const usage = usageOf(tokens);
  const inner = innermostOpeners(tokens);
  const topLevel = topLevelLocals(tokens, inner);
  const report = { aliases: 0, params: 0, folded: 0, substitutions: 0 };

  const aliases = collectAliases(tokens, usage, inner, topLevel);
  report.aliases = aliases.size;

  if (!opts.noParams) {
    const found = collectParamAliases(tokens);
    for (const [name, value] of found.aliases) {
      // the outer parameter must be the only declaration and never assigned
      if ((usage.decls.get(name) || 0) !== 1) continue;
      if ((usage.assigns.get(name) || 0) !== 0) continue;
      if (aliases.has(name)) continue;
      // the actual must be re-readable inside the body (no calls/varargs/
      // shadowable names), and every use must sit inside the body: a use
      // past `end` would bind to a global of the same name
      if (!valueSafe(tokens, usage, topLevel, value, found.fnIdx)) continue;
      if (useOutsideRange(tokens, name, found.fnIdx, found.bodyEnd)) continue;
      aliases.set(name, value);
      report.params++;
    }
  }

  report.folded = foldConstants(tokens);
  report.substitutions = substitute(tokens, aliases);
  const flat = serialize(tokens);
  // No reflow by default: the output keeps the input's line structure exactly,
  // which line-sensitive loaders require. Pass { beautify: true } (or beautify
  // options) for a reflowed copy meant for human reading only.
  const text = opts.beautify ? beautify(flat, opts.beautify === true ? {} : opts.beautify) : flat;
  return { text, report, aliases };
}

module.exports = { normalize, collectAliases, collectParamAliases, foldConstants, usageOf, serialize, tokenize, substitute };
