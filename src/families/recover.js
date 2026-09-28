'use strict';

// ---------------------------------------------------------------------------
// Payload recovery for non-Luraph obfuscators.
//
// Every obfuscator runs its protected program one way or another, and the
// runtime already records what it executes: `runtime/envlog.luau` reports each
// string handed to loadstring()/load(), the decoded string constants, and the
// URLs the script asks for. This module turns that into artefacts:
//
//   * the recovered payload as *readable Luau* (beautified, never reworded);
//   * a report describing what was recognised and what came out.
//
// The same path serves every family - it is the "best effort that always
// works" layer underneath the specialised lifters.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const { beautify, looksLikeSource, tokenize } = require('../util/beautify');

const BYTECODE_MAGIC = /^\x1bL/;   // Luau/Lua compiled chunk

function classify(text) {
  if (!text || !text.length) return { kind: 'empty', note: 'empty chunk' };
  if (BYTECODE_MAGIC.test(text.slice(0, 4))) {
    return { kind: 'bytecode', note: 'compiled chunk (string.dump output)' };
  }
  const printable = (text.match(/[\x09\x0a\x0d\x20-\x7e]/g) || []).length / text.length;
  if (printable < 0.85) return { kind: 'data', note: 'not text (encrypted or binary payload)' };
  return { kind: 'source', note: 'Luau source' };
}

// Does the text still lex to the same tokens after beautifying? If not, the
// beautifier is not safe to emit and we keep the original bytes.
function safeBeautify(text) {
  try {
    const out = beautify(text);
    const before = tokenize(text).map(t => t.type + '\u0000' + t.text).join('\u0001');
    const after = tokenize(out).map(t => t.type + '\u0000' + t.text).join('\u0001');
    return before === after ? out : null;
  } catch {
    return null;
  }
}

// Short human summary of what a payload is, used in the report and in stderr.
function describe(text) {
  const tokens = tokenize(text);
  const names = new Map();
  let strings = 0;
  for (const t of tokens) {
    if (t.type === 'name') names.set(t.text, (names.get(t.text) || 0) + 1);
    if (t.type === 'string') strings++;
  }
  const globals = ['game', 'script', 'getgenv', 'getfenv', 'loadstring', 'require', 'task', 'wait']
    .filter(g => names.has(g));
  const lines = text.split('\n').length;
  return { lines, strings, globals, identifiers: names.size };
}

// ---------------------------------------------------------------------------
// recover(): read what the trace captured, write the payloads out.
// ---------------------------------------------------------------------------
function recover(job, meta = {}, opts = {}) {
  const chunks = job._lastChunks || {};
  const keys = Object.keys(chunks);
  const files = [];
  const notes = [];

  // results belong next to the output file, not in the throw-away work dir
  const dir = job.resultDir || path.dirname(job.tracePath);
  const stem = path.basename(job.input).replace(/\.(luau?|txt)$/i, '');
  fs.mkdirSync(dir, { recursive: true });

  // Biggest first: the real payload is usually the largest captured chunk.
  const ordered = keys
    .map(k => ({ key: k, text: chunks[k] }))
    .sort((a, b) => b.text.length - a.text.length);

  ordered.forEach(({ key, text }, index) => {
    const info = classify(text);
    const base = `${stem}.payload${ordered.length > 1 ? index + 1 : ''}`;

    if (info.kind === 'source') {
      const pretty = opts.beautify === false ? text : (safeBeautify(text) || text);
      const target = path.join(dir, `${base}.luau`);
      fs.writeFileSync(target, pretty, 'latin1');
      const d = describe(pretty);
      files.push({
        key,
        path: target,
        kind: 'source',
        bytes: text.length,
        lines: d.lines,
        strings: d.strings,
        globals: d.globals,
      });
      return;
    }

    if (info.kind === 'bytecode') {
      const target = path.join(dir, `${base}.luac`);
      fs.writeFileSync(target, Buffer.from(text, 'latin1'));
      files.push({ key, path: target, kind: 'bytecode', bytes: text.length });
      return;
    }

    if (info.kind === 'data') {
      // keep the raw bytes: another pass (or a human) can still use them
      const target = path.join(dir, `${base}.bin`);
      fs.writeFileSync(target, Buffer.from(text, 'latin1'));
      files.push({ key, path: target, kind: 'data', bytes: text.length });
    }
  });

  if (!ordered.length) {
    notes.push('no payload was captured by loadstring(); the script may run its bytecode in place');
  }

  const urls = job._lastUrls || [];
  const stringsPath = job.path('.strings.txt');
  let stringCount = 0;
  if (fs.existsSync(stringsPath)) {
    stringCount = fs.readFileSync(stringsPath, 'utf8').split('\n').filter(Boolean).length;
  }

  const report = buildReport(job, meta, { files, notes, urls, stringCount, chunks: ordered.length });
  const reportPath = path.join(dir, `${stem}.recovered.md`);
  fs.writeFileSync(reportPath, report, 'utf8');

  return { files, notes, urls, reportPath, stringCount };
}

function buildReport(job, meta, info) {
  const out = [];
  out.push(`# Recovered payloads - ${path.basename(job.input)}`);
  out.push('');
  out.push(`* obfuscator: **${meta.label || job.obfuscator || 'unknown'}**`);
  if (meta.strategy) out.push(`* strategy: ${meta.strategy}`);
  if (meta.version) out.push(`* version: ${meta.version}`);
  out.push(`* original size: ${job.source.length} bytes`);
  out.push('');
  out.push('## Payloads');
  out.push('');
  if (!info.files.length) {
    out.push('_Nothing was loadstring\'d during the trace._');
  } else {
    out.push('| file | kind | bytes | lines | strings | notable globals |');
    out.push('| --- | --- | --- | --- | --- | --- |');
    for (const f of info.files) {
      out.push(
        `| \`${f.path}\` | ${f.kind} | ${f.bytes} | ${f.lines || '-'} | ${f.strings || '-'} | ` +
        `${f.globals && f.globals.length ? f.globals.join(', ') : '-'} |`
      );
    }
  }
  out.push('');
  if (info.urls.length) {
    out.push('## URLs requested during the trace');
    out.push('');
    for (const u of info.urls) out.push(`* ${u}`);
    out.push('');
  }
  out.push('## Trace artefacts');
  out.push('');
  out.push(`* behaviour trace: \`${job.tracePath}\``);
  if (info.stringCount) out.push(`* decoded strings: \`${job.path('.strings.txt')}\` (${info.stringCount})`);
  out.push(`* chunks captured: ${info.chunks}`);
  for (const n of info.notes) out.push(`* note: ${n}`);
  out.push('');
  return out.join('\n');
}

module.exports = { recover, classify, describe, safeBeautify, looksLikeSource };
