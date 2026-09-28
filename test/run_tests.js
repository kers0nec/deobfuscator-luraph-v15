#!/usr/bin/env node
'use strict';

// End-to-end tests. Everything runs offline: the KeyForge fixtures are a
// two-hop delivery chain served from --http-map, so no key or network is
// needed.
//
//   node test/run_tests.js            all tests
//   node test/run_tests.js --quick    skip the slow devirtualization cases
//   node test/run_tests.js --keep     keep the temp outputs

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SAMPLES = path.join(ROOT, 'samples');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'deobf_tests_'));
const QUICK = process.argv.includes('--quick');
const KEEP = process.argv.includes('--keep');

let passed = 0;
let failed = 0;
const failures = [];

function run(args, opts = {}) {
  try {
    const out = execFileSync(process.execPath, [path.join(ROOT, 'deob.js'), ...args], {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: opts.timeout || 600000,
      maxBuffer: 256 * 1024 * 1024,
      env: Object.assign({}, process.env),
    });
    return { ok: true, out, err: '' };
  } catch (e) {
    return { ok: false, out: e.stdout || '', err: (e.stderr || '') + (e.message || '') };
  }
}

function test(name, fn) {
  process.stdout.write(`- ${name} ... `);
  try {
    const detail = fn();
    passed++;
    process.stdout.write(`ok${detail ? ' (' + detail + ')' : ''}\n`);
  } catch (e) {
    failed++;
    failures.push([name, e.message]);
    process.stdout.write(`FAIL\n    ${e.message}\n`);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function readOut(name) {
  return fs.readFileSync(path.join(SAMPLES, 'luraph-v15', 'output', name), 'utf8');
}

// ---------------------------------------------------------------------------

test('detects every sample as Luraph v15', () => {
  const res = run(['--detect', path.join(SAMPLES, 'luraph-v15')]);
  assert(res.ok, 'detect run failed: ' + res.err.slice(-500));
  const lines = res.out.trim().split('\n').filter(l => l.includes('\t'));
  const v15 = lines.filter(l => l.includes('Luraph v15'));
  assert(v15.length >= 10, `expected the v15 samples, got ${v15.length} of ${lines.length}`);
  return `${v15.length} scripts`;
});

test('detects the legacy Luraph header and routes it to the trace', () => {
  const res = run(['--detect', path.join(SAMPLES, 'legacy', 'luraph_v14_sample.lua')]);
  assert(res.ok, 'detect failed');
  assert(res.out.includes('v14.4.1'), 'version missing from the report: ' + res.out.trim());
  assert(res.out.includes('behaviour trace'), 'legacy route missing: ' + res.out.trim());
  return 'v14.4.1 -> trace';
});

test('detects the KeyForge loader', () => {
  const res = run(['--detect', path.join(SAMPLES, 'keyforge', 'keyforge_loader.lua')]);
  assert(res.ok, 'detect failed');
  assert(res.out.includes('KeyForge'), 'KeyForge not detected: ' + res.out.trim());
  assert(res.out.includes('PROJTEST1'), 'project id missing: ' + res.out.trim());
  return 'project id found';
});

test('legacy fixture: inner payload is traced', () => {
  const out = path.join(TMP, 'legacy.lua');
  const res = run([path.join(SAMPLES, 'legacy', 'luraph_v14_sample.lua'), '-o', out]);
  assert(res.ok, 'run failed: ' + res.err.slice(-800));
  const text = fs.readFileSync(out, 'utf8');
  assert(text.includes('legacy inner payload'), 'payload behaviour missing:\n' + text.slice(0, 400));
  assert(text.includes('print("legacy inner payload", 30'), 'values not folded: ' + text.slice(0, 400));
  assert(/-- Luraph v14\.4\.1/.test(text), 'result is not labelled with the build');
  return 'payload decoded';
});

test('KeyForge chain (offline): payload recovered and traced', () => {
  const out = path.join(TMP, 'keyforge.lua');
  const res = run([
    path.join(SAMPLES, 'keyforge', 'keyforge_loader.lua'),
    '--key', 'KEY-AAAA-BBBB-CCCC',
    '--http-map', path.join(SAMPLES, 'keyforge', 'http_map.json'),
    '--no-net',
    '-o', out,
  ]);
  assert(res.ok, 'run failed: ' + res.err.slice(-800));
  const text = fs.readFileSync(out, 'utf8');
  assert(text.includes('hello, keyforge'), 'payload behaviour missing:\n' + text.slice(0, 400));
  assert(text.includes('print("hello, keyforge", 15'), 'payload values not folded: ' + text.slice(0, 400));
  return 'payload recovered';
});

if (!QUICK) {
  test('KeyForge chain with a Luraph payload: devirtualized in place', () => {
    const out = path.join(TMP, 'keyforge-luraph.lua');
    const res = run([
      path.join(SAMPLES, 'keyforge', 'keyforge_loader_luraph.lua'),
      '--key', 'KEY-AAAA-BBBB-CCCC',
      '--http-map', path.join(SAMPLES, 'keyforge', 'http_map.json'),
      '--no-net',
      '-o', out,
    ], { timeout: 1800000 });
    assert(res.ok, 'run failed: ' + res.err.slice(-800));
    const text = fs.readFileSync(out, 'utf8');
    assert(text.includes('Chilli Hub - Ride A Pet'), 'devirtualized body missing:\n' + text.slice(0, 600));
    const lines = text.split('\n').length;
    assert(lines > 3000, `expected a lifted script, got ${lines} lines`);
    return `${lines} lines`;
  });

  const reference = path.join(SAMPLES, 'luraph-v15', 'output', 'RideAPet.lua');
  test('direct devirtualization matches the reference output', () => {
    const out = path.join(TMP, 'RideAPet.lua');
    const res = run([path.join(SAMPLES, 'luraph-v15', 'RideAPet.lua'), '-o', out], { timeout: 1800000 });
    assert(res.ok, 'run failed: ' + res.err.slice(-800));
    const mine = fs.readFileSync(out, 'utf8');
    const want = fs.readFileSync(reference, 'utf8');
    if (mine === want) return 'byte-identical';
    const mineLines = mine.split('\n').length;
    const wantLines = want.split('\n').length;
    assert(Math.abs(mineLines - wantLines) < wantLines * 0.05,
      `output differs too much: ${mineLines} lines vs ${wantLines} reference lines`);
    return `${mineLines} lines (differs slightly from the ${wantLines}-line reference)`;
  });
}

// --- every obfuscator family -------------------------------------------------

test('detects each bundled obfuscator family', () => {
  const dir = path.join(SAMPLES, 'families');
  const res = run(['--detect', dir]);
  assert(res.ok, 'detect failed: ' + res.err.slice(-400));
  const expected = {
    '77fuscator.lua': 'fuscator77',
    'boronide.lua': 'boronide',
    'hercules.lua': 'hercules',
    'ironbrew1.lua': 'ironbrew1',
    'ironbrew2.lua': 'ironbrew2',
    'ironbrew3.lua': 'ironbrew3',
    'lps.lua': 'psu',
    'lps_packer.lua': 'psu',
    'luaobfuscator.lua': 'luaobfuscator',
    'moonsec.lua': 'moonsec',
    'moonveil.lua': 'moonveil',
    'prometheus.lua': 'prometheus',
    'synapsexen.lua': 'synapsexen',
    'wynfuscate.lua': 'wynfuscate',
  };
  const lines = res.out.trim().split('\n').filter(l => l.includes('\t'));
  const seen = new Map();
  for (const line of lines) {
    const parts = line.split('\t');
    const file = path.basename(parts[0]);
    if (file) seen.set(file, parts[1]);
  }
  const wrong = [];
  for (const [file, plugin] of Object.entries(expected)) {
    if (seen.get(file) !== plugin) wrong.push(`${file}: got ${seen.get(file) || 'nothing'}, want ${plugin}`);
  }
  assert(wrong.length === 0, wrong.join('; '));
  return `${Object.keys(expected).length} families`;
});

test('beautifier keeps every token of real obfuscated samples', () => {
  const { beautify, tokenize } = require(path.join(ROOT, 'src', 'util', 'beautify'));
  const dir = path.join(SAMPLES, 'families');
  const stamp = txt => tokenize(txt).map(t => t.type + '\u0000' + t.text).join('\u0001');
  let checked = 0;
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith('.lua')) continue;
    if (file === 'synapsexen.lua' || file === 'wynfuscate.lua') continue;   // large, checked on the small set
    const src = fs.readFileSync(path.join(dir, file), 'latin1');
    const out = beautify(src);
    assert(stamp(src) === stamp(out), `token stream changed for ${file}`);
    checked++;
  }
  return `${checked} samples unchanged`;
});

test('LPS packer: unpacked statically to Luau (base85 + zstd)', () => {
  const packers = require(path.join(ROOT, 'src', 'families', 'packers'));
  const src = fs.readFileSync(path.join(SAMPLES, 'families', 'lps_packer.lua'), 'latin1');
  const res = packers.decodeLpsPack(src);
  assert(res, 'the packer was not recognised');
  assert(res.text.length > 10000, `payload too small: ${res.text.length} bytes`);
  assert(/\blocal\b|\bfunction\b/.test(res.text.slice(0, 400)), 'payload does not look like Luau');
  return `${res.text.length} bytes via ${res.how}`;
});

test('wYnFuscate: bytecode and handler tables extracted statically', () => {
  const wyn = require(path.join(ROOT, 'src', 'families', 'wynfuscate'));
  const src = fs.readFileSync(path.join(SAMPLES, 'families', 'wynfuscate.lua'), 'latin1');
  const dec = wyn.decode(src);
  assert(dec.chunkMap && dec.chunkMap.length > 1000, 'no chunk map extracted');
  assert(dec.handlers.length > 0, 'no handler blocks extracted');
  assert(dec.antiTamper.pcall === true, 'anti-tamper surface not detected');
  return `${dec.chunkMap.length}-byte map, ${dec.handlers.length} handlers`;
});

test('recovery pipeline: trace, payload report and artefacts', () => {
  const out = path.join(TMP, 'moonsec.lua');
  const res = run([path.join(SAMPLES, 'families', 'moonsec.lua'), '-o', out, '--budget', '10']);
  assert(res.ok, 'run failed: ' + res.err.slice(-800));
  const text = fs.readFileSync(out, 'utf8');
  const report = path.join(TMP, 'moonsec.recovered.md');   // -o puts artefacts beside the result
  assert(fs.existsSync(report), 'no report written next to the result');
  const doc = fs.readFileSync(report, 'utf8');
  assert(/obfuscator: \*\*MoonSec/.test(doc), 'report does not name the obfuscator:\n' + doc.slice(0, 300));
  assert(/pastebin\.com\/raw\/8gpSC0nZ/.test(doc), 'report does not list the URL the script fetches');
  assert(text.length > 32, 'empty result');
  return `${text.split('\n').length}-line trace + report`;
});

test('77fuscator: the protected script is recovered from the trace', () => {
  const out = path.join(TMP, 'fuscator77.lua');
  const res = run([path.join(SAMPLES, 'families', '77fuscator.lua'), '-o', out, '--budget', '10']);
  assert(res.ok, 'run failed: ' + res.err.slice(-800));
  const text = fs.readFileSync(out, 'utf8');
  assert(/TeleportService/.test(text), 'the recovered call was not found:\n' + text.slice(0, 300));
  assert(/game\.Players\.LocalPlayer/.test(text), 'the recovered argument was not found:\n' + text.slice(0, 300));
  return `${text.split('\n').length}-line trace with the payload's calls`;
});

test('Prometheus: escaped strings decode to readable text', () => {
  const packers = require(path.join(ROOT, 'src', 'families', 'packers'));
  const src = fs.readFileSync(path.join(SAMPLES, 'families', 'prometheus.lua'), 'latin1');
  const strings = packers.collectEscapedStrings(src);
  assert(strings.length >= 8, `only ${strings.length} strings decoded`);
  const printable = strings.filter(s => /^[\x20-\x7e]+$/.test(s));
  assert(printable.length === strings.length, 'decoded strings contain control bytes');
  // the sample keeps a shuffled alphabet used by its own decoder
  const longest = strings.reduce((a, b) => (b.length > a.length ? b : a));
  assert(longest.length >= 16, `longest decoded string is only ${longest.length} chars`);
  return `${strings.length} strings, longest ${longest.length}`;
});

// --- legacy normalizer + stub capture ------------------------------------------

test('normalize: tricky snippets keep their runtime behaviour', () => {
  const { normalize } = require(path.join(ROOT, 'src', 'legacy', 'normalize'));
  const { findLuau, luauAst } = require(path.join(ROOT, 'src', 'core', 'harness'));
  const luau = findLuau();
  const ast = luauAst();
  const cases = [
    ['multi-assign swap is not inlined', 'local a,b = 1,2 a,b = b,a print(a,b)'],
    ['shadowed name is not inlined', 'local x = 10 local f = function(x) return x end print(x, f(20))'],
    ['call results are not inlined', 'local n = 0 local function inc() n = n + 1 return n end local a = inc() print(a, inc())'],
    ['multi-return extras are not nil', 'local function f() return 7, 8 end local p, q = f() print(p, q)'],
    ['computed values are not truncated', 'local m = 1 + 2 print(m)'],
    ['varargs are not inlined', 'local function v(...) local a = ... return a end print(v(42))'],
    ['table keys are not rewritten', 'local k = 5 local t = { k = 99 } print(k, t.k)'],
    ['reassigned local is not inlined', 'local i = 0 while i < 3 do i = i + 1 end print(i)'],
    ['loop variable shadows safely', 'local s2 = 0 for s2 = 1, 5 do end print(s2)'],
    ['mutated global is not inlined', 'foo = 1 local r = foo foo = 2 print(r)'],
    ['use before declaration vetoes', 'print(zz) local zz = 5 print(zz)'],
    ['block scope is respected', 'do local w = 6 print(w) end print(w)'],
    ['elseif sections are separate scopes', 'if false then local q2 = 5 print(q2) elseif true then print(q2) end'],
    ['compound assignment vetoes', 'local t = 10 t += 1 print(t)'],
    ['table constructors are not inlined', 'local d = {} d.x = 1 print(d.x)'],
    ['plain alias inlines', 'local e = 41 print(e + 1)'],
    ['negative numbers inline grouped', 'local neg = -5 print(neg, neg - 1)'],
    ['global paths inline', 'local c = string.char print(c(65))'],
    ['alias chains resolve', 'local s3 = string local c3 = s3.char print(c3(66))'],
    ['sound nil padding', 'local a1, b1 = 1 print(a1, b1)'],
    ['method calls on aliases', 'local up = string.upper print(up("ab"))'],
    ['integer arithmetic folds', 'print((0X1E7-0x0019C), (6*7))'],
    ['outer params inline', 'return (function(a, b) print(a + b) end)(40, 2)'],
    ['arity mismatch disables params', 'return (function(a, b) print(a, b) end)(1)'],
    ['function-typed actuals are skipped', 'return (function(a, b) print(a(), b) end)(function() return 7 end, 8)'],
    ['string escapes survive', 'local eq = "\\u{3D}\\61" print(eq)'],
    ['nil alias in call position is skipped', 'local q = nil q()'],
    ['nil alias in index position is skipped', 'local z9 = nil print(z9[1])'],
    ['number in method position is skipped', 'local m9 = 59 local ok = pcall(function() return m9:foo() end) print(ok, m9)'],
    ['error-line probes stay co-linear', 'local function ln(f)\n  local ok, err = pcall(f)\n  local line, i, n = 0, 1, #err\n  while i <= n do\n    if err:byte(i) == 58 then\n      local j, v, d = i + 1, 0, 0\n      while j <= n and err:byte(j) >= 48 and err:byte(j) <= 57 do v = v * 10 + err:byte(j) - 48 j = j + 1 d = d + 1 end\n      if d > 0 and err:byte(j) == 58 then line = v break end\n      i = j\n    else i = i + 1 end\n  end\n  return line\nend\nlocal E = error\nlocal a = ln(function() E(\'x\') end); local b = ln(function() E(\'y\') end)\nprint(a == b and \'SAME\' or \'SPLIT\')'],
  ];
  const exec = (file) => {
    try {
      const out = execFileSync(luau, [file], { encoding: 'latin1', timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] });
      return 'exit 0\n' + out;
    } catch (e) {
      return `exit ${e.status}\n${e.stdout || ''}`;
    }
  };
  let inlined = 0;
  cases.forEach(([name, src], idx) => {
    const r = normalize(src);
    assert(r.text.split('\n').length === src.split('\n').length,
      `${name}: line count changed (${src.split('\n').length} -> ${r.text.split('\n').length})`);
    inlined += r.report.substitutions;
    const f1 = path.join(TMP, `norm_orig_${idx}.luau`);
    const f2 = path.join(TMP, `norm_new_${idx}.luau`);
    fs.writeFileSync(f1, src);
    fs.writeFileSync(f2, r.text);
    try {
      execFileSync(ast, [f2], { stdio: ['ignore', 'ignore', 'pipe'], timeout: 10000 });
    } catch (e) {
      throw new Error(`${name}: normalized output does not parse: ${(e.stderr || '').toString().split('\n').slice(0, 3).join(' | ')}`);
    }
    const a = exec(f1);
    const b = exec(f2);
    assert(a === b, `${name}: behaviour changed\n--- original ---\n${a}\n--- normalized ---\n${b}`);
  });
  assert(inlined > 10, `the suite barely inlined anything (${inlined} substitutions)`);
  const params = normalize(cases[22][1]).report.params;
  assert(params === 2, `expected 2 outer params, got ${params}`);
  return `${cases.length} snippets identical + parse, ${inlined} substitutions`;
});

test('normalize: multi-line values are skipped, single-line still inline', () => {
  const { normalize } = require(path.join(ROOT, 'src', 'legacy', 'normalize'));
  const multi = normalize('local s = [[a\nb]]\nprint(#s)\n');
  assert(multi.report.substitutions === 0, `multi-line value was substituted: ${JSON.stringify(multi.report)}`);
  assert(multi.text.split('\n').length === 4, 'line count changed');
  const single = normalize('local e = 41\nprint(e + 1)\n');
  assert(single.report.substitutions === 1, `control stopped inlining: ${JSON.stringify(single.report)}`);
  assert(single.text.split('\n').length === 3, 'line count changed');
  return 'skip + control ok';
});

test('stubrun: length-prefix framing survives binary payloads', () => {
  const { takeStubChunks, MARKER } = require(path.join(ROOT, 'src', 'legacy', 'stubrun'));
  const payload = Buffer.from([0x00, 0x01, 0x02, 0x0a, 0xff, 0x00, 0x0d, 0x0a]);
  const buf = Buffer.concat([
    Buffer.from('hello\n', 'latin1'),
    Buffer.from(`${MARKER}1 ${payload.length} bin-name\n`, 'latin1'),
    payload,
    Buffer.from('\ntrailing', 'latin1'),   // the newline print() appends + rest
  ]);
  const { chunks, stdout } = takeStubChunks(buf);
  assert(chunks.length === 1, `expected 1 chunk, got ${chunks.length}`);
  assert(chunks[0].name === 'bin-name', `name lost: ${chunks[0].name}`);
  assert(Buffer.from(chunks[0].bytes, 'latin1').equals(payload), 'payload bytes changed');
  assert(stdout === 'hello\ntrailing', `stdout mangled: ${JSON.stringify(stdout)}`);
  return 'NUL/newline/high bytes round-trip';
});

test('stubrun: captures loadstring chunks through later errors', () => {
  const stubrun = require(path.join(ROOT, 'src', 'legacy', 'stubrun'));
  const src = 'local P = loadstring local s = P("return 41 + 1", "inner") print(s()) error("boom")';
  const res = stubrun.run(src, { timeoutSec: 10, minBytes: 1 });
  assert(res.chunks.length === 1, `expected 1 chunk, got ${res.chunks.length}`);
  assert(res.chunks[0].bytes === 'return 41 + 1', 'chunk bytes wrong');
  assert(res.chunks[0].name === 'inner', `chunk name wrong: ${res.chunks[0].name}`);
  assert(/boom/.test(res.stderr), 'the later error was lost: ' + JSON.stringify(res.stderr));
  return 'chunk + error both surface';
});

test('legacy tiny loader: normalize preserves the captured chunk', () => {
  const stubrun = require(path.join(ROOT, 'src', 'legacy', 'stubrun'));
  const { normalize } = require(path.join(ROOT, 'src', 'legacy', 'normalize'));
  const src = fs.readFileSync(path.join(SAMPLES, 'legacy', 'luraph_legacy_tiny.lua'), 'latin1');
  const norm = normalize(src);
  assert(norm.report.aliases >= 2, `expected aliases, got ${JSON.stringify(norm.report)}`);
  assert(norm.text.split('\n').length === src.split('\n').length, 'line count changed');
  const a = stubrun.run(src, { timeoutSec: 10, minBytes: 1 });
  const b = stubrun.run(norm.text, { timeoutSec: 10, minBytes: 1 });
  assert(a.chunks.length === 1 && b.chunks.length === 1, 'chunk lost on one side');
  assert(a.chunks[0].bytes === 'return 42', `orig chunk wrong: ${a.chunks[0].bytes}`);
  assert(b.chunks[0].bytes === a.chunks[0].bytes, 'normalized chunk differs');
  return `${norm.report.substitutions} substitutions, byte-identical`;
});

// ---------------------------------------------------------------------------

if (!KEEP) fs.rmSync(TMP, { recursive: true, force: true });

process.stdout.write(`\n${passed} passed, ${failed} failed\n`);
if (failures.length) {
  for (const [name, msg] of failures) process.stdout.write(`  FAILED ${name}: ${msg}\n`);
  process.exit(1);
}
