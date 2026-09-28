'use strict';

// ---------------------------------------------------------------------------
// Stub run: execute a script under *stock* Luau with a minimal prelude.
//
// Some loaders (Luraph v14's LPH range coder, big base85 blobs) are pure-Lua
// decoders that do millions of string/arithmetic operations before they ever
// touch the game. Under the instrumented sandbox that is minutes of silent
// compute, so the run looks stalled and gets killed. Here the same code runs
// at native speed; the only instrumentation is a `loadstring`/`load` shim
// that dumps every chunk it is handed and then carries on, so multi-layer
// loaders are captured layer by layer.
//
// This is a *capture* pass, not an execution pass: whatever the payload does
// afterwards is irrelevant. The process runs with no `require`, an empty
// working directory and a hard timeout, and anything it prints is treated as
// untrusted bytes.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const harness = require('../core/harness');

const MARKER = '\0STUBCHUNK ';

// The prelude is deliberately small: loaders only need the standard library
// plus a couple of executor-isms to reach their loadstring call.
function prelude(minBytes) {
  return `
local __MIN = ${minBytes | 0}
local __REAL_LOADSTRING = loadstring
local __REAL_LOAD = load
local __n = 0
local function __dump(chunk, name)
  if type(chunk) ~= 'string' or #chunk < __MIN then return end
  __n = __n + 1
  io = nil
  -- length-prefixed framing: the bytes follow the marker line verbatim
  print("\\0STUBCHUNK " .. __n .. " " .. #chunk .. " " .. tostring(name or ''))
  print(chunk)
end
loadstring = function(chunk, name, ...)
  __dump(chunk, name)
  if type(chunk) == 'string' then
    return __REAL_LOADSTRING(chunk, name, ...)
  end
  return __REAL_LOADSTRING(chunk, ...)
end
if load ~= nil then
  load = function(chunk, name, ...)
    __dump(chunk, name)
    return __REAL_LOAD(chunk, name, ...)
  end
end
-- executor-isms some loaders probe before they decode
if getfenv == nil then getfenv = function() return _G end end
if setfenv == nil then setfenv = function() end end
if getgenv == nil then getgenv = function() return _G end end
if getrenv == nil then getrenv = function() return _G end end
require = nil
`;
}

function buildHarness(source, minBytes) {
  // The sample keeps top-level `return`s, so it runs as a function body and
  // any error it raises is reported instead of killing the capture.
  return (
    prelude(minBytes) +
    '\nlocal function __sample(...)\n' +
    source +
    '\nend\n' +
    'local __ok, __err = pcall(__sample)\n' +
    'if not __ok then print("\\0STUBERROR " .. tostring(__err):gsub("\\n", " ")) end\n'
  );
}

// Parse length-prefixed chunks out of raw stdout bytes.
function takeStubChunks(buf) {
  const chunks = [];
  const marker = Buffer.from(MARKER, 'latin1');
  let at = 0;
  let rest = [];
  let cursor = 0;
  const text = buf.toString('latin1');
  while (true) {
    const found = buf.indexOf(marker, at);
    if (found === -1) break;
    rest.push(text.slice(cursor, found));
    const eol = buf.indexOf(0x0a, found); // print() terminates the marker with \n
    if (eol === -1) break;
    const header = buf.slice(found + marker.length, eol).toString('latin1').trim().split(/\s+/);
    const len = parseInt(header[1], 10);
    const name = header.slice(2).join(' ') || null;
    if (!Number.isFinite(len) || len < 0 || eol + 1 + len > buf.length) break;
    chunks.push({ name, bytes: buf.slice(eol + 1, eol + 1 + len).toString('latin1') });
    cursor = eol + 1 + len;
    // skip the newline print() appends after the chunk
    if (buf[cursor] === 0x0a) cursor++;
    else if (buf[cursor] === 0x0d && buf[cursor + 1] === 0x0a) cursor += 2;
    at = cursor;
  }
  rest.push(text.slice(cursor));
  return { chunks, stdout: rest.join('') };
}

// Run the sample; returns whatever loadstring calls were captured, even when
// the script itself errors or the timeout hits mid-decode.
function run(source, opts = {}) {
  const luau = opts.luau || harness.findLuau();
  const minBytes = opts.minBytes != null ? opts.minBytes : 64;
  const timeoutMs = (opts.timeoutSec || 120) * 1000;

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'stubrun_'));
  const hpath = path.join(dir, 'stub.luau');
  fs.writeFileSync(hpath, buildHarness(source, minBytes), 'latin1');

  let res;
  try {
    res = spawnSync(luau, [hpath], {
      cwd: dir,
      timeout: timeoutMs,
      maxBuffer: 512 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
  } catch (e) {
    fs.rmSync(dir, { recursive: true, force: true });
    return { ok: false, chunks: [], error: `could not start luau: ${e.message}`, timedOut: false };
  }

  const out = res.stdout ? Buffer.from(res.stdout) : Buffer.alloc(0);
  const { chunks, stdout } = takeStubChunks(out);
  const stderr = res.stderr ? res.stderr.toString('latin1') : '';
  const stubError = /^\0STUBERROR (.*)$/m.exec(stdout);

  if (!opts.keepDir) fs.rmSync(dir, { recursive: true, force: true });

  return {
    ok: true,
    chunks: chunks.map((c, i) => ({ key: `stub${i + 1}`, ...c })),
    stdout,
    stderr: (stubError ? stubError[1] : '') + (stderr ? (stubError ? '\n' : '') + stderr : ''),
    timedOut: res.error && res.error.code === 'ETIMEDOUT',
    exitCode: res.status,
  };
}

module.exports = { run, prelude, buildHarness, takeStubChunks, MARKER };
