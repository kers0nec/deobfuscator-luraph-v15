'use strict';

// ---------------------------------------------------------------------------
// wYnFuscate (wynfuscate.com) static decoder.
//
// wYnFuscate ships a Luau VM whose bytecode is stored as base-91 text: every
// pair of characters is a little-endian base-91 digit pair carrying 13 or 14
// bits, and the decoded stream is a Huffman-style bit sequence feeding the
// VM's handlers. Nothing has to run to read it, so this works even when the
// anti-tamper probes would trap a trace.
//
// Port of the reference dumper (kers0nec/deobfuscators/wynfuscate-dump.py),
// re-implemented here so the pipeline has no Python/lupa dependency.
// ---------------------------------------------------------------------------

// character code -> 0..90
const ALPHABET = {
  74: 0, 51: 1, 93: 2, 33: 3, 57: 4, 55: 5, 64: 6, 60: 7, 120: 8, 102: 9,
  108: 10, 70: 11, 117: 12, 63: 13, 53: 14, 124: 15, 100: 16, 105: 17, 79: 18, 68: 19,
  49: 20, 87: 21, 110: 22, 112: 23, 104: 24, 114: 25, 62: 26, 122: 27, 41: 28, 118: 29,
  71: 30, 89: 31, 67: 32, 113: 33, 76: 34, 80: 35, 84: 36, 52: 37, 96: 38, 88: 39,
  40: 40, 35: 41, 116: 42, 42: 43, 107: 44, 77: 45, 106: 46, 78: 47, 126: 48, 59: 49,
  54: 50, 86: 51, 65: 52, 125: 53, 75: 54, 69: 55, 43: 56, 103: 57, 36: 58, 47: 59,
  90: 60, 45: 61, 98: 62, 85: 63, 37: 64, 119: 65, 61: 66, 73: 67, 66: 68, 58: 69,
  115: 70, 48: 71, 91: 72, 46: 73, 101: 74, 81: 75, 95: 76, 44: 77, 94: 78, 56: 79,
  111: 80, 97: 81, 123: 82, 99: 83, 72: 84, 109: 85, 82: 86, 38: 87, 83: 88, 50: 89,
  121: 90,
};

const MODULUS = 2147483647;

// --- Lua string literal -> bytes -------------------------------------------
function luaStringBytes(literal) {
  const out = [];
  let i = 0;
  while (i < literal.length) {
    if (literal[i] === '\\') {
      i++;
      let num = '';
      while (i < literal.length && literal[i] >= '0' && literal[i] <= '9' && num.length < 3) {
        num += literal[i];
        i++;
      }
      if (num) {
        out.push(parseInt(num, 10) & 0xff);
      } else if (i < literal.length) {
        const c = literal[i];
        const esc = { n: 10, t: 9, r: 13, a: 7, b: 8, f: 12, v: 11, '\\': 92, '"': 34, "'": 39, '\n': 10 };
        out.push(esc[c] !== undefined ? esc[c] : c.charCodeAt(0));
        i++;
      }
    } else {
      out.push(literal.charCodeAt(i) & 0xff);
      i++;
    }
  }
  return Buffer.from(out);
}

// --- extractors -------------------------------------------------------------
const STRING_VALUE = /\[(\d+)\]\s*=\s*"((?:[^"\\]|\\.)*)"/g;

function extractChunkMap(src) {
  // bW: either a [n]="..." map or a plain array of single-char strings
  const entries = new Map();
  let m;
  STRING_VALUE.lastIndex = 0;
  while ((m = STRING_VALUE.exec(src))) entries.set(Number(m[1]), luaStringBytes(m[2]));

  if (!entries.size) {
    const arr = /local\s+\w+\s*=\s*\{\s*(?:"(?:[^"\\]|\\.)*"\s*,?\s*)+\}/.exec(src);
    if (arr) {
      const re = /"((?:[^"\\]|\\.)*)"/g;
      let i = 1;
      let am;
      while ((am = re.exec(arr[0]))) entries.set(i++, luaStringBytes(am[1]));
    }
  }

  const parts = [];
  for (const key of [...entries.keys()].sort((a, b) => a - b)) parts.push(entries.get(key));
  return Buffer.concat(parts);
}

function extractBase91(src) {
  const m = /local\s+j0\s*=\s*"((?:[^"\\]|\\.)*)"/.exec(src);
  return m ? luaStringBytes(m[1]) : null;
}

// base-91 text -> VM bytecode
function decodeBase91(data) {
  const out = [];
  let dl = -1;
  let accumulator = 0;
  let bitCount = 0;
  let emitted = 0;

  for (let i = 0; i < data.length; i++) {
    const digit = ALPHABET[data[i]];
    if (digit === undefined) continue;
    if (dl < 0) {
      dl = digit;
      continue;
    }
    dl = dl + digit * 91;
    accumulator += dl * Math.pow(2, bitCount);
    bitCount += (dl % 8192) > 88 ? 13 : 14;
    while (bitCount >= 8) {
      out.push(accumulator % 256);
      emitted++;
      accumulator = Math.floor(accumulator / 256);
      bitCount -= 8;
    }
    dl = -1;
  }
  if (dl >= 0) {
    accumulator += dl * Math.pow(2, bitCount);
    bitCount += 7;
    while (bitCount >= 8) {
      out.push(accumulator % 256);
      emitted++;
      accumulator = Math.floor(accumulator / 256);
      bitCount -= 8;
    }
  }
  return Buffer.from(out);
}

// handler bodies: `if <slot> < <bound> then <body>` chains
function extractHandlers(src) {
  const out = [];
  const re = /if\s+\w+\s*<\s*(0[xX][0-9A-Fa-f]+|0[bB][01_]+|\d+)\s+then\s+([\s\S]*?)(?=elseif\s+\w+\s*<|else\s|end\b)/g;
  let m;
  while ((m = re.exec(src))) out.push({ bound: Number(m[1].replace(/_/g, '')), body: m[2].trim() });
  return out;
}

// `local x = ((expr))` folded modulo 2^31-1
function extractLoaderConstants(src) {
  const out = {};
  const re = /local\s+(\w+)\s*=\s*\(\(([^()]*)\)/g;
  let m;
  while ((m = re.exec(src))) {
    try {
      // only plain integer arithmetic - never eval arbitrary text
      if (!/^[\d\s+\-*/%()]+$/.test(m[2]) || m[2].length > 200) continue;
      // eslint-disable-next-line no-new-func
      const v = Function(`"use strict";return (${m[2]})`)();
      if (Number.isFinite(v)) out[m[1]] = ((v % MODULUS) + MODULUS) % MODULUS;
    } catch { /* not a constant */ }
  }
  return out;
}

function extractAntiTamper(src) {
  const probe = name => new RegExp(`\\b${name}\\s*=\\s*false\\b`).test(src);
  return {
    getfenv: /\bgetfenv\b/.test(src),
    getgenv: /\bgetgenv\b/.test(src),
    setfenv: /\bsetfenv\b/.test(src),
    getmetatable: /\bgetmetatable\b/.test(src),
    rawset: /\brawset\b/.test(src),
    pcall: /\bpcall\b/.test(src),
    hP_probe: probe('hP'),
    dr_probe: probe('dr'),
    df_probe: probe('df'),
    frida_url_check: /FRIDA_SERVER_URL/.test(src),
    frida_helper_check: /FRIDA_HELPER_PATH/.test(src),
  };
}

// Neutralise the environment probes so an optional trace does not stop early.
function patchProbes(src) {
  let out = src;
  for (const name of ['hP', 'dr', 'df']) {
    out = out.replace(new RegExp(`\\blocal\\s+${name}\\s*=\\s*false\\b`), `local ${name} = true`);
    out = out.replace(new RegExp(`if\\s+${name}\\s+then\\s+by\\s*=\\s*1`), 'if false then by = 1');
  }
  return out;
}

// --- the whole picture ------------------------------------------------------
function decode(src) {
  const chunkMap = extractChunkMap(src);
  const raw = extractBase91(src);
  const bytecode = raw ? decodeBase91(raw) : null;
  return {
    chunkMap,
    base91: raw,
    bytecode,
    handlers: extractHandlers(src),
    constants: extractLoaderConstants(src),
    antiTamper: extractAntiTamper(src),
  };
}

// Printable strings inside the decoded bytecode - the quickest way to see what
// the protected script is about.
function bytecodeStrings(bytecode, min = 5) {
  if (!bytecode) return [];
  const found = [];
  let run = [];
  for (const byte of bytecode) {
    if (byte >= 0x20 && byte < 0x7f) {
      run.push(byte);
    } else {
      if (run.length >= min) found.push(Buffer.from(run).toString('latin1'));
      run = [];
    }
  }
  if (run.length >= min) found.push(Buffer.from(run).toString('latin1'));
  return [...new Set(found)];
}

module.exports = {
  decode,
  decodeBase91,
  extractChunkMap,
  extractBase91,
  extractHandlers,
  extractLoaderConstants,
  extractAntiTamper,
  patchProbes,
  bytecodeStrings,
  luaStringBytes,
  ALPHABET,
};
