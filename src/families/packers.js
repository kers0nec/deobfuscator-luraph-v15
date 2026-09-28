'use strict';

// ---------------------------------------------------------------------------
// Static packers.
//
// Some obfuscators do not virtualize anything: they compress the original
// script, wrap it in a decoder, and loadstring() the result. When the decoder
// is a fixed, published scheme the payload can be recovered without executing
// anything - exact bytes, not a trace. Each entry here is a real decoder for
// one such scheme, verified against samples of the family.
// ---------------------------------------------------------------------------

const zlib = require('zlib');

// --- LPS ("stage machine" and packer builds) --------------------------------
// The packer build carries a big `[==[LPS/....]==]` literal. Groups of five
// characters are base-85 digits offset by 33, decoded little-endian into four
// bytes, and the byte stream is a zlib stream holding the original Luau:
//
//   local c=(t-33)+(s-33)*85+(r-33)*7225+(q-33)*614125+(c-33)*52200625
//   local q,r,s,c = c%256, ... ; string.char(q,r,s,c)
//
const LPS_B85_RE = /\[==\[\s*LPS\/([\s\S]*?)\]==\]/;

function base85GroupToBytes(group) {
  if (group.length !== 5) return null;
  let value = 0;
  let mul = 1;
  // least significant digit first, exactly like the Luau decoder
  const order = [4, 3, 2, 1, 0];
  for (const idx of order) {
    const digit = group.charCodeAt(idx) - 33;
    if (digit < 0 || digit > 84) return null;
    value += digit * mul;
    mul *= 85;
  }
  return [value % 256, Math.floor(value / 256) % 256, Math.floor(value / 65536) % 256, Math.floor(value / 16777216) % 256];
}

function decodeLpsPack(source) {
  const m = LPS_B85_RE.exec(source);
  if (!m) return null;

  // the encoder expands 'z' into five '!' digits; do the same before grouping
  const text = m[1].replace(/\s+/g, '').replace(/[^!-uz]/g, '').replace(/z/g, '!!!!!');
  const bytes = [];
  for (let i = 0; i + 5 <= text.length; i += 5) {
    const group = base85GroupToBytes(text.slice(i, i + 5));
    if (!group) return null;
    bytes.push(...group);
  }
  const raw = Buffer.from(bytes);
  const magic = raw.slice(0, 4).toString('hex');

  // zstd (current builds): 28 b5 2f fd
  if (magic === '28b52ffd' && typeof zlib.zstdDecompressSync === 'function') {
    try {
      const out = zlib.zstdDecompressSync(raw);
      if (out.length) return { text: out.toString('latin1'), how: 'base85 + zstd' };
    } catch { /* not zstd after all */ }
  }

  // zlib / deflate (older builds)
  for (const [name, fn] of [['zlib', zlib.inflateSync], ['deflate', zlib.inflateRawSync]]) {
    try {
      const out = fn(raw);
      if (out.length) return { text: out.toString('latin1'), how: `base85 + ${name}` };
    } catch { /* keep trying */ }
  }

  if (raw.length > 64 && (raw.match(/[\x09\x0a\x0d\x20-\x7e]/g) || []).length / raw.length > 0.9) {
    return { text: raw.toString('latin1'), how: 'base85 (uncompressed)' };
  }
  return null;
}

// --- simple numeric / escape encodings --------------------------------------
// `"\104\101\108\108\111"` style decimal escapes, commonly used by Prometheus.
function decodeEscapedString(literal) {
  const bytes = [];
  let i = 0;
  while (i < literal.length) {
    if (literal[i] === '\\') {
      let num = '';
      let j = i + 1;
      while (j < literal.length && num.length < 3 && literal[j] >= '0' && literal[j] <= '9') num += literal[j++];
      if (num) {
        bytes.push(parseInt(num, 10) & 0xff);
        i = j;
        continue;
      }
      const esc = { n: 10, t: 9, r: 13, '\\': 92, '"': 34, "'": 39 };
      const c = literal[i + 1];
      bytes.push(esc[c] !== undefined ? esc[c] : (c ? c.charCodeAt(0) : 10));
      i += 2;
      continue;
    }
    bytes.push(literal.charCodeAt(i) & 0xff);
    i++;
  }
  return Buffer.from(bytes);
}

// Collect every escaped string literal in a script. For Prometheus and its kin
// this alone reveals the interesting half of the payload (URLs, game paths,
// error text) even when the VM cannot be lifted.
function collectEscapedStrings(source, minLength = 4) {
  const out = new Map();
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(source))) {
    const raw = m[1];
    if (!/\\[0-9]{2,3}/.test(raw)) continue;
    let text = decodeEscapedString(raw).toString('latin1');
    // samples that are escaped twice (`"\\115\\103..."`, the value still holding
    // `\115`) carry the real bytes one decode further in
    if (/^(?:\\\d{2,3})+$/.test(text) && text.length <= raw.length * 1.2) {
      text = decodeEscapedString(text).toString('latin1');
    }
    if (text.length < minLength) continue;
    const printable = (text.match(/[\x09\x0a\x0d\x20-\x7e]/g) || []).length / text.length;
    if (printable < 0.9) continue;
    out.set(text, (out.get(text) || 0) + 1);
  }
  return [...out.keys()];
}

// `local x = "\27\76\117\97..."` - a whole embedded compiled chunk as escapes
function findEmbeddedChunks(source, minLength = 256) {
  const chunks = [];
  const re = /"((?:[^"\\]|\\.){50,})"/g;
  let m;
  while ((m = re.exec(source))) {
    const raw = m[1];
    if (!/\\[0-9]{2,3}/.test(raw)) continue;
    const bytes = decodeEscapedString(raw);
    if (bytes.length < minLength) continue;
    const printable = (bytes.toString('latin1').match(/[\x09\x0a\x0d\x20-\x7e]/g) || []).length / bytes.length;
    if (printable < 0.55) continue;
    chunks.push(bytes);
  }
  return chunks;
}

module.exports = {
  decodeLpsPack,
  decodeEscapedString,
  collectEscapedStrings,
  findEmbeddedChunks,
  base85GroupToBytes,
};
