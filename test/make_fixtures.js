#!/usr/bin/env node
'use strict';

// Builds the KeyForge test fixtures: a two-hop delivery chain whose last hop
// hands back a base64 + XOR encoded script (the same shape a hosted delivery
// uses: fetch -> decode -> loadstring). Nothing here talks to the network, so
// the whole pipeline can be tested offline.
//
//   node test/make_fixtures.js

const fs = require('fs');
const path = require('path');

const DIR = __dirname;
const SAMPLES = path.join(DIR, '..', 'samples');
const KF = path.join(SAMPLES, 'keyforge');
const LEG = path.join(SAMPLES, 'legacy');
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function b64(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i], b1 = bytes[i + 1] || 0, b2 = bytes[i + 2] || 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63] + ALPHABET[n & 63];
  }
  return out;
}

function encode(plain, key) {
  // pad to a multiple of 3 so the decoder needs no '=' handling
  let text = plain;
  while (text.length % 3 !== 0) text += '\n';
  const bytes = Buffer.from(text, 'utf8');
  const out = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = bytes[i] ^ key.charCodeAt(i % key.length);
  }
  return b64(out);
}

const KEY = 'KEY-AAAA-BBBB-CCCC';

// A v14-era Luraph header with a small decoder in front of a Lua payload. Real
// v14 builds use a much larger VM, but the routing (header -> legacy pipeline,
// inner chunk inspected) is exactly the same, and this fixture needs no
// network and no key.
const legacyInner = `-- inner payload of the legacy fixture
local Players = game:GetService("Players")
local total = 0
for i = 1, 4 do
	total = total + i * i
end
print("legacy inner payload", total, Players.LocalPlayer.Name)
`;
const legacyBytes = [...Buffer.from(legacyInner, 'utf8')].map(b => b ^ 7);
const legacy = `-- This file was protected using Luraph Obfuscator v14.4.1 [https://lura.ph/]
return (function(...)
	local out = {}
	local n = select("#", ...)
	for i = 1, n do
		out[i] = string.char(bit32.bxor((select(i, ...)), 7))
	end
	return loadstring(table.concat(out))()
end)(${legacyBytes.join(', ')})
`;

const loader = `-- KeyForge default loader (test fixture, not a real project)
_G.script_key = "${KEY}"
loadstring(game:HttpGet("https://www.keyforge.win/v1/load/PROJTEST1"))()
`;

const delivery = `-- fixture: the body the /v1/load endpoint serves
local key = _G.script_key
assert(type(key) == "string" and #key > 0, "KeyForge: no script key")

local url = "https://cdn.example-keyforge.test/payload.enc?k=" .. key
local body = game:HttpGet(url)
assert(type(body) == "string" and #body > 0, "KeyForge: empty delivery")

local b64 = body:gsub("%s+", "")
local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local lookup = {}
for i = 1, #alphabet do
	lookup[alphabet:sub(i, i)] = i - 1
end

local bytes = {}
for i = 1, #b64, 4 do
	local a = lookup[b64:sub(i, i)] or 0
	local b = lookup[b64:sub(i + 1, i + 1)] or 0
	local c = lookup[b64:sub(i + 2, i + 2)] or 0
	local d = lookup[b64:sub(i + 3, i + 3)] or 0
	local n = a * 262144 + b * 4096 + c * 64 + d
	bytes[#bytes + 1] = math.floor(n / 65536) % 256
	bytes[#bytes + 1] = math.floor(n / 256) % 256
	bytes[#bytes + 1] = n % 256
end

local out = {}
for i = 1, #bytes do
	out[i] = string.char(bit32.bxor(bytes[i], string.byte(key, (i - 1) % #key + 1)))
end

local chunk = loadstring(table.concat(out))
assert(chunk, "KeyForge: payload did not compile")
return chunk()
`;

const hidden = `-- the "protected" script behind the chain (fixture)
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local function greet(name)
	return "hello, " .. name
end

local count = 0
for i = 1, 5 do
	count = count + i
end

print(greet("keyforge"), count, Players.LocalPlayer and Players.LocalPlayer.Name)
`;

// A chain whose payload is a real Luraph v15 build, when one is available, so
// the hand-off into the devirtualizer is covered too.
const sampleDir = path.join(SAMPLES, 'luraph-v15');
const luraphSample = ['RideAPet.lua', 'JumpForAnimals.lua', 'Blox Fruit.lua']
  .map(f => path.join(sampleDir, f))
  .find(f => fs.existsSync(f));

fs.mkdirSync(KF, { recursive: true });
fs.mkdirSync(LEG, { recursive: true });
fs.writeFileSync(path.join(KF, 'keyforge_loader.lua'), loader, 'utf8');
fs.writeFileSync(path.join(KF, 'keyforge_delivery.lua'), delivery, 'utf8');
fs.writeFileSync(path.join(KF, 'hidden_payload.lua'), hidden, 'utf8');
fs.writeFileSync(path.join(KF, 'payload_plain.enc'), encode(hidden, KEY), 'utf8');
fs.writeFileSync(path.join(LEG, 'luraph_v14_sample.lua'), legacy, 'utf8');

const map = {
  'https://www.keyforge.win/v1/load/PROJTEST1': 'keyforge_delivery.lua',
  'https://cdn.example-keyforge.test/payload.enc': 'payload_plain.enc',
};

if (luraphSample) {
  const src = fs.readFileSync(luraphSample, 'latin1');
  fs.writeFileSync(path.join(KF, 'payload_luraph.enc'), encode(src, KEY), 'utf8');
  map['https://cdn-luraph.example-keyforge.test/payload.enc'] = 'payload_luraph.enc';
  fs.writeFileSync(
    path.join(KF, 'keyforge_delivery_luraph.lua'),
    delivery.replace('https://cdn.example-keyforge.test/payload.enc', 'https://cdn-luraph.example-keyforge.test/payload.enc'),
    'utf8'
  );
  map['https://www.keyforge.win/v1/load/PROJTEST2'] = 'keyforge_delivery_luraph.lua';
  fs.writeFileSync(
    path.join(KF, 'keyforge_loader_luraph.lua'),
    loader.replace('PROJTEST1', 'PROJTEST2'),
    'utf8'
  );
}

fs.writeFileSync(path.join(KF, 'http_map.json'), JSON.stringify(map, null, 2) + '\n', 'utf8');

const sizes = [KF, LEG].flatMap(d => fs.readdirSync(d).sort().map(f => {
  const rel = path.relative(SAMPLES, path.join(d, f));
  const s = fs.statSync(path.join(d, f)).size;
  return `${rel} (${s} bytes)`;
}));
console.log('fixtures written to samples/:\n  ' + sizes.join('\n  '));
if (!luraphSample) console.log('(!) no Luraph sample found: the Luraph hand-off fixture was skipped');
