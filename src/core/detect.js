'use strict';

// ---------------------------------------------------------------------------
// Obfuscator detection.
//
// Every plugin answers a confidence between 0 and 1 plus a `meta` table that
// carries what was recognised (Luraph version, KeyForge project id, ...).
// The routing in deob.js picks the strongest plugin; when nothing matches we
// fall back to the generic behaviour tracer, which works on any obfuscator.
// ---------------------------------------------------------------------------

// Two header generations exist in the wild:
//   v14+  : "This file was protected using Luraph Obfuscator v15.0 [https://lura.ph/]"
//   v10-13: "This file was generated using Luraph Obfuscator v12.2 by memcorrupt."
const families = require('../families/families');

const LURAPH_HEADER = /This file was (protected|generated) using Luraph Obfuscator v(\d+)(?:\.(\d+))?(?:\.(\d+))?/;
const LURAPH_VM_SHAPE = /\[\d+\]=(bit32|buffer|string|table|math)\.\w+/;
const LURAPH_MARKERS = /LPH_[A-Z]|LPH:/;

// KeyForge (keyforge.win) is a delivery / key-system layer. A loader script
// holds the project id and asks the service for a protected payload.
const KF_LOAD_URL = /https?:\/\/(?:www\.)?keyforge\.win\/v1\/load\/([A-Za-z0-9_\-]{4,})/i;
const KF_ANY_URL = /https?:\/\/(?:www\.)?keyforge\.win\//i;
const KF_SDK_MARKER = /keyforge\.win\/sdk\/client\.lua/i;
const KF_API_HINT = /\bkeyforge\b|\bscript_key\b|KeyForgeKey|kf_[A-Za-z0-9]{8,}/i;

const SUPPORTED_VERSIONS = ['12', '13', '14', '15'];

function head(source, n) {
  return source.slice(0, n);
}

function luaEscape(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// --- Luraph ----------------------------------------------------------------

function luraphVersion(source) {
  const head500 = source.slice(0, 800);
  const m = LURAPH_HEADER.exec(head500);
  if (m) {
    return {
      major: m[2],
      minor: m[3] || null,
      patch: m[4] || null,
      full: [m[2], m[3], m[4]].filter(Boolean).join('.'),
      generation: m[1] === 'generated' ? 'legacy' : 'protected',
    };
  }
  return null;
}

function detectLuraph(source) {
  const v = luraphVersion(source);
  if (v) {
    // The header is authoritative: any version gets full confidence, and the
    // pipeline picks the strongest lifting strategy for that version.
    const exact = v.major === '15';
    return {
      confidence: exact ? 1.0 : 0.97,
      meta: {
        family: 'luraph',
        version: v.full,
        major: v.major,
        minor: v.minor,
        header: true,
        generation: v.generation,
      },
    };
  }

  const head2k = source.trimStart().slice(0, 2000);
  const looksLikeVm =
    (head2k.startsWith('return setmetatable({') &&
      (LURAPH_VM_SHAPE.test(head2k) || source.slice(0, 200000).includes('LPH'))) ||
    (LURAPH_MARKERS.test(source.slice(0, 4000)) && LURAPH_VM_SHAPE.test(head2k));
  if (looksLikeVm) {
    // Header stripped (re-pasted, or a chunk embedded in another script).
    return {
      confidence: 0.8,
      meta: { family: 'luraph', version: null, major: '15', minor: null, header: false },
    };
  }
  return { confidence: 0.0, meta: null };
}

// --- KeyForge --------------------------------------------------------------

function keyforgeInfo(source) {
  const loader = KF_LOAD_URL.exec(source);
  const anyUrl = KF_ANY_URL.exec(source);
  const sdk = KF_SDK_MARKER.test(source);
  if (!loader && !anyUrl && !sdk) return null;

  // _G.script_key = "..." / getgenv().SCRIPT_KEY = "..."
  let inlineKey = null;
  const keyRe = /(?:script_key|SCRIPT_KEY|ScriptKey|keyforge_key)\s*(?:=|]\s*=|\.\w+\s*=)\s*(["'])([^"'\n]{4,})\1/gi;
  const km = keyRe.exec(source);
  if (km) inlineKey = km[2];
  const gm = /(?:getgenv|getfenv)\(\)\s*\.\s*(?:SCRIPT_KEY|script_key)\s*(?:=|])\s*(["'])([^"'\n]{4,})\1/i.exec(source);
  if (gm) inlineKey = gm[2];

  return {
    projectId: loader ? loader[1] : null,
    url: loader ? loader[0] : (anyUrl ? anyUrl[0] : null),
    sdk,
    inlineKey,
    mentions: KF_API_HINT.test(source),
  };
}

function detectKeyForge(source) {
  const info = keyforgeInfo(source);
  if (!info) return { confidence: 0.0, meta: null };
  // A direct /v1/load/{id} reference is the canonical loader.
  let confidence = 0.0;
  if (info.projectId) confidence = 0.95;
  else if (info.sdk) confidence = 0.85;
  else if (info.url) confidence = 0.7;
  if (confidence > 0 && info.mentions) confidence = Math.min(1.0, confidence + 0.05);
  return { confidence, meta: { family: 'keyforge', ...info } };
}

// --- other obfuscators ------------------------------------------------------
// Fingerprints for every family in github.com/kers0nec/obfuscator-samples
// live in families.js; each one carries a strategy that tells the driver how
// far it can go (see src/families/recover.js).

const SUPPORT_TEXT = {
  vmp: 'behaviour trace + payload/string recovery (VM bytecode is not lifted)',
  loader: 'payload recovery + beautification (real source when the loader is decodable)',
  static: 'payload recovery + beautified source',
};

const FAMILY_PLUGINS = families.FAMILIES
  .filter(f => f.name !== 'luraph')       // rich handling above
  .map(f => ({
    name: f.name,
    label: f.label,
    family: f.name,
    strategy: f.strategy,
    note: f.note,
    supports: SUPPORT_TEXT[f.strategy] || 'behaviour trace',
    detect: (source) => f.detect(source),
  }));

// --- registry --------------------------------------------------------------

const PLUGINS = [
  {
    name: 'luraph_v15',
    label: 'Luraph v15',
    family: 'luraph',
    detect: detectLuraph,
    supports: 'full devirtualization (source reconstruction)',
  },
  {
    name: 'keyforge',
    label: 'KeyForge',
    family: 'keyforge',
    detect: detectKeyForge,
    supports: 'delivery-chain resolution + payload hand-off',
  },
];

for (const p of FAMILY_PLUGINS) PLUGINS.push(p);

const GENERIC = {
  name: 'generic',
  label: 'unknown obfuscator (behaviour trace only)',
  family: 'generic',
  supports: 'behaviour trace',
};

// Rewrites "Luraph v15" into "Luraph v14.4.1" once the version is known.
function labelFor(plugin, meta) {
  if (plugin.family === 'luraph' && meta && meta.version) {
    const exact = meta.header ? `Luraph v${meta.version}` : `Luraph (v${meta.major}-style VM, header missing)`;
    if (meta.major === '15') return exact + ' · full devirtualization';
    return exact + ' · VM hooks + behaviour trace';
  }
  if (plugin.family === 'luraph') return 'Luraph (headerless VMs) · VM hooks + behaviour trace';
  if (plugin.family === 'keyforge') {
    return meta && meta.projectId ? `KeyForge (project ${meta.projectId})` : 'KeyForge loader';
  }
  if (plugin.strategy) {
    const v = meta && meta.version ? ` v${meta.version}` : '';
    return `${plugin.label}${v} · ${SUPPORT_TEXT[plugin.strategy] || 'behaviour trace'}`;
  }
  return plugin.label;
}

function detect(source) {
  let best = { plugin: null, confidence: 0, meta: null };
  for (const p of PLUGINS) {
    let res;
    try {
      res = p.detect(source);
    } catch {
      continue;
    }
    if (!res) continue;
    const confidence = typeof res === 'number' ? res : (res.confidence || 0);
    const meta = typeof res === 'number' ? null : (res.meta || null);
    if (confidence > best.confidence) best = { plugin: p, confidence, meta };
  }
  if (!best.plugin || best.confidence < 0.5) {
    return { plugin: GENERIC, confidence: 0, meta: null, label: GENERIC.label };
  }
  return { ...best, label: labelFor(best.plugin, best.meta) };
}

function byName(name) {
  const p = PLUGINS.find(x => x.name === name);
  if (!p) throw new Error(`Unknown obfuscator '${name}' (known: ${PLUGINS.map(x => x.name).join(', ')})`);
  return p;
}

const HEADER_LINE_RE = /\s*--[ \t]*This file was protected using Luraph Obfuscator v[\d.]+[ \t]*\[https?:\/\/lura\.ph\/?\]/;

function restoreHeaderNewline(source) {
  const m = HEADER_LINE_RE.exec(source);
  if (m) {
    const end = m.index + m[0].length;
    const next = source[end];
    if (next !== '' && next !== '\n' && next !== '\r') {
      return source.slice(0, end) + '\n' + source.slice(end).replace(/^[ \t]+/, '');
    }
  }
  return source;
}

module.exports = {
  detect,
  SUPPORT_TEXT,
  byName,
  restoreHeaderNewline,
  keyforgeInfo,
  luraphVersion,
  labelFor,
  PLUGINS,
  GENERIC,
  SUPPORTED_VERSIONS,
  luaEscape,
};
