'use strict';

// ---------------------------------------------------------------------------
// Fingerprints for the obfuscators people actually hit, taken from real
// samples (github.com/kers0nec/obfuscator-samples). Each entry says what it is
// and which strategy the pipeline should use:
//
//   vmp     a virtual machine - the payload is bytecode, source is recovered
//           by devirtualization (only Luraph v15 today) or traced
//   loader  the script decrypts a plain-Luau payload and loadstring's it; the
//           payload can be recovered and printed as real source
//   static  static source transformation (string tables, control flow) - the
//           script runs as-is, so the trace plus the decoded strings is the
//           result
// ---------------------------------------------------------------------------

// helpers ------------------------------------------------------------------
const anyOf = (...pats) => {
  const res = pats.map(p => (p instanceof RegExp ? p : new RegExp(p)));
  return {
    test: src => {
      for (let i = 0; i < res.length; i++) {
        const m = res[i].exec(src);
        if (m) return { match: m, index: i };
      }
      return null;
    },
    patterns: res,
  };
};

// Samples circulating online often carry a banner, a markdown code fence or a
// stray `lua` word in front of the actual script; look through that noise.
function stripPreamble(source) {
  let out = source.replace(/^\uFEFF/, '');
  for (;;) {
    const before = out;
    out = out.replace(/^\s+/, '');
    out = out.replace(/^--\[(=*)\[[\s\S]*?\]\1\]\s*/, '');
    out = out.replace(/^(--[^\n]*\n)+\s*/, '');
    out = out.replace(/^(?:```|~~~)[a-z]*\s*/i, '');
    out = out.replace(/^CODE\s+lang=\s*["']?lua["']?[^\]]*\]\s*/i, '');
    out = out.replace(/^lua\s*\n/, '');
    if (out === before) break;
  }
  return out;
}

function firstMatch(pats, source, window = 4000) {
  const head = source.slice(0, window);
  for (const p of pats) {
    const m = p.exec(head);
    if (m) return m;
  }
  return null;
}

// ---------------------------------------------------------------------------
// The registry. `detect` returns { confidence, meta } or a number.
// ---------------------------------------------------------------------------
const FAMILIES = [
  {
    name: 'luraph',
    label: 'Luraph',
    strategy: 'vmp',
    note: 'v15 devirtualizes fully; older builds are traced',
    detect(source) {
      // v14+ : "This file was protected using Luraph Obfuscator v15.0 [https://lura.ph/]"
      // v10-13: "This file was generated using Luraph Obfuscator v12.2 by memcorrupt."
      const head = source.slice(0, 800);
      let m = /This file was (?:protected|generated) using Luraph Obfuscator v(\d+(?:\.\d+)*)/.exec(head);
      if (m) {
        const major = m[1].split('.')[0];
        const legacy = /generated using/i.test(m[0]);
        return {
          confidence: major === '15' ? 1.0 : 0.97,
          meta: { version: m[1], major, generation: legacy ? 'legacy header' : 'protected header' },
        };
      }
      if (/Luraph Obfuscator v([\d.]+)/.exec(head)) {
        const v = /Luraph Obfuscator v([\d.]+)/.exec(head)[1];
        return { confidence: 0.95, meta: { version: v, major: v.split('.')[0] } };
      }
      return 0;
    },
  },
  {
    name: 'wynfuscate',
    label: 'wYnFuscate (KeyForge)',
    strategy: 'vmp',
    note: 'KeyForge\'s hosted obfuscator: static bytecode/string extraction',
    detect(source) {
      const m = /--\s*Protected by wYnFuscate[: ].*/.exec(source.slice(0, 400));
      if (m) return { confidence: 0.97, meta: { banner: m[0].trim() } };
      if (/wYnFuscate|wynfuscate\.com/.test(source.slice(0, 2000))) return { confidence: 0.6, meta: null };
      return 0;
    },
  },
  {
    name: 'moonsec',
    label: 'MoonSec',
    strategy: 'loader',
    note: 'loadstring-based: the payload can come back as source',
    detect(source) {
      const head = source.slice(0, 2000);
      let m = /protected with MoonSec\s*(V\d(?:\.\d+)*)/i.exec(head);
      if (m) return { confidence: 0.98, meta: { version: 'V' + m[1].replace(/^V/i, '') } };
      m = /MoonSec\s*V(\d)/.exec(head);
      if (m) return { confidence: 0.9, meta: { version: 'V' + m[1] } };
      if (/MoonSec/i.test(head)) return { confidence: 0.6, meta: null };
      return 0;
    },
  },
  {
    name: 'moonveil',
    label: 'MoonVeil',
    strategy: 'vmp',
    note: 'VM: traced; static tables are decoded',
    detect(source) {
      const m = /This script was protected using the MoonVeil Obfuscator v([\d.]+)/i.exec(source.slice(0, 500));
      if (m) return { confidence: 0.98, meta: { version: m[1] } };
      if (/moonveil\.cc/i.test(source.slice(0, 2000))) return { confidence: 0.6, meta: null };
      return 0;
    },
  },
  {
    name: 'prometheus',
    label: 'Prometheus',
    strategy: 'loader',
    note: 'string-encrypted source: recovered payload plus decoded strings',
    detect(source) {
      const head = source.slice(0, 6000);
      const stringArray = /return\s*\(function\s*\(\.\.\.\)\s*local\s+\w+\s*=\s*\{\s*"\\\d{2,3}\\\d{2,3}/.test(head);
      if (stringArray) {
        const strong = /Prometheus/i.test(source.slice(0, 200000));
        return { confidence: strong ? 0.95 : 0.85, meta: { variant: strong ? 'strong' : 'weak/medium' } };
      }
      if (/Prometheus/i.test(source.slice(0, 3000))) return { confidence: 0.7, meta: null };
      return 0;
    },
  },
  {
    name: 'ironbrew1',
    label: 'IronBrew 1',
    strategy: 'vmp',
    note: 'VM: traced',
    detect(source) {
      if (/this file was generated using ironbrew1/i.test(source.slice(0, 400))) return { confidence: 0.98, meta: { version: '1' } };
      return 0;
    },
  },
  {
    name: 'ironbrew2',
    label: 'IronBrew 2',
    strategy: 'vmp',
    note: 'VM: traced, decoded strings dumped',
    detect(source) {
      const head = stripPreamble(source).slice(0, 600);
      const shape = /^local\s+\w+=string\.byte;local\s+\w+=string\.char;local\s+\w+=string\.sub;/.test(head.replace(/^[\s;]+/, ''));
      if (shape) return { confidence: 0.9, meta: { version: '2' } };
      if (/ironbrew2/i.test(source.slice(0, 2000))) return { confidence: 0.85, meta: { version: '2' } };
      return 0;
    },
  },
  {
    name: 'ironbrew3',
    label: 'IronBrew 3',
    strategy: 'vmp',
    note: 'VM: traced',
    detect(source) {
      const m = /--\s*ironbrew3:tm:,\s*v([\d.]+)/i.exec(source.slice(0, 300));
      if (m) return { confidence: 0.98, meta: { version: m[1] } };
      return 0;
    },
  },
  {
    name: 'hercules',
    label: 'Hercules',
    strategy: 'loader',
    note: 'loadstring-based: payload recovered as source',
    detect(source) {
      const m = /Obfuscated by Hercules v([\d.]+)/i.exec(source.slice(0, 300));
      if (m) return { confidence: 0.98, meta: { version: m[1] } };
      if (/hercules-obfuscator/i.test(source.slice(0, 400))) return { confidence: 0.8, meta: null };
      return 0;
    },
  },
  {
    name: 'fuscator77',
    label: '77fuscator',
    strategy: 'vmp',
    note: 'VM: traced',
    detect(source) {
      const m = /\[\[\s*77fuscator\s*([\d.]+)/i.exec(source.slice(0, 300));
      if (m) return { confidence: 0.98, meta: { version: m[1] } };
      // the same banner rendered as block art followed by a plain-text credit
      const head = source.slice(0, 4000);
      if (/77fuscator/i.test(head) || /CEHsVcBcuf/i.test(head)) {
        const v = /77fuscator[^\d]{0,10}([\d.]+)/i.exec(head);
        return { confidence: 0.9, meta: { version: v ? v[1] : null } };
      }
      return 0;
    },
  },
  {
    name: 'boronide',
    label: 'Boronide',
    strategy: 'loader',
    note: 'loadstring-based: payload recovered as source',
    detect(source) {
      const m = /herrtt'?s obfuscator,?\s*v([\d.]+)/i.exec(source.slice(0, 300));
      if (m) return { confidence: 0.98, meta: { version: m[1] } };
      if (/herrtts obf|Boronide/i.test(source.slice(0, 400))) return { confidence: 0.7, meta: null };
      return 0;
    },
  },
  {
    name: 'synapsexen',
    label: 'Synapse Xen',
    strategy: 'vmp',
    note: 'VM: traced, decoded strings dumped',
    detect(source) {
      const m = /Synapse Xen v([\d.]+)\s*by Synapse GP/.exec(source.slice(0, 400));
      if (m) return { confidence: 0.98, meta: { version: m[1] } };
      if (/SynapseXen_/.test(source.slice(0, 4000))) return { confidence: 0.85, meta: null };
      return 0;
    },
  },
  {
    name: 'luaobfuscator',
    label: 'LuaObfuscator.com',
    strategy: 'loader',
    note: 'string-encrypted source: recovered payload plus decoded strings',
    detect(source) {
      const head = source.slice(0, 600);
      // the site's banner, or the shape its generator always emits
      const banner = /LuaObfuscator|\.____\s+____+/.test(source.slice(0, 4000));
      const stripped = stripPreamble(source);
      // the generator always opens with a run of `local vN=` aliases; which
      // library each one points at varies with the build
      const window = stripped.slice(0, 400);
      const shape = /local\s+v0\s*=\s*\w+;local\s+v1\s*=\s*string\.byte;local\s+v2\s*=\s*string\.char;/.test(window)
        || /local\s+v0\s*=\s*string\.char;local\s+v1\s*=\s*string\.byte;local\s+v2\s*=\s*string\.sub;local\s+v3\s*=\s*bit32/.test(window)
        // table-of-renamed-functions build: v0["StrToNumber%0"]=tonumber; ...
        || /local\s+v0\s*=\s*\{\}\s*;[^\n]{0,200}?\["[A-Za-z]+%\d+"\]\s*=/.test(window);
      if (!banner && !shape) return 0;
      const m = /LuaObfuscator[\s\S]{0,200}?v?(\d+\.\d+\.\d+)/.exec(source.slice(0, 2000));
      const bxorTable = /string\.sub;local\s+v3\s*=\s*bit32/.test(stripped.slice(0, 200));
      return {
        confidence: banner ? (shape ? 0.95 : 0.9) : 0.85,
        meta: { version: m ? m[1] : null, variant: bxorTable ? 'xor string table' : null },
      };
    },
  },
  {
    name: 'psu',
    label: 'PSU / LPS',
    strategy: 'vmp',
    note: 'stage-machine VM with binary literals: traced',
    detect(source) {
      const head400 = stripPreamble(source).slice(0, 400);
      if (!/^return\(function\(/.test(head400)) return 0;
      const body = source.slice(0, 6000);
      // stage machine: `while <flag> do if <slot> <= <bound> then`, with the
      // stage numbers written as 0X18_ / 0B1_011_ / 25 depending on the build
      const machine = /while\s*\(\s*\w+\s*\)\s*do\s*if\s*\(\s*\w+\s*<=\s*(?:0[xX][0-9A-Fa-f_]+|0[bB][01_]+|\d+)\s*\)/.exec(body);
      const styled = /0[xX][0-9A-Fa-f]*_[0-9A-Fa-f_]*|0[bB][01_]+/.test(source.slice(0, 20000));
      if (/\[==\[\s*LPS\//.test(source.slice(0, 2000))) {
        // the packer build: base85 text that inflates to the real script
        return { confidence: 0.95, meta: { variant: 'packer (base85 + zstd)' } };
      }
      if (machine && (styled || /0[bB]/.test(body))) return { confidence: 0.8, meta: { variant: 'stage machine' } };
      if (machine) return { confidence: 0.7, meta: { variant: 'stage machine' } };
      return 0;
    },
  },
  {
    // Seen as the inner layer of LPS packer output and in IronBrew 1 builds:
    // a table of handler functions driven by `while true do if ((<folded
    // arithmetic>) ...` state numbers. Naming the *technique* is the honest
    // call here - the same shape ships under several vendor names.
    name: 'luau_state_vm',
    label: 'Luau state-machine VM',
    strategy: 'vmp',
    note: 'handler table dispatched by arithmetic-folded state numbers: traced',
    detect(source) {
      const head = stripPreamble(source).slice(0, 600);
      const tableVm = /^return\s*\(?\s*\{/.test(head);
      const folded = /\(\(\d+\s*[-+]\s*\d+\)\s*[-+]\s*\d+\)/.test(source.slice(0, 4000));
      const stateLoop = /while\s+true\s+do\s+if\s*\(\s*\(?\s*\w+\s*<=/.test(source.slice(0, 4000));
      if (tableVm && folded && stateLoop) return { confidence: 0.7, meta: { variant: 'numeric state machine' } };
      if (tableVm && folded) return { confidence: 0.55, meta: null };
      return 0;
    },
  },
  {
    name: 'kersfuscator',
    label: 'Kersfuscator',
    strategy: 'loader',
    note: 'local obfuscator: payload recovered as source',
    detect(source) {
      if (/kersfuscator|Kers0ne/i.test(source.slice(0, 500))) return { confidence: 0.8, meta: null };
      return 0;
    },
  },
];

function byName(name) {
  const f = FAMILIES.find(x => x.name === name);
  if (!f) throw new Error(`unknown obfuscator '${name}' (known: ${FAMILIES.map(x => x.name).join(', ')})`);
  return f;
}

function register(plugin) {
  FAMILIES.unshift(plugin);
}

module.exports = { FAMILIES, byName, register, anyOf, firstMatch, stripPreamble };
