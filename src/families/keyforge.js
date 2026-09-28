'use strict';

// ---------------------------------------------------------------------------
// KeyForge (keyforge.win) delivery-chain resolution.
//
// A KeyForge protected release is not a single script. What the user pastes
// into their executor is a *loader*:
//
//     _G.script_key = "KEY"
//     loadstring(game:HttpGet("https://www.keyforge.win/v1/load/PROJECT_ID"))()
//
// The service answers that request with a (protected) Luau payload. Fetching
// it needs network + a key, which an offline sandbox cannot do, so the chain is
// resolved here and the payload is then handed to the normal pipeline
// (Luraph devirtualization, or the behaviour tracer).
//
// Everything is read-only: we fetch exactly what the loader would fetch and
// never execute the loader with live credentials.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const detectModule = require('../core/detect');
const { keyforgeInfo } = detectModule;

const USER_AGENTS = ['Roblox/WinInet', 'okhttp/3.10.0', 'KeyForge-Loader/1.0'];

// How a key can be attached when we replay the loader's own request. KeyForge
// loaders usually read _G.script_key and forward it themselves; when we replay
// that request we have to guess the same channel, so every common one is tried
// until the service answers with a script.
const KEY_CHANNELS = [
  { name: 'header x-script-key', headers: k => ({ 'x-script-key': k }) },
  { name: 'header script-key', headers: k => ({ 'script-key': k }) },
  { name: 'header x-keyforge-key', headers: k => ({ 'x-keyforge-key': k }) },
  { name: 'header x-api-key', headers: k => ({ 'x-api-key': k }) },
  { name: 'header authorization', headers: k => ({ authorization: k }) },
  { name: 'header authorization: Bearer', headers: k => ({ authorization: 'Bearer ' + k }) },
  { name: 'query ?key=', query: k => ({ key: k }) },
  { name: 'query ?script_key=', query: k => ({ script_key: k }) },
  { name: 'query ?k=', query: k => ({ k }) },
  { name: 'body (POST text)', body: k => k },
  { name: 'body json (POST)', body: k => JSON.stringify({ key: k, script_key: k }) },
];

// A URL can also be a file: "file:///x/loader.lua" or a plain path. That keeps
// the whole KeyForge flow usable offline, with a delivery response saved by
// hand (and makes the pipeline testable without touching the service).
function localFile(url) {
  let p = null;
  if (/^file:\/\//i.test(url)) {
    try {
      p = require('url').fileURLToPath(url);
    } catch {
      return null;
    }
  } else if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url) && fs.existsSync(url)) {
    p = url;
  }
  if (!p || !fs.existsSync(p) || !fs.statSync(p).isFile()) return null;
  return p;
}

function request(url, opts = {}) {
  const local = localFile(url);
  if (local) {
    return Promise.resolve({
      statusCode: 200,
      headers: {},
      contentType: 'text/plain',
      body: fs.readFileSync(local, 'utf8'),
      local: true,
    });
  }
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (e) {
      return reject(new Error(`invalid URL: ${url}`));
    }
    const client = parsed.protocol === 'https:' ? https : http;
    const headers = Object.assign(
      {
        'User-Agent': USER_AGENTS[0],
        Accept: '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        Connection: 'close',
      },
      opts.headers || {}
    );
    const payload = opts.body != null ? Buffer.from(String(opts.body), 'utf8') : null;
    if (payload) {
      headers['Content-Type'] = opts.contentType || 'text/plain; charset=utf-8';
      headers['Content-Length'] = payload.length;
    }

    const req = client.request(
      url,
      { method: opts.method || (payload ? 'POST' : 'GET'), headers },
      res => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return resolve(request(new URL(res.headers.location, url).href, opts));
        }
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () =>
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            contentType: res.headers['content-type'] || '',
            body: Buffer.concat(chunks).toString('utf8'),
          })
        );
      }
    );
    req.on('error', reject);
    req.setTimeout(opts.timeout || 20000, () => {
      req.destroy();
      reject(new Error(`timeout after ${(opts.timeout || 20000) / 1000}s`));
    });
    if (payload) req.write(payload);
    req.end();
  });
}

function maskKey(key) {
  if (!key) return '(none)';
  if (key.length <= 8) return key[0] + '***' + key[key.length - 1];
  return key.slice(0, 4) + '***' + key.slice(-4);
}

function withQuery(url, params) {
  const u = new URL(url);
  for (const [k, v] of Object.entries(params || {})) u.searchParams.set(k, v);
  return u.href;
}

// A response is "a script" when it looks like Luau rather than JSON/HTML.
function looksLikeLua(text) {
  if (!text || text.length < 20) return false;
  const t = text.trim();
  if (t.startsWith('{') || t.startsWith('[{"') || t.startsWith('<')) return false;
  if (/^\s*<!doctype html/i.test(t)) return false;
  const luaish =
    /(^|\n)\s*(local|function|return|if|for|while|repeat|do|--)/.test(t) ||
    /LPH_|Luraph|loadstring|game:HttpGet|setmetatable/.test(t.slice(0, 4000));
  const printable = (t.match(/[\x09\x0a\x0d\x20-\x7e]/g) || []).length / t.length;
  return luaish && printable > 0.9;
}

// Peel obvious static wrappers: base64, \xNN / \ddd escapes, hex blobs.
function staticUnwrap(text) {
  const notes = [];
  let out = text;

  // Already a script: nothing to unwrap (and rewriting escapes here would
  // corrupt the source we just fetched).
  if (looksLikeLua(text)) return { text, notes };

  const tryDecode = (label, fn) => {
    try {
      const dec = fn(out);
      if (dec && dec.length >= 64 && looksLikeLua(dec)) {
        out = dec;
        notes.push(label);
        return true;
      }
    } catch {}
    return false;
  };

  for (let i = 0; i < 3; i++) {
    const before = out;
    tryDecode('base64', t => Buffer.from(t.trim(), 'base64').toString('utf8'));
    tryDecode('hex escapes', t =>
      t.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    );
    tryDecode('decimal escapes', t =>
      t.replace(/\\([0-9]{1,3})/g, (_, d) => String.fromCharCode(parseInt(d, 10)))
    );
    if (out === before) break;
  }
  return { text: out, notes };
}

// Finds the follow-up endpoints a delivered loader talks to, so the request
// that produces the real payload can be replayed with the user's key.
function followUpTargets(loaderText, origin) {
  const targets = [];
  const seen = new Set();
  const urlRe = /https?:\/\/[^\s"'<>()\\]+/g;
  const push = (url) => {
    const clean = url.replace(/[.,;:]+$/, '');
    if (!clean || seen.has(clean)) return;
    if (/\.(png|jpg|jpeg|gif|svg|ico|woff2?|css|js)$/i.test(clean)) return;
    if (/github\.com\/luau-lang/i.test(clean)) return;
    seen.add(clean);
    targets.push(clean);
  };

  const concatRe = /["'](https?:\/\/[^"']*?)["']\s*\.\.\s*(?:[A-Za-z_][\w.]*|[A-Za-z_][\w.]*\([^)]*\))?/g;
  let m;
  while ((m = concatRe.exec(loaderText)) !== null) push(m[1]);

  while ((m = urlRe.exec(loaderText)) !== null) push(m[0]);

  // Relative endpoints ("/v1/...", "/api/...") are resolved against the host.
  let base = origin;
  try {
    base = new URL(origin).origin;
  } catch {}
  const relRe = /["'](\/(?:v1|api|script|lib|loader)[^"'\s]*)["']/g;
  while ((m = relRe.exec(loaderText)) !== null) push(base + m[1]);

  return targets;
}

function isKeyForgeHost(url) {
  try {
    return /(^|\.)keyforge\.win$/i.test(new URL(url).hostname);
  } catch {
    return false;
  }
}

// Used by the sandbox pass: fetch a URL the loader asked for. No key is sent
// first (CDN payloads need none); if that does not produce a body, the key is
// tried through every channel.
// --http-map {"<url>": "<file path | inline body>"}: responses the user saved
// (from an executor's log, a proxy, or a previous run). Checked before the
// network, so a chain can be followed with no connection at all.
function fromMap(url, map) {
  if (!map) return null;
  const direct = map[url] || map[url.replace(/\/$/, '')] || map[url.replace(/\?.*$/, '')];
  if (direct == null) {
    for (const [k, v] of Object.entries(map)) {
      if (k.length >= 12 && url.startsWith(k)) return v;
    }
    return null;
  }
  return direct;
}

// A map value is either the response body itself, or the path of a file
// holding it. Relative paths are resolved against the map file's directory so
// a committed map works no matter where the repository is checked out.
function resolveMapPath(p, baseDir) {
  if (typeof p !== 'string' || !p) return null;
  const candidates = baseDir ? [p, path.resolve(baseDir, p)] : [p];
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
    } catch { /* keep looking */ }
  }
  return null;
}

function mapBody(value, baseDir) {
  if (value == null) return null;
  if (typeof value === 'string') {
    const file = resolveMapPath(value, baseDir);
    if (file) return fs.readFileSync(file, 'utf8');
  }
  if (typeof value === 'object' && value.file) {
    const file = resolveMapPath(value.file, baseDir);
    return file ? fs.readFileSync(file, 'utf8') : null;
  }
  return String(value);
}

async function fetchForCache(url, key, opts = {}) {
  const mapped = mapBody(fromMap(url, opts.map), opts.mapDir);
  if (mapped != null) {
    return { ok: true, body: mapped, status: 'map', method: 'MAP', channel: '--http-map' };
  }

  const attempt = async (headers, query, channel) => {
    const target = query ? withQuery(url, query) : url;
    const res = await request(target, { timeout: opts.timeout || 30000, headers });
    const good =
      res.statusCode === 200 &&
      res.body.length > 16 &&
      !/^\s*(<|<!doctype|\{"?error)/i.test(res.body) &&
      !/invalid|denied|expired|unauthorized|HWID/i.test(res.body.slice(0, 300));
    return { ok: good && looksLikeLua(res.body), body: res.body, status: res.statusCode, channel };
  };

  const tried = [];
  try {
    const plain = await attempt({}, null, null);
    if (plain.ok) return { ...plain, method: 'GET' };
    tried.push('no key');
    if (!key) return { ok: false, body: plain.body, status: plain.status, method: 'GET', error: 'no usable body' };
  } catch (e) {
    tried.push(`no key: ${e.message}`);
    if (!key) return { ok: false, method: 'GET', error: e.message };
  }

  for (const ch of KEY_CHANNELS) {
    if (ch.body) continue; // bodies are only used when replaying a POST
    try {
      const res = await attempt(ch.headers ? ch.headers(key) : {}, ch.query ? ch.query(key) : null, ch.name);
      if (res.ok) return { ...res, method: 'GET' };
      tried.push(`${ch.name}: ${res.status}`);
    } catch (e) {
      tried.push(`${ch.name}: ${e.message}`);
    }
  }
  return { ok: false, method: 'GET', error: tried.join(', ') };
}

function parseArgsOverride(args) {
  return {
    url: args.kfUrl || null,
    key: args.key || null,
    header: args.kfHeader || null,
    method: args.kfMethod || null,
    timeout: (args.timeout || 90) * 1000,
    offline: !!args.noNet,
    saveChain: args.saveChain !== false,
  };
}

function keyFromEnvironment(args) {
  const env = process.env;
  return (
    args.key ||
    env.KEYFORGE_KEY ||
    env.KEYFORGE_SCRIPT_KEY ||
    env.KF_KEY ||
    env.SCRIPT_KEY ||
    null
  );
}

// ---------------------------------------------------------------------------
// resolve(): follow the delivery chain hop by hop.
//
//   /v1/load/{project}  ->  hosted loader (Lua)
//   hosted loader       ->  CDN / API endpoint (Lua, or an encoded blob)
//   last hop            ->  the protected payload
//
// Every response is kept in `cache` so the sandbox pass can replay the chain
// even when one hop is an envelope we cannot read on our own (encrypted,
// keyed, split across two requests, ...). The key is sent through every common
// channel until one is accepted.
// ---------------------------------------------------------------------------
async function resolve(job, options = {}) {
  const { args } = job;
  const o = parseArgsOverride(args);
  const map = args.httpMap || {};
  const mapDir = args.httpMapDir || null;
  const note = msg => process.stderr.write(msg + '\n');
  const steps = [];
  const cache = {};
  const maxHops = Math.max(1, args.chainRounds || 4);

  const info = keyforgeInfo(job.source) || {};
  let url = o.url || info.url;
  if (info.projectId && !o.url) url = `https://www.keyforge.win/v1/load/${info.projectId}`;
  if (!url) {
    return { ok: false, reason: 'no keyforge.win URL found in the script (use --kf-url)', steps, cache };
  }

  const key = o.key || keyFromEnvironment(args) || info.inlineKey || null;
  const keyOrigin = o.key
    ? '--key'
    : (process.env.KEYFORGE_KEY || process.env.KEYFORGE_SCRIPT_KEY || process.env.KF_KEY || process.env.SCRIPT_KEY)
      ? 'environment'
      : info.inlineKey
        ? 'script'
        : 'missing';

  note(`[*] keyforge: project ${info.projectId || '(unknown)'}, key ${maskKey(key)} (${keyOrigin})`);
  steps.push(`loader url: ${url}`);

  if (o.offline && !localFile(url) && mapBody(fromMap(url, map), mapDir) == null) {
    return {
      ok: false,
      reason: 'offline mode (--no-net) and the first hop is not in --http-map',
      steps, url, key, cache,
    };
  }

  let current = url;
  for (let hop = 1; hop <= maxHops; hop++) {
    let fetched = null;

    // saved response first (offline-friendly), then the network
    const mapped = mapBody(fromMap(current, map), mapDir);
    if (mapped != null) {
      fetched = { statusCode: 200, body: mapped, contentType: 'text/plain', headers: {}, local: true };
      steps.push(`GET ${current} -> --http-map (${mapped.length} bytes)`);
    } else if (!o.offline) {
      const tried = [];
      const list = key ? KEY_CHANNELS.filter(c => !c.body).slice(0, 6) : [null];
      for (const ch of list) {
        const target = ch && ch.query ? withQuery(current, ch.query(key)) : current;
        try {
          const res = await request(target, {
            timeout: Math.min(o.timeout, 20000),
            headers: Object.assign({}, ch && ch.headers ? ch.headers(key) : {}, o.header ? parseHeaderFlag(o.header) : {}),
          });
          fetched = res;
          if (res.statusCode === 200 && res.body.length > 16) {
            steps.push(`GET ${current}${ch && ch.query ? ' [...query]' : ''} -> ${res.statusCode} (${res.body.length} bytes)`);
            break;
          }
          tried.push(`${res.statusCode}`);
          fetched = null;
        } catch (e) {
          tried.push(e.message);
        }
      }
      if (!fetched) {
        return {
          ok: false,
          reason: `could not fetch ${current}${tried.length ? ' (' + tried.join(', ') + ')' : ''}`,
          steps, url: current, key, cache,
        };
      }
      note(`[*] keyforge: ${steps[steps.length - 1]}`);
    } else {
      return { ok: false, reason: `offline mode: ${current} is not in --http-map`, steps, url: current, key, cache };
    }

    cache[current] = fetched.body;

    if (/invalid|denied|expired|not\s*authorized|unknown\s*key|no\s*access/i.test(fetched.body.slice(0, 400)) && fetched.body.length < 400) {
      return {
        ok: false,
        reason: `the service rejected the request (key ${key ? 'present' : 'missing'}): ${fetched.body.trim().slice(0, 200)}`,
        steps, url: current, key, cache,
      };
    }

    if (!looksLikeLua(fetched.body)) {
      // An encoded / binary hop: only the script itself can decode this one.
      const unwrapped = staticUnwrap(fetched.body);
      if (unwrapped.text !== fetched.body && looksLikeLua(unwrapped.text)) {
        note(`[*] keyforge: unwrapped payload layers (${unwrapped.notes.join(', ')})`);
        return { ok: true, payload: unwrapped.text, raw: fetched.body, url: current, key, steps, cache, kind: `hop ${hop}` };
      }
      steps.push(`hop ${hop} (${current}) is not plain Lua (${fetched.body.length} bytes): handing it to the script`);
      return {
        ok: false,
        reason: 'the delivery is encoded from here on (base64/xor/custom), so the loader has to decode it',
        steps, url: current, key, cache, encodedLastHop: current,
      };
    }

    // A Lua body: is it the payload, or another loader?
    const nextTargets = followUpTargets(fetched.body, current).filter(t => t !== current);
    {
      const unwrapped = staticUnwrap(fetched.body);
      const text = unwrapped.text;
      const { plugin, confidence } = detectModule.detect(text);
      const hasLoadstring = /loadstring\s*\(|load\s*\(/.test(text);
      if (unwrapped.notes.length) note(`[*] keyforge: unwrapped payload layers (${unwrapped.notes.join(', ')})`);
      if (plugin.name === 'luraph_v15' && confidence >= 0.8) {
        steps.push(`hop ${hop} is ${plugin.family === 'luraph' ? 'a Luraph build' : 'the payload'}`);
        return { ok: true, payload: text, raw: fetched.body, url: current, key, steps, cache, kind: `hop ${hop}` };
      }
      if (!nextTargets.length || !hasLoadstring) {
        steps.push(`hop ${hop} is plain Luau (${text.length} bytes) with no further endpoint`);
        return { ok: true, payload: text, raw: fetched.body, url: current, key, steps, cache, kind: `hop ${hop}` };
      }
    }

    steps.push(`hop ${hop} is a loader; following ${nextTargets.length} endpoint(s)`);
    note(`[*] keyforge: hop ${hop} is another loader (${nextTargets.length} endpoint(s))`);
    current = nextTargets[0];
  }

  return {
    ok: false,
    reason: `chain longer than ${maxHops} hops (raise --chain-rounds)`,
    steps, url: current, key, cache,
  };
}

function parseHeaderFlag(text) {
  const i = text.indexOf(':');
  if (i < 0) return {};
  return { [text.slice(0, i).trim()]: text.slice(i + 1).trim() };
}

// Writes the resolved payload next to the other intermediates, so it can be
// re-run through the pipeline on its own.
function savePayload(job, payload) {
  const target = job.path('.keyforge.luau');
  fs.writeFileSync(target, payload, 'utf8');
  job.wrote(target);
  return target;
}

function saveChainNotes(job, steps) {
  const target = job.path('.keyforge.log');
  fs.writeFileSync(target, steps.map(s => '- ' + s).join('\n') + '\n', 'utf8');
  job.wrote(target);
  return target;
}

module.exports = {
  resolve,
  request,
  fetchForCache,
  fromMap,
  mapBody,
  resolveMapPath,
  localFile,
  staticUnwrap,
  looksLikeLua,
  followUpTargets,
  savePayload,
  saveChainNotes,
  maskKey,
  withQuery,
  parseHeaderFlag,
  KEY_CHANNELS,
  isKeyForgeHost,
};
