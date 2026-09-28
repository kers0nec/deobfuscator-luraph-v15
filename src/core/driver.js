'use strict';

const fs = require('fs');
const path = require('path');
const vmmap = require('./vmmap');
const harness = require('./harness');
const trace = require('./traceout');
const tidy = require('./tidy');
const detect = require('./detect');

const SPIN_CHECKS = 24;

// A child job shares every option with its parent but analyses a different
// text (a loadstring'd chunk, a recovered KeyForge payload, ...).
function forkJob(job, overrides) {
  const child = Object.create(Object.getPrototypeOf(job));
  Object.assign(child, job);
  Object.assign(child, overrides);
  return child;
}

// The trace header lists every URL the script asked for; the KeyForge loader
// chain is rebuilt from that list.
function extractUrls(body) {
  const found = [];
  const m = /-- URLs requested:\n((?:--[ \t]+[^\n]*\n)*)/.exec(body);
  if (!m) return found;
  for (const line of m[1].split('\n')) {
    const url = line.replace(/^--[ \t]+/, '').trim();
    if (url && !found.includes(url)) found.push(url);
  }
  return found;
}

function patchChunk(src, tmpdir, chunkTag) {
  const p = path.join(tmpdir, `_chunk_${harness.chunkKey(src)}.luau`);
  fs.writeFileSync(p, src, 'latin1');
  try {
    return vmmap.patchEntries(src, p, chunkTag);
  } catch (e) {
    process.stderr.write(`[!] could not instrument chunk (${e.message})\n`);
    return src;
  } finally {
    try { fs.unlinkSync(p); } catch {}
  }
}

async function run(job) {
  const { args } = job;
  const devirtOn = !args.noDevirt;
  let source = job.source;

  let patched;
  try {
    patched = args.noHooks ? source : vmmap.patchEntries(source, job.sourcePath, harness.chunkKey(source));
  } catch (e) {
    process.stderr.write(`[!] AST parse failed: ${e.message}\n`);
    throw e;
  }

  let spin = true;
  if (spin) patched = vmmap.patchSpin(patched);

  const cachePath = harness.loadP2dCache(job.input);
  const runner = new harness.Runner(job);

  const skip = [];
  const chunks = {};
  const rawChunks = {};
  let body = null;
  let trapped = null;
  let cfg = null;

  for (let attempt = 1; attempt <= args.maxRuns; attempt++) {
    cfg = {
      time_budget: args.budget,
      dump_strings: args.strings,
      executor: args.executor,
      skip_protos: skip,
      devirt: devirtOn,
    };
    if (args.inputText) cfg.input_text = args.inputText;
    if (args.noFold) cfg.fold = false;
    if (spin) cfg.spin = SPIN_CHECKS;
    // a chain the loader needs (KeyForge delivery, CDN payload, ...) is served
    // from the recorded responses while the VM runs, so it can build itself up
    if (job.httpCache && Object.keys(job.httpCache).length) cfg.http_cache = job.httpCache;

    process.stderr.write(`[*] tracing ${job.input} (run ${attempt})...\n`);
    const res = await runner.run(patched, cfg, chunks);
    body = res.body;

    if (!body) {
      runner.finish();
      throw new Error(res.err || 'Trace failed without output');
    }

    body = harness.takeP2d(body);

    const { chunks: found, body: cleanBody } = harness.takeChunks(body);
    body = cleanBody;
    let added = 0;
    for (const [key, src] of found) {
      if (!chunks[key]) {
        rawChunks[key] = src;
        chunks[key] = patchChunk(src, job.outdir, key);
        if (spin) chunks[key] = vmmap.patchSpin(chunks[key]);
        added++;
      }
    }
    if (added > 0) {
      process.stderr.write(`[*] script loadstring'd ${added} new VM chunk(s); instrumenting and re-running\n`);
      continue;
    }

    const trig = /\x00TRIGGER (\d+)/.exec(body);
    if (trapped !== null && trace.stmtCount(body) < trace.stmtCount(trapped[0])) {
      process.stderr.write(`[*] disabling function #${skip[skip.length - 1]} made script stop earlier: keeping run ${attempt - 1}\n`);
      body = trapped[0];
      skip.pop();
      break;
    }
    if (!trig) break;

    trapped = [body, harness.getLastRaw()];
    const pid = parseInt(trig[1], 10);
    if (skip.includes(pid)) {
      process.stderr.write(`[!] anti-tamper trigger ${pid} fired again; giving up on reruns\n`);
      break;
    }
    process.stderr.write(`[*] anti-tamper trap reached through function #${pid}; disabling it and re-running\n`);
    skip.push(pid);
  }

  const runText = harness.traceText(body);
  body = harness.p2dMiss(body, cachePath);
  body = body.replace(/\x00TRIGGER \d+\n?/g, '');

  const [protosJson, b1] = trace.takeLine(body, 'PROTOS');
  body = b1;
  const [force, b2] = trace.takeLine(body, 'FORCE');
  body = b2;
  if (force && devirtOn) process.stderr.write(`[*] constants decoded on request: ${force}\n`);

  const [unscrambled, b3] = trace.takeLine(body, 'UNSCRAMBLED');
  body = b3;
  if (unscrambled && devirtOn)
    process.stderr.write(`[*] ${unscrambled} function(s) scrambled by LPH_CRASH(): dumped as created\n`);

  const [b4, strings] = trace.takeStrings(body);
  body = b4;

  const notes = skip.length ? [`anti-tamper trap functions disabled: ${skip.map(p => '#' + p).join(', ')}`] : [];
  const text = trace.header(job.input, notes) + body;

  function writeTrace() {
    job.write(job.tracePath, tidy.tidy(text, { preamble: !args.keepPreamble }));
  }

  if (!devirtOn && !job.debug) {
    writeTrace();
  }

  if (strings) job.write(job.path('.strings.txt'), strings);

  const dpath = job.path('.devirt.luau');
  if (protosJson) {
    const ppath = job.path('.protos.json');
    if (protosJson.startsWith('error:')) {
      process.stderr.write(`[!] proto capture failed: ${protosJson}\n`);
    } else {
      job.write(ppath, protosJson);
      if (devirtOn) {
        const chunkPaths = Object.entries(rawChunks).map(([k, src]) =>
          job.write(job.path(`.chunk_${k}.luau`), src, 'latin1')
        );

        const cfgData = {
          input: job.input,
          source: job.source,
          source_path: job.sourcePath,
          trace_path: job.tracePath,
          debug: job.debug,
          obfuscator: job.obfuscator,
          luau_exe: runner.luau,
          patched: patched,
          cfg: cfg,
          chunks: chunks,
          run_text: runText,
          ppath: ppath,
          dpath: dpath,
          chunk_paths: chunkPaths,
          args: {
            budget: args.budget,
            timeout: args.timeout,
            devirt_rounds: args.devirtRounds || 200,
            studio: false,
            no_fold: args.noFold || false,
            strings: args.strings || false,
            executor: args.executor || 'Wave',
          },
        };
        const cfgPath = job.path('.cfg.json');
        fs.writeFileSync(cfgPath, JSON.stringify(cfgData), 'utf8');

        const { execFileSync } = require('child_process');
        const { getPythonBin } = require('./pyenv');
        const pythonBin = getPythonBin();
        const bridgePy = path.join(__dirname, 'devirt_bridge.py');
        const coreDir = path.join(__dirname, '..', '..', 'core');
        try {
          execFileSync(pythonBin, [bridgePy, 'pipeline', cfgPath], {
            env: Object.assign({}, process.env, { PYTHONPATH: coreDir }),
            stdio: 'inherit',
          });
        } catch (e) {
          // A VM the lifter cannot read (another Luraph generation, or a
          // different obfuscator entirely) still has a behaviour trace.
          process.stderr.write(`[!] devirtualization did not complete (${e.message || e})\n`);
        } finally {
          try { fs.unlinkSync(cfgPath); } catch {}
        }
      }
    }
  }

  runner.finish();
  trace.statusLine(body);

  if (devirtOn && fs.existsSync(dpath)) {
    const lifted = fs.readFileSync(dpath, 'utf8');
    const nilCalls = (lifted.match(/\(nil\)\(/g) || []).length;
    const lines = lifted.split('\n').length;
    if (nilCalls < 50 || nilCalls * 100 < lines) {
      return dpath;
    }
    process.stderr.write(`[!] the devirtualized output is broken (${nilCalls} calls of nil); writing behaviour trace instead\n`);
    if (!job.debug) { try { fs.unlinkSync(dpath); } catch {} }
    writeTrace();
    return job.tracePath;
  }

  if (devirtOn) {
    process.stderr.write('[!] devirtualization produced no output; writing behaviour trace\n');
    if (!fs.existsSync(job.tracePath)) writeTrace();
  }
  return job.tracePath;
}

async function liftWithRounds(job, runner, patched, cfg, chunks, runText, ppath, dpath, chunkPaths) {
  const { args } = job;
  const rounds = args.devirtRounds || 200;
  const requested = new Set();
  let lastBufs = '';
  let text = null;
  let quick = true;

  for (let rnd = 1; rnd <= rounds; rnd++) {
    const t1 = Date.now();
    let full = !quick;

    if (quick) {
      let res;
      try {
        res = devirt.collectRequests(job.sourcePath, ppath, chunkPaths);
      } catch (e) {
        process.stderr.write(`[!] collect failed: ${e.message}\n`);
        break;
      }
      const { stats, reqs, bufs } = res;
      const newReqs = [...reqs].filter(x => !requested.has(x));
      process.stderr.write(
        `[*] devirt round ${rnd}: ${stats.functions} functions (${stats.walked} walked), ${stats.errors} unlifted blocks, ${newReqs.length} new constant requests (${((Date.now() - t1) / 1000).toFixed(1)}s)\n`
      );

      if (newReqs.length === 0 || rnd === rounds) {
        full = true;
      } else {
        newReqs.forEach(r => requested.add(r));
        lastBufs = bufs;

        const c = Object.assign({}, cfg, {
          force_req: [...requested].sort().join(';'),
          force_buf: bufs,
        });
        const runRes = await runner.run(patched, c, chunks);
        if (!runRes.body) {
          process.stderr.write('[!] constant request run failed\n');
          break;
        }
        const m = /\x00PROTOS ([^\n]*)\n/.exec(runRes.body);
        if (!m || m[1].startsWith('error:')) {
          process.stderr.write('[!] constant request run gave no protos\n');
          break;
        }
        fs.writeFileSync(ppath, m[1], 'utf8');
      }
    }

    if (full) {
      process.stderr.write(`[*] devirtualizing (round ${rnd})...\n`);
      const tFull = Date.now();
      let res;
      try {
        res = devirt.liftProgram(job.sourcePath, ppath, chunkPaths, dpath);
      } catch (e) {
        process.stderr.write(`[!] lift failed: ${e.message}\n`);
        break;
      }
      const { text: liftedText, stats, reqs } = res;
      text = liftedText;
      const newReqs = [...reqs].filter(x => !requested.has(x));
      process.stderr.write(
        `[*]   ${stats.functions} functions, ${stats.errors} unlifted blocks, ${stats.fallbacks} unstructured jumps, ${newReqs.length} new constant requests (${((Date.now() - tFull) / 1000).toFixed(1)}s)\n`
      );

      if (newReqs.length === 0 || rnd === rounds) break;
      if (quick) {
        process.stderr.write('[*]   the full lift needs more constants: continuing with full lifts\n');
        quick = false;
      }
      newReqs.forEach(r => requested.add(r));
    }
  }

  if (text) {
    const header = job.creditHeader();
    const prefix = header ? header + '\n' : '';
    job.write(dpath, prefix + text + '\n');
  }
}

// ---------------------------------------------------------------------------
// runTrace(): the behaviour tracer. Works on *any* Lua/Luau script: it runs the
// input inside the offline Roblox sandbox and records what it does (calls,
// conditions, decoded strings, URLs, loaded chunks). This is the universal
// fallback for obfuscators whose VM layout is not the one the lifter knows -
// including older Luraph builds - and it is also what a KeyForge payload gets
// when it is not a Luraph v15 VM.
// ---------------------------------------------------------------------------
async function runTrace(job, opts = {}) {
  const { args } = job;
  const cachePath = harness.loadP2dCache(job.input);
  const runner = new harness.Runner(job);

  let source = job.source;
  if (!args.noHooks) {
    try {
      source = vmmap.patchEntries(source, job.sourcePath, harness.chunkKey(source));
    } catch (e) {
      process.stderr.write(`[!] could not instrument VM entries (${e.message}); tracing as-is\n`);
    }
  }
  source = vmmap.patchSpin(source);

  const cfg = {
    time_budget: args.budget,
    executor: args.executor,
    dump_strings: args.strings,
  };
  if (args.inputText) cfg.input_text = args.inputText;
  if (args.noFold) cfg.fold = false;
  if (args.spin !== false) cfg.spin = SPIN_CHECKS;
  // responses recorded outside the sandbox (KeyForge loader chains): the
  // script then works with the real bodies instead of stand-ins
  if (opts.httpCache && Object.keys(opts.httpCache).length) cfg.http_cache = opts.httpCache;
  // a loader chain decrypts its payload with loadstring(): capture even small
  // payloads so the recovered source can be analysed on its own
  if (opts.chunkMin) cfg.chunk_min = opts.chunkMin;

  const chunks = {};
  let body = null;
  let trapped = false;

  for (let attempt = 1; attempt <= args.maxRuns; attempt++) {
    process.stderr.write(`[*] tracing ${path.basename(job.input)}${opts.stage ? ' (' + opts.stage + ')' : ''} (run ${attempt})...\n`);
    const res = await runner.run(source, cfg, chunks);
    if (!res.body) {
      runner.finish();
      throw new Error(res.err || 'Trace failed without output');
    }
    body = res.body;
    body = harness.takeP2d(body);

    const { chunks: found, body: cleanBody } = harness.takeChunks(body);
    body = cleanBody;
    for (const [key, src] of found) {
      if (!chunks[key]) chunks[key] = src;
    }
    if (found.length) {
      process.stderr.write(`[*] script loadstring'd ${found.length} chunk(s) (captured for analysis)\n`);
    }
    const trig = /\x00TRIGGER (\d+)/.exec(body);
    if (trig) {
      trapped = true;
      break;
    }
    break;
  }

  runner.finish();
  body = harness.p2dMiss(body, cachePath);
  body = body.replace(/\x00TRIGGER \d+\n?/g, '');
  const [b2, strings] = trace.takeStrings(body);
  body = b2;

  job._lastChunks = chunks;
  job._lastUrls = extractUrls(body);

  const notes = [...(opts.notes || [])];
  if (trapped) {
    notes.push('the script reached an anti-tamper trap; the trace stops at the last statement before it');
  }
  if (Object.keys(chunks).length) {
    notes.push(`loadstring'd chunks captured: ${Object.keys(chunks).length} (see the .chunk_* files with --debug)`);
  }

  const text = trace.header(job.input, notes) + body;
  job.write(job.tracePath, tidy.tidy(text, { preamble: false }));
  if (strings) job.write(job.path('.strings.txt'), strings);
  trace.statusLine(body);
  return job.tracePath;
}

// ---------------------------------------------------------------------------
// runLegacy(): Luraph builds whose VM layout the devirtualizer does not lift
// (v12 - v14.x, headerless copies, method-based state machines). The VM entry
// hooks are still applied - they cost nothing when no dispatcher matches - and
// the result is the behaviour trace plus a clear note about what was possible.
// ---------------------------------------------------------------------------
async function runLegacy(job, meta = {}) {
  const version = meta.version ? `v${meta.version}` : (meta.major ? `v${meta.major}-style` : 'legacy');
  process.stderr.write(
    `[*] ${version} Luraph build detected: this pipeline reconstructs control flow for v15 VMs; ` +
    'for older builds the behaviour trace (every call, string and branch the script really takes) is produced,\n' +
    '    and any loadstring\'d chunk is inspected on its own - a v15 or plain-Luau inner chunk is lifted normally.\n'
  );

  // Inner chunks may well be v15 VMs. Capture them, and when one is, lift it.
  const result = await runTrace(job, {
    stage: 'behaviour trace',
    notes: [
      `${meta.header ? 'Luraph ' + version : 'Luraph VM'} (older VM layout): behaviour trace`,
      'full source reconstruction is available for v15 VMs; inner chunks were checked for one',
    ],
  });
  await liftCapturedChunks(job);
  return result;
}

// Runs the v15 pipeline on the chunks a script loadstring'd, if any of them is
// a v15 VM (a common pattern: an older loader that pulls in a v15 build).
async function liftCapturedChunks(job) {
  const chunks = job._lastChunks || {};
  let lifted = null;

  for (const [key, source] of Object.entries(chunks)) {
    const { plugin, confidence, label } = detect.detect(source);
    if (plugin.name !== 'luraph_v15') {
      if (confidence > 0.4) process.stderr.write(`[*] chunk ${key} looks like ${label}; no v15 lifter for it\n`);
      continue;
    }
    process.stderr.write(`[*] the script loadstring's a ${label} chunk (${confidence.toFixed(2)}); devirtualizing it\n`);
    const chunkPath = job.write(job.path(`.chunk_${key}.luau`), source, 'latin1');
    const child = forkJob(job, {
      source,
      sourcePath: chunkPath,
      tracePath: job.base + `.chunk_${key}.deobf.luau`,
      obfuscator: label,
    });
    try {
      lifted = await run(child);
    } catch (e) {
      process.stderr.write(`[!] chunk devirtualization failed: ${e.message || e}\n`);
    }
  }
  return lifted;
}

// ---------------------------------------------------------------------------
// runKeyforge(): resolve the keyforge.win delivery chain (key -> protected
// payload) and analyse whatever comes back with the right plugin.
// ---------------------------------------------------------------------------
async function runKeyforge(job) {
  const keyforge = require('../families/keyforge');
  const { args } = job;

  process.stderr.write('[*] KeyForge loader detected: resolving the delivery chain\n');
  let res;
  try {
    res = await keyforge.resolve(job);
  } catch (e) {
    res = { ok: false, reason: e.message || String(e), steps: [] };
  }
  const steps = res.steps ? [...res.steps] : [];

  if (res.ok) {
    if (steps.length) keyforge.saveChainNotes(job, steps);
    return await handOffPayload(job, res.payload, {
      how: `${res.kind}${res.channel ? ' via ' + res.channel : ''}`,
      key: res.key,
    });
  }

  if (res.reason) process.stderr.write(`[!] keyforge: ${res.reason}\n`);

  // The direct replay did not hand us a script. Run the loader once to see
  // exactly what it asks for, fetch those responses, and run it again with
  // them served from the cache: the loader then decrypts its own payload and
  // the sandbox captures the result as a chunk.
  const found = await keyforgeThroughSandbox(job, res.key, steps, res.cache || {});
  if (found) {
    if (steps.length) keyforge.saveChainNotes(job, steps);
    return await handOffPayload(job, found.payload, {
      how: 'loader decryption (sandbox capture)',
      key: res.key,
      httpCache: found.cache,
    });
  }

  if (steps.length) keyforge.saveChainNotes(job, steps);
  process.stderr.write('[i] pass the key with --key <KEY> (or set KEYFORGE_KEY); a HWID-locked key only works on its own machine\n');
  return runTrace(job, {
    stage: 'loader trace',
    notes: [
      'KeyForge loader: the delivery chain could not be resolved, so this is the loader\'s behaviour trace',
      `reason: ${res.reason}`,
      'pass --key <KEY> (or set KEYFORGE_KEY) to resolve the chain and deobfuscate the payload itself',
    ],
  });
}

// Trace the loader, fetch whatever it asked for, and trace it again with those
// bodies served from the sandbox cache. Each pass reveals the next hop of the
// chain, so this loops (with --http-map entries counting as already cached).
// Returns the decrypted payload, if the loader produced one.
async function keyforgeThroughSandbox(job, key, steps, preloaded = {}) {
  const keyforge = require('../families/keyforge');

  // Responses already fetched while following the chain, plus the ones the user
  // saved with --http-map (whose values may be file paths).
  const cache = Object.assign({}, preloaded);
  const map = job.args.httpMap || {};
  let fromMap = 0;
  for (const [url, value] of Object.entries(map)) {
    if (cache[url] != null) continue;
    const body = keyforge.mapBody(value, job.args.httpMapDir || null);
    if (body != null) {
      cache[url] = body;
      fromMap++;
    }
  }
  if (fromMap) process.stderr.write(`[*] keyforge: ${fromMap} response(s) preloaded with --http-map\n`);
  if (Object.keys(preloaded).length) {
    process.stderr.write(`[*] keyforge: ${Object.keys(preloaded).length} response(s) kept from the chain walk\n`);
  }

  const rounds = Math.max(1, job.args.chainRounds || 4);
  let payload = null;

  for (let round = 1; round <= rounds && !payload; round++) {
    await runTrace(job, { stage: `loader pass ${round}`, httpCache: cache, chunkMin: 64 });

    payload = pickPayload(job._lastChunks || {}, cache);
    if (payload) break;

    const urls = (job._lastUrls || []).filter(u => /^(https?:\/\/|file:\/\/|\/)/i.test(u));
    const missing = urls.filter(u => !cache[u] && !cache[u.replace(/\/$/, '')]);
    if (!missing.length) {
      process.stderr.write('[!] keyforge: no further endpoint to follow\n');
      break;
    }

    process.stderr.write(`[*] keyforge: pass ${round} requested ${missing.length} new endpoint(s):\n`);
    for (const u of missing) process.stderr.write(`      ${u}\n`);

    let fetched = 0;
    for (const url of missing) {
      const got = await keyforge.fetchForCache(url, key, {
        timeout: job.args.timeout * 1000,
        map: job.args.httpMap || {},
        mapDir: job.args.httpMapDir || null,
      });
      steps.push(`${got.method || 'GET'} ${url}${got.channel ? ' [' + got.channel + ']' : ''} -> ${got.status || got.error} (${got.body ? got.body.length : 0} bytes)`);
      if (got.ok && got.body) {
        cache[url] = got.body;
        fetched++;
        process.stderr.write(`[+] keyforge: cached ${got.body.length} bytes for ${url}\n`);
      } else {
        process.stderr.write(`[!] keyforge: no usable response from ${url} (${got.status || got.error})\n`);
      }
    }
    if (!fetched) break;
  }

  if (!payload) payload = pickPayload(job._lastChunks || {}, cache);
  if (!payload) {
    process.stderr.write('[!] keyforge: the loader did not loadstring a payload even with the responses served\n');
    return null;
  }
  return { payload, cache };
}

// Which loadstring'd chunk is the payload? A chain reports them in execution
// order (the delivered loader first, its decrypted payload last), so:
//   1. a chunk that looks like a protected VM wins outright;
//   2. a chunk that is just one of the fetched responses is not a payload;
//   3. otherwise the last one captured is the deepest layer of the chain.
function pickPayload(chunks, cache = {}) {
  const bodies = new Set(Object.values(cache || {}).filter(v => typeof v === 'string'));
  const candidates = Object.entries(chunks).filter(([, src]) => src && src.length >= 64);
  if (!candidates.length) return null;

  const scored = candidates.map(([key, src], index) => {
    const { plugin, confidence } = detect.detect(src);
    const vm = confidence >= 0.5 || plugin.name !== 'generic';
    const echoed = bodies.has(src);
    return { src, index, vm, echoed, confidence };
  });

  const vmBest = scored.filter(s => s.vm && !s.echoed).pop();
  const chosen = vmBest || scored.filter(s => !s.echoed).pop() || scored.pop();

  process.stderr.write(
    `[+] keyforge: the loader produced a ${chosen.src.length}-byte payload` +
    `${chosen.vm ? ' that looks like a protected VM' : ''}; analysing that\n`
  );
  return chosen.src;
}

// Detects what a recovered payload is and runs the right pipeline on it.
async function handOffPayload(job, payload, info = {}) {
  const keyforge = require('../families/keyforge');
  const payloadPath = keyforge.savePayload(job, payload);
  const size = payload.length;
  process.stderr.write(
    `[+] keyforge: payload recovered (${size} bytes${info.how ? ', ' + info.how : ''})\n`
  );

  const { plugin, confidence, label } = detect.detect(payload);
  process.stderr.write(`[*] keyforge: payload is ${label} (${confidence.toFixed(2)})\n`);

  const child = forkJob(job, {
    source: payload,
    sourcePath: payloadPath,
    tracePath: job.base + '.keyforge.deobf.luau',
    obfuscator: label,
  });

  if (plugin.name === 'luraph_v15') {
    // The payload is the VM chunk the loader assembles. Lifting it through the
    // loader keeps the environment it was built in (upvalues, decoded buffers)
    // and lets the chunk instrumentation work as usual.
    if (info.httpCache && Object.keys(info.httpCache).length) {
      process.stderr.write('[*] keyforge: lifting the payload inside the loader so its context is intact\n');
      const loaderChild = forkJob(job, {
        tracePath: job.base + '.keyforge.inplace.deobf.luau',
        obfuscator: label,
        httpCache: info.httpCache,
      });
      try {
        const out = await run(loaderChild);
        if (out && out.endsWith('.devirt.luau') && fs.existsSync(out)) return out;
        process.stderr.write('[!] keyforge: in-loader lift produced no devirtualized output; trying the payload on its own\n');
      } catch (e) {
        process.stderr.write(`[!] keyforge: in-loader lift failed: ${e.message || e}\n`);
      }
    }
    return await run(child);
  }
  if (plugin.name === 'keyforge') {
    process.stderr.write('[!] keyforge: the payload is another KeyForge loader (nested delivery); tracing it as-is\n');
  }
  // Not Luraph, not another loader: run it through the universal recovery path
  // so a wYnFuscate/Prometheus/MoonSec/... payload still yields readable code.
  child._lastChunks = job._lastChunks;
  child._lastUrls = job._lastUrls;
  return await runRecovered(child, {
    family: plugin.family,
    label,
    strategy: plugin.strategy || 'vmp',
    keyResolved: Boolean(info.key),
  });
}

// Known static packers: the original script can be recovered byte-exactly.
function tryStaticUnpack(job) {
  const packers = require('../families/packers');
  const attempts = [
    () => {
      const res = packers.decodeLpsPack(job.source);
      return res ? { ...res, kind: 'lps packer' } : null;
    },
  ];
  for (const attempt of attempts) {
    try {
      const res = attempt();
      if (res) return res;
    } catch { /* try the next scheme */ }
  }
  return null;
}

// ---------------------------------------------------------------------------
// runRecovered(): every obfuscator that is not Luraph and not KeyForge.
//
// There is no single algorithm that unwraps an arbitrary protection, but every
// one of them ends up handing real code to loadstring() - and the runtime
// records that. So the script is traced, the payload it builds is captured and
// written out as readable Luau, and a report lists what was recognised. For
// wYnFuscate the static decoder runs first: its bytecode can be read without
// executing anything, which still works when the anti-tamper probes would stop
// a trace.
// ---------------------------------------------------------------------------
async function runRecovered(job, meta = {}, depth = 0) {
  const recover = require('../families/recover');
  const notes = [];

  // 0. static unpacking: some builds carry the original script compressed
  //    behind a fixed decoder, so it can be recovered exactly - no execution
  const unpacked = tryStaticUnpack(job);
  if (unpacked && unpacked.text && unpacked.text !== job.source && unpacked.text.length > 32) {
    const dir = job.resultDir || job.outdir;
    const stem = path.basename(job.input).replace(/\.(luau?|txt)$/i, '');
    const target = path.join(dir, `${stem}.unpacked.luau`);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(target, unpacked.text, 'latin1');
    process.stderr.write(
      `[+] ${meta.label || 'packer'}: unpacked ${job.source.length} -> ${unpacked.text.length} bytes (${unpacked.how})\n`
    );
    process.stderr.write(`[+] wrote ${target}\n`);

    const inner = detect.detect(unpacked.text);
    if (inner.confidence >= 0.5) process.stderr.write(`[*] the unpacked script is ${inner.label} (${inner.confidence.toFixed(2)})\n`);
    const child = forkJob(job, {
      source: unpacked.text,
      sourcePath: target,
      tracePath: job.path('.unpacked.deobf.luau'),
      obfuscator: inner.label,
    });
    child.resultDir = dir;

    // a Luraph v15 build inside a packer gets the full devirtualizer
    const major = inner.meta && inner.meta.major;
    if (inner.plugin.name === 'luraph_v15' && (!major || major === '15')) {
      try {
        return await run(child);
      } catch (e) {
        process.stderr.write(`[!] devirtualizing the unpacked payload failed (${e.message || e}); tracing it instead\n`);
      }
    }
    if (depth < 3) {
      return await runRecovered(child, {
        family: inner.plugin.family,
        label: inner.label,
        strategy: inner.plugin.strategy || 'vmp',
        version: inner.meta && inner.meta.version,
      }, depth + 1);
    }
  }


  if (meta.strategy === 'vmp') {
    notes.push(
      `${meta.label || 'this obfuscator'} runs its program on an embedded virtual machine; ` +
      'the trace shows every call it makes and the payload/string tables it builds'
    );
  }

  // 1. static extraction (independent of execution)
  let staticInfo = null;
  if (meta.family === 'wynfuscate') {
    try {
      staticInfo = wynfuscateStatic(job, meta);
      notes.push('wYnFuscate bytecode and handler tables were extracted statically (see .wynfuscate/)');
    } catch (e) {
      process.stderr.write(`[!] wYnFuscate static extraction failed: ${e.message || e}\n`);
    }
  }

  // 2. the script itself: what it calls, what it decodes, what it loads
  const tracePath = await runTrace(job, {
    stage: `${meta.label || 'obfuscated'} trace`,
    chunkMin: 64,
    notes,
  });

  // 3. turn captured payloads into readable source
  const res = recover.recover(job, meta, {});

  let result = tracePath;
  const sources = res.files.filter(f => f.kind === 'source');
  if (sources.length) {
    const biggest = sources.reduce((a, b) => (b.bytes > a.bytes ? b : a));
    result = biggest.path;
    process.stderr.write(`[+] recovered a ${biggest.bytes}-byte payload as Luau source\n`);
  } else if (res.files.length) {
    process.stderr.write(`[i] recovered ${res.files.length} payload file(s), none of them readable source\n`);
  } else {
    process.stderr.write('[i] no payload was handed to loadstring(); the script runs its bytecode in place\n');
  }
  process.stderr.write(`[+] report: ${res.reportPath}\n`);

  if (staticInfo) process.stderr.write(`[+] static extraction: ${staticInfo.dir}\n`);
  return result;
}

// wYnFuscate's bytecode lives in the file as base-91 text; this writes it out
// together with the handler tables and the anti-tamper surface.
function wynfuscateStatic(job, meta = {}) {
  const wyn = require('../families/wynfuscate');
  const dir = path.join(job.resultDir || job.outdir, `${path.basename(job.input).replace(/\.(luau?|txt)$/i, '')}.wynfuscate`);
  fs.mkdirSync(dir, { recursive: true });

  const dec = wyn.decode(job.source);
  const written = [];

  if (dec.bytecode && dec.bytecode.length) {
    written.push(job.write(path.join(dir, 'bytecode.bin'), dec.bytecode, 'latin1'));
  }
  if (dec.chunkMap && dec.chunkMap.length) {
    written.push(job.write(path.join(dir, 'chunk-map.bin'), dec.chunkMap, 'latin1'));
  }
  if (dec.base91) written.push(job.write(path.join(dir, 'base91.txt'), dec.base91, 'latin1'));

  const strings = wyn.bytecodeStrings(dec.bytecode || dec.chunkMap, 5);
  if (strings.length) {
    written.push(job.write(path.join(dir, 'strings.txt'), strings.join('\n') + '\n', 'utf8'));
  }

  const report = [];
  report.push('# wYnFuscate static extraction');
  report.push('');
  if (meta.version) report.push(`* sample: ${meta.version}`);
  report.push(`* bytecode: ${dec.bytecode ? dec.bytecode.length : 0} bytes`);
  report.push(`* chunk map: ${dec.chunkMap ? dec.chunkMap.length : 0} bytes`);
  report.push(`* base-91 blob: ${dec.base91 ? dec.base91.length : 0} bytes`);
  report.push(`* handler blocks: ${dec.handlers.length}`);
  report.push(`* loader constants: ${Object.keys(dec.constants).length}`);
  report.push('');
  report.push('## Anti-tamper surface');
  report.push('');
  for (const [k, v] of Object.entries(dec.antiTamper)) report.push(`* ${k}: ${v}`);
  if (dec.handlers.length) {
    report.push('');
    report.push('## Handler blocks');
    report.push('');
    for (const h of dec.handlers) {
      report.push(`* bound ${h.bound}: ${h.body.slice(0, 120).replace(/\n/g, ' ')}${h.body.length > 120 ? ' ...' : ''}`);
    }
  }
  report.push('');
  report.push('The VM bytecode is packed with a per-build bit scheme; the extracted');
  report.push('stream is kept verbatim so a build-specific decoder can be added without');
  report.push('re-running the extraction.');
  written.push(job.write(path.join(dir, 'README.md'), report.join('\n'), 'utf8'));

  return { dir, files: written, decoded: dec };
}

// Kept for callers of the old name: the generic path *is* the behaviour trace.
async function runGeneric(job) {
  return runTrace(job, { stage: 'behaviour trace' });
}

module.exports = { run, runGeneric, runTrace, runRecovered, runLegacy, runKeyforge, handOffPayload, forkJob };
