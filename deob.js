#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const detectModule = require('./src/core/detect');
const driver = require('./src/core/driver');

const VERSION = require('./package.json').version;
const SUPPORTED_EXTENSIONS = ['.lua', '.luau', '.txt'];

const HELP = `
Luau obfuscator deobfuscator - Luraph, KeyForge and 14 families  (v${VERSION})

Usage
  node deob.js <input.lua | folder> [more inputs...] [options]

Input
  Any .lua/.luau/.txt file, or a folder (subfolders are walked). The obfuscator
  is detected automatically:

    Luraph v15            full devirtualization -> readable Luau source
    Luraph v10 - v14.x    VM hooks + behaviour trace (every call, string, branch)
    KeyForge (keyforge.win)
                          delivery chain resolved, payload handed to the
                          matching pipeline (--key needed for gated scripts)
    wYnFuscate            static bytecode/handler extraction + trace
    packers (LPS, ...)    static unpack -> the original script, byte-exact
    MoonSec, Prometheus, IronBrew, Hercules, Boronide, 77fuscator, Synapse Xen,
    LuaObfuscator, PSU/LPS stage machines, MoonVeil, other state machines
                          behaviour trace + recovered payloads as readable Luau
                          + a <name>.recovered.md report

  Run  node deob.js --detect <folder>  to see what a whole tree contains.

Options
  -o, --output <file>     write the result here (single input only)
      --key <KEY>         KeyForge script key (or set KEYFORGE_KEY)
      --kf-url <url>      override the KeyForge delivery URL (a file:// path works)
      --kf-header <h: v>  extra header used when replaying the delivery request
      --http-map <json>   saved responses, as JSON text or a .json file:
                            {"https://host/path": "saved.lua"}
                          used before the network, so chains work offline
      --chain-rounds <n>  KeyForge loader passes to follow   (default 4)
      --no-net            never touch the network (KeyForge chain is not fetched)
      --strings           also dump decoded strings to <name>.strings.txt
      --detect            only report what the file is, then exit
      --no-devirt         skip lifting: behaviour trace only
      --no-hooks          do not instrument VM functions (no trap attribution)
      --no-fold           disable constant folding in the trace
      --timeout <s>       per trace run timeout            (default 90)
      --budget <s>        script execution budget          (default 30)
      --max-runs <n>      maximum trace runs (trap reruns) (default 12)
      --devirt-rounds <n> max lift + constant rounds       (default 200)
      --executor <name>   executor to emulate              (default Wave)
      --input-text <s>    text to type into TextBoxes before tracing
      --debug             keep intermediate files in output/ and announce them
      --keep-harness      keep the generated harness next to its output
      --keep-preamble     keep the trace preamble in the result
  -h, --help              this help
  -v, --version           print the version

Output
  <input dir>/output/<name>.lua - deobfuscated script, unpacked payload or trace
  <name>.payload*.luau          - payloads the script built for itself
  <name>.recovered.md           - what was recovered, with URLs and strings
  <name>.strings.txt            - decoded strings (with --strings)
  intermediate files land in output/ with --debug, otherwise in a temp dir
`.trimEnd();

// --http-map accepts inline JSON or a path to a .json file.
// Accepts inline JSON or the path of a .json file. Returns the parsed map plus
// the directory it was read from, so relative `file` entries inside it resolve
// against the map (not against the current working directory).
function loadHttpMap(value) {
  if (value == null) return { map: null, dir: null };
  let text = value;
  let dir = null;
  if (fs.existsSync(value) && fs.statSync(value).isFile()) {
    text = fs.readFileSync(value, 'utf8');
    dir = path.dirname(path.resolve(value));
  }
  try {
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
    return { map: parsed, dir };
  } catch (e) {
    process.stderr.write(`[!] --http-map is not valid JSON (${e.message})\n`);
    process.exit(2);
  }
}

function parseArgs(argv) {
  const args = {
    inputs: [],
    output: null,
    detect: false,
    noDevirt: false,
    noHooks: false,
    noFold: false,
    debug: false,
    strings: false,
    keepHarness: false,
    keepPreamble: false,
    timeout: 90,
    budget: 30,
    maxRuns: 12,
    devirtRounds: 200,
    executor: 'Wave',
    inputText: null,
    key: null,
    kfUrl: null,
    kfHeader: null,
    httpMap: null,
    httpMapDir: null,
    chainRounds: 4,
    noNet: false,
    help: false,
    version: false,
  };

  const need = (i, flag) => {
    if (i + 1 >= argv.length) {
      process.stderr.write(`[!] ${flag} needs a value\n`);
      process.exit(2);
    }
    return argv[i + 1];
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--detect') { args.detect = true; }
    else if (a === '--no-devirt') { args.noDevirt = true; }
    else if (a === '--no-hooks') { args.noHooks = true; }
    else if (a === '--no-fold') { args.noFold = true; }
    else if (a === '--debug') { args.debug = true; }
    else if (a === '--strings') { args.strings = true; }
    else if (a === '--keep-harness') { args.keepHarness = true; }
    else if (a === '--keep-preamble') { args.keepPreamble = true; }
    else if (a === '--no-net' || a === '--offline') { args.noNet = true; }
    else if (a === '-h' || a === '--help') { args.help = true; }
    else if (a === '-v' || a === '--version') { args.version = true; }
    else if (a === '-o' || a === '--output') { args.output = need(i, a); i++; }
    else if (a === '--timeout') { args.timeout = parseInt(need(i, a), 10); i++; }
    else if (a === '--budget') { args.budget = parseInt(need(i, a), 10); i++; }
    else if (a === '--max-runs') { args.maxRuns = parseInt(need(i, a), 10); i++; }
    else if (a === '--devirt-rounds') { args.devirtRounds = parseInt(need(i, a), 10); i++; }
    else if (a === '--executor') { args.executor = need(i, a); i++; }
    else if (a === '--input-text') { args.inputText = need(i, a); i++; }
    else if (a === '--key' || a === '--script-key') { args.key = need(i, a); i++; }
    else if (a === '--kf-url') { args.kfUrl = need(i, a); i++; }
    else if (a === '--kf-header') { args.kfHeader = need(i, a); i++; }
    else if (a === '--http-map') {
      const loaded = loadHttpMap(need(i, a));
      args.httpMap = loaded.map;
      args.httpMapDir = loaded.dir;
      i++;
    }
    else if (a === '--chain-rounds') { args.chainRounds = parseInt(need(i, a), 10); i++; }
    else if (!a.startsWith('-')) { args.inputs.push(a); }
    else { process.stderr.write(`[!] unknown option ${a} (see --help)\n`); process.exit(2); }
  }

  for (const [name, value, min] of [
    ['--timeout', args.timeout, 1],
    ['--budget', args.budget, 1],
    ['--max-runs', args.maxRuns, 1],
    ['--devirt-rounds', args.devirtRounds, 1],
    ['--chain-rounds', args.chainRounds, 1],
  ]) {
    if (!Number.isFinite(value) || value < min) {
      process.stderr.write(`[!] ${name} must be a number >= ${min}\n`);
      process.exit(2);
    }
  }

  return args;
}

class Job {
  constructor(inputPath, source, args, tracePath, debug, obfuscator = '') {
    this.input = inputPath;
    this.source = source;
    this.sourcePath = inputPath;
    this.args = args;
    this.tracePath = tracePath;
    this.debug = debug;
    this.obfuscator = obfuscator;
  }

  creditHeader() {
    return '';
  }

  get base() {
    return this.tracePath.replace(/\.(deobf\.luau|luau)$/, '');
  }

  path(suffix) {
    return this.base + suffix;
  }

  wrote(p) {
    if (this.debug) process.stderr.write(`[+] wrote ${p}\n`);
  }

  write(p, text, encoding = 'utf8') {
    fs.writeFileSync(p, text, { encoding });
    this.wrote(p);
    return p;
  }

  get outdir() {
    return path.dirname(path.resolve(this.tracePath));
  }
}

function collectInputFiles(rawPaths) {
  const files = [];
  const seen = new Set();

  for (const raw of rawPaths) {
    const abs = path.resolve(raw);
    if (!fs.existsSync(abs)) {
      process.stderr.write(`[!] path not found, skipping: ${raw}\n`);
      continue;
    }
    const stat = fs.statSync(abs);
    if (stat.isDirectory()) {
      // whole sample trees are normal input (one folder per obfuscator), so a
      // directory is walked completely; `output/` is skipped to avoid
      // re-processing results
      const walk = dir => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
          const filePath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            if (entry.name === 'output' || entry.name === '.git') continue;
            walk(filePath);
          } else if (entry.isFile() && SUPPORTED_EXTENSIONS.includes(path.extname(entry.name).toLowerCase())) {
            if (!seen.has(filePath)) {
              seen.add(filePath);
              files.push(filePath);
            }
          }
        }
      };
      walk(abs);
    } else if (stat.isFile()) {
      const ext = path.extname(abs).toLowerCase();
      if (!SUPPORTED_EXTENSIONS.includes(ext)) {
        process.stderr.write(`[!] unsupported extension for ${raw} (expected ${SUPPORTED_EXTENSIONS.join(', ')})\n`);
        continue;
      }
      if (!seen.has(abs)) {
        seen.add(abs);
        files.push(abs);
      }
    }
  }

  return files;
}

function routeFor(plugin, meta) {
  if (plugin.name === 'luraph_v15') {
    if (meta && meta.major && meta.major !== '15' && meta.header) return 'luraph_legacy';
    return 'luraph_v15';
  }
  if (plugin.name === 'keyforge') return 'keyforge';
  // every other recognised obfuscator: trace + payload recovery
  if (plugin.strategy || plugin.family === 'generic') return 'recover';
  return 'generic';
}

function stripResultComments(text) {
  return text.replace(/^(\s*--(?:[ \t]*(?:Deobfuscated by|Detected obfuscation|Local names are inferred|source:|NOTE: reconstructed|during the trace)[^\n]*\n?|\s*\n))+/, '');
}

async function processFile(absInput, args) {
  const source = fs.readFileSync(absInput, 'latin1');
  const { plugin, confidence, label, meta } = detectModule.detect(source);

  if (args.detect) {
    const route = routeFor(plugin, meta);
    const extra = route === 'luraph_v15' ? ' [full devirtualization]'
      : route === 'luraph_legacy' ? ' [behaviour trace]'
        : route === 'recover' ? ' [trace + payload recovery]'
          : route === 'keyforge' ? ' [delivery chain]' : '';
    console.log(`${path.basename(absInput)}\t${plugin.name}\t${confidence.toFixed(2)}\t${label}${extra}`);
    return null;
  }

  process.stderr.write(`[*] obfuscator: ${label} (detected, ${confidence.toFixed(2)})\n`);

  const outdir = path.join(path.dirname(absInput), 'output');
  fs.mkdirSync(outdir, { recursive: true });

  const tracename = path.basename(absInput).replace(/(\.luau?|\.txt)?$/, '.deobf.luau');
  const workdir = args.debug ? null : fs.mkdtempSync(path.join(os.tmpdir(), 'deobf_node_'));

  const tracePath = args.debug
    ? (args.output || path.join(outdir, tracename))
    : path.join(workdir, tracename);
  const final = (args.output && args.inputs.length === 1)
    ? args.output
    : path.join(outdir, path.basename(absInput));

  fs.mkdirSync(path.dirname(path.resolve(final)), { recursive: true });

  try {
    const fixed = detectModule.restoreHeaderNewline(source);
    let jobSource = source;
    let sourcePath = absInput;

    if (fixed !== source) {
      process.stderr.write('[*] header comment ran into the code: split it\n');
      jobSource = fixed;
      sourcePath = path.join(workdir || outdir, path.basename(absInput) + '.src.lua');
      fs.writeFileSync(sourcePath, fixed, 'latin1');
    }

    const job = new Job(absInput, jobSource, args, tracePath, args.debug, plugin.label);
    job.sourcePath = sourcePath;
    // artefacts that are results (recovered payloads, reports) belong next to
    // the output file - in output/ when no -o was given - and never in the
    // throw-away work dir
    job.resultDir = (args.output && args.inputs.length === 1)
      ? path.dirname(path.resolve(args.output))
      : outdir;

    const route = routeFor(plugin, meta);
    const routed = { ...(meta || {}), family: plugin.family, label, strategy: plugin.strategy || null };
    let result;
    if (route === 'luraph_v15') result = await driver.run(job);
    else if (route === 'luraph_legacy') result = await driver.runLegacy(job, routed);
    else if (route === 'keyforge') result = await driver.runKeyforge(job);
    else if (route === 'recover') result = await driver.runRecovered(job, routed);
    else result = await driver.runGeneric(job);

    if (final && result && fs.existsSync(result)) {
      let content = fs.readFileSync(result, 'utf8');
      content = stripResultComments(content);
      fs.writeFileSync(final, content, 'utf8');
      process.stderr.write(`[+] result: ${final}\n`);
      return final;
    }
    process.stderr.write(`[!] no result for ${path.basename(absInput)}\n`);
    return null;
  } finally {
    if (workdir && fs.existsSync(workdir)) {
      try { fs.rmSync(workdir, { recursive: true, force: true }); } catch {}
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.version) {
    console.log(VERSION);
    return;
  }
  if (args.help || args.inputs.length === 0) {
    console.log(HELP);
    process.exit(args.help ? 0 : 2);
  }

  const files = collectInputFiles(args.inputs);
  if (files.length === 0) {
    console.error('[!] no valid .lua / .luau input files found');
    process.exit(1);
  }

  if (args.detect) {
    for (const file of files) {
      const source = fs.readFileSync(file, 'latin1');
      const { plugin, confidence, label, meta } = detectModule.detect(source);
      const route = routeFor(plugin, meta);
      const kind = route === 'luraph_v15' ? 'full lift'
        : route === 'luraph_legacy' ? 'behaviour trace'
        : route === 'keyforge' ? 'chain + payload'
        : 'behaviour trace';
      console.log(`${path.basename(file)}\t${plugin.name}\t${confidence.toFixed(2)}\t${label}\t${kind}`);
    }
    return;
  }

  if (files.length > 1 && args.output) {
    process.stderr.write('[!] --output is ignored for multiple inputs (each file goes into its own output/ folder)\n');
  }

  const rows = [];
  let succeeded = 0;
  let failed = 0;

  for (const file of files) {
    process.stderr.write(`\n[*] processing ${file}\n`);
    const started = Date.now();
    try {
      const res = await processFile(file, args);
      const secs = (Date.now() - started) / 1000;
      if (res) {
        succeeded++;
        rows.push([path.basename(file), 'ok', secs, res]);
      } else {
        failed++;
        rows.push([path.basename(file), 'failed', secs, '']);
      }
    } catch (err) {
      const secs = (Date.now() - started) / 1000;
      process.stderr.write(`[!] failed on ${path.basename(file)}: ${err.message || err}\n`);
      failed++;
      rows.push([path.basename(file), 'failed', secs, '']);
    }
  }

  if (rows.length > 1) {
    process.stderr.write('\n[*] summary\n');
    for (const [name, status, secs, out] of rows) {
      process.stderr.write(`    ${status === 'ok' ? '  ok  ' : ' fail '} ${name}  (${secs.toFixed(1)}s)${out ? '  -> ' + out : ''}\n`);
    }
  }
  process.stderr.write(`\n[*] done: ${succeeded} succeeded, ${failed} failed out of ${files.length}\n`);
  if (failed > 0 && succeeded === 0) process.exit(1);
}

main().catch(err => {
  process.stderr.write('[!] Fatal error: ' + (err.message || err) + '\n');
  process.exit(1);
});

module.exports = { Job, parseArgs, routeFor };
