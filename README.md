# Luau Obfuscator Deobfuscator (Luraph, KeyForge and friends)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green.svg)](#requirements)
[![Target](https://img.shields.io/badge/Target-Luraph%20v12--v15-red.svg)](https://lura.ph/)
[![Target](https://img.shields.io/badge/Target-KeyForge%20(keyforge.win)-purple.svg)](https://www.keyforge.win)
[![Target](https://img.shields.io/badge/Target-14%20obfuscator%20families-orange.svg)](#supported-obfuscators)

A standalone, high-performance deobfuscator for Roblox Luau scripts protected by **Luraph**, delivered through **KeyForge**, or run through any of the
**13 other obfuscators** that ship in the [kers0nec/obfuscator-samples](https://github.com/kers0nec/obfuscator-samples) corpus (MoonSec, Prometheus, IronBrew, wYnFuscate, …).

It reverse-compiles Luraph v15's virtual machine back into readable Luau, follows KeyForge (`keyforge.win`) delivery chains to the payload behind them,
unpacks packers byte-exactly, and for everything else produces a full behaviour trace plus the recovered payload — with a written report for each run.

> ⚠️ For research, malware analysis and interoperability only. Two of the samples in `samples/luraph-v15/` are laced with a password-stealing chain. Do not run obfuscated scripts from untrusted sources on your own machine.

---

## Supported targets

| Input | What you get |
|---|---|
| **Luraph v15** (and v15-style VM chunks without a header) | **Full devirtualization** — control flow, closures, scoping and names restored as readable Luau |
| **Luraph v10 – v14.x** | VM entry hooks + **behaviour trace**: every call, branch, string and URL the script really performs, with any inner chunk inspected on its own |
| **KeyForge loader** (`keyforge.win/v1/load/...`, SDK, `_G.script_key`) | **Delivery chain resolution**: the loader is traced, every endpoint it requests is fetched (with your key), the payload is decrypted by the loader itself inside the sandbox, and the recovered payload is fed to the pipeline above |
| **Any other supported obfuscator** (see below) | Detection, **behaviour trace**, recovered payloads written out as beautified Luau, decoded string dump, and a `*.recovered.md` report |
| **LPS packer builds** | **Static unpack** (base85 + zstd) back to the original script — byte-exact, no execution |
| **wYnFuscate** | Static extraction of the VM bytecode, chunk map, handler blocks and anti-tamper surface, plus the trace |

Anything a script pulls in with `loadstring` is captured too: a v15 VM inside an older loader is devirtualized, a Luraph payload inside a packer is devirtualized, a KeyForge payload inside a plain loader is analysed on its own.

### Supported obfuscators

Detection runs on every file automatically; `node deob.js --detect <folder>` reports what a whole tree is.

| Family | Recognised by | Pipeline |
|---|---|---|
| **Luraph v15** | `This file was protected using Luraph Obfuscator v15…` | full devirtualization |
| **Luraph v10–v14** | `…generated using Luraph Obfuscator v12.2 by memcorrupt` | VM hooks + behaviour trace |
| **KeyForge** | `keyforge.win/v1/load/<project>`, SDK, `_G.script_key` | delivery chain + payload hand-off |
| **wYnFuscate** | `-- Protected by wYnFuscate: …` | static bytecode/handler extraction + trace |
| **MoonSec V1–V3** | `This file was protected with MoonSec V3` | payload recovery + trace |
| **MoonVeil** | `protected using the MoonVeil Obfuscator v…` | trace + string recovery |
| **IronBrew 1 / 2 / 3** | `ironbrew1`, IronBrew 2's `local i=string.byte…` shape, `--ironbrew3:tm:` | trace + payload recovery |
| **Prometheus** | `return(function(...)local n={"\115\103…"` decimal-escape table | escaped-string decoding + trace |
| **Hercules** | `--[Obfuscated by Hercules v…]` | payload recovery + trace |
| **Boronide / herrtt's obfuscator** | `herrtt's obfuscator, v0.2.4` | payload recovery + trace |
| **77fuscator** | `77fuscator 0.5.0` (plain or as block art) | trace (the protected calls come out readable) |
| **Synapse Xen** | `Synapse Xen v1.1.2 by Synapse GP` | trace + string recovery |
| **LuaObfuscator.com** | site banner or the `local v0=…v1=string.byte…` alias run | escaped-string decoding + trace |
| **PSU / LPS stage machines** | `while <flag> do if <slot> <= 0X18_` (binary/underscore literals) | trace + binary-literal aware decoding |
| **Luau state-machine VMs** | handler table driven by `while true do if ((<folded arithmetic>))` | trace and payload recovery |

Adding a family is a self-contained change: one fingerprint object in [`src/families/families.js`](src/families/families.js) (`detect()` + `strategy`).

---

## Requirements

- **Node.js 18+**
- **Python 3.10+** (symbolic execution backend)

The Luau runtime is bundled for **Windows** (`bin/luau.exe`, `bin/luau-ast.exe`) and **Linux** (`bin/luau`, `bin/luau-ast`). If a binary is missing, the tool downloads the official release for your platform automatically.

```bash
git clone https://github.com/your-name/deobfuscator-luraph-v15.git
cd deobfuscator-luraph-v15
node deob.js --help
```

No `npm install` step is needed — there are no dependencies.

---

## Quick start

```bash
# Deobfuscate one script -> <folder>/output/<name>.lua
node deob.js input.lua

# Any Luraph version, one after another
node deob.js samples/luraph-v15/

# Just tell me what this file is
node deob.js input.lua --detect

# Fast look: behaviour trace only (~2 seconds, no lifting)
node deob.js input.lua --no-devirt

# Full result for one file, custom path
node deob.js input.lua -o clean.lua
```

### KeyForge

```bash
# The loader the buyer pastes in
node deob.js "keyforge_loader.lua" --key YOUR-KEY

# Key from the environment instead
KEYFORGE_KEY=YOUR-KEY node deob.js keyforge_loader.lua

# Key-locked chains: save the responses once, then work fully offline
node deob.js keyforge_loader.lua --key YOUR-KEY --http-map saved.json
```

What happens: the loader is traced in the sandbox, every URL it asks for is fetched (the key is offered through every common header/query channel until one is accepted), the responses are served back to the script, and the script's **own** decryptor runs — so whatever obfuscation the delivery used, the payload comes out the way the loader builds it. A Luraph payload is then devirtualized in place, with the loader's environment still intact.

`--http-map` takes `{"https://host/path": "saved.lua"}` as JSON text or a `.json` file and is consulted before the network, which makes the whole chain reproducible offline (that is exactly how `test/` works).

If the key is missing or HWID-locked you still get the loader's behaviour trace, and the tool says why.

---

## How it works

```
┌────────────────────────────┐
│ Luraph / KeyForge script   │
└─────────────┬──────────────┘
              ▼
┌────────────────────────────┐
│ 1. Detect & route          │  version, family, key project
└─────────────┬──────────────┘
              ▼
┌────────────────────────────┐
│ 2. AST hooking (`vmmap`)   │  VM dispatch loops & closure makers
└─────────────┬──────────────┘
              ▼
┌────────────────────────────┐
│ 3. Sandboxed simulation    │  offline Roblox VM (`envlog.luau`),
│    (`harness`)             │  anti-tamper traps isolated & skipped,
│                            │  HTTP responses replayed, chunks captured
└─────────────┬──────────────┘
              ▼
┌────────────────────────────┐
│ 4. Live constant decrypt   │  lazy constants queried from the running
│    (`devirt`)              │  Luau VM over IPC, thousands per round
└─────────────┬──────────────┘
              ▼
┌────────────────────────────┐
│ 5. CFG / SSA reconstruction│  loops, if/else, closures, scoping
└─────────────┬──────────────┘
              ▼
┌────────────────────────────┐
│ 6. Naming & polish         │  Roblox-aware names, `luau-ast` verified
└─────────────┬──────────────┘
              ▼
        Clean Luau source
```

**Non-Luraph obfuscators** use steps 1, 3 and a recovery step: the script runs in the sandbox, anything it hands to `loadstring` is captured, and the captured
payloads are written out as beautified Luau (the beautifier is token-preserving: `tokenize(input) === tokenize(output)`, covered by a test) together with a
report listing payloads, URLs and decoded strings. Known packers are unpacked statically first, so an LPS → Luraph v15 chain still ends in a full devirtualization.

**KeyForge delivery chains** are handled between steps 1 and 3: the chain is walked outside the sandbox (following redirects, trying key channels, honouring `--http-map`), the responses are cached, and the loader is then run *with those responses served* so its own decoder produces the payload as a chunk — which the pipeline above can lift like any other script.

> Deep dive into the VM internals, SCCP, opcode dispatch mapping and the KeyForge chain: [TECHNICAL.md](TECHNICAL.md).

---

## Features

- **Full devirtualization for v15 builds** — recovers high-level control flow, closures and scoping instead of trace logging.
- **Version-aware routing** — v12–v14.x headers are recognised and reported with their exact version; headerless v15-style chunks are still lifted.
- **KeyForge delivery resolution** — key handling, redirect following, an offline HTTP cache for the sandbox, and automatic payload hand-off.
- **Chunk stitching** — anything `loadstring`'d (an inner VM, a fetched library, a decrypted payload) is captured and analysed on its own.
- **Anti-tamper isolation** — when a `LPH_CRASH()`-style trap fires, the responsible function is identified, disabled, and the trace continues along the stable path.
- **Roblox sandbox** — offline models for services, `Path2D`, `UDim2`, `Vector3`, `CFrame`, UI libraries and executor globals. No Roblox client needed.
- **Self-contained** — Luau binaries, runtime emulators and analysis modules ship in the repository.
- **14 obfuscator families detected** — 2,643 of 2,645 real samples from the public corpus are recognised and routed to the right pipeline.
- **Payload recovery for every family** — captured `loadstring` payloads are written out as readable Luau, with a `*.recovered.md` report (payloads, URLs, strings).
- **Static unpackers** — LPS packer builds are decoded byte-exactly (base85 → zstd) without executing anything.
- **Token-preserving beautifier** — one-line obfuscator output becomes readable source without changing a single token (checked by test).

---

## Command line options

| Option | Default | Description |
|---|---|---|
| `-o, --output <file>` | `<folder>/output/<name>.lua` | Result path (single input only); recovered payloads and the report land next to it |
| `--key <KEY>` | — | KeyForge script key (or `KEYFORGE_KEY`) |
| `--kf-url <url>` | from the script | Override the delivery URL (a `file://` path works) |
| `--kf-header <h: v>` | — | Extra header when replaying the delivery request |
| `--http-map <json>` | — | Saved responses (`{"url": "file.lua"}`), used before the network |
| `--chain-rounds <n>` | `4` | Delivery-chain hops / loader passes to follow |
| `--no-net` | off | Never touch the network |
| `--detect` | off | Report the obfuscator (and route) for each file, then exit |
| `--no-devirt` | off | Behaviour trace only (skips lifting) |
| `--no-hooks` | off | Do not instrument VM functions |
| `--no-fold` | off | Disable trace-time constant folding |
| `--strings` | off | Also write `<name>.strings.txt` with decoded strings |
| `--timeout <s>` | `90` | Hard timeout per run |
| `--budget <s>` | `30` | Script execution budget |
| `--max-runs <n>` | `12` | Maximum trace runs (anti-tamper reruns) |
| `--devirt-rounds <n>` | `200` | Maximum lift + constant-request rounds |
| `--executor <name>` | `Wave` | Executor profile to emulate |
| `--input-text <s>` | — | Text typed into TextBoxes before tracing |
| `--debug` | off | Keep intermediates in `output/` and announce them |
| `--keep-harness` | off | Keep the generated harness file |
| `--keep-preamble` | off | Keep the trace preamble in the result |
| `-h, --help` / `-v, --version` | | Help / version |

---

## Output

```
samples/luraph-v15/output/RideAPet.lua ← deobfuscated source (or behaviour trace)
samples/luraph-v15/output/RideAPet.strings.txt ← with --strings
samples/luraph-v15/output/RideAPet.* ← intermediates with --debug
```

A result is always labelled. A lifted v15 script is plain Luau; a trace starts
with a short header saying which obfuscator it came from and why a trace was
the best available answer:

```lua
-- Luraph v14.4.1 (older VM layout): behaviour trace
-- full source reconstruction is available for v15 VMs; inner chunks were checked for one
```

---

## Performance

| Benchmark | Size | Functions | Time | Result |
|---|---|---|---|---|
| `Blox Fruit.lua` | 646 KB | 520 | ~1m | 520 functions lifted |
| `Grow a Garden.lua` | 804 KB | 767 | ~1m 51s | 767 functions lifted |
| `StealAnEgg.lua` | **1.62 MB** | 1,723 | ~12m | 32,435 lines |
| `Steal-a-Brainrot.lua` | **1.07 MB** | 1,138 | ~7m | 19,407 lines |
| `RideAPet.lua` | 397 KB | 328 | ~55s | 5,170 lines |
| Any script, `--no-devirt` | any | — | 1–3s | behaviour trace |
| KeyForge chain (2 hops, offline) | — | — | < 1s | payload recovered |

Every input in the table ships in [`samples/luraph-v15/`](samples/luraph-v15/) and its expected result is
committed in [`samples/luraph-v15/output/`](samples/luraph-v15/output), so you can reproduce the numbers
on your own machine:

```bash
node deob.js "samples/luraph-v15/RideAPet.lua" -o /tmp/RideAPet.lua
diff <(cat /tmp/RideAPet.lua) "samples/luraph-v15/output/RideAPet.lua" && echo identical
```

---

## Tests

```bash
node test/make_fixtures.js   # build the offline KeyForge fixtures
node test/run_tests.js       # everything (several minutes)
node test/run_tests.js --quick   # detection + chains + legacy only
```

The KeyForge tests need no key and no network: they run a two-hop delivery
chain (loader → delivery endpoint → encrypted CDN payload) served from
`--http-map`, including one whose payload is a real Luraph v15 build that must
come out devirtualized.

`--quick` skips the two slow devirtualization cases; everything else (14 tests in
total) runs in seconds. The obfuscator fixtures live in
[`samples/families/`](samples/families/README.md) — one real sample per
family, with provenance.

---

## FAQ

**How long does it take?** Small scripts: seconds. 500–800 functions: about a
minute. A 1.7 MB script with 1,700 functions: a few minutes. `--no-devirt`
gives a behaviour trace of any size in 1–3 seconds.

**The result is a trace, not source. Why?** The file is either not a v15 VM
(some obfuscators keep their bytecode in a form the lifter does not model), or
the VM's layout differs from the ones it knows. The trace is still complete:
every call, string, branch and URL the script really performs — and any payload
the script builds for itself is written out next to it.

**Can you add obfuscator X?** Yes — a fingerprint plus a strategy flag in
`src/families/families.js` is enough to get detection, tracing and payload recovery; a
specialised decoder (like the LPS and wYnFuscate ones in `src/families/packers.js` /
`src/families/wynfuscate.js`) can be added on top when the format is known.

**KeyForge says the key was rejected.** Keys are per-project and can be
HWID-locked; a HWID-locked key only works on the machine it was bound to. Try
`--kf-header "x-script-key: <KEY>"`, or save the responses you already have
into an `--http-map` file and work offline.

**Windows / Linux / macOS?** Both architectures of the Luau runtime are
bundled. `bin/luau` is the Linux build; on macOS, put a native `luau` and
`luau-ast` in `bin/` (or on your `PATH`) — the tool picks them up.

**A different Python?** Set `PYTHON_BIN` (e.g. `PYTHON_BIN=python3.12`).

---

## License

[MIT](LICENSE)
