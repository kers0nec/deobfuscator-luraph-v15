# Luraph & KeyForge Deobfuscation Internals

This document covers the architecture and reverse-engineering pipeline used by
this engine for **Luraph** (v12 – v15) protected scripts and for **KeyForge**
(`keyforge.win`) releases, which wrap a protected payload behind a key-checked
delivery endpoint.

---

## 1. How the targets work

### Luraph v15

Luraph v15 transforms a Luau script into an interpreted virtual machine:

1. **Virtual instruction set** — the original bytecode is compiled into a
   custom register/stack machine with dynamic opcodes and encrypted dispatch
   tables.
2. **Flattened control flow** — jump targets live in one state loop
   (`while true do local op = ARR[PC]; if-tree ... end`), so the original
   `while` / `repeat` / `for` / `if` structure is gone.
3. **Lazy constant encryption** — strings, numbers and jump destinations sit in
   encrypted buffers (`LPH_ENCSTR`, `LPH_ENCFUNC`) and are decrypted in place
   the first time a branch reaches them.
4. **Anti-tamper probes** — hook detection, stack-depth checks and metatable
   inspection; on detection the VM corrupts its own bytecode and spins
   (`LPH_CRASH()`).

### Luraph v12 – v14.x

Older generations use the same idea with a different VM layout: a
self-decrypting preamble, a dispatch table that is rebuilt at run time, and (in
v13/v14) method-based state objects rather than a single flat dispatcher. The
lifter is written against the v15 shape, so those builds take the tracing path
below; their `loadstring`'d chunks are still inspected for a v15 VM or plain
Luau.

### KeyForge

A KeyForge release is delivered, not shipped:

```
executor -> GET /v1/load/{projectId}   (the hosted loader)
loader   -> reads _G.script_key, requests the payload endpoint (server checks
            status, expiry, HWID, rate limits, script match)
payload  -> protected Luau (often a Luraph build), decrypted by the loader
            itself and executed with loadstring
```

Nothing in the chain is fixed: the endpoint, the encoding (base64, XOR, chunked
buffers, custom cipher) and the number of hops vary per project.

---

## 2. Pipeline

```
[Target script]
       │
       ▼
0. Detect & route            version, family, KeyForge project id
       │
       ▼
1. KeyForge chain walk       out-of-sandbox: redirects, key channels,
                             --http-map, response cache
       │
       ▼
2. AST analysis & hooking    VM dispatchers, closure makers, entry hooks
       │
       ▼
3. Sandboxed simulation      offline Roblox VM, trap isolation,
                             recorded HTTP responses, chunk capture
       │
       ▼
4. Symbolic execution        SCCP over vm registers; lazy constants fetched
                             live from the running VM over IPC
       │
       ▼
5. CFG / SSA                 loops, conditionals, register webs, scoping
       │
       ▼
6. Naming & polish           Roblox-aware names, luau-ast verification
       │
       ▼
[Clean Luau code]
```

### Stage 0 — detection and routing (`src/core/detect.js`, `src/families/families.js`)

`detect()` returns the plugin, a confidence and a `meta` table:

| Signal | Result |
|---|---|
| `This file was protected using Luraph Obfuscator vX` | confidence 1.0 (v15) / 0.97 (older), version recorded |
| `return setmetatable({...})` + VM shape, no header | confidence 0.8, treated as a v15-style VM |
| `keyforge.win/v1/load/{id}` | confidence 0.95, project id recorded |
| `keyforge.win/sdk/client.lua` | confidence 0.85 |
| nothing | generic behaviour trace |

Routing: v15 → the full lifter; older Luraph → hooks + behaviour trace, then a
check of every captured chunk; KeyForge → chain resolution first.

The registry has two halves. `src/core/detect.js` owns the two plugins that drive a
dedicated pipeline (Luraph and KeyForge) and keeps their rich metadata — exact
version, header generation, project id, key channel. `src/families/families.js` holds one
fingerprint object per other obfuscator family:

```js
{
  name: 'moonsec', label: 'MoonSec', strategy: 'loader',
  detect(source) { … return { confidence, meta } | 0 },
}
```

`strategy` decides what the driver is allowed to promise: `vmp` (the payload is
bytecode for an embedded VM — trace and recover), `loader` (the script builds its
own source and `loadstring`s it — the payload comes back as real code), `static`
(a source-to-source transform — trace plus decoded tables). Detection returns
`{ plugin, confidence, meta, label }`; anything below 0.5 falls back to the
generic behaviour trace, so an unknown obfuscator still yields a full trace
instead of an error.

Fingerprints are deliberately cheap and order-independent: a header comment
(73 % of the corpus), a generator shape in the first few hundred bytes (the
`v0..vN` alias run LuaObfuscator emits), a state-machine form
(`while <flag> do if <slot> <= 0X18_`), or a fixed literal (the LPS base-85 blob).
`stripPreamble()` first removes banners, markdown fences and stray `lua` words,
because samples circulating on forums carry them. On the public corpus this
recognises 2 643 of 2 645 files (the two misses are a zero-byte file and one
unreleased build).

### Stage 1 — KeyForge chain walk (`src/families/keyforge.js`)

The walk never executes the loader with live credentials. It follows the chain
the way the executor would:

1. Start at the loader URL (or `--kf-url`), and at each hop try
   `--http-map` → recorded responses → network.
2. Offer the key through every common channel (`x-script-key`, `script-key`,
   `x-keyforge-key`, `x-api-key`, `Authorization`, `Authorization: Bearer`,
   `?key=`, `?script_key=`, `?k=`, POST body, POST JSON) until the service
   answers with something that is not an error envelope. The key is never
   logged unmasked.
3. Decide what a hop is: Lua that references another endpoint is a loader
   (continue); Lua that does not is the payload; a non-Lua blob is handed to
   the script itself to decode (see stage 3).
4. Keep every response in a cache that stage 3 replays.

### Stage 1b — payload recovery (`src/families/recover.js`, `src/families/packers.js`, `src/families/wynfuscate.js`)

Every non-Luraph family goes through the same recovery machinery, because every
one of them ends up handing real code to `loadstring` sooner or later:

1. **static unpack** — known packers are decoded without executing anything. The
   LPS packer carries a `[==[LPS/…]==]` literal: five-character groups are
   base-85 digits offset by 33 (with `z` expanding to five `!`), decoded
   little-endian into four bytes each, and the result is a **zstd** stream
   (older builds: zlib). The recovered script is written out byte-exactly and
   re-enters the pipeline — an LPS file whose payload is a Luraph v15 build ends
   in a full devirtualization.
2. **trace** — the script runs in the sandbox with `chunk_min` lowered to 64
   bytes, so even small payloads are reported instead of being executed inline.
3. **materialise** — each captured chunk is classified (`source`, `bytecode`,
   `data`), source chunks are beautified and written as `<name>.payload*.luau`,
   and a `<name>.recovered.md` report lists payloads, URLs the script requested,
   decoded strings and trace artefacts.

Two details matter for correctness. The beautifier (`src/util/beautify.js`) never
reorders, adds or removes tokens — it only writes whitespace — and it is
validated by re-tokenising its own output (`tokenize(input) === tokenize(output)`,
asserted for every bundled fixture). And Lua's `\ddd` escapes are **decimal**,
not octal: decoding them the wrong way turns a Prometheus string table into
noise, which is exactly what the escaped-string tests pin down.

wYnFuscate gets a static pass of its own (`src/families/wynfuscate.js`): the `[n]="…"`
chunk map (or the base-91 `j0` blob), the handler bodies, folded loader constants
and the anti-tamper surface (probe variables, FRIDA checks) are extracted and
written to `<name>.wynfuscate/` — useful precisely when the probes would stop a
trace.

### Stage 2 — AST hooking (`src/core/vmmap.js`, `core/obfuscators/luraph_v15/vmmap.py`)

`luau-ast` dumps the AST; the mapper finds `while true do local op = ARR[PC]`
dispatchers and the closure-maker functions around them, then injects
non-destructive hooks:

- a **proto counter and entry log** (`__PID`, `__ENT`, `__PLAST`) — also the
  mechanism behind `__SKIPP`, which is how a trapped function gets disabled;
- a **maker hook** (`__PA`, `__PF`, `__PK`) that records, per proto, the VM
  closure it builds and the upvalues the maker captured.

The hooks only use table operations, so the VM's stack, upvalue and
`debug.info` views are unchanged — which is exactly what anti-tamper checks
inspect.

### Stage 3 — sandboxed simulation (`runtime/envlog.luau`, `src/core/harness.js`)

The script runs inside an offline Roblox VM:

- **Engine model** — services, instances, datatypes (`Vector3`, `CFrame`,
  `UDim2`, `Path2D`, …), UI libraries, remotes, executor globals.
- **Statement recording** — calls, conditions, strings, loop marks and
  metatable use are emitted as a structured trace.
- **Trap isolation** — a detected `LPH_CRASH()` pinpoints the function
  (`\0TRIGGER <id>`), the driver disables it and re-runs; a trap that turns out
  to be the script's own crash check is kept instead.
- **`loadstring` capture** — every chunk the script compiles is reported
  (`\0CHUNK`) once it is at least `__CONFIG.chunk_min` bytes (default 4096;
  lowered to 64 while following a KeyForge chain). The loader chain therefore
  reveals its payload.
- **`__CONFIG.http_cache`** — a URL → body table. When a script asks for a
  recorded URL, the real body is returned instead of a stand-in, so the
  script's own decoder runs for real. This is what turns a KeyForge delivery
  into a decrypted payload without re-implementing its cipher.
- **Spin watchdog** (`__SPIN`) — a step counter in dispatch heads aborts a VM
  that spins instead of running.

### Stage 4 — symbolic execution and live constants (`core/obfuscators/luraph_v15/devirt.py`)

Each proto is walked with sparse conditional constant propagation. Values that
exist only in the running VM (buffers decrypted in place, closures built by a
maker, upvalue chains) are requested from the long-lived harness over IPC
(`HarnessServer`), which decrypts them on the fly and returns them in
milliseconds. Constants are requested in bulk, several thousand per round, and
the loop stops as soon as a round adds nothing new.

For a KeyForge payload the lifter runs **inside the loader**: the loader is
traced with the recorded responses, the payload chunk is instrumented like the
main script during the same run, and the lift therefore sees the environment
the payload was built in (decoded buffers, upvalues, maker closures). Lifting
the extracted chunk standalone is only the fallback.

### Stage 5 — control flow reconstruction (`core/structure.py`, `core/loops.py`)

Basic blocks collected during the walk are assembled into a directed graph.
Dominator analysis identifies loops (`while true`, numeric `for`, generic
`for-in`), and conditionals are rebuilt from the guard chains
(`if/elseif/else`). Blocks made unreachable by opaque predicates are pruned;
blocks whose successor was never explored are emitted with an explicit
`error("devirt: unexplored successor ...")` marker rather than silently wrong
code.

### Stage 6 — registers, naming and polish (`core/variables.py`, `core/names.py`, `core/codegen.py`)

Virtual registers are followed across basic blocks with SSA web analysis,
merged where they alias, and named from usage context (`Players`,
`ReplicatedStorage`, `TweenService`, …). Function assignments become
`local function name(...)`, indentation is normalised, and the result is
verified by re-parsing it with `luau-ast`.

---

## 3. Fast-path controller

After the first full lift the engine knows how many constants are still
unresolved and how many blocks were unlifted. When a round finishes with zero
unlifted blocks and no new constant requests, the remaining collection passes
are skipped and code generation starts immediately — 40–60 seconds saved on
500+ function scripts.

---

## 4. Testing

`test/run_tests.js` runs the pipeline end to end and needs neither network nor
key:

- detection of every bundled sample and of a v14-era header;
- a **legacy fixture** (v14 header, decoder, inner payload) that must come out
  as a labelled behaviour trace with the payload's constants resolved;
- a **KeyForge fixture chain** — loader → `/v1/load` → encrypted CDN payload —
  served from `--http-map`, where the payload must be recovered and traced;
- the same chain with a **real Luraph v15 payload**, which must be
  devirtualized in place;
- a direct run of `samples/luraph-v15/RideAPet.lua`, compared against the committed
  reference output in `samples/luraph-v15/output/`;
- detection of the 14 bundled obfuscator families, and the beautifier's token
  invariant on real obfuscated samples;
- the LPS static unpacker (base85 + zstd), the wYnFuscate extractors, Prometheus
  escaped strings, and end-to-end payload recovery for a traced family.

Fixtures are generated by `test/make_fixtures.js` (they are small, deterministic
and committed, so the tests run anywhere). The per-family fixtures are real
samples from `kers0nec/obfuscator-samples`, with provenance listed in
`samples/families/README.md`.

### Regression suite

`samples/luraph-v15/*.lua` are nine Luraph v15 builds with committed reference outputs. Nine
of the eleven reference pairs reproduce byte-identically; the exceptions are a
sample whose committed reference predates the current pipeline (it contains 46
`devirt: unexplored successor` markers and does **not** reproduce at the base
commit either — the current pipeline lifts it completely) and one sample that
never had a reference committed. The comparison is run after every change.
