# Obfuscator fixtures

One real sample per obfuscator family, taken from
[`kers0nec/obfuscator-samples`](https://github.com/kers0nec/obfuscator-samples)
and used by `test/run_tests.js` to check detection and the recovery pipeline.
The files are the smallest sample of each family so the repository stays small;
they are third-party scripts, included only as test data.

| fixture | family | original sample |
| --- | --- | --- |
| `77fuscator.lua` | 77fuscator 0.5.0 | `60f04b5dbeec47c1.lua` |
| `boronide.lua` | herrtt's obfuscator (Boronide) 0.2.4 | `40005c112c58e1fa.lua` |
| `hercules.lua` | Hercules (Minimum) 1.6.2 | `Hercules_Minimum_487a91c7a0a3b7ed.lua` |
| `ironbrew1.lua` | IronBrew 1 | `85acba075c426444.lua` |
| `ironbrew2.lua` | IronBrew 2 | `26d9d1a19aa5aca2.lua` |
| `ironbrew3.lua` | IronBrew 3 | `beb19bf10ac64604.lua` |
| `lps.lua` | LPS (stage machine) | `517e74ca546d9bea.lua` |
| `luaobfuscator.lua` | LuaObfuscator.com | `40b7f5a523f6a858.lua` |
| `moonsec.lua` | MoonSec V3 | `MoonSec_V3_31894a3d57a2e241.lua` |
| `moonveil.lua` | MoonVeil 1.2.1 | `MoonVeil_v1.2.1_6ec6fa58e8e5a550.lua` |
| `prometheus.lua` | Prometheus (weak) | `Prometheus_Weak_a3437f4f1d903603.lua` |
| `synapsexen.lua` | Synapse Xen 1.1.2 | `SynapseXen_v1.1.2_c436ab809badd0d9.lua` |
| `wynfuscate.lua` | wYnFuscate 2026Q3 | `wYnFuscate_2026Q3_678b9b00992d9ac5.lua` |

Not included as fixtures (too large for the repository, still supported):
Boronide/Hercules/MoonSec/MoonVeil/Luraph collections, PSU stage machines,
and the Luraph v10-v15 version ladder.

`lps_packer.lua` is the packer build of the same family (base85 + zstd) and is
used by the static-unpack test.
