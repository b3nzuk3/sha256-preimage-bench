# Earlier exact solver experiment

This directory preserves the original restricted-domain comparison. The forward model uses the same fixed 40-byte message family as the primary benchmark. It compares a Z3 bit-vector encoding with a variant that adds redundant projected GF(2) equations. The script also contains an optional explicit XOR/AND encoding.

The [historical results](sha256_step4_results_12bit.json) use `W0 = 173`, a 12-bit search domain, a 256-bit target and a 2-second nominal budget per solver check.

| Rounds | Bit-vector encoding | Bit-vector + GF(2) |
| ---: | --- | --- |
| 1 | Verified witness | Verified witness |
| 2 | Verified witness | Verified witness |
| 4 | Verified witness | Verified witness |
| 8 | Verified witness | Verified witness |
| 16 | Unknown | Unknown |
| 64 | Unknown | Unknown |

The raw JSON reports model construction, first solver check, and any optional second-solution check. A witness and a uniqueness proof are distinct outcomes. `unknown` at 16 and 64 rounds records a solver limit in this experiment. The primary benchmark tests direct recovery under a separate protocol.

## Re-run on Linux

Install a native Z3 shared library (for example `libz3-4` on Debian or Ubuntu) and run from this directory.

```sh
python -m unittest -v test_sha256_step4_sat.py
python sha256_step4_sat.py --rounds 1 2 4 8 16 64 --unknown-bits 12 --secret 173 --timeout-ms 2000 --output solver-local.json
```

The archived source includes the reference compression and projected-equation builder. The earlier results were retained as measured. The primary benchmark and its CI workflow require no Z3 installation.
