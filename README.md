# SHA-256 Preimage Bench

**Direct recovery of one 32-bit message word through 16 SHA-256 rounds.**

Given the full output of a reduced-round, single-block SHA-256 computation, this lab recovers the first message word when the other 36 message bytes are fixed. The same derivation works from round 1 through round 16. In round 17, the message schedule first feeds the unknown word back into the computation.

[Research presentation](docs/SHA256_Preimage_Bench.pdf) · [Derivation and protocol](docs/experiment.md) · [Raw measurements](results/recovery-benchmark.json)

## Results

The reference run recovered **1,024 of 1,024** full-width test cases (64 seeded words at each of 16 round counts). Separately, 24 paired 12-bit trials per round measured time to a verified first match.

| Rounds | Direct recovery, median | Enumeration, median |
| ---: | ---: | ---: |
| 1 | 8.30 µs | 4.83 ms |
| 4 | 16.60 µs | 10.53 ms |
| 8 | 25.85 µs | 18.12 ms |
| 16 | 46.70 µs | 33.57 ms |

Timings are local measurements on Windows x86-64 with CPython 3.12.14. The direct method and ascending enumeration used identical targets. Each method includes its candidate verification or matching computation. Timing varies with the implementation, machine, and candidate order.

An earlier [Z3 comparison](archive/README.md) tested two exact encodings on a 12-bit input space. Both found verified witnesses at eight rounds and returned `unknown` at 16 and 64 rounds with a 2-second solver budget. These are separate runs with a different protocol. The full 64-round implementation is cross-checked against Python's `hashlib`.

## Reproduce

Python 3.11 or newer. The primary experiment uses the standard library.

```sh
python -X utf8 -m unittest discover -s tests -v
python -X utf8 benchmark.py
```

The benchmark writes `benchmark-local.json`. It includes the input words, per-trial timings, candidate counts and environment metadata. Use `--help` to change the seed, sample size, or output path.

```python
from sha256_lab import digest, recover_word

target = digest(0xDEADBEEF, rounds=16)
assert recover_word(target, rounds=16) == 0xDEADBEEF
```

## Scope

The direct method requires all 256 output bits, a known initial state, and a single padded block where only `W0` varies. Rounds 1–16 use the 16 words in that block. Round 17 uses `W16`, the first expanded word. For this message family, `W16` changes with `W0`. The full 64-round experiment covers a deliberately restricted 12-bit search domain.

Algorithm reference: [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
