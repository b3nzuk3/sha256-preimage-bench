# Experimental method

## Message family and target

The 40-byte message is a four-byte big-endian `W0`, followed by bytes `01` through `24` in hexadecimal. Standard SHA-256 padding makes it one 512-bit block. The initialization vector and round constants are those in [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

For each tested round count, the target is all eight words of the resulting working state with the standard feed-forward addition. At 64 rounds this equals the standard SHA-256 digest for the family. The tests compare it with `hashlib.sha256` for 67 boundary and seeded inputs.

## Why recovery works through round 16

1. Subtract the known initial state word by word modulo 2³² to recover the final working state.
2. Reverse each later round using its fixed message word, from the last round back to the state immediately after round 1. Six registers are recovered from the register shifts. The two remaining registers follow from the modular additions in the round.
3. In the first round, the initial registers are public. The first working-state word after that round equals a known constant plus `W0` modulo 2³². Subtract the constant to obtain the unique possible `W0`.
4. Verify that the candidate reconstructs the first-round state and the full target. An arbitrary 256-bit target can fail these checks.

Every step before candidate verification is deterministic and reversible on outputs of this family. The 1,024 observed cases check the implementation across the supported range. The argument gives uniqueness for every valid output in the family.

## Why the direct method stops at round 17

The first expanded word is `W16 = σ1(W14) + W9 + σ0(W1) + W0 mod 2³²`. For this family, the first three terms are fixed. The reverse step for round 17 would therefore require a word that depends on the value being recovered. The raw benchmark records `W16` for `W0 = 0` and `W0 = 1`.

## Measurement protocol

- Full-width validation uses 64 words drawn from a seeded Python PRNG. The same words are tested at all 16 round counts.
- The timed comparison uses 24 seeded 12-bit words at each of 1, 4, 8 and 16 rounds. Both methods get the same target, and the order of the two methods alternates by trial.
- Timing starts after target creation and ends when a matching candidate is returned. Direct recovery includes recomputing the digest. Enumeration starts at zero and stops at its first matching digest. At reduced rounds enumeration uses the reference implementation. The optional 64-round enumeration path uses `hashlib`.
- The report summarizes medians of elapsed wall-clock time. The raw file carries every measurement and candidate count. These are single-machine results for the stated input distribution and search order.
- The historical Z3 experiment used one 12-bit input per round count and a separate timing protocol. Its JSON records solver and construction time separately. `unknown` means the solver returned no determination under the configured budget.

## Files

| File | Purpose |
| --- | --- |
| [sha256_lab.py](../sha256_lab.py) | Reference compression, inverse rounds and first-match enumeration |
| [benchmark.py](../benchmark.py) | Seeded trials and raw result export |
| [tests/test_sha256_lab.py](../tests/test_sha256_lab.py) | Standard digest, round-trip, target verification and boundary checks |
| [results/recovery-benchmark.json](../results/recovery-benchmark.json) | Checked-in reference run |
| [archive/README.md](../archive/README.md) | Earlier solver experiment, source and recorded results |
