"""Run the reproducible SHA-256 experiments and write raw results as JSON."""
from __future__ import annotations

import argparse
import json
import platform
import random
from pathlib import Path
from statistics import median
from time import perf_counter_ns

from sha256_lab import digest, exhaustive_first, recover_word, schedule

SEED = 20261028
TIMED_ROUNDS = (1, 4, 8, 16)
FULL_WIDTH_ROUNDS = range(1, 17)


def full_width_check(seed: int, trials_per_round: int) -> dict:
    rng = random.Random(seed)
    trials = [rng.getrandbits(32) for _ in range(trials_per_round)]
    recovered = 0
    for rounds in FULL_WIDTH_ROUNDS:
        for word in trials:
            actual = recover_word(digest(word, rounds), rounds)
            if actual != word:
                raise RuntimeError(f"failed recovery at round count {rounds} for W0={word:#010x}")
            recovered += 1
    return {"input_bits": 32, "words": trials, "rounds": list(FULL_WIDTH_ROUNDS), "recovered": recovered}


def compare(seed: int, trials: int, bits: int) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    words = [rng.randrange(1 << bits) for _ in range(trials)]
    rows = []
    for rounds in TIMED_ROUNDS:
        for index, word in enumerate(words):
            target = digest(word, rounds)
            methods = ("direct", "enumeration") if index % 2 == 0 else ("enumeration", "direct")
            measurements = {}
            for method in methods:
                start = perf_counter_ns()
                if method == "direct":
                    candidate, checked = recover_word(target, rounds), None
                else:
                    candidate, checked = exhaustive_first(target, rounds, bits)
                measurements[method] = (perf_counter_ns() - start, checked)
                if candidate != word:
                    raise RuntimeError(f"{method} returned {candidate} for W0={word}")
            rows.append({
                "rounds": rounds, "trial": index + 1, "word": word,
                "direct_ns": measurements["direct"][0],
                "enumeration_ns": measurements["enumeration"][0],
                "enumerated_candidates": measurements["enumeration"][1],
            })
    summary = []
    for rounds in TIMED_ROUNDS:
        group = [row for row in rows if row["rounds"] == rounds]
        summary.append({
            "rounds": rounds,
            "direct_median_us": round(median(row["direct_ns"] for row in group) / 1_000, 2),
            "enumeration_median_ms": round(median(row["enumeration_ns"] for row in group) / 1_000_000, 2),
            "enumerated_candidates_median": median(row["enumerated_candidates"] for row in group),
        })
    return rows, summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bits", type=int, default=12, choices=range(1, 17), metavar="1..16")
    parser.add_argument("--trials", type=int, default=24, choices=range(1, 101), metavar="1..100")
    parser.add_argument("--full-width-trials", type=int, default=64, choices=range(1, 1001), metavar="1..1000")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--output", type=Path, default=Path("benchmark-local.json"))
    args = parser.parse_args()

    full_width = full_width_check(args.seed, args.full_width_trials)
    rows, summary = compare(args.seed, args.trials, args.bits)
    data = {
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "seed": args.seed,
        "full_width_check": full_width,
        "paired_benchmark": {"input_bits": args.bits, "trials_per_round": args.trials,
                             "summary": summary, "runs": rows},
        "schedule_boundary": {
            "words_compared": [0, 1],
            "w16": [schedule(word, 17)[16] for word in (0, 1)],
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {full_width['recovered']} full-width recoveries across rounds 1–16")
    for row in summary:
        print(f"{row['rounds']:>2} rounds  direct {row['direct_median_us']:>7.2f} µs"
              f"  enumeration {row['enumeration_median_ms']:>7.2f} ms")
    print(f"Raw data: {args.output}")


if __name__ == "__main__":
    main()
