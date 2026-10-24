"""
benchmark.py - Roaring vs Bitset vs HashSet               OWNER: Rithika
-----------------------------------------------------------------
    python -m rithika.benchmark                       (1M events, mixed data)
    python -m rithika.benchmark --n 2000000 --mode sparse
"""
import argparse, time

from nishanth.roaring import Roaring
from sandeep.baselines import BitsetSet, HashSet
from sandeep.datagen import generate_events

QUERIES = {
    "failed AND suspicious":
        lambda S: S["failed_login"] & S["suspicious_ip"],
    "failed AND suspicious AND NOT whitelisted":
        lambda S: (S["failed_login"] & S["suspicious_ip"]) - S["whitelisted"],
    "unusual_hour OR sensitive":
        lambda S: S["unusual_hour"] | S["sensitive_resource"],
    "(unusual AND sensitive) AND NOT whitelisted":
        lambda S: (S["unusual_hour"] & S["sensitive_resource"]) - S["whitelisted"],
}


def best_time(fn, repeat=3):
    best = float("inf")
    for _ in range(repeat):
        t = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t)
    return best


def build(kind, flags, n):
    t = time.perf_counter()
    if kind == "Roaring":
        S = {k: Roaring.from_iterable(v) for k, v in flags.items()}
    elif kind == "Bitset":
        S = {k: BitsetSet(n, v) for k, v in flags.items()}
    else:
        S = {k: HashSet(v) for k, v in flags.items()}
    return S, time.perf_counter() - t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1_000_000)
    ap.add_argument("--mode", choices=["mixed", "sparse", "dense"], default="mixed")
    a = ap.parse_args()

    print(f"Generating {a.n:,} synthetic security events (mode={a.mode}) ...")
    flags = generate_events(a.n, a.mode)
    print("Flag sizes:", {k: len(v) for k, v in flags.items()})

    structures, results = {}, {}
    for kind in ("Roaring", "Bitset", "HashSet"):
        S, bt = build(kind, flags, a.n)
        mem = sum(x.size_bytes() for x in S.values())
        structures[kind] = S
        results[kind] = {"build_s": bt, "mem_kb": mem / 1024, "q": {}}

    for qname, q in QUERIES.items():
        outs = {}
        for kind, S in structures.items():
            results[kind]["q"][qname] = best_time(lambda: q(S)) * 1000
            outs[kind] = list(q(S))
        assert outs["Roaring"] == outs["Bitset"] == outs["HashSet"], f"MISMATCH on {qname}"
    print("Correctness check: all three structures return identical results.\n")

    print(f"{'Structure':<10}{'Build (s)':>11}{'Memory (KB)':>14}")
    for kind, r in results.items():
        print(f"{kind:<10}{r['build_s']:>11.2f}{r['mem_kb']:>14,.0f}")
    print()
    print(f"{'Query time (ms)':<46}" + "".join(f"{k:>11}" for k in results))
    for qname in QUERIES:
        print(f"{qname:<46}" + "".join(f"{results[k]['q'][qname]:>11.2f}" for k in results))
    print("\nRoaring container mix per flag:")
    for k, c in structures["Roaring"].items():
        print(f"  {k:<20}{c.stats()}")


if __name__ == "__main__":
    main()
