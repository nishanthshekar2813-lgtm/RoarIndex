"""
demo.py - "ThreatBoard" live demo                          OWNER: Nishanth
-----------------------------------------------------------------
    python -m nishanth.threatboard                      interactive (1M synthetic events)
    python -m nishanth.threatboard --auto               scripted run, good for a quick walkthrough
    python -m nishanth.threatboard --n 50000000 --mode sparse

Commands inside the demo:
    stats                               memory + container mix for every flag
    query failed_login AND suspicious_ip AND NOT whitelisted
    burst                               inject a 50,000-event attack burst
    regen <n> <mixed|sparse|dense>      new synthetic log
    help | quit
"""
import argparse, random, time

from nishanth.roaring import Roaring
from sandeep.baselines import BitsetSet, HashSet
from sandeep.datagen import generate_events, FLAGS

BURST_LEN = 50_000


def build_all(flags, n):
    return {
        "Roaring": {k: Roaring.from_iterable(v) for k, v in flags.items()},
        "Bitset": {k: BitsetSet(n, v) for k, v in flags.items()},
        "HashSet": {k: HashSet(v) for k, v in flags.items()},
    }


def total_bytes(S):
    return sum(x.size_bytes() for x in S.values())


def kb(b):
    return f"{b / 1024:,.1f} KB"


def parse_query(text):
    """'failed_login AND suspicious_ip AND NOT whitelisted' -> (first, [(op, flag), ...]), left to right."""
    t = text.replace("&", " AND ").replace("|", " OR ").split()
    if not t:
        raise ValueError("empty query")
    if t[0].lower() not in FLAGS:
        raise ValueError(f"unknown flag '{t[0]}'. Flags: {', '.join(FLAGS)}")
    first, steps, i = t[0].lower(), [], 1
    while i < len(t):
        op = t[i].upper()
        if op == "AND" and i + 1 < len(t) and t[i + 1].upper() == "NOT":
            op, i = "ANDNOT", i + 1
        if op not in ("AND", "OR", "ANDNOT") or i + 1 >= len(t):
            raise ValueError("use: <flag> AND|OR|AND NOT <flag> ...")
        flag = t[i + 1].lower()
        if flag not in FLAGS:
            raise ValueError(f"unknown flag '{flag}'. Flags: {', '.join(FLAGS)}")
        steps.append((op, flag))
        i += 2
    return first, steps


def evaluate(S, first, steps):
    r = S[first]
    for op, f in steps:
        r = (r & S[f]) if op == "AND" else (r | S[f]) if op == "OR" else (r - S[f])
    return r


def cmd_stats(structs):
    print(f"\n{'flag':<20}{'IDs':>10}{'Roaring':>14}{'Bitset':>14}{'HashSet':>14}   Roaring containers")
    for f in FLAGS:
        R = structs["Roaring"][f]
        st = R.stats()
        print(f"{f:<20}{len(R):>10,}{kb(R.size_bytes()):>14}{kb(structs['Bitset'][f].size_bytes()):>14}"
              f"{kb(structs['HashSet'][f].size_bytes()):>14}   "
              f"array={st['array']} bitmap={st['bitmap']} run={st['run']}")
    print(f"{'TOTAL':<20}{'':>10}{kb(total_bytes(structs['Roaring'])):>14}"
          f"{kb(total_bytes(structs['Bitset'])):>14}{kb(total_bytes(structs['HashSet'])):>14}\n")


def cmd_query(structs, text):
    first, steps = parse_query(text)
    print(f"\nQuery: {first} " + " ".join(f"{op.replace('ANDNOT', 'AND NOT')} {f}" for op, f in steps))
    answers = {}
    for name, S in structs.items():
        t = time.perf_counter()
        r = evaluate(S, first, steps)
        ms = (time.perf_counter() - t) * 1000
        answers[name] = r
        print(f"  {name:<8} {len(r):>10,} events   {ms:>9.2f} ms")
    ids = list(answers["Roaring"])
    assert ids == list(answers["Bitset"]) == list(answers["HashSet"]), "structures disagree!"
    print("  All three structures agree. First IDs:", ids[:8], "\n")


def cmd_burst(structs, n, rng):
    if n < 2 * BURST_LEN:
        print("Use at least 100,000 events for the burst demo.\n")
        return
    start = rng.randrange(0, n - BURST_LEN)
    ids = range(start, start + BURST_LEN)
    print(f"\nInjecting an attack burst: events {start:,} .. {start + BURST_LEN - 1:,} "
          f"-> flags failed_login and suspicious_ip")
    R = structs["Roaring"]
    before = total_bytes(R)
    for f in ("failed_login", "suspicious_ip"):
        for x in ids:
            for S in structs.values():
                S[f].add(x)
    mid = total_bytes(R)
    for r in R.values():
        r.optimize()
    after = total_bytes(R)
    alone = Roaring.from_iterable(ids).size_bytes()
    print(f"  The burst on its own: {2 * BURST_LEN:,} bytes as a plain array of IDs, "
          f"{alone:,} bytes as Roaring runs")
    print(f"  Roaring memory before burst             : {kb(before)}")
    print(f"  after adding IDs one by one (naive)     : {kb(mid)}")
    print(f"  after optimize() -> run containers      : {kb(after)}   <- the burst is stored as a few runs")
    print(f"  Bitset memory (unchanged, fixed size)   : {kb(total_bytes(structs['Bitset']))}")
    print(f"  HashSet memory                          : {kb(total_bytes(structs['HashSet']))}\n")


def setup(n, mode):
    print(f"Generating {n:,} synthetic security events (mode={mode}) ...")
    flags = generate_events(n, mode)
    structs = build_all(flags, n)
    print("Ready. Flags:", ", ".join(FLAGS), "\n")
    return structs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1_000_000)
    ap.add_argument("--mode", choices=["mixed", "sparse", "dense"], default="mixed")
    ap.add_argument("--auto", action="store_true")
    a = ap.parse_args()
    n, mode, rng = a.n, a.mode, random.Random(7)
    structs = setup(n, mode)

    if a.auto:
        cmd_stats(structs)
        for q in ("failed_login AND suspicious_ip",
                  "failed_login AND suspicious_ip AND NOT whitelisted",
                  "unusual_hour OR sensitive_resource"):
            cmd_query(structs, q)
        cmd_burst(structs, n, rng)
        return

    print(__doc__)
    while True:
        try:
            line = input("threatboard> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        cmd, _, rest = line.partition(" ")
        try:
            if cmd == "quit":
                break
            elif cmd == "help":
                print(__doc__)
            elif cmd == "stats":
                cmd_stats(structs)
            elif cmd == "query":
                cmd_query(structs, rest)
            elif cmd == "burst":
                cmd_burst(structs, n, rng)
            elif cmd == "regen":
                parts = rest.split()
                n = int(parts[0]) if parts else n
                mode = parts[1] if len(parts) > 1 else mode
                structs = setup(n, mode)
            else:
                print("Unknown command. Type help.")
        except Exception as e:                     # keep the demo alive on bad input
            print("Error:", e, "\n")


if __name__ == "__main__":
    main()
