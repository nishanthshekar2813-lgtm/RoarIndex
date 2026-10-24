"""
datagen.py - Synthetic security-log generator            OWNER: Sandeep
-----------------------------------------------------------------
Event IDs are 0..n-1 in time order. Each flag becomes a sorted list of the
event IDs that have it. No real network data is used.
"""
import random

FLAGS = ["failed_login", "suspicious_ip", "unusual_hour", "sensitive_resource", "whitelisted"]


def _random_subset(rng, n, p):
    return sorted(rng.sample(range(n), max(1, int(n * p))))


def generate_events(n, mode="mixed", seed=42):
    """
    mode = "mixed"  : realistic mix (rare random flags, night-time blocks, bursts, dense whitelist)
           "sparse" : every flag is random and rare (0.1%)  -> shows Roaring's weak spot
           "dense"  : every flag is random and common (50%)
    Returns {flag_name: sorted list of event IDs}.
    """
    rng = random.Random(seed)
    if mode == "sparse":
        return {f: _random_subset(rng, n, 0.001) for f in FLAGS}
    if mode == "dense":
        return {f: _random_subset(rng, n, 0.5) for f in FLAGS}

    flags = {}
    flags["failed_login"] = _random_subset(rng, n, 0.02)
    flags["suspicious_ip"] = _random_subset(rng, n, 0.01)

    # unusual hour: the first quarter of every "day" (long consecutive blocks -> runs)
    day = max(n // 30, 4)
    night = []
    for d in range(0, n, day):
        night.extend(range(d, min(d + day // 4, n)))
    flags["unusual_hour"] = night

    # sensitive resource: 20 attack bursts of 200-3000 consecutive events
    burst = set()
    for _ in range(20):
        s = rng.randrange(n)
        burst.update(range(s, min(s + rng.randint(200, 3000), n)))
    flags["sensitive_resource"] = sorted(burst)

    flags["whitelisted"] = _random_subset(rng, n, 0.40)
    return flags
