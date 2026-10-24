"""
baselines.py - Plain bitset and hash set (comparison)       OWNER: Sandeep
-----------------------------------------------------------------
Both classes support  &  |  -  len()  iteration  and size_bytes()
so the benchmark can treat all three structures the same way.
"""
import sys


class BitsetSet:
    """One bit for every possible ID in 0..universe-1 (fast, but memory is fixed)."""

    def __init__(self, universe, ids=()):
        self.universe = universe
        self.bits = bytearray((universe + 7) // 8)
        for x in ids:
            self.bits[x >> 3] |= 1 << (x & 7)

    @classmethod
    def _from_int(cls, universe, value):
        s = cls(universe)
        s.bits = bytearray(value.to_bytes(len(s.bits), "little"))
        return s

    def _int(self):
        return int.from_bytes(self.bits, "little")

    def add(self, x):
        self.bits[x >> 3] |= 1 << (x & 7)

    def __contains__(self, x):
        return 0 <= x < self.universe and bool((self.bits[x >> 3] >> (x & 7)) & 1)

    def __len__(self):
        return bin(self._int()).count("1")

    def __iter__(self):
        for i, b in enumerate(self.bits):
            if b:
                for j in range(8):
                    if (b >> j) & 1:
                        yield (i << 3) + j

    def __and__(self, o):
        return BitsetSet._from_int(self.universe, self._int() & o._int())

    def __or__(self, o):
        return BitsetSet._from_int(self.universe, self._int() | o._int())

    def __sub__(self, o):
        return BitsetSet._from_int(self.universe, self._int() & ~o._int())

    def size_bytes(self):
        return len(self.bits)


class HashSet:
    """Python set wrapper (fast lookup, high memory per ID)."""

    def __init__(self, ids=()):
        self.s = set(ids)

    def add(self, x):
        self.s.add(x)

    def __contains__(self, x):
        return x in self.s

    def __len__(self):
        return len(self.s)

    def __iter__(self):
        return iter(sorted(self.s))

    def __and__(self, o):
        r = HashSet(); r.s = self.s & o.s; return r

    def __or__(self, o):
        r = HashSet(); r.s = self.s | o.s; return r

    def __sub__(self, o):
        r = HashSet(); r.s = self.s - o.s; return r

    def size_bytes(self):
        # table overhead + the int objects stored in it (approximate)
        return sys.getsizeof(self.s) + sum(sys.getsizeof(x) for x in self.s)
