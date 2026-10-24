"""
roaring.py - Core Roaring Bitmap            OWNER: Nishanth
-----------------------------------------------------------------
A 32-bit ID is split into a chunk number (high 16 bits) and an offset
(low 16 bits). A sorted index holds the non-empty chunk numbers, and each
chunk is stored in the smallest of three containers:

    ArrayContainer   sorted 16-bit values      2 bytes x count   (<= 4096 values)
    BitmapContainer  65,536 bits               8192 bytes (fixed)
    RunContainer     (start, length) pairs     4 bytes per run
"""
import bisect

ARRAY_MAX = 4096            # 4096 values x 2 bytes = 8192 bytes = size of a bitmap
BITMAP_BYTES = 8192         # 65,536 bits
LOW_MASK = 0xFFFF
MAX_ID = (1 << 32) - 1
CHUNK_HEADER_BYTES = 4      # per chunk: 2-byte key + 2-byte cardinality (approximate)

# BYTE_BITS[b] = positions of the 1-bits inside byte b (speeds up bitmap -> values)
BYTE_BITS = [[j for j in range(8) if (b >> j) & 1] for b in range(256)]


class ArrayContainer:
    kind = "array"

    def __init__(self, vals=None):
        self.vals = vals if vals is not None else []      # sorted, unique

    def contains(self, lo):                               # O(log k), k <= 4096
        i = bisect.bisect_left(self.vals, lo)
        return i < len(self.vals) and self.vals[i] == lo

    def add(self, lo):
        i = bisect.bisect_left(self.vals, lo)
        if i < len(self.vals) and self.vals[i] == lo:
            return False
        self.vals.insert(i, lo)
        return True

    def remove(self, lo):
        i = bisect.bisect_left(self.vals, lo)
        if i < len(self.vals) and self.vals[i] == lo:
            del self.vals[i]
            return True
        return False

    def cardinality(self):
        return len(self.vals)

    def values(self):
        return iter(self.vals)

    def size_bytes(self):
        return 2 * len(self.vals)

    def copy(self):
        return ArrayContainer(list(self.vals))


class BitmapContainer:
    kind = "bitmap"

    def __init__(self, bits=None, n=None):
        self.bits = bits if bits is not None else bytearray(BITMAP_BYTES)
        if n is None:
            n = bin(int.from_bytes(self.bits, "little")).count("1")
        self.n = n                                        # cached cardinality

    def contains(self, lo):                               # O(1)
        return bool((self.bits[lo >> 3] >> (lo & 7)) & 1)

    def add(self, lo):
        if self.contains(lo):
            return False
        self.bits[lo >> 3] |= 1 << (lo & 7)
        self.n += 1
        return True

    def remove(self, lo):
        if not self.contains(lo):
            return False
        self.bits[lo >> 3] &= ~(1 << (lo & 7)) & 0xFF
        self.n -= 1
        return True

    def cardinality(self):
        return self.n

    def values(self):
        bits = self.bits
        for i in range(BITMAP_BYTES):
            b = bits[i]
            if b:
                base = i << 3
                for j in BYTE_BITS[b]:
                    yield base + j

    def size_bytes(self):
        return BITMAP_BYTES

    def copy(self):
        return BitmapContainer(bytearray(self.bits), self.n)


class RunContainer:
    kind = "run"

    def __init__(self, runs):
        self.runs = runs      # [(start, length)] sorted, non-overlapping

    def contains(self, lo):                               # O(log r)
        i = bisect.bisect_right(self.runs, (lo, 1 << 17)) - 1
        if i < 0:
            return False
        start, length = self.runs[i]
        return lo < start + length

    def cardinality(self):
        return sum(length for _, length in self.runs)

    def values(self):
        for start, length in self.runs:
            yield from range(start, start + length)

    def size_bytes(self):
        return 4 * len(self.runs)

    def copy(self):
        return RunContainer(list(self.runs))


def to_bitmap(container):
    bm = bytearray(BITMAP_BYTES)
    n = 0
    for v in container.values():
        bm[v >> 3] |= 1 << (v & 7)
        n += 1
    return BitmapContainer(bm, n)


def count_runs(vals):
    if not vals:
        return 0
    runs = 1
    for i in range(1, len(vals)):
        if vals[i] != vals[i - 1] + 1:
            runs += 1
    return runs


def make_container(vals):
    """Pick the smallest container for a SORTED list of unique 16-bit values.
    Ties prefer array, then run, then bitmap. Returns None for an empty list."""
    n = len(vals)
    if n == 0:
        return None
    runs = count_runs(vals)
    options = [(4 * runs, 1, "run"), (BITMAP_BYTES, 2, "bitmap")]
    if n <= ARRAY_MAX:
        options.append((2 * n, 0, "array"))
    _, _, kind = min(options)
    if kind == "array":
        return ArrayContainer(list(vals))
    if kind == "run":
        out, start, prev = [], vals[0], vals[0]
        for v in vals[1:]:
            if v != prev + 1:
                out.append((start, prev - start + 1))
                start = v
            prev = v
        out.append((start, prev - start + 1))
        return RunContainer(out)
    bm = bytearray(BITMAP_BYTES)
    for v in vals:
        bm[v >> 3] |= 1 << (v & 7)
    return BitmapContainer(bm, n)


class Roaring:
    def __init__(self):
        self.keys = []      # sorted chunk numbers
        self.conts = []     # conts[i] is the container for keys[i]

    # ---------- building ----------
    @classmethod
    def from_iterable(cls, ids):
        """Bulk build: groups IDs by chunk and picks the best container."""
        ids = sorted(set(ids))
        if ids and (ids[0] < 0 or ids[-1] > MAX_ID):
            raise ValueError("IDs must be in 0 .. 2^32-1")
        r = cls()
        i, n = 0, len(ids)
        while i < n:
            hi = ids[i] >> 16
            j = i
            while j < n and (ids[j] >> 16) == hi:
                j += 1
            r.keys.append(hi)
            r.conts.append(make_container([x & LOW_MASK for x in ids[i:j]]))
            i = j
        return r

    def optimize(self):
        """Re-pick the best container for every chunk (creates run containers)."""
        self.conts = [make_container(list(c.values())) for c in self.conts]

    # ---------- single-element operations ----------
    def add(self, x):
        if not 0 <= x <= MAX_ID:
            raise ValueError("ID must be in 0 .. 2^32-1")
        hi, lo = x >> 16, x & LOW_MASK
        i = bisect.bisect_left(self.keys, hi)                 # O(log C)
        if i == len(self.keys) or self.keys[i] != hi:
            self.keys.insert(i, hi)
            self.conts.insert(i, ArrayContainer([lo]))
            return True
        c = self.conts[i]
        if isinstance(c, RunContainer):                       # runs are rebuilt, not edited
            if c.contains(lo):
                return False
            vals = list(c.values())
            bisect.insort(vals, lo)
            self.conts[i] = make_container(vals)
            return True
        added = c.add(lo)
        if added and isinstance(c, ArrayContainer) and len(c.vals) > ARRAY_MAX:
            self.conts[i] = to_bitmap(c)                      # array -> bitmap at 4097
        return added

    def remove(self, x):
        hi, lo = x >> 16, x & LOW_MASK
        i = bisect.bisect_left(self.keys, hi)
        if i == len(self.keys) or self.keys[i] != hi:
            return False
        c = self.conts[i]
        if isinstance(c, RunContainer):
            if not c.contains(lo):
                return False
            vals = [v for v in c.values() if v != lo]
            new = make_container(vals)
        else:
            if not c.remove(lo):
                return False
            new = c
            if isinstance(c, BitmapContainer) and c.n <= ARRAY_MAX:
                new = ArrayContainer(list(c.values()))        # bitmap -> array
        if new is None or new.cardinality() == 0:
            del self.keys[i]
            del self.conts[i]
        else:
            self.conts[i] = new
        return True

    def __contains__(self, x):
        if not 0 <= x <= MAX_ID:
            return False
        hi = x >> 16
        i = bisect.bisect_left(self.keys, hi)                 # O(log C)
        if i == len(self.keys) or self.keys[i] != hi:
            return False
        return self.conts[i].contains(x & LOW_MASK)           # O(log k) or O(1)

    # ---------- info ----------
    def __len__(self):
        return sum(c.cardinality() for c in self.conts)

    def __iter__(self):
        for hi, c in zip(self.keys, self.conts):
            base = hi << 16
            for lo in c.values():
                yield base | lo

    def size_bytes(self):
        return sum(c.size_bytes() for c in self.conts) + CHUNK_HEADER_BYTES * len(self.keys)

    def stats(self):
        s = {"chunks": len(self.keys), "array": 0, "bitmap": 0, "run": 0}
        for c in self.conts:
            s[c.kind] += 1
        return s

    def copy(self):
        r = Roaring()
        r.keys = list(self.keys)
        r.conts = [c.copy() for c in self.conts]
        return r

    # ---------- set operators (implemented in setops.py) ----------
    def __and__(self, other):
        from neeraj.setops import roaring_and
        return roaring_and(self, other)

    def __or__(self, other):
        from neeraj.setops import roaring_or
        return roaring_or(self, other)

    def __sub__(self, other):
        from neeraj.setops import roaring_andnot
        return roaring_andnot(self, other)
