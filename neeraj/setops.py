"""
setops.py - AND / OR / AND NOT           OWNER: Neeraj
-----------------------------------------------------------------
Chunk-level: walk both sorted chunk lists with two pointers, O(C1 + C2).
Chunks present in only one set are skipped (AND) or copied (OR / AND NOT).
Container-level: pick the cheapest method for each pair of container types.
"""
from nishanth.roaring import (Roaring, ArrayContainer, BitmapContainer, RunContainer,
                     make_container, BITMAP_BYTES, BYTE_BITS)


# ---------- helpers ----------
def _to_bits(c):
    """Bytes of the 65,536-bit bitmap for any container type."""
    if isinstance(c, BitmapContainer):
        return c.bits
    bm = bytearray(BITMAP_BYTES)
    for v in c.values():
        bm[v >> 3] |= 1 << (v & 7)
    return bm


def _bits_to_values(x):
    data = x.to_bytes(BITMAP_BYTES, "little")
    vals = []
    for i, b in enumerate(data):
        if b:
            base = i << 3
            vals.extend(base + j for j in BYTE_BITS[b])
    return vals


def _int(c):
    if isinstance(c, RunContainer):                    # a run is just a block of 1-bits
        x = 0
        for start, length in c.runs:
            x |= ((1 << length) - 1) << start
        return x
    return int.from_bytes(_to_bits(c), "little")


def _merge_and(x, y):
    i = j = 0
    out = []
    while i < len(x) and j < len(y):
        if x[i] == y[j]:
            out.append(x[i]); i += 1; j += 1
        elif x[i] < y[j]:
            i += 1
        else:
            j += 1
    return out


def _merge_or(x, y):
    i = j = 0
    out = []
    while i < len(x) and j < len(y):
        if x[i] == y[j]:
            out.append(x[i]); i += 1; j += 1
        elif x[i] < y[j]:
            out.append(x[i]); i += 1
        else:
            out.append(y[j]); j += 1
    out.extend(x[i:])
    out.extend(y[j:])
    return out


# ---------- container level (each returns a container, or None if empty) ----------
def container_and(a, b):
    if isinstance(a, ArrayContainer) and isinstance(b, ArrayContainer):
        vals = _merge_and(a.vals, b.vals)                       # array x array: merge
    elif isinstance(a, ArrayContainer) or isinstance(b, ArrayContainer):
        arr, other = (a, b) if isinstance(a, ArrayContainer) else (b, a)
        vals = [v for v in arr.vals if other.contains(v)]       # array x other: probe
    elif isinstance(a, BitmapContainer) and isinstance(b, BitmapContainer):
        vals = _bits_to_values(_int(a) & _int(b))               # bitmap x bitmap: word AND
    else:                                                       # a run is involved
        small, big = (a, b) if a.cardinality() <= b.cardinality() else (b, a)
        vals = [v for v in small.values() if big.contains(v)]
    return make_container(vals)


def container_or(a, b):
    if isinstance(a, ArrayContainer) and isinstance(b, ArrayContainer):
        vals = _merge_or(a.vals, b.vals)
    else:
        vals = _bits_to_values(_int(a) | _int(b))
    return make_container(vals)


def container_andnot(a, b):
    if isinstance(a, ArrayContainer):
        vals = [v for v in a.vals if not b.contains(v)]
    else:
        vals = _bits_to_values(_int(a) & ~_int(b))
    return make_container(vals)


# ---------- chunk level ----------
def roaring_and(A, B):
    out = Roaring()
    i = j = 0
    while i < len(A.keys) and j < len(B.keys):
        ka, kb = A.keys[i], B.keys[j]
        if ka == kb:
            c = container_and(A.conts[i], B.conts[j])
            if c is not None:
                out.keys.append(ka)
                out.conts.append(c)
            i += 1; j += 1
        elif ka < kb:
            i += 1                                              # chunk only in A: skipped
        else:
            j += 1
    return out


def roaring_or(A, B):
    out = Roaring()
    i = j = 0
    while i < len(A.keys) or j < len(B.keys):
        ka = A.keys[i] if i < len(A.keys) else None
        kb = B.keys[j] if j < len(B.keys) else None
        if kb is None or (ka is not None and ka < kb):
            out.keys.append(ka); out.conts.append(A.conts[i].copy()); i += 1
        elif ka is None or kb < ka:
            out.keys.append(kb); out.conts.append(B.conts[j].copy()); j += 1
        else:
            c = container_or(A.conts[i], B.conts[j])
            out.keys.append(ka); out.conts.append(c)
            i += 1; j += 1
    return out


def roaring_andnot(A, B):
    out = Roaring()
    j = 0
    for i, ka in enumerate(A.keys):
        while j < len(B.keys) and B.keys[j] < ka:
            j += 1
        if j < len(B.keys) and B.keys[j] == ka:
            c = container_andnot(A.conts[i], B.conts[j])
            if c is not None:
                out.keys.append(ka)
                out.conts.append(c)
        else:
            out.keys.append(ka)
            out.conts.append(A.conts[i].copy())                 # no matching chunk in B
    return out
