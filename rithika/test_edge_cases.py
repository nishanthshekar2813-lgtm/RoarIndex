"""
test_edge_cases.py - Edge-case tests                     OWNER: Rithika
Run from the project root:   python -m unittest discover -s rithika -t . -p "test_*.py" -v
"""
import random, unittest

from nishanth.roaring import Roaring, ArrayContainer, BitmapContainer, RunContainer, MAX_ID
from sandeep.baselines import BitsetSet, HashSet
from sandeep.datagen import generate_events


class TestBasics(unittest.TestCase):
    def test_empty(self):
        r = Roaring()
        self.assertEqual(len(r), 0)
        self.assertNotIn(5, r)
        self.assertEqual(list(r), [])
        self.assertEqual(len(r & Roaring()), 0)

    def test_single_element(self):
        r = Roaring(); r.add(42)
        self.assertIn(42, r); self.assertNotIn(43, r); self.assertEqual(len(r), 1)

    def test_duplicates(self):
        r = Roaring()
        self.assertTrue(r.add(7)); self.assertFalse(r.add(7))
        self.assertEqual(len(r), 1)

    def test_missing_key(self):
        r = Roaring.from_iterable([1, 2, 3])
        self.assertNotIn(4, r); self.assertNotIn(10**9, r); self.assertNotIn(-1, r)

    def test_chunk_boundary(self):
        r = Roaring(); r.add(65535); r.add(65536)
        self.assertEqual(r.keys, [0, 1])
        self.assertIn(65535, r); self.assertIn(65536, r); self.assertNotIn(65537, r)

    def test_max_id(self):
        r = Roaring(); r.add(MAX_ID); r.add(0)
        self.assertIn(MAX_ID, r); self.assertEqual(list(r), [0, MAX_ID])
        with self.assertRaises(ValueError):
            r.add(MAX_ID + 1)

    def test_remove(self):
        r = Roaring.from_iterable([1, 2, 3])
        self.assertTrue(r.remove(2)); self.assertFalse(r.remove(2))
        self.assertEqual(list(r), [1, 3])
        r.remove(1); r.remove(3)
        self.assertEqual(r.keys, [])             # empty chunk is deleted


class TestContainerSwitch(unittest.TestCase):
    def test_array_to_bitmap_at_4097(self):
        r = Roaring()
        for i in range(0, 8192, 2):              # 4096 values, not consecutive -> array
            r.add(i)
        self.assertIsInstance(r.conts[0], ArrayContainer)
        r.add(8193)                              # 4097th value
        self.assertIsInstance(r.conts[0], BitmapContainer)
        self.assertEqual(len(r), 4097)

    def test_bitmap_back_to_array(self):
        r = Roaring()
        for i in range(0, 8194, 2):
            r.add(i)                             # 4097 values -> bitmap
        r.remove(0)                              # back to 4096
        self.assertIsInstance(r.conts[0], ArrayContainer)

    def test_run_container_for_burst(self):
        r = Roaring.from_iterable(range(1000, 51000))   # 50,000 consecutive IDs
        self.assertTrue(all(isinstance(c, RunContainer) for c in r.conts))
        self.assertLess(r.size_bytes(), 100)             # vs ~100,000 bytes as arrays
        self.assertEqual(len(r), 50000)

    def test_add_into_run_container(self):
        r = Roaring.from_iterable(range(100, 200))
        r.add(500); r.add(150)                           # new value + duplicate
        self.assertEqual(len(r), 101); self.assertIn(500, r)

    def test_optimize_creates_runs(self):
        r = Roaring()
        for i in range(2000):
            r.add(i)                                     # array container
        r.optimize()
        self.assertIsInstance(r.conts[0], RunContainer)


class TestSetOps(unittest.TestCase):
    def _compare(self, a_ids, b_ids):
        A, B = Roaring.from_iterable(a_ids), Roaring.from_iterable(b_ids)
        sa, sb = set(a_ids), set(b_ids)
        self.assertEqual(list(A & B), sorted(sa & sb))
        self.assertEqual(list(A | B), sorted(sa | sb))
        self.assertEqual(list(A - B), sorted(sa - sb))

    def test_disjoint(self):
        self._compare([1, 2, 3], [100000, 100001])

    def test_same_set(self):
        self._compare(range(500), range(500))

    def test_one_empty(self):
        self._compare([], [1, 2, 3]); self._compare([1, 2, 3], [])

    def test_array_vs_array(self):
        self._compare(range(0, 3000, 3), range(0, 3000, 5))

    def test_bitmap_vs_bitmap(self):
        self._compare(range(0, 20000, 2), range(0, 20000, 3))

    def test_array_vs_bitmap(self):
        self._compare(range(0, 100, 7), range(0, 40000, 2))

    def test_run_vs_others(self):
        self._compare(range(1000, 9000), range(0, 20000, 2))
        self._compare(range(1000, 9000), range(5000, 7000))
        self._compare(range(1000, 9000), [1, 5000, 9999])

    def test_multi_chunk_random(self):
        rng = random.Random(1)
        for _ in range(5):
            a = rng.sample(range(500000), 20000)
            b = rng.sample(range(500000), 30000)
            self._compare(a, b)

    def test_results_do_not_alias_inputs(self):
        A = Roaring.from_iterable([1, 2, 3]); B = Roaring.from_iterable([100000])
        C = A | B
        C.add(4)
        self.assertNotIn(4, A)


class TestAgainstBaselines(unittest.TestCase):
    def test_all_three_agree(self):
        n = 200000
        flags = generate_events(n, "mixed")
        R = {k: Roaring.from_iterable(v) for k, v in flags.items()}
        S = {k: BitsetSet(n, v) for k, v in flags.items()}
        H = {k: HashSet(v) for k, v in flags.items()}
        q = lambda X: (X["failed_login"] & X["suspicious_ip"]) - X["whitelisted"]
        q2 = lambda X: X["unusual_hour"] | X["sensitive_resource"]
        for f in (q, q2):
            self.assertEqual(list(f(R)), list(f(S)))
            self.assertEqual(list(f(R)), list(f(H)))


if __name__ == "__main__":
    unittest.main()
