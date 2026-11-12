#!/usr/bin/env python3
"""Step 4 independent correctness tests. Requires libz3.so.4."""
import hashlib
import unittest
from sha256_tree_lab import TAIL,compress
from sha256_step4_sat import run, run_xor_and

class Tests(unittest.TestCase):
    def test_full_sha256(self):
        for w0 in (0,1,7,173,4095,65535,0xffffffff):
            digest=''.join(f'{x:08x}' for x in compress(w0,64))
            self.assertEqual(digest,hashlib.sha256(w0.to_bytes(4,'big')+TAIL).hexdigest())

    def test_bitvector_exact_and_unique(self):
        for rounds in (1,2,4):
            result=run(rounds,8,173,'bv',1500)
            self.assertEqual(result['result'],'sat')
            self.assertEqual(result['witness'],173)
            self.assertTrue(result['witness_verified'])
            self.assertEqual(result['other_solution_check'],'unsat')

    def test_projected_constraints_sound(self):
        for rounds in (1,2,4,8):
            result=run(rounds,8,173,'hybrid',2000)
            self.assertEqual(result['result'],'sat')
            self.assertTrue(result['witness_verified'])
            self.assertGreaterEqual(result['projection']['remaining_input_space'],1)

    def test_xor_and_exact(self):
        for rounds in (1,2,4):
            result=run_xor_and(rounds,8,173,2000)
            self.assertEqual(result['result'],'sat')
            self.assertEqual(result['witness'],173)
            self.assertTrue(result['witness_verified'])

    def test_prefix_constraint(self):
        result=run(4,10,173,'bv',1000,8)
        self.assertEqual(result['result'],'sat')
        self.assertTrue(result['witness_verified'])
        a=compress(result['witness'],4)
        b=compress(173,4)
        self.assertEqual(a[0]>>24,b[0]>>24)

if __name__=='__main__':unittest.main(verbosity=2)
