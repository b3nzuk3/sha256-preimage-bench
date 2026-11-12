import hashlib
import random
import unittest

from sha256_lab import (
    MASK, digest, exhaustive_first, forward_round, initial_words,
    message, recover_word, reverse_round, schedule,
)


class Sha256LabTest(unittest.TestCase):
    def test_full_rounds_match_hashlib(self):
        rng = random.Random(1804)
        words = [0, 1, MASK, *(rng.getrandbits(32) for _ in range(64))]
        for word in words:
            with self.subTest(word=word):
                self.assertEqual(digest(word, 64), hashlib.sha256(message(word)).digest())

    def test_inverse_round_restores_arbitrary_state(self):
        rng = random.Random(1804)
        for index in range(64):
            state = tuple(rng.getrandbits(32) for _ in range(8))
            word = rng.getrandbits(32)
            self.assertEqual(reverse_round(forward_round(state, word, index), word, index), state)

    def test_recovers_full_width_words_in_all_supported_rounds(self):
        rng = random.Random(1600)
        words = [0, 1, MASK, 1 << 31, *(rng.getrandbits(32) for _ in range(32))]
        for rounds in range(1, 17):
            for word in words:
                with self.subTest(rounds=rounds, word=word):
                    self.assertEqual(recover_word(digest(word, rounds), rounds), word)

    def test_checks_entire_output(self):
        target = bytearray(digest(173, 1))
        target[-1] ^= 1
        self.assertIsNone(recover_word(bytes(target), 1))
        with self.assertRaises(ValueError):
            recover_word(bytes(target[:8]), 1)

    def test_first_extended_schedule_word_depends_on_w0(self):
        self.assertEqual(initial_words(0)[1:], initial_words(1)[1:])
        self.assertEqual((schedule(1, 17)[16] - schedule(0, 17)[16]) & MASK, 1)
        with self.assertRaises(ValueError):
            recover_word(digest(0, 17), 17)

    def test_enumeration_first_match_and_bounded_miss(self):
        self.assertEqual(exhaustive_first(digest(173, 8), 8, 8), (173, 174))
        self.assertEqual(exhaustive_first(digest(256, 8), 8, 8), (None, 256))
        self.assertEqual(exhaustive_first(digest(3, 64), 64, 4), (3, 4))
