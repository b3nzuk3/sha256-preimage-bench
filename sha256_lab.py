"""Single-block SHA-256 experiment with one variable message word."""
from __future__ import annotations

import hashlib
import struct

MASK = 0xFFFFFFFF
TAIL = bytes(range(1, 37))
IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)
State = tuple[int, int, int, int, int, int, int, int]


def message(word: int) -> bytes:
    return word.to_bytes(4, "big") + TAIL


def initial_words(word: int) -> tuple[int, ...]:
    padded = message(word) + b"\x80" + bytes(15) + (320).to_bytes(8, "big")
    return struct.unpack(">16I", padded)


def rotate_right(word: int, bits: int) -> int:
    return ((word >> bits) | (word << (32 - bits))) & MASK


def small_sigma0(word: int) -> int:
    return rotate_right(word, 7) ^ rotate_right(word, 18) ^ (word >> 3)


def small_sigma1(word: int) -> int:
    return rotate_right(word, 17) ^ rotate_right(word, 19) ^ (word >> 10)


def big_sigma0(word: int) -> int:
    return rotate_right(word, 2) ^ rotate_right(word, 13) ^ rotate_right(word, 22)


def big_sigma1(word: int) -> int:
    return rotate_right(word, 6) ^ rotate_right(word, 11) ^ rotate_right(word, 25)


def choose(e: int, f: int, g: int) -> int:
    return (e & f) ^ (~e & g)


def majority(a: int, b: int, c: int) -> int:
    return (a & b) ^ (a & c) ^ (b & c)


def schedule(word: int, rounds: int) -> list[int]:
    words = list(initial_words(word))
    for index in range(16, rounds):
        extended = (
            small_sigma1(words[index - 2]) + words[index - 7]
            + small_sigma0(words[index - 15]) + words[index - 16]
        )
        words.append(extended & MASK)
    return words[:rounds]


def forward_round(state: State, word: int, index: int) -> State:
    a, b, c, d, e, f, g, h = state
    t1 = h + big_sigma1(e) + choose(e, f, g) + K[index] + word
    t2 = big_sigma0(a) + majority(a, b, c)
    return ((t1 + t2) & MASK, a, b, c, (d + t1) & MASK, e, f, g)


def reverse_round(state: State, word: int, index: int) -> State:
    next_a, a, b, c, next_e, e, f, g = state
    t2 = big_sigma0(a) + majority(a, b, c)
    t1 = (next_a - t2) & MASK
    d = (next_e - t1) & MASK
    h = (t1 - big_sigma1(e) - choose(e, f, g) - K[index] - word) & MASK
    return a, b, c, d, e, f, g, h


def digest(word: int, rounds: int) -> bytes:
    """Return a feed-forward compression output using standard SHA-256 padding."""
    if not 1 <= rounds <= 64:
        raise ValueError("round count must be 1 through 64")
    state = IV
    for index, round_word in enumerate(schedule(word, rounds)):
        state = forward_round(state, round_word, index)
    return struct.pack(">8I", *((value + initial) & MASK for value, initial in zip(state, IV)))


def recover_word(target: bytes, rounds: int) -> int | None:
    """Recover W0 from the full output for 1–16 rounds, or return no match."""
    if not 1 <= rounds <= 16:
        raise ValueError("direct recovery requires 1 through 16 rounds")
    if len(target) != 32:
        raise ValueError("direct recovery requires all 32 output bytes")

    state = tuple(
        (value - initial) & MASK
        for value, initial in zip(struct.unpack(">8I", target), IV)
    )
    public_words = initial_words(0)
    for index in range(rounds - 1, 0, -1):
        state = reverse_round(state, public_words[index], index)

    a, b, c, _, e, f, g, h = IV
    t2 = big_sigma0(a) + majority(a, b, c)
    word = (state[0] - t2 - h - big_sigma1(e) - choose(e, f, g) - K[0]) & MASK
    if forward_round(IV, word, 0) == state and digest(word, rounds) == target:
        return word
    return None


def exhaustive_first(target: bytes, rounds: int, bits: int) -> tuple[int | None, int]:
    """Return the first matching word and candidates checked in ascending order."""
    if not 1 <= bits <= 24:
        raise ValueError("exhaustive baseline requires 1 through 24 bits")
    for candidate in range(1 << bits):
        candidate_digest = (
            hashlib.sha256(message(candidate)).digest()
            if rounds == 64 else digest(candidate, rounds)
        )
        if candidate_digest == target:
            return candidate, candidate + 1
    return None, 1 << bits
