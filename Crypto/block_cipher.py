# Учебный шифр - сеть Фейстеля - Вариант 4

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Tuple, Optional
import secrets


# -------------------- утилиты --------------------

def parse_bits(s: str, width: int) -> int:
    s = s.strip().replace(" ", "")
    if len(s) != width or any(c not in "01" for c in s):
        raise ValueError(f"Expected {width}-bit string, got: {s!r}")
    return int(s, 2)


def to_bits(x: int, width: int) -> str:
    return format(x & ((1 << width) - 1), f"0{width}b")


def bit_from_left(x: int, width: int, pos_1_based: int) -> int:
    # pos=1 — самый левый (MSB), pos=width — самый правый (LSB)
    return (x >> (width - pos_1_based)) & 1


def permute(x: int, in_width: int, table: Iterable[int]) -> int:
    out = 0
    for p in table:
        out = (out << 1) | bit_from_left(x, in_width, p)
    return out


# -------------------- шифр --------------------

@dataclass(frozen=True)
class TrainingFeistelCipher:
    """
    Блок 16 бит: L||R, L=8, R=8.
    Шифрование: (L XOR F(R,K)) || R
    Ключ K: 12 бит.
    """
    key12: int

    # Extend-Permutate 8 -> 12 
    E: Tuple[int, ...] = (3, 4, 1, 2, 6, 8, 5, 7, 3, 8, 2, 4)

    # S1 (4 -> 3)
    # var. 4
    S1_row0: Tuple[int, ...] = (3, 4, 1, 1, 2, 3, 6, 6)
    S1_row1: Tuple[int, ...] = (6, 7, 2, 4, 1, 5, 7, 5)

    # S2 (4 -> 3)
    # var. 4
    S2_row0: Tuple[int, ...] = (1, 1, 2, 3, 2, 7, 4, 6)
    S2_row1: Tuple[int, ...] = (3, 7, 3, 6, 4, 5, 5, 1)

    # S3 (4 -> 2)
    # rows: a1a4 = 00,01,10,11; 
    # cols: a2a3 = 00,01,10,11;
    # var. 4
    S3: Tuple[Tuple[int, int, int, int], ...] = (
        (2, 1, 2, 3),  # 00
        (3, 2, 3, 1),  # 01
        (1, 2, 3, 2),  # 10
        (2, 3, 1, 3),  # 11
    )

    # Permutate 8 -> 8
    P: Tuple[int, ...] = (8, 7, 3, 2, 5, 4, 1, 6)

    def __post_init__(self) -> None:
        if not (0 <= self.key12 < (1 << 12)):
            raise ValueError("key12 must be a 12-bit integer (0..4095)")

    def _sbox1(self, x4: int) -> int:
        a1 = bit_from_left(x4, 4, 1)
        col = x4 & 0b111  # a2a3a4
        return (self.S1_row1 if a1 else self.S1_row0)[col]  # 0..7

    def _sbox2(self, x4: int) -> int:
        a1 = bit_from_left(x4, 4, 1)
        col = x4 & 0b111
        return (self.S2_row1 if a1 else self.S2_row0)[col]  # 0..7

    def _sbox3(self, x4: int) -> int:
        a1 = bit_from_left(x4, 4, 1)
        a4 = bit_from_left(x4, 4, 4)
        row = (a1 << 1) | a4  # a1a4
        a2 = bit_from_left(x4, 4, 2)
        a3 = bit_from_left(x4, 4, 3)
        col = (a2 << 1) | a3  # a2a3
        return self.S3[row][col]  # 0..3

    def F(self, r8: int) -> int:
        x12 = permute(r8, 8, self.E) ^ self.key12  # 12 бит
        b1 = (x12 >> 8) & 0xF
        b2 = (x12 >> 4) & 0xF
        b3 = x12 & 0xF

        y1 = self._sbox1(b1)  # 3 бита
        y2 = self._sbox2(b2)  # 3 бита
        y3 = self._sbox3(b3)  # 2 бита

        y8 = (y1 << 5) | (y2 << 2) | y3
        return permute(y8, 8, self.P)

    def encrypt_block(self, pt16: int) -> int:
        L = (pt16 >> 8) & 0xFF
        R = pt16 & 0xFF
        return ((L ^ self.F(R)) << 8) | R


# -------------------- генерация пар --------------------

def generate_random_pairs(key_bits12: str, n: int) -> List[Tuple[int, int]]:
    key12 = parse_bits(key_bits12, 12)
    cipher = TrainingFeistelCipher(key12)
    pairs: List[Tuple[int, int]] = []
    seen = set()
    while len(pairs) < n:
        pt = secrets.randbits(16)
        if pt in seen:
            continue
        seen.add(pt)
        ct = cipher.encrypt_block(pt)
        pairs.append((pt, ct))
    return pairs
