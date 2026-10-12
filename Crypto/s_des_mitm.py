import random
from collections import defaultdict

# S-DES tables
P10     = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8      = [6, 3, 7, 4, 8, 5, 10, 9]
IP      = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV  = [4, 1, 3, 5, 7, 2, 8, 6]
EP      = [4, 1, 2, 3, 2, 3, 4, 1]
P4      = [2, 4, 3, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]
S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]


# Bit helpers
def int_to_bits(x: int, n: int) -> list[int]:
    return [(x >> (n - 1 - i)) & 1 for i in range(n)]

def bits_to_int(bits: list[int]) -> int:
    x = 0
    for b in bits:
        x = (x << 1) | b
    return x

def permute(bits: list[int], table: list[int]) -> list[int]:
    # table is 1-based indexing
    return [bits[i - 1] for i in table]

def left_rotate(bits: list[int], n: int) -> list[int]:
    n %= len(bits)
    return bits[n:] + bits[:n]

def xor_bits(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]

def split(bits: list[int]) -> tuple[list[int], list[int]]:
    mid = len(bits) // 2
    return bits[:mid], bits[mid:]


# Key schedule: 10-bit key -> two 8-bit subkeys
def generate_subkeys(key10: int) -> tuple[list[int], list[int]]:
    key_bits = int_to_bits(key10, 10)
    p10 = permute(key_bits, P10)
    left, right = split(p10)

    # LS-1
    left1 = left_rotate(left, 1)
    right1 = left_rotate(right, 1)
    k1 = permute(left1 + right1, P8)

    # LS-2 (from LS-1 state)
    left2 = left_rotate(left1, 2)
    right2 = left_rotate(right1, 2)
    k2 = permute(left2 + right2, P8)

    return k1, k2


# F function for fk
def sbox_lookup(sbox: list[list[int]], bits4: list[int]) -> list[int]:
    # row = b1b4, col = b2b3
    row = (bits4[0] << 1) | bits4[3]
    col = (bits4[1] << 1) | bits4[2]
    val = sbox[row][col]  # 0..3
    return int_to_bits(val, 2)

def F(right4: list[int], subkey8: list[int]) -> list[int]:
    expanded = permute(right4, EP)         # 8 bits
    x = xor_bits(expanded, subkey8)        # 8 bits
    left4, right4b = split(x)              # 4 + 4
    out0 = sbox_lookup(S0, left4)          # 2
    out1 = sbox_lookup(S1, right4b)        # 2
    p4 = permute(out0 + out1, P4)          # 4
    return p4

def fk(bits8: list[int], subkey8: list[int]) -> list[int]:
    left4, right4 = split(bits8)
    f = F(right4, subkey8)
    new_left = xor_bits(left4, f)
    return new_left + right4

def sw(bits8: list[int]) -> list[int]:
    left4, right4 = split(bits8)
    return right4 + left4


# S-DES encrypt/decrypt (8-bit block, 10-bit key)
def sdes_encrypt_block(plain8: int, key10: int) -> int:
    k1, k2 = generate_subkeys(key10)
    bits = int_to_bits(plain8, 8)
    bits = permute(bits, IP)
    bits = fk(bits, k1)
    bits = sw(bits)
    bits = fk(bits, k2)
    bits = permute(bits, IP_INV)
    return bits_to_int(bits)

def sdes_decrypt_block(cipher8: int, key10: int) -> int:
    k1, k2 = generate_subkeys(key10)
    bits = int_to_bits(cipher8, 8)
    bits = permute(bits, IP)
    bits = fk(bits, k2)   # reverse order
    bits = sw(bits)
    bits = fk(bits, k1)
    bits = permute(bits, IP_INV)
    return bits_to_int(bits)


# Double S-DES
# C = S-DES(S-DES(M, K1), K2)
def double_sdes_encrypt(m8: int, k1_10: int, k2_10: int) -> int:
    return sdes_encrypt_block(sdes_encrypt_block(m8, k1_10), k2_10)

def double_sdes_decrypt(c8: int, k1_10: int, k2_10: int) -> int:
    # обратный порядок и обратные операции
    return sdes_decrypt_block(sdes_decrypt_block(c8, k2_10), k1_10)


# Meet-in-the-middle attack
def mitm_candidates_from_pair(m8: int, c8: int) -> set[tuple[int, int]]:
    # Step 1: E = S-DES(M, K1) for all K1
    enc_map = defaultdict(list)  # intermediate -> [K1,...]
    for k1 in range(1 << 10):
        mid = sdes_encrypt_block(m8, k1)
        enc_map[mid].append(k1)

    # Step 2: D = reverse-S-DES(C, K2) for all K2 & match
    candidates = set()
    for k2 in range(1 << 10):
        mid = sdes_decrypt_block(c8, k2)
        if mid in enc_map:
            for k1 in enc_map[mid]:
                candidates.add((k1, k2))

    return candidates

def refine_candidates(candidates: set[tuple[int, int]], pairs: list[tuple[int, int]]) -> set[tuple[int, int]]:
    # Filter V by additional pairs (M', C')
    for m, c in pairs:
        candidates = { (k1, k2) for (k1, k2) in candidates if double_sdes_encrypt(m, k1, k2) == c }
        if len(candidates) <= 1:
            break
    return candidates


def bits10_str(x: int) -> str:
    return format(x, "010b")

def bits8_str(x: int) -> str:
    return format(x, "08b")

def main(seed: int | None = None) -> None:
    if seed is not None:
        random.seed(seed)

    # 2) Random K1, K2 (10 bit)
    K1 = random.getrandbits(10)
    K2 = random.getrandbits(10)

    # 3) Random M (8 bit)
    M = random.getrandbits(8)

    # 4) C = Double S-DES
    C = double_sdes_encrypt(M, K1, K2)

    print("Canonical values:")
    print(f"K1 = {bits10_str(K1)} ({K1})")
    print(f"K2 = {bits10_str(K2)} ({K2})")
    print(f"M = {bits8_str(M)} ({M})")
    print(f"C = {bits8_str(C)} ({C})")
    print()

    # sanity check: decryption
    M_back = double_sdes_decrypt(C, K1, K2)
    assert M_back == M, "Double S-DES decrypt failed"

    # 5) MITM for (M, C)
    V = mitm_candidates_from_pair(M, C)
    print(f"After 1-st pair (M,C) have |V| = {len(V)}")

    # 6) Do until got 1 pair
    rounds = 0
    extra_pairs = []
    while len(V) != 1:
        rounds += 1
        M2 = random.getrandbits(8)
        C2 = double_sdes_encrypt(M2, K1, K2)
        extra_pairs.append((M2, C2))
        V = refine_candidates(V, [(M2, C2)])
        print(f"Checking round #{rounds}: M'={bits8_str(M2)}, C'={bits8_str(C2)} => |V|={len(V)}")
        if rounds > 50:
            print("Too many checks, try other seed")
            break

    if len(V) == 1:
        (k1_found, k2_found) = next(iter(V))
        print("\nKey pair found:")
        print(f"K1* = {bits10_str(k1_found)} ({k1_found})")
        print(f"K2* = {bits10_str(k2_found)} ({k2_found})")
        print("\nMatch canonical values?" , (k1_found == K1 and k2_found == K2))


if __name__ == "__main__":
    main()
