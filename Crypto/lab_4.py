'''
Лаб 4 - Слайдовая атака на блочный шифр (S-DES)
Вариант 4.
'''
import random
from dataclasses import dataclass, field


def main() -> None:
    S_DES = SdesCipher()
    MASK = bits_to_int('1111')
    ROUNDS = 2
    S_KEY = random.randint(0, 255)

    print(f'1) Secret key K: {int_to_bits(S_KEY, 8)}')

    print('\n2) Cipher S-blocks stats:')
    print_cipher_info(S_DES)
    print()

    print(f'3) Slide mask: {int_to_bits(MASK, 4)}')
    slide_pairs = generate_slide_pairs(S_DES, S_KEY, ROUNDS, MASK)
    if slide_pairs:
        print(f'Found {len(slide_pairs)} slide pairs!')
        print_slide_pairs(slide_pairs)
    else:
        print('No slide pairs found!')
        exit()

    print('\n4) Applying slide attack...')
    result = slide_attack(slide_pairs, S_DES)
    print('\n5) RESULT:')
    if len(result) == 1:
        print(f'Restored key: {int_to_bits(list(result)[-1], 8)}')
    elif result:
        candidates = sorted([int_to_bits(k, 8) for k in result])
        print('Few possible keys restored:')
        for c in candidates:
            print(c)
    else:
        print('No possible keys found! (no suitable slide pairs?)')


def bits_to_int(bits: str) -> int:
    return int(bits, base=2)


def int_to_bits(x: int, len: int) -> str:
    return f'{x:0{len}b}'


def split_8_4_bits(x: int) -> tuple[int, int]:
    return (x >> 4) & 0x0f, x & 0x0f


def merge_4_8_bits(l: int, r: int) -> int:
    return ((l & 0x0f) << 4) | (r & 0x0f)


def build_s_block(mtx: list[list[int]]) -> dict[int, int]:
    '''
    4x4 i/o matrix -> 4x2 substituion blocks
    '''
    s = {}
    for row in range(4):
        for col in range(4):
            i = (row << 2) | col
            o = mtx[row][col] & 3
            s[i] = o
    return s
    

@dataclass
class SdesCipher:
    EP: list[int] = field(
        default_factory=lambda: [3, 2, 4, 1, 4, 1, 3, 2]
    )
    P4: list[int] = field(
        default_factory=lambda: [1, 4, 3, 2]
    )
    S1: dict[int, int] = field(
        default_factory=lambda: build_s_block([
            [1, 1, 2, 0],
            [3, 2, 3, 0],
            [0, 0, 1, 3],
            [3, 2, 1, 2]
        ])
    )
    S2: dict[int, int] = field(
        default_factory=lambda: build_s_block([
            [2, 2, 0, 3],
            [1, 1, 0, 0],
            [3, 3, 2, 2],
            [0, 3, 1, 1]
        ])
    )


def print_cipher_info(cipher: SdesCipher):
    print(f'EP-block: {cipher.EP}')
    print(f'P4-block: {cipher.P4}')
    print('S-blocks I/O stats:')
    print('| Input (4 bits) | Output S1 | Output S2 |')
    print('| -------------- | --------- | --------- |')
    for i in range(16):
        in_bits = int_to_bits(i, 4)
        out_s1 = int_to_bits(cipher.S1[i], 2)
        out_s2 = int_to_bits(cipher.S2[i], 2)
        print(f'| {in_bits:<14} | {out_s1:<9} | {out_s2:<9} |')
    print('| -------------- | --------- | --------- |')
        

def feistel_round(cipher: SdesCipher, right: int, key: int) -> int:
    exp = 0
    for i in cipher.EP:
        bit = (right >> (3 - (i - 1))) & 1
        exp = (exp << 1) | bit

    xored = exp ^ key

    s1_in = (xored >> 4) & 0x0f
    s2_in = xored & 0x0f

    s1_out = cipher.S1[s1_in]
    s2_out = cipher.S2[s2_in]
        
    merged = ((s1_out & 3) << 2) | (s2_out & 3)

    result = 0
    for i in cipher.P4:
        bit = (merged >> (3 - (i - 1))) & 1
        result = (result << 1) | bit
    return result
    

def encrypt(cipher: SdesCipher, text: int, key: int, rounds: int) -> int:
    L, R = split_8_4_bits(text)
    for _ in range(rounds):
        f_out = feistel_round(cipher, R, key)
        L, R = R, L ^ f_out
    return merge_4_8_bits(L, R)


def generate_slide_pairs(cipher: SdesCipher, key: int, rounds: int, mask: int):
    pairs = []
    for x_l in range(16):
        X = merge_4_8_bits(x_l, mask)
        Y = encrypt(cipher, X, key, rounds)
        for x_r in range(16):
            X_r = merge_4_8_bits(mask, x_r)
            Y_r = encrypt(cipher, X_r, key, rounds)
            _, Y_R = split_8_4_bits(Y)
            Y_rL, _ = split_8_4_bits(Y_r)
            if Y_rL == Y_R:
                pairs.append((X, Y, X_r, Y_r))
    return pairs


def print_slide_pairs(pairs: list):
    print(f"{'#':>3} {'X':^10} {'Y = E(X)':^10} {'X*':^10} {'Y* = E(X*)':^10}")
    print('-' * 52)
    for i, (X, Y, X_r, Y_r) in enumerate(pairs, 1):
        print(f'{i:>3} {int_to_bits(X,8):^10} {int_to_bits(Y,8):^10} {int_to_bits(X_r,8):^10} {int_to_bits(Y_r,8):^10}')


def slide_attack(pairs: list, cipher: SdesCipher):
    inv_s1 = {}
    inv_s2 = {}
    for i in range(16):
        out = cipher.S1[i]
        inv_s1.setdefault(out, []).append(i)
        out = cipher.S2[i]
        inv_s2.setdefault(out, []).append(i)

    inv_p4 = [0] * 4
    for i, p in enumerate(cipher.P4):
        inv_p4[p-1] = i + 1
    
    
    # VOTING: each pair votes for its key candidate hit.
    # Real key gains most votes from real pairs.
    # Fake pairs vote for random candidate keys.
    key_votes = {}
    for i, (X, Y, X_r, Y_r) in enumerate(pairs):
        XL, XR = split_8_4_bits(X)
        XL_r, XR_r = split_8_4_bits(X_r)
        YL, YR = split_8_4_bits(Y)
        YL_r, YR_r = split_8_4_bits(Y_r)

        # 1st round
        out_f1 = XL ^ XR_r
        in_f1 = XR

        s_out = 0
        for _, p in enumerate(inv_p4):
            bit = (out_f1 >> (3 - (p - 1))) & 1
            s_out = (s_out << 1) | bit
        s1_out = (s_out >> 2) & 3
        s2_out = s_out & 3

        exp = 0
        for j in cipher.EP:
            bit = (in_f1 >> (3 - (j - 1))) & 1
            exp = (exp << 1) | bit
        
        l_exp, r_exp = split_8_4_bits(exp)
        poss_k1 = set(l_exp ^ s_in for s_in in inv_s1[s1_out])
        poss_k2 = set(r_exp ^ s_in for s_in in inv_s2[s2_out])

        # 2nd round
        out_f2 = YL ^ YR_r
        in_f2 = YR

        s_out_2 = 0
        for _, p in enumerate(inv_p4):
            bit = (out_f2 >> (3 - (p - 1))) & 1
            s_out_2 = (s_out_2 << 1) | bit
        s1_out_2 = (s_out_2 >> 2) & 3
        s2_out_2 = s_out_2 & 3

        exp_2 = 0
        for j in cipher.EP:
            bit = (in_f2 >> (3 - (j - 1))) & 1
            exp_2 = (exp_2 << 1) | bit
        l_exp_2, r_exp_2 = split_8_4_bits(exp_2)
        poss_k1_2 = set(l_exp_2 ^ s_in for s_in in inv_s1[s1_out_2])
        poss_k2_2 = set(r_exp_2 ^ s_in for s_in in inv_s2[s2_out_2])

        # Key intersections
        common_k1 = poss_k1.intersection(poss_k1_2)
        common_k2 = poss_k2.intersection(poss_k2_2)

        print(f'\n[keys] Pair #{i+1}')
        print(f'Possible K1 (1st round): {sorted([int_to_bits(k, 4) for k in poss_k1])}')
        print(f'Possible K2 (1st round): {sorted([int_to_bits(k, 4) for k in poss_k2])}')

        print(f'Possible K1 (2nd round): {sorted([int_to_bits(k, 4) for k in poss_k1_2])}')
        print(f'Possible K2 (2nd round): {sorted([int_to_bits(k, 4) for k in poss_k2_2])}')

        print(f'K1 intersection: {sorted([int_to_bits(k, 4) for k in common_k1])}')
        print(f'K2 intersection: {sorted([int_to_bits(k, 4) for k in common_k2])}')

        # add votes for key hits
        if common_k1 and common_k2:
            pair_keys = {
                (k1 << 4) | k2
                for k1 in common_k1
                for k2 in common_k2
            }
            for k in pair_keys:
                key_votes[k] = key_votes.get(k, 0) + 1
    
    if not key_votes:
        return set()
    
    print('\n[keys] Key voting results:')
    print(f"{'Key (8-bit)':<14} | Votes")
    print('-' * 22)
    for k, votes in sorted(key_votes.items(), key=lambda x: -x[1]):
        print(f'{int_to_bits(k, 8):<14} | {votes}')

    # 1+ candidates
    max_votes = max(key_votes.values())
    return {k for k, v in key_votes.items() if v == max_votes}


if __name__ == '__main__':
    main()
