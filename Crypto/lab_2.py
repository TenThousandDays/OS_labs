"""
Lab 2 (var. 4) - Linear Cryptoanalysis
"""
from typing import Optional

from block_cipher import generate_random_pairs, to_bits, bit_from_left, TrainingFeistelCipher


def _parity(x: int) -> int:
    return x.bit_count() & 1


def analyze_s1() -> None:
    S1 = [
        3,4,1,1,2,3,6,6,
        6,7,2,4,1,5,7,5
    ]

    # Linear Approximation Table
    lat = [[0]*8 for _ in range(16)]

    for alpha in range(16):
        for beta in range(8):
            cnt = 0
            for x in range(16):
                lhs = _parity(alpha & x)
                rhs = _parity(beta & S1[x])
                if lhs == rhs:
                    cnt += 1
            lat[alpha][beta] = cnt
    print(" "*4, end="")
    for b in range(8):
        print(f"{b:>4}", end="")
    print()

    for a in range(16):
        print(f"{a:2}", end=" ")
        for b in range(8):
            print(f"{lat[a][b]:4}", end="")
        print()

    # Find best LAT candidates
    best = []

    for alpha in range(1,16):
        for beta in range(1,8):
            bias = abs(lat[alpha][beta]-8)

            best.append((bias, alpha, beta, lat[alpha][beta]))

    best.sort(reverse=True)

    print()
    for bias,a,b,val in best[:15]:
        p = val / 16
        delta = abs(1 - 2*p)
        print(
            f"alpha={a:04b} beta={b:03b}  "
            f"S={val}  delta={delta}"
        )


def analyze_s2() -> None:
    S2 = [
        1,1,2,3,2,7,4,6,
        3,7,3,6,4,5,5,1
    ]

    # Linear Approximation Table
    lat = [[0]*8 for _ in range(16)]

    for alpha in range(16):
        for beta in range(8):
            cnt = 0
            for x in range(16):
                lhs = _parity(alpha & x)
                rhs = _parity(beta & S2[x])
                if lhs == rhs:
                    cnt += 1
            lat[alpha][beta] = cnt
    print(" "*4, end="")
    for b in range(8):
        print(f"{b:>4}", end="")
    print()

    for a in range(16):
        print(f"{a:2}", end=" ")
        for b in range(8):
            print(f"{lat[a][b]:4}", end="")
        print()

    # Find best LAT candidates
    best = []

    for alpha in range(1,16):
        for beta in range(1,8):
            bias = abs(lat[alpha][beta]-8)

            best.append((bias, alpha, beta, lat[alpha][beta]))

    best.sort(reverse=True)

    print()
    for bias,a,b,val in best[:15]:
        p = val / 16
        delta = abs(1 - 2*p)
        print(
            f"alpha={a:04b} beta={b:03b}  "
            f"S={val}  delta={delta}"
        )


def analyze_s3() -> None:
    S3 = [
        2, 1, 2, 3,
        3, 2, 3, 1,
        1, 2, 3, 2,
        2, 3, 1, 3
    ]

    # Linear Approximation Table
    lat = [[0]*4 for _ in range(16)]

    for alpha in range(16):
        for beta in range(4):
            cnt = 0
            for x in range(16):
                lhs = _parity(alpha & x)
                rhs = _parity(beta & S3[x])
                if lhs == rhs:
                    cnt += 1
            lat[alpha][beta] = cnt
    print(" "*4, end="")
    for b in range(4):
        print(f"{b:4}", end="")
    print()

    for a in range(16):
        print(f"{a:2}", end=" ")
        for b in range(4):
            print(f"{lat[a][b]:4}", end=" ")
        print()

    # Find best LAT candidates
    best = []

    for alpha in range(1,16):
        for beta in range(1,4):
            bias = abs(lat[alpha][beta]-8)

            best.append((bias, alpha, beta, lat[alpha][beta]))

    best.sort(reverse=True)

    print()
    for bias,a,b,val in best[:15]:
        p = val / 16
        delta = abs(1 - 2*p)
        print(
            f"alpha={a:04b} beta={b:02b}  "
            f"S={val}  delta={delta}"
        )


# -------------------- Линейный анализ --------------------

def _get_bit16(x: int, i: int) -> int:
    return bit_from_left(x, 16, i)


def _lhs(pt16: int, ct16: int, terms: list[tuple[str, int]]) -> int:
    v = 0
    for src, idx in terms:
        v ^= _get_bit16(pt16, idx) if src == "X" else _get_bit16(ct16, idx)
    return v


# Уравнения: (термы LHS, p, свободный член в RHS)
EQS = {
    1: ([("X", 11), ("X", 12), ("X", 4), ("Y", 4)], 13 / 16, 0),
    2: ([("X", 12), ("X", 10), ("X", 7), ("X", 4), ("X", 3), ("Y", 7), ("Y", 4), ("Y", 3)], 13 / 16, 0),
    3: ([("X", 12), ("X", 9), ("X", 7), ("Y", 7)], 3 / 16, 0),

    4: ([("X", 14), ("X", 16), ("X", 13), ("X", 15), ("X", 5), ("Y", 5), ("X", 8), ("Y", 8)], 13 / 16, 0),
    5: ([("X", 14), ("X", 16), ("X", 5), ("Y", 5)], 13 / 16, 0),
    6: ([("X", 15), ("X", 6), ("Y", 6), ("X", 5), ("Y", 5)], 3 / 16, 0),
    7: ([("X", 16), ("X", 6), ("Y", 6)], 12 / 16, 0),

    8: ([("X", 11), ("X", 16), ("X", 12), ("X", 1), ("Y", 1)], 14 / 16, 0),
    9: ([("X", 11), ("X", 16), ("X", 12), ("X", 2), ("Y", 2), ("X", 1), ("Y", 1)], 2 / 16, 1),
    10: ([("X", 16), ("X", 10), ("X", 2), ("Y", 2)], 12/16, 0)
}


def infer_rhs_from_stats(pairs: list[tuple[int, int]], terms: list[tuple[str, int]], p: float, const=0) -> tuple[int, int, float]:
    """
    Считаем T0 = # случаев LHS=0, a=T0/N.
    Если RHS=0 => ожидаем a ~ p
    Если RHS=1 => ожидаем a ~ 1-p
    Выбираем RHS по тому, к чему ближе a.
    """
    n = len(pairs)
    t0 = sum(1 for x, y in pairs if _lhs(x, y, terms) == 0)
    a = t0 / n
    rhs0_dist = abs(a - p)
    rhs1_dist = abs(a - (1 - p))
    rhs = 0 if rhs0_dist <= rhs1_dist else 1
    rhs ^= const
    return rhs, t0, a


def build_candidates(inf: dict[int, int]) -> list[int]:
    """
    Построение кандидатов ключа для набора линейных уравнений.
    После линейной стадии остаются 3 свободных бита:
        K2, K9, K10.
    Всего получается 8 кандидатов.
    """

    # ---------- S1 ----------
    a12 = inf[1]      # K1 ^ K2
    a24 = inf[2]      # K2 ^ K4
    a23 = inf[3]      # K2 ^ K3

    # ---------- S2 ----------
    a5678 = inf[4]    # K5 ^ K6 ^ K7 ^ K8
    a56 = inf[5]      # K5 ^ K6
    K8 = inf[6]       # K8
    K6 = inf[7]       # K6

    K5 = a56 ^ K6
    K7 = a5678 ^ K5 ^ K6 ^ K8

    # ---------- S3 ----------
    a91012 = inf[8]   # K9 ^ K10 ^ K12
    a1011 = inf[10]   # K10 ^ K11

    candidates = []

    # свободный бит K2
    for K2 in (0, 1):

        K1 = a12 ^ K2
        K3 = a23 ^ K2
        K4 = a24 ^ K2

        # свободные K9,K10
        for K9 in (0, 1):
            for K10 in (0, 1):

                K11 = a1011 ^ K10
                K12 = a91012 ^ K9 ^ K10

                bits = [
                    K1, K2, K3, K4,
                    K5, K6, K7, K8,
                    K9, K10, K11, K12
                ]

                key = 0
                for b in bits:
                    key = (key << 1) | b

                candidates.append(key)

    return candidates


def pick_key_by_check(candidates: list[int], pairs: list[tuple[int, int]], check_pairs: int = 6) -> Optional[int]:
    for k in candidates:
        cipher = TrainingFeistelCipher(k)
        ok = True
        for x, y in pairs[:check_pairs]:
            if cipher.encrypt_block(x) != y:
                ok = False
                break
        if ok:
            return k
    return None


def main() -> None:
    KEY_12 = "101010100101"
    N = 30

    print(f'Key K(12) = {KEY_12}')
    print(f'N pairs: {N} (random plaintexts)')

    pairs = generate_random_pairs(KEY_12, N)

    for X, Y in pairs:
        print(f'X: {to_bits(X, 16)}\tY: {to_bits(Y, 16)}')

    print('\nS1 block analysis:')
    analyze_s1()

    print('\nS2 block analysis:')
    analyze_s2()

    print('\nS3 block analysis:')
    analyze_s3()

    # 1) статистика и вывод RHS для уравнений
    inferred: dict[int, int] = {} 
    stats_rows = [] 
    for no in sorted(EQS.keys()): 
        terms, p, const = EQS[no] 
        rhs, t0, a = infer_rhs_from_stats(pairs, terms, p, const) 
        inferred[no] = rhs 
        stats_rows.append((no, p, t0, N - t0, a, rhs)) 
        
    print("\n--- Equation statistics ---") 
    print("no | p | T0(#LHS=0) | T1 | a=T0/N | inferred RHS") 
    print("---+----------+------------+----+-----------+-------------") 
    for no, p, t0, t1, a, rhs in stats_rows: 
        print(f"{no:2d} | {p:0.6f} | {t0:10d} | {t1:2d} | {a:0.6f} | {rhs}") 
        
    # 2) восстановление кандидатов 
    candidates = build_candidates(inferred) 
    
    # 3) проверка кандидата на сгенерированных парах 
    found = pick_key_by_check(candidates, pairs, check_pairs=len(pairs)) 
    
    # 4) печать промежуточных восстановленных XOR-ов 
    print("\n--- Recovered XOR relations ---") 
    print(f"(1) K1^K2 = {inferred[1]}") 
    print(f"(2) K2^K4 = {inferred[2]}") 
    print(f"(3) K2^K3 = {inferred[3]}") 
    print(f"(4) K5^K6^K7^K8 = {inferred[4]}") 
    print(f"(5) K5^K6 = {inferred[5]}") 
    print(f"(6) K8 = {inferred[6]}") 
    print(f"(7) K6 = {inferred[7]}") 
    print(f"(8) K9^K10^K12 = {inferred[8]}") 
    print(f"(9) K9^K10^K12^1 = {inferred[9]}")
    print(f"(10) K10^K11 = {inferred[10]}")

    # 5) вывод итога 
    print("\n--- Candidate keys ---") 
    print(f"Candidates after linear stage: {len(candidates)} (expected ~8)")
    for i, cand in enumerate(candidates):
        print(f"({i+1}) {to_bits(cand, 12)}")
    if found is None: 
        print("FOUND KEY: None (increase N or check equations/indexing)") 
    else: 
        print(f"FOUND KEY: {to_bits(found, 12)}") 
        print(f"MATCHES GIVEN KEY: {to_bits(found, 12) == KEY_12}")


if __name__ == '__main__':
    main()
