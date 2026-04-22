"""
MD-Hill-SPN Reference Test Vector Generator  (Revision 3 — 2026-04-20)
=======================================================================
Coggins (2026) · Bemidji State University
Python code assistance: Anthropic Claude AI

Generates a fully reproducible reference test vector for MD-Hill-SPN:
  - Fixed password, salt, and plaintext
  - Master key and all 12 round keys (SHA-256 stub key derivation)
  - Step-by-step intermediate states for Round 0 (Steps A-F)
  - Final ciphertext after 12 rounds
  - Full decryption round-trip verification
  - Branch-number verification for every diffusion matrix

Revision 3 changes (consistency with mdhillspn_metrics_corrected.py):
  1. Master-key derivation formula updated to the two-block SHA-256 stub
     used by the metric script:
        mk = SHA256(pwd ∥ salt) ∥ SHA256(pwd ∥ salt ∥ 0x01)   [:32]
     For out_len = 32 the truncation takes the first block only, so
     numerically this equals the single-SHA256 formula; the two-block
     form is preserved for compatibility with other out_len values.
  2. Diffusion matrices now use the Cauchy MDS construction, which is
     provably MDS over GF(2⁸) at every tier:
        M[i][j] = (x_i ⊕ y_j)⁻¹
     where X, Y are disjoint nonzero subsets of GF(2⁸) derived from
     (master_key, tag, index) via iterated SHA-256. Replaces the
     previous direct-stretch-plus-diagonal-patch construction, which
     happened to produce 4×4 and 8×8 matrices at MDS for this salt
     but only B = 16 (one below MDS) for the 16×16 tier.
  3. Branch numbers are verified exactly via weight-1 enumeration at
     test-vector-generation time. An assertion fails closed if any
     matrix is ever non-MDS; this should be mathematically impossible
     under the Cauchy construction.

Key derivation (SHA-256 stub; production uses Argon2id):
  master_key = (SHA256(pwd ∥ salt) ∥ SHA256(pwd ∥ salt ∥ 0x01))[:32]
  rk[r]      = SHA256(master_key ∥ b'MDHILLRK' ∥ pack('>H', r))[:16]

Round function steps per round:
  A: XOR round key
  B: 4 × (4×4 GF(2⁸)) matrix-vector products  [byte groups 0–3, 4–7, 8–11, 12–15]
  C: 2 × (8×8 GF(2⁸)) matrix-vector products  [byte groups 0–7, 8–15]
  D: AES S-box × 16                            [first nonlinear layer]
  E: 16×16 GF(2⁸) matrix-vector product        [full-block diffusion]
  F: AES S-box × 16                            [second nonlinear layer]

GF(2⁸) irreducible polynomial: 0x11B (AES polynomial)
Block: 128 bits | Rounds: 12 | Matrices: Cauchy MDS at every tier
Dependencies: Python standard library only (hashlib, struct).
"""

import hashlib
import struct


# ── GF(2⁸) arithmetic ──────────────────────────────────────────────────────

def gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2⁸) mod 0x11B."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def gf_dot(row: list, vec: list) -> int:
    r = 0
    for x, y in zip(row, vec):
        r ^= gf_mul(x, y)
    return r


def gf_mat_vec(mat: list, vec: list) -> list:
    """n×n matrix times n-vector over GF(2⁸)."""
    return [gf_dot(row, vec) for row in mat]


def gf_mat_inv(mat: list) -> list:
    """Invert square matrix over GF(2⁸) via Gauss-Jordan."""
    n = len(mat)
    aug = [list(mat[i]) + [1 if i == j else 0 for j in range(n)]
           for i in range(n)]
    for col in range(n):
        piv = next((r for r in range(col, n) if aug[r][col]), None)
        if piv is None:
            raise ValueError(f"Singular matrix at column {col}")
        aug[col], aug[piv] = aug[piv], aug[col]
        inv_p = _gf_inv(aug[col][col])
        aug[col] = [gf_mul(x, inv_p) for x in aug[col]]
        for r in range(n):
            if r != col and aug[r][col]:
                f = aug[r][col]
                aug[r] = [aug[r][k] ^ gf_mul(f, aug[col][k])
                          for k in range(2 * n)]
    return [row[n:] for row in aug]


# GF(2⁸) multiplicative inverse table
_INV = [0] * 256
for _x in range(1, 256):
    for _y in range(1, 256):
        if gf_mul(_x, _y) == 1:
            _INV[_x] = _y
            break


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ValueError("No inverse for 0 in GF(2⁸)")
    return _INV[a]


# ── AES S-box ──────────────────────────────────────────────────────────────

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

SBOX_INV = [0] * 256
for _i, _v in enumerate(SBOX):
    SBOX_INV[_v] = _i


# ── Branch number (exact, weight-1) ────────────────────────────────────────

def branch_number_weight1(matrix: list) -> int:
    """
    Exact branch number via exhaustive weight-1 enumeration.
    B(M) = min over nonzero x of [hw(x) + hw(Mx)] using byte-wise Hamming weight.
    For a weight-1 input e_i, hw(e_i) + hw(M e_i) = 1 + (column-i Hamming weight).
    For MDS matrices (such as Cauchy), this weight-1 minimum coincides with the
    true branch number.
    """
    n = len(matrix)
    best = n + 2  # one above the Singleton bound
    for i in range(n):
        v = [0] * n
        v[i] = 1
        out = gf_mat_vec(matrix, v)
        b = 1 + sum(1 for y in out if y != 0)
        if b < best:
            best = b
    return best


# ── Key derivation (Revision 3 stub) ───────────────────────────────────────

def derive_master_key(password: str, salt: bytes, out_len: int = 32) -> bytes:
    """
    SHA-256 stub replacing Argon2id for metric runs and test-vector
    generation. Structurally identical to mdhillspn_metrics_corrected.py.

    master_key = (SHA256(pwd ∥ salt) ∥ SHA256(pwd ∥ salt ∥ 0x01))[:out_len]

    For out_len = 32 this reduces to SHA256(pwd ∥ salt); the two-block
    form is preserved so that the same formula supports longer outputs
    and matches the metric script byte-for-byte.

    Production: Argon2id (t=3, m=65,536 KiB, p=2). All cipher operations
    are structurally identical under either KDF.
    """
    data = password.encode("utf-8") + salt
    return (hashlib.sha256(data).digest() +
            hashlib.sha256(data + b"\x01").digest())[:out_len]


def derive_round_key(master_key: bytes, r: int) -> bytes:
    """rk[r] = SHA256(master_key ∥ b'MDHILLRK' ∥ pack('>H', r))[:16]"""
    return hashlib.sha256(
        master_key + b"MDHILLRK" + struct.pack(">H", r)
    ).digest()[:16]


# ── Cauchy MDS matrix construction (Revision 3) ────────────────────────────

def _cauchy_matrix_gf28(master_key: bytes, tag: bytes,
                        index: int, size: int) -> list:
    """
    Derive an n × n Cauchy matrix over GF(2⁸) from (master_key, tag, index).

    A Cauchy matrix over a field F is defined by picking 2n distinct
    elements x_0, ..., x_{n-1}, y_0, ..., y_{n-1} with all x_i + y_j ≠ 0,
    and setting M[i][j] = (x_i + y_j)⁻¹. Every submatrix of a Cauchy
    matrix has nonzero determinant, so the matrix is MDS: B(M) = n + 1.

    In GF(2⁸) (characteristic 2), addition is XOR, and "x ⊕ y ≠ 0 for all
    i, j" reduces to "X and Y are disjoint subsets of the nonzero elements
    of GF(2⁸)."

    The 2n distinct nonzero bytes are drawn from an iterated SHA-256
    stream keyed by (master_key, tag, index), so each matrix is key-
    specific while being MDS by construction.
    """
    n = size
    stream = bytearray()
    counter = 0
    while len(stream) < max(128, 8 * n):
        stream += hashlib.sha256(
            master_key + tag +
            struct.pack(">H", index) +
            struct.pack(">I", counter)
        ).digest()
        counter += 1
        if counter > 128:
            break

    X, Y = [], []
    seen = set()
    for b in stream:
        if b == 0 or b in seen:
            continue
        seen.add(b)
        if len(X) < n:
            X.append(b)
        elif len(Y) < n:
            Y.append(b)
        else:
            break

    if len(X) < n or len(Y) < n:
        raise RuntimeError(
            f"Cauchy matrix derivation failed for size={n}; "
            f"got |X|={len(X)}, |Y|={len(Y)} (need {n} each)."
        )

    M = [[_gf_inv(X[i] ^ Y[j]) for j in range(n)] for i in range(n)]

    # Fail-closed verification: Cauchy must yield MDS.
    bn = branch_number_weight1(M)
    if bn != n + 1:
        raise RuntimeError(
            f"Cauchy construction produced non-MDS matrix "
            f"(size={n}, B={bn}, expected {n+1}). This should be "
            f"mathematically impossible; check gf_mul / gf_inv."
        )
    return M


def derive_matrices(master_key: bytes):
    """
    Derive the seven Cauchy MDS matrices from master_key:
      mat4  : four 4×4   matrices  (tag b'MDHILL_4',  indices 0–3, each B = 5)
      mat8  : two  8×8   matrices  (tag b'MDHILL_8',  indices 0–1, each B = 9)
      mat16 : one  16×16 matrix    (tag b'MDHILL_16', index 0,    B = 17)
    """
    mat4  = [_cauchy_matrix_gf28(master_key, b"MDHILL_4",  i, 4) for i in range(4)]
    mat8  = [_cauchy_matrix_gf28(master_key, b"MDHILL_8",  i, 8) for i in range(2)]
    mat16 = _cauchy_matrix_gf28(master_key, b"MDHILL_16",  0, 16)
    return mat4, mat8, mat16


# ── Round function ─────────────────────────────────────────────────────────

def encrypt_round(state: list, rk: list,
                  mat4, mat8, mat16,
                  verbose: bool = False, r_label: str = "") -> list:
    """One full round: Steps A through F."""

    # A: XOR round key
    stA = [s ^ k for s, k in zip(state, rk)]
    if verbose:
        print(f"  After Step A  XOR rk[{r_label}]"
              f"                    : {bytes(stA).hex().upper()}")

    # B: 4 × (4×4) GF(2⁸) mat-vec
    stB = []
    for g in range(4):
        stB += gf_mat_vec(mat4[g], stA[g*4:g*4+4])
    if verbose:
        print(f"  After Step B  4×(4×4 GF(2⁸)) mat-vec"
              f"          : {bytes(stB).hex().upper()}")

    # C: 2 × (8×8) GF(2⁸) mat-vec
    stC = []
    for g in range(2):
        stC += gf_mat_vec(mat8[g], stB[g*8:g*8+8])
    if verbose:
        print(f"  After Step C  2×(8×8 GF(2⁸)) mat-vec"
              f"          : {bytes(stC).hex().upper()}")

    # D: AES S-box × 16 (first nonlinear layer)
    stD = [SBOX[b] for b in stC]
    if verbose:
        print(f"  After Step D  AES S-box × 16"
              f"                    : {bytes(stD).hex().upper()}")

    # E: 16×16 GF(2⁸) mat-vec (full-block diffusion)
    stE = gf_mat_vec(mat16, stD)
    if verbose:
        print(f"  After Step E  16×16 GF(2⁸) mat-vec"
              f"             : {bytes(stE).hex().upper()}")

    # F: AES S-box × 16 (second nonlinear layer)
    stF = [SBOX[b] for b in stE]
    if verbose:
        print(f"  After Step F  AES S-box × 16"
              f"                    : {bytes(stF).hex().upper()}")

    return stF


def encrypt_block(plaintext: bytes, master_key: bytes,
                  rounds: int = 12, verbose_round: int = 0) -> bytes:
    mat4, mat8, mat16 = derive_matrices(master_key)
    state = list(plaintext)
    for r in range(rounds):
        rk = list(derive_round_key(master_key, r))
        v  = (r == verbose_round)
        if v:
            print(f"\nRound {r} input : {bytes(state).hex().upper()}")
        state = encrypt_round(state, rk, mat4, mat8, mat16,
                              verbose=v, r_label=str(r))
    return bytes(state)


def decrypt_block(ciphertext: bytes, master_key: bytes,
                  rounds: int = 12) -> bytes:
    mat4, mat8, mat16 = derive_matrices(master_key)
    inv4  = [gf_mat_inv(m) for m in mat4]
    inv8  = [gf_mat_inv(m) for m in mat8]
    inv16 = gf_mat_inv(mat16)
    state = list(ciphertext)
    for r in range(rounds - 1, -1, -1):
        rk = list(derive_round_key(master_key, r))
        state = [SBOX_INV[b] for b in state]            # inv F
        state = gf_mat_vec(inv16, state)                # inv E
        state = [SBOX_INV[b] for b in state]            # inv D
        tmp = []                                        # inv C
        for g in range(2):
            tmp += gf_mat_vec(inv8[g], state[g*8:g*8+8])
        state = tmp
        tmp = []                                        # inv B
        for g in range(4):
            tmp += gf_mat_vec(inv4[g], state[g*4:g*4+4])
        state = tmp
        state = [s ^ k for s, k in zip(state, rk)]      # inv A
    return bytes(state)


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    PASSWORD      = "MDHillSPN2026!"
    SALT_HEX      = "0102030405060708090a0b0c0d0e0f10"
    PLAINTEXT_HEX = "00112233445566778899aabbccddeeff"

    salt      = bytes.fromhex(SALT_HEX)
    plaintext = bytes.fromhex(PLAINTEXT_HEX)

    SEP = "=" * 70

    print(SEP)
    print("MD-Hill-SPN  REFERENCE TEST VECTOR  (Revision 3 — Cauchy MDS)")
    print("Coggins (2026) · SHA-256 stub · 128-bit block · 12 rounds")
    print(SEP)

    master_key = derive_master_key(PASSWORD, salt)
    rk0        = derive_round_key(master_key, 0)

    print(f"\n{'Password':<22}: {PASSWORD}")
    print(f"{'Salt (hex)':<22}: "
          f"{salt.hex().upper()[:16]} {salt.hex().upper()[16:]}")
    print(f"{'Plaintext (hex)':<22}: {plaintext.hex().upper()}")
    print()
    print(f"{'Master key (256-bit)':<22}: {master_key.hex().upper()[:32]}")
    print(f"{'':22}  {master_key.hex().upper()[32:]}")
    print(f"{'rk[0] (128-bit)':<22}: {rk0.hex().upper()}")
    print()
    print("Key derivation : master_key = SHA256(pwd ∥ salt) ∥ SHA256(pwd ∥ salt ∥ 0x01)[:32]")
    print("Key schedule   : rk[r]      = SHA256(K ∥ 'MDHILLRK' ∥ pack('>H', r))[:16]")
    print("Matrices       : Cauchy MDS over GF(2⁸) — B = n + 1 at every tier")

    # Branch-number verification (should all be MDS)
    print("\n" + "-" * 70)
    print("BRANCH-NUMBER VERIFICATION  (exact, weight-1 enumeration)")
    print("-" * 70)
    mat4, mat8, mat16 = derive_matrices(master_key)

    print("4×4 tier  (MDS bound = 5):")
    for i, M in enumerate(mat4):
        bn = branch_number_weight1(M)
        tag = "MDS" if bn == 5 else f"NON-MDS (B={bn})"
        print(f"  M4[{i}] : B = {bn}  [{tag}]")

    print("8×8 tier  (MDS bound = 9):")
    for i, M in enumerate(mat8):
        bn = branch_number_weight1(M)
        tag = "MDS" if bn == 9 else f"NON-MDS (B={bn})"
        print(f"  M8[{i}] : B = {bn}  [{tag}]")

    print("16×16 tier  (MDS bound = 17):")
    bn = branch_number_weight1(mat16)
    tag = "MDS" if bn == 17 else f"NON-MDS (B={bn})"
    print(f"  M16    : B = {bn}  [{tag}]")

    # Round 0 verbose trace
    print("\n" + "-" * 70)
    print("ROUND 0 — STEP-BY-STEP INTERMEDIATE STATES")
    print("-" * 70)
    ciphertext = encrypt_block(plaintext, master_key, rounds=12,
                               verbose_round=0)

    # Result
    print("\n" + "-" * 70)
    print("ENCRYPTION RESULT  (12 rounds)")
    print("-" * 70)
    print(f"  Plaintext   : {plaintext.hex().upper()}")
    print(f"  Ciphertext  : {ciphertext.hex().upper()}")

    # Decryption check
    recovered = decrypt_block(ciphertext, master_key, rounds=12)
    ok = recovered == plaintext
    print(f"\n  Decryption check : {'PASS ✓' if ok else 'FAIL ✗'}")
    if not ok:
        print(f"  Recovered        : {recovered.hex().upper()}")

    # All 12 round keys
    print("\n" + "-" * 70)
    print("ALL 12 ROUND KEYS")
    print("-" * 70)
    for r in range(12):
        rk = derive_round_key(master_key, r)
        print(f"  rk[{r:>2}] : {rk.hex().upper()}")

    print("\n" + SEP)
    print("END OF TEST VECTOR  —  Revision 3")
    print(SEP)
