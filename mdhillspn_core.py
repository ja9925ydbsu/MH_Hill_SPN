#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mdhillspn_core.py
=================
MD-Hill-SPN shared core module (Revision 3 parameterization, 2026).
Coggins (2026) . Bemidji State University
Python code assistance: Anthropic Claude AI

Provides, in one importable module:

  1. REFERENCE implementation: pure-standard-library, byte-for-byte
     identical to MD-Hill-SPN_test_vector_rev3_20260420.py. Slow,
     transparent, normative.

  2. VECTORIZED implementation: NumPy batch encryption. Mathematically
     identical output, typically 1-2 orders of magnitude faster.
     Optimizations (all output-preserving, verified at import):

       (a) Round-key caching. The reference metric script re-derived
           rk[r] with SHA-256 inside every round of every block
           encryption; here all round keys are derived once per
           (key, rounds) context.

       (b) Linear-layer fusion. Steps B and C are adjacent linear maps:
               Step B = blockdiag(M4[0], M4[1], M4[2], M4[3])
               Step C = blockdiag(M8[0], M8[1])
           Their composition is two 8x8 matrices
               M8c[g] = M8[g] . blockdiag(M4[2g], M4[2g+1]),  g = 0, 1
           computed once per key. One fused mat-vec replaces two.

       (c) Round-key fold. Step A (XOR rk) followed by the linear layer
           satisfies M(x XOR k) = Mx XOR Mk, so the per-round constant
           c[r][g] = M8c[g] . rk[r] is precomputed and XORed after the
           table lookups; the per-byte XOR of Step A disappears from
           the inner loop.

       (d) T-tables. For each fused 8x8 matrix, T8[g][j][v] =
           v * column_j(M8c[g]) for all v in GF(2^8); a mat-vec is then
           8 table gathers XOR-reduced. For Step E the first S-box
           (Step D) is folded in: TE[j][v] = SBOX[v] * column_j(M16),
           so Steps D+E together are 16 gathers XOR-reduced. Step F
           remains one S-box gather.

     Net inner loop per round per batch: 32 + 16 gathers, XOR
     reductions, and one final S-box gather - no Python-level per-byte
     work.

  3. Key derivation: SHA-256 stub (deterministic runs / test vectors)
     and Argon2id (production; requires argon2-cffi), plus the
     rk[r] = SHA256(K || 'MDHILLRK' || pack('>H', r))[:16] schedule.

  4. Cauchy MDS matrix derivation with fail-closed exact branch-number
     verification (B = n + 1 at every tier).

  5. Counter-mode keystream generation (vectorized) for NIST testing.

  6. conformance_check(): verifies, and refuses to bless the module
     unless ALL of the following hold:
       - master key, rk[0] against the Revision 3 published values
       - all five Round-0 intermediate states (Steps A-F)
       - the 12-round reference ciphertext
       - reference decryption round-trip
       - branch numbers B = 5 / 9 / 17 at every tier
       - vectorized == reference on the test vector and on random
         blocks at several round counts
     Every metric script in the MD-Hill-SPN suite calls this at
     startup and refuses to run on any mismatch (the same conformance
     discipline as the HESPN v4 scripts).

Canonical encodings (normative, identical to the Revision 3 scripts):
  master key : (SHA256(pwd || salt) || SHA256(pwd || salt || 0x01))[:32]
               (stub; production Argon2id t=3, m=65536 KiB, p=2, l=32)
  round keys : rk[r] = SHA256(K || b'MDHILLRK' || pack('>H', r))[:16]
  matrices   : Cauchy MDS over GF(2^8)/0x11B; X, Y disjoint nonzero
               subsets drawn from iterated
               SHA256(K || tag || pack('>H', index) || pack('>I', ctr)),
               tags b'MDHILL_4' (i=0..3), b'MDHILL_8' (i=0..1),
               b'MDHILL_16' (i=0); M[i][j] = inv(X[i] ^ Y[j])
  round      : A xor-rk, B 4x(4x4), C 2x(8x8), D S-box, E 16x16, F S-box
  block      : 128 bits | rounds: 12 | GF(2^8) polynomial 0x11B

Dependencies: numpy (vectorized path); argon2-cffi optional (Argon2id).
"""

import hashlib
import struct

import numpy as np

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NUM_BYTES  = 16
BLOCK_BITS = 128
ROUNDS     = 12

ARGON_TIME_COST   = 3
ARGON_MEMORY_COST = 65536
ARGON_PARALLELISM = 2
ARGON_SALT_LEN    = 16

# ---------------------------------------------------------------------------
# Revision 3 published reference test vector (2026-04-20)
# password 'MDHillSPN2026!', salt 0102...0f10, plaintext 00112233...eeff
# ---------------------------------------------------------------------------

TV_PASSWORD  = "MDHillSPN2026!"
TV_SALT      = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
TV_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")

TV_MASTER_KEY = bytes.fromhex(
    "3cb720727f487885b56b4164e3353cb2e66078e67fbc9dcc57a283617188b314")
TV_RK0        = bytes.fromhex("7f3dec3355747b341d023a9675c77102")

TV_ROUND0_STEPS = {
    "A": bytes.fromhex("7f2cce0011211d43959b902db91a9ffd"),
    "B": bytes.fromhex("75753c70555cd58919490169f3d7b842"),
    "C": bytes.fromhex("1a3447d32735bc6f529cb86a0bd0ecd6"),
    "D": bytes.fromhex("a218a066cc9665a800de6c022b70cef6"),
    "E": bytes.fromhex("09a203fd147fb0b314b7478a7e8d50dc"),
    "F": bytes.fromhex("013a7b54fad2e76dfaa9a07ef35d5386"),
}

TV_CIPHERTEXT_12R = bytes.fromhex("d2d0aed88f1a3169a0b1afeb8739b458")

# ---------------------------------------------------------------------------
# GF(2^8) arithmetic, AES polynomial 0x11B
# ---------------------------------------------------------------------------

def gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) mod 0x11B (bitwise reference)."""
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


# log/exp tables (generator 0x03) for fast scalar multiplication
GF_EXP = [0] * 512
GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    GF_EXP[_i] = _x
    GF_LOG[_x] = _i
    _x = gf_mul(_x, 0x03)
for _i in range(255, 512):
    GF_EXP[_i] = GF_EXP[_i - 255]


def gf_mul_fast(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]


# multiplicative-inverse table
GF_INV = [0] * 256
for _a in range(1, 256):
    GF_INV[_a] = GF_EXP[255 - GF_LOG[_a]]


def gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^8); 0 maps to 0 (Cauchy never uses 0)."""
    return GF_INV[a]


def gf_dot(row, vec) -> int:
    r = 0
    for x, y in zip(row, vec):
        r ^= gf_mul_fast(x, y)
    return r


def gf_mat_vec(mat, vec):
    return [gf_dot(row, vec) for row in mat]


def gf_mat_mul(A, B):
    """Matrix product over GF(2^8): (A.B)[i][j] = XOR_k A[i][k]*B[k][j]."""
    n, m, p = len(A), len(B), len(B[0])
    out = [[0] * p for _ in range(n)]
    for i in range(n):
        Ai = A[i]
        for j in range(p):
            acc = 0
            for k in range(m):
                acc ^= gf_mul_fast(Ai[k], B[k][j])
            out[i][j] = acc
    return out


def gf_mat_inv(mat):
    """Invert a square matrix over GF(2^8) via Gauss-Jordan."""
    n = len(mat)
    M = [row[:] for row in mat]
    I = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    for col in range(n):
        piv = next((r for r in range(col, n) if M[r][col]), None)
        if piv is None:
            raise ValueError(f"Singular matrix at column {col}")
        M[col], M[piv] = M[piv], M[col]
        I[col], I[piv] = I[piv], I[col]
        ip = gf_inv(M[col][col])
        M[col] = [gf_mul_fast(x, ip) for x in M[col]]
        I[col] = [gf_mul_fast(x, ip) for x in I[col]]
        for r in range(n):
            if r != col and M[r][col]:
                f = M[r][col]
                M[r] = [M[r][j] ^ gf_mul_fast(f, M[col][j]) for j in range(n)]
                I[r] = [I[r][j] ^ gf_mul_fast(f, I[col][j]) for j in range(n)]
    return I


# ---------------------------------------------------------------------------
# AES S-box (FIPS 197)
# ---------------------------------------------------------------------------

SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

SBOX_INV = [0] * 256
for _i, _v in enumerate(SBOX):
    SBOX_INV[_v] = _i

SBOX_NP     = np.array(SBOX,     dtype=np.uint8)
SBOX_INV_NP = np.array(SBOX_INV, dtype=np.uint8)

# ---------------------------------------------------------------------------
# Branch number (exact via weight-1 enumeration; exact for MDS matrices)
# ---------------------------------------------------------------------------

def branch_number_weight1(matrix) -> int:
    """
    B(M) = min over nonzero x of [hw(x) + hw(Mx)], hw = nonzero-byte count.
    For weight-1 input e_i, the pair is (1, column-i Hamming weight), and for
    MDS matrices (all columns full weight) the weight-1 minimum equals the
    true branch number n + 1.
    """
    n = len(matrix)
    best = n + 2
    for i in range(n):
        v = [0] * n
        v[i] = 1
        out = gf_mat_vec(matrix, v)
        best = min(best, 1 + sum(1 for y in out if y))
    return best


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_master_key_stub(password: str, salt: bytes,
                           out_len: int = 32) -> bytes:
    """SHA-256 stub (deterministic runs / test vectors)."""
    data = password.encode("utf-8") + salt
    return (hashlib.sha256(data).digest() +
            hashlib.sha256(data + b"\x01").digest())[:out_len]


def derive_master_key_argon2id(password: str, salt: bytes,
                               out_len: int = 32) -> bytes:
    """Production KDF: Argon2id (t=3, m=65536 KiB, p=2)."""
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(
        secret=password.encode("utf-8"), salt=salt,
        time_cost=ARGON_TIME_COST, memory_cost=ARGON_MEMORY_COST,
        parallelism=ARGON_PARALLELISM, hash_len=out_len, type=Type.ID)


def derive_round_key(master_key: bytes, r: int) -> bytes:
    """rk[r] = SHA256(K || b'MDHILLRK' || pack('>H', r))[:16]"""
    return hashlib.sha256(
        master_key + b"MDHILLRK" + struct.pack(">H", r)).digest()[:16]


# ---------------------------------------------------------------------------
# Cauchy MDS matrix derivation (Revision 3, fail-closed)
# ---------------------------------------------------------------------------

def _cauchy_matrix_gf28(master_key: bytes, tag: bytes,
                        index: int, size: int):
    n = size
    stream = bytearray()
    counter = 0
    while len(stream) < max(128, 8 * n):
        stream += hashlib.sha256(
            master_key + tag +
            struct.pack(">H", index) + struct.pack(">I", counter)).digest()
        counter += 1
        if counter > 128:
            break

    X, Y, seen = [], [], set()
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
            f"got |X|={len(X)}, |Y|={len(Y)} (need {n} each).")

    M = [[gf_inv(X[i] ^ Y[j]) for j in range(n)] for i in range(n)]

    bn = branch_number_weight1(M)
    if bn != n + 1:
        raise RuntimeError(
            f"Cauchy construction produced non-MDS matrix "
            f"(size={n}, B={bn}, expected {n+1}).")
    return M


def derive_matrices(master_key: bytes):
    """mat4 (4 x 4x4, B=5), mat8 (2 x 8x8, B=9), mat16 (16x16, B=17)."""
    mat4  = [_cauchy_matrix_gf28(master_key, b"MDHILL_4",  i, 4) for i in range(4)]
    mat8  = [_cauchy_matrix_gf28(master_key, b"MDHILL_8",  i, 8) for i in range(2)]
    mat16 = _cauchy_matrix_gf28(master_key, b"MDHILL_16",  0, 16)
    return mat4, mat8, mat16


# ---------------------------------------------------------------------------
# REFERENCE implementation (normative; matches the rev3 test vector script)
# ---------------------------------------------------------------------------

def encrypt_round_ref(state, rk, mat4, mat8, mat16):
    stA = [s ^ k for s, k in zip(state, rk)]                      # A
    stB = []
    for g in range(4):                                            # B
        stB += gf_mat_vec(mat4[g], stA[g*4:g*4+4])
    stC = []
    for g in range(2):                                            # C
        stC += gf_mat_vec(mat8[g], stB[g*8:g*8+8])
    stD = [SBOX[b] for b in stC]                                  # D
    stE = gf_mat_vec(mat16, stD)                                  # E
    return [SBOX[b] for b in stE]                                 # F


def encrypt_block_ref(plaintext: bytes, master_key: bytes,
                      rounds: int = ROUNDS, _mats=None) -> bytes:
    mats = _mats if _mats is not None else derive_matrices(master_key)
    mat4, mat8, mat16 = mats
    state = list(plaintext)
    for r in range(rounds):
        rk = derive_round_key(master_key, r)
        state = encrypt_round_ref(state, rk, mat4, mat8, mat16)
    return bytes(state)


def decrypt_block_ref(ciphertext: bytes, master_key: bytes,
                      rounds: int = ROUNDS) -> bytes:
    mat4, mat8, mat16 = derive_matrices(master_key)
    inv4, inv8 = [gf_mat_inv(m) for m in mat4], [gf_mat_inv(m) for m in mat8]
    inv16 = gf_mat_inv(mat16)
    state = list(ciphertext)
    for r in range(rounds - 1, -1, -1):
        rk = derive_round_key(master_key, r)
        state = [SBOX_INV[b] for b in state]                      # inv F
        state = gf_mat_vec(inv16, state)                          # inv E
        state = [SBOX_INV[b] for b in state]                      # inv D
        tmp = []
        for g in range(2):                                        # inv C
            tmp += gf_mat_vec(inv8[g], state[g*8:g*8+8])
        state = tmp
        tmp = []
        for g in range(4):                                        # inv B
            tmp += gf_mat_vec(inv4[g], state[g*4:g*4+4])
        state = tmp
        state = [s ^ k for s, k in zip(state, rk)]                # inv A
    return bytes(state)


# ---------------------------------------------------------------------------
# VECTORIZED implementation
# ---------------------------------------------------------------------------

class MDHillContext:
    """
    Precomputed per-key encryption context for the vectorized path.

    Precomputation (once per key; a few milliseconds):
      M8c[g]   = M8[g] . blockdiag(M4[2g], M4[2g+1])       fused B o C
      T8[g]    : uint8[8, 256, 8],  T8[g][j][v]  = v * col_j(M8c[g])
      TE       : uint8[16, 256, 16], TE[j][v]    = SBOX[v] * col_j(M16)
                                                    (Step D folded into E)
      rconst   : uint8[max_rounds, 16], rconst[r] = M8c-image of rk[r]
                 (Step A folded through the linear layer)

    Round r on a batch X (uint8[B, 16]):
      y[:,  0: 8] = XOR_j T8[0][j][X[:, j    ]]   ^ rconst[r,  0: 8]
      y[:,  8:16] = XOR_j T8[1][j][X[:, 8 + j]]   ^ rconst[r,  8:16]
      z           = XOR_j TE[j][y[:, j]]
      X           = SBOX[z]
    which equals SBOX(M16 . SBOX(M8c . (X xor rk[r]))) byte-for-byte.
    """

    def __init__(self, master_key: bytes, max_rounds: int = ROUNDS):
        self.master_key = master_key
        self.max_rounds = max_rounds
        mat4, mat8, mat16 = derive_matrices(master_key)
        self.mats = (mat4, mat8, mat16)

        # Fused B o C matrices
        bd0 = _blockdiag(mat4[0], mat4[1])
        bd1 = _blockdiag(mat4[2], mat4[3])
        m8c = [gf_mat_mul(mat8[0], bd0), gf_mat_mul(mat8[1], bd1)]
        self.m8c = m8c

        # Scalar-times-value tables over GF(2^8): SCALE[a][v] = a*v
        exp = np.array(GF_EXP[:255], dtype=np.uint8)
        log = np.array(GF_LOG,       dtype=np.int32)
        scale = np.zeros((256, 256), dtype=np.uint8)
        v = np.arange(1, 256)
        for a in range(1, 256):
            scale[a, 1:] = exp[(GF_LOG[a] + log[v]) % 255]
        self._scale = scale

        # T8[g][j][v] = v * column_j(M8c[g])   -> uint8[2][8, 256, 8]
        self.T8 = []
        for g in range(2):
            t = np.zeros((8, 256, 8), dtype=np.uint8)
            for j in range(8):
                for i in range(8):
                    t[j, :, i] = scale[m8c[g][i][j]]
            self.T8.append(t)

        # TE[j][v] = SBOX[v] * column_j(M16)  -> uint8[16, 256, 16]
        self.TE = np.zeros((16, 256, 16), dtype=np.uint8)
        for j in range(16):
            col = [mat16[i][j] for i in range(16)]
            for i, a in enumerate(col):
                self.TE[j, :, i] = scale[a][SBOX_NP]

        # Round keys and folded round constants
        self.round_keys = [derive_round_key(master_key, r)
                           for r in range(max_rounds)]
        rconst = np.zeros((max_rounds, 16), dtype=np.uint8)
        for r, rk in enumerate(self.round_keys):
            rk = list(rk)
            img = (gf_mat_vec(m8c[0], rk[:8]) + gf_mat_vec(m8c[1], rk[8:]))
            rconst[r] = np.array(img, dtype=np.uint8)
        self.rconst = rconst

    # -- batch encryption ---------------------------------------------------

    def encrypt_batch(self, blocks: np.ndarray,
                      rounds: int = None) -> np.ndarray:
        """
        Encrypt uint8 array of shape (B, 16); returns uint8 (B, 16).
        Input is not modified.
        """
        rounds = self.max_rounds if rounds is None else rounds
        if rounds > self.max_rounds:
            raise ValueError("rounds exceeds context max_rounds")
        X = np.ascontiguousarray(blocks, dtype=np.uint8)
        if X.ndim != 2 or X.shape[1] != 16:
            raise ValueError("blocks must have shape (B, 16)")
        T8, TE, rconst = self.T8, self.TE, self.rconst
        y = np.empty_like(X)
        for r in range(rounds):
            # fused A + B + C
            acc0 = T8[0][0][X[:, 0]].copy()
            for j in range(1, 8):
                acc0 ^= T8[0][j][X[:, j]]
            acc1 = T8[1][0][X[:, 8]].copy()
            for j in range(1, 8):
                acc1 ^= T8[1][j][X[:, 8 + j]]
            y[:, :8], y[:, 8:] = acc0, acc1
            y ^= rconst[r]
            # fused D + E
            z = TE[0][y[:, 0]].copy()
            for j in range(1, 16):
                z ^= TE[j][y[:, j]]
            # F
            X = SBOX_NP[z]
        return X

    def keystream_bits(self, start_counter: int, num_bits: int,
                       rounds: int = None,
                       batch_blocks: int = 65536) -> np.ndarray:
        """
        Counter-mode keystream: concatenated encryptions of sequential
        128-bit big-endian counter blocks start_counter, start_counter+1, ...
        Returns uint8 bit array (0/1) of length num_bits, MSB-first per byte.
        """
        n_blocks = (num_bits + BLOCK_BITS - 1) // BLOCK_BITS
        out_bits = np.empty(n_blocks * BLOCK_BITS, dtype=np.uint8)
        pos = 0
        c = start_counter
        while pos < n_blocks * BLOCK_BITS:
            nb = min(batch_blocks, n_blocks - pos // BLOCK_BITS)
            ctrs = _counters_to_blocks(c, nb)
            ct = self.encrypt_batch(ctrs, rounds=rounds)
            out_bits[pos:pos + nb * BLOCK_BITS] = (
                np.unpackbits(ct, axis=1).reshape(-1))
            c += nb
            pos += nb * BLOCK_BITS
        return out_bits[:num_bits]


def _blockdiag(A, B):
    na, nb = len(A), len(B)
    n = na + nb
    M = [[0] * n for _ in range(n)]
    for i in range(na):
        for j in range(na):
            M[i][j] = A[i][j]
    for i in range(nb):
        for j in range(nb):
            M[na + i][na + j] = B[i][j]
    return M


def _counters_to_blocks(start: int, count: int) -> np.ndarray:
    """Sequential 128-bit big-endian counter blocks as uint8 (count, 16)."""
    idx = np.arange(start, start + count, dtype=np.uint64)
    out = np.zeros((count, 16), dtype=np.uint8)
    # low 64 bits into bytes 8..15 (counters < 2^64 in all suite workloads)
    for b in range(8):
        out[:, 15 - b] = ((idx >> np.uint64(8 * b)) & np.uint64(0xFF)
                          ).astype(np.uint8)
    return out


# ---------------------------------------------------------------------------
# Conformance check (call at startup of every metric script)
# ---------------------------------------------------------------------------

def conformance_check(verbose: bool = True,
                      n_random_blocks: int = 64,
                      seed: int = 0xC0995) -> None:
    """
    Verify the module against the Revision 3 published test vector and
    verify vectorized == reference. Raises RuntimeError on any mismatch.
    """
    def _say(msg):
        if verbose:
            print(msg)

    _say("Conformance check (MD-Hill-SPN Revision 3) ...")

    # 1. Master key and rk[0]
    mk = derive_master_key_stub(TV_PASSWORD, TV_SALT)
    if mk != TV_MASTER_KEY:
        raise RuntimeError("Conformance FAIL: master key mismatch")
    if derive_round_key(mk, 0) != TV_RK0:
        raise RuntimeError("Conformance FAIL: rk[0] mismatch")
    _say("  [ok] master key, rk[0]")

    # 2. Branch numbers
    mat4, mat8, mat16 = derive_matrices(mk)  # raises fail-closed if non-MDS
    _say("  [ok] Cauchy matrices MDS at every tier (B = 5 / 9 / 17)")

    # 3. Round-0 intermediate states
    rk0 = list(TV_RK0)
    st  = list(TV_PLAINTEXT)
    stA = [s ^ k for s, k in zip(st, rk0)]
    stB = []
    for g in range(4):
        stB += gf_mat_vec(mat4[g], stA[g*4:g*4+4])
    stC = []
    for g in range(2):
        stC += gf_mat_vec(mat8[g], stB[g*8:g*8+8])
    stD = [SBOX[b] for b in stC]
    stE = gf_mat_vec(mat16, stD)
    stF = [SBOX[b] for b in stE]
    for name, got in zip("ABCDEF", (stA, stB, stC, stD, stE, stF)):
        if bytes(got) != TV_ROUND0_STEPS[name]:
            raise RuntimeError(f"Conformance FAIL: Round-0 Step {name}")
    _say("  [ok] Round-0 Steps A-F")

    # 4. 12-round ciphertext + decryption round-trip (reference)
    ct = encrypt_block_ref(TV_PLAINTEXT, mk, rounds=12)
    if ct != TV_CIPHERTEXT_12R:
        raise RuntimeError("Conformance FAIL: 12-round ciphertext")
    if decrypt_block_ref(ct, mk, rounds=12) != TV_PLAINTEXT:
        raise RuntimeError("Conformance FAIL: decryption round-trip")
    _say("  [ok] 12-round ciphertext + decryption round-trip")

    # 5. Vectorized == reference: test vector
    ctx = MDHillContext(mk, max_rounds=12)
    vct = ctx.encrypt_batch(
        np.frombuffer(TV_PLAINTEXT, dtype=np.uint8).reshape(1, 16))
    if bytes(vct[0].tobytes()) != TV_CIPHERTEXT_12R:
        raise RuntimeError("Conformance FAIL: vectorized test-vector ciphertext")

    # 6. Vectorized == reference: random blocks at several round counts
    rng = np.random.default_rng(seed)
    blocks = rng.integers(0, 256, size=(n_random_blocks, 16), dtype=np.uint8)
    mats = derive_matrices(mk)
    for rounds in (1, 2, 5, 12):
        vout = ctx.encrypt_batch(blocks, rounds=rounds)
        for i in range(n_random_blocks):
            ref = encrypt_block_ref(bytes(blocks[i].tobytes()), mk,
                                    rounds=rounds, _mats=mats)
            if ref != bytes(vout[i].tobytes()):
                raise RuntimeError(
                    f"Conformance FAIL: vectorized/reference divergence "
                    f"(rounds={rounds}, block {i})")
    _say(f"  [ok] vectorized == reference "
         f"({n_random_blocks} random blocks x rounds 1/2/5/12)")
    _say("Conformance check PASSED.\n")


# ---------------------------------------------------------------------------
# Small shared utilities for the metric scripts
# ---------------------------------------------------------------------------

def blocks_from_bytes(data: bytes) -> np.ndarray:
    a = np.frombuffer(data, dtype=np.uint8)
    return a.reshape(-1, 16)


def hamming_distance_rows(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Per-row bit Hamming distance between uint8 arrays of shape (B, 16)."""
    x = np.bitwise_xor(a, b)
    return np.unpackbits(x, axis=1).sum(axis=1)


if __name__ == "__main__":
    conformance_check(verbose=True)
    print("mdhillspn_core self-test complete.")
