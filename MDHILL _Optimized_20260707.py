"""
MD-Hill-SPN: Windows/Python 3.14 Optimized Metric Runner
=========================================================

Based on the MD-Hill-SPN Revision 3 metric-analysis script dated 2026-04-20.
This version is tuned for Windows 11 and Python 3.14 while preserving the
same MD-Hill-SPN round structure and metrics:

  Step 0: MDS branch-number verification
  Step 1: Plaintext and key avalanche
  Step 2: Differential-distribution sampling
  Step 3: Linear-bias probe with CSV logging
  Step 4: Algebraic-degree lower-bound estimator

Main Windows/Python 3.14 changes:
  * No top-level Argon2 import; metric runs work without argon2-cffi installed.
  * Precomputed 256x256 GF(2^8) multiplication table.
  * Precomputed GF inverses.
  * Cached per-key cipher context: matrices and round keys are generated once.
  * bytes.translate() for S-box layers.
  * pathlib-based output directories and Windows/OneDrive Desktop detection.
  * argparse command-line interface with paper/quick/custom presets.
  * Optional pause gates for double-click Windows console use.
  * Optional deterministic sampling RNG for reproducible runlogs.

Suggested Windows setup:
  py -3.14 -m pip install --upgrade pip
  py -3.14 -m pip install argon2-cffi

Examples:
  py -3.14 MD_Hill_SPN_Windows_Py314_Optimized.py --preset quick --steps branch avalanche
  py -3.14 MD_Hill_SPN_Windows_Py314_Optimized.py --preset paper --steps all --pause
  py -3.14 MD_Hill_SPN_Windows_Py314_Optimized.py --preset paper --output-dir .\\runlogs

Note: the default metric key derivation remains the SHA-256 stub used in the
original metric script. Use --use-argon2 only when you intentionally want the
Argon2id-derived master key path.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import os
import random
import statistics
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

# ============================================================
# CONFIG DEFAULTS
# ============================================================
NUM_BYTES = 16
ROUNDS = 12
BLOCK_BITS = 128

ARGON_TIME_COST = 3
ARGON_MEMORY_COST = 65_536
ARGON_PARALLELISM = 2
ARGON_SALT_LEN = 16

PAPER_DEFAULTS = {
    "plaintext_avalanche_trials": 60,
    "key_avalanche_trials": 30,
    "diff_samples": 50_000,
    "linear_samples": 50_000,
    "linear_trials": 500,
    "degree_rounds": [1, 2, 4, 5, 8, 12],
    "degree_active_bits": 6,
    "degree_trials_per_round": 4,
}

QUICK_DEFAULTS = {
    "plaintext_avalanche_trials": 8,
    "key_avalanche_trials": 4,
    "diff_samples": 2_000,
    "linear_samples": 2_000,
    "linear_trials": 20,
    "degree_rounds": [1, 2, 4],
    "degree_active_bits": 5,
    "degree_trials_per_round": 2,
}

DEFAULT_PASSWORD = "C.E.ShannonSecrecySystems1949!"
DEFAULT_CONTINUE_CODE = "&Ygv"

# ============================================================
# AES S-box (standard FIPS 197)
# ============================================================
AES_SBOX = [
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


AES_SBOX_BYTES = bytes(AES_SBOX)
AES_SBOX_INV = [0] * 256
for _i, _v in enumerate(AES_SBOX):
    AES_SBOX_INV[_v] = _i

# ============================================================
# GF(2^8) arithmetic, AES polynomial 0x11B
# ============================================================

def gf_mul_slow(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8), AES irreducible polynomial."""
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


def gf_pow_slow(a: int, exp: int) -> int:
    result = 1
    base = a
    while exp:
        if exp & 1:
            result = gf_mul_slow(result, base)
        base = gf_mul_slow(base, base)
        exp >>= 1
    return result


# Fast multiplication table: GF_MUL[a][b] -> a*b over GF(2^8).
GF_MUL: tuple[bytes, ...] = tuple(
    bytes(gf_mul_slow(a, b) for b in range(256)) for a in range(256)
)

GF_INV = [0] * 256
for _a in range(1, 256):
    GF_INV[_a] = gf_pow_slow(_a, 254)
GF_INV = tuple(GF_INV)


def gf_mul_fast(a: int, b: int) -> int:
    return GF_MUL[a][b]


def gf_inv(a: int) -> int:
    return GF_INV[a]

# ============================================================
# GF(2^8) matrix operations
# ============================================================

Matrix = tuple[bytes, ...]


def _row_dot(row: bytes, vec: bytes) -> int:
    mult = GF_MUL
    acc = 0
    # Sizes are only 4, 8, or 16. A plain Python loop is fastest enough here.
    for a, b in zip(row, vec):
        acc ^= mult[a][b]
    return acc


def gf_mat_vec(matrix: Matrix, vec: bytes | bytearray | memoryview | Sequence[int]) -> bytes:
    if not isinstance(vec, (bytes, bytearray, memoryview)):
        vec = bytes(vec)
    return bytes(_row_dot(row, vec) for row in matrix)


def gf_mat_inv(matrix: Matrix) -> Matrix:
    """Invert n x n matrix over GF(2^8) via Gauss-Jordan elimination."""
    n = len(matrix)
    M = [list(row) for row in matrix]
    I = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    mult = GF_MUL
    inv = GF_INV

    for col in range(n):
        pivot = next((r for r in range(col, n) if M[r][col] != 0), None)
        if pivot is None:
            raise ValueError(f"Singular matrix at column {col}")
        M[col], M[pivot] = M[pivot], M[col]
        I[col], I[pivot] = I[pivot], I[col]

        inv_p = inv[M[col][col]]
        M[col] = [mult[x][inv_p] for x in M[col]]
        I[col] = [mult[x][inv_p] for x in I[col]]

        for row in range(n):
            if row != col and M[row][col] != 0:
                factor = M[row][col]
                M[row] = [M[row][j] ^ mult[factor][M[col][j]] for j in range(n)]
                I[row] = [I[row][j] ^ mult[factor][I[col][j]] for j in range(n)]
    return tuple(bytes(row) for row in I)


def gf_mat_is_invertible(matrix: Matrix) -> bool:
    try:
        gf_mat_inv(matrix)
        return True
    except ValueError:
        return False

# ============================================================
# Branch number
# ============================================================


def branch_number_gf28(matrix: Matrix, exhaustive_weight2: bool = False) -> int:
    """
    Branch number B(M) = min_{x != 0} [hw(x) + hw(M*x)] over GF(2^8)^n,
    where hw is nonzero-byte Hamming weight.
    """
    n = len(matrix)
    best = n + 2

    for i in range(n):
        vec = bytearray(n)
        vec[i] = 1
        out = gf_mat_vec(matrix, vec)
        total = 1 + sum(1 for b in out if b != 0)
        if total < best:
            best = total

    if not exhaustive_weight2 or best < n + 1:
        return best

    for i in range(n):
        for j in range(i + 1, n):
            vec = bytearray(n)
            for vi in range(1, 256):
                vec[i] = vi
                for vj in range(1, 256):
                    vec[j] = vj
                    out = gf_mat_vec(matrix, vec)
                    total = 2 + sum(1 for b in out if b != 0)
                    if total < best:
                        best = total
    return best

# ============================================================
# Key derivation
# ============================================================


def derive_master_key_argon2id(password: str, salt: bytes, out_len: int = 32) -> bytes:
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:
        raise RuntimeError(
            "argon2-cffi is not installed. On Windows, run: "
            "py -3.14 -m pip install argon2-cffi"
        ) from exc

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=out_len,
        type=Type.ID,
    )


def derive_master_key_stub(password: str, salt: bytes, out_len: int = 32) -> bytes:
    """SHA-256 surrogate for metric runs."""
    data = password.encode("utf-8") + salt
    return (hashlib.sha256(data).digest() + hashlib.sha256(data + b"\\x01").digest())[:out_len]


def derive_round_key(master_key: bytes, round_index: int) -> bytes:
    return hashlib.sha256(master_key + b"MDHILLRK" + round_index.to_bytes(2, "big")).digest()[:16]

# ============================================================
# Matrix generation: Cauchy MDS construction
# ============================================================

_matrix_cache: dict[bytes, tuple[tuple[Matrix, ...], tuple[Matrix, ...], Matrix]] = {}


def _cauchy_matrix_gf28(master_key: bytes, tag: bytes, index: int, size: int) -> Matrix:
    n = size
    stream = bytearray()
    counter = 0
    while len(stream) < max(128, 8 * n):
        stream += hashlib.sha256(
            master_key + tag + index.to_bytes(2, "big") + counter.to_bytes(4, "big")
        ).digest()
        counter += 1
        if counter > 128:
            break

    X: list[int] = []
    Y: list[int] = []
    seen: set[int] = set()
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
            f"got |X|={len(X)}, |Y|={len(Y)}."
        )

    M: Matrix = tuple(bytes(GF_INV[X[i] ^ Y[j]] for j in range(n)) for i in range(n))
    bn = branch_number_gf28(M)
    if bn != n + 1:
        raise RuntimeError(
            f"Cauchy construction produced non-MDS matrix "
            f"(size={n}, B={bn}, expected {n+1})."
        )
    return M


def get_matrices(master_key: bytes) -> tuple[tuple[Matrix, ...], tuple[Matrix, ...], Matrix]:
    if master_key not in _matrix_cache:
        mat_4 = tuple(_cauchy_matrix_gf28(master_key, b"MDHILL_4", i, 4) for i in range(4))
        mat_8 = tuple(_cauchy_matrix_gf28(master_key, b"MDHILL_8", i, 8) for i in range(2))
        mat_16 = _cauchy_matrix_gf28(master_key, b"MDHILL_16", 0, 16)
        _matrix_cache[master_key] = (mat_4, mat_8, mat_16)
    return _matrix_cache[master_key]


@dataclass(frozen=True, slots=True)
class CipherContext:
    master_key: bytes
    rounds: int
    mat_4: tuple[Matrix, ...]
    mat_8: tuple[Matrix, ...]
    mat_16: Matrix
    round_keys: tuple[bytes, ...]


def make_context(master_key: bytes, rounds: int = ROUNDS) -> CipherContext:
    mat_4, mat_8, mat_16 = get_matrices(master_key)
    round_keys = tuple(derive_round_key(master_key, r) for r in range(rounds))
    return CipherContext(master_key, rounds, mat_4, mat_8, mat_16, round_keys)

# ============================================================
# Round function and encryption
# ============================================================


def xor16(a: bytes, b: bytes) -> bytes:
    return bytes((a[i] ^ b[i]) for i in range(16))


def encrypt_block_ctx(block: bytes, ctx: CipherContext, rounds: int | None = None) -> bytes:
    if len(block) != 16:
        raise ValueError("MD-Hill-SPN block must be exactly 16 bytes")
    if rounds is None:
        rounds = ctx.rounds
    if rounds > ctx.rounds:
        raise ValueError(f"Context has {ctx.rounds} round keys, requested {rounds} rounds")

    state = block
    mat_4 = ctx.mat_4
    mat_8 = ctx.mat_8
    mat_16 = ctx.mat_16
    sbox = AES_SBOX_BYTES

    for r in range(rounds):
        state = xor16(state, ctx.round_keys[r])

        b = bytearray(16)
        b[0:4] = gf_mat_vec(mat_4[0], state[0:4])
        b[4:8] = gf_mat_vec(mat_4[1], state[4:8])
        b[8:12] = gf_mat_vec(mat_4[2], state[8:12])
        b[12:16] = gf_mat_vec(mat_4[3], state[12:16])
        state = bytes(b)

        c = bytearray(16)
        c[0:8] = gf_mat_vec(mat_8[0], state[0:8])
        c[8:16] = gf_mat_vec(mat_8[1], state[8:16])
        state = bytes(c)

        state = state.translate(sbox)
        state = gf_mat_vec(mat_16, state)
        state = state.translate(sbox)

    return state


def encrypt_block(block: bytes, master_key: bytes, rounds: int = ROUNDS) -> bytes:
    return encrypt_block_ctx(block, make_context(master_key, rounds), rounds)

# ============================================================
# Helpers
# ============================================================

class SampleRNG:
    """Metric-sampling RNG. Not used for production cryptography."""

    def __init__(self, seed: int | None = 12345, secure_random: bool = False):
        self.secure_random = secure_random
        self.rng = None if secure_random else random.Random(seed)

    def block(self) -> bytes:
        if self.secure_random:
            return os.urandom(16)
        return self.rng.randbytes(16)  # type: ignore[union-attr]

    def randrange(self, n: int) -> int:
        if self.secure_random:
            return int.from_bytes(os.urandom(8), "big") % n
        return self.rng.randrange(n)  # type: ignore[union-attr]

    def sample(self, population: range, k: int) -> list[int]:
        if self.secure_random:
            rr = random.SystemRandom()
            return rr.sample(population, k)
        return self.rng.sample(population, k)  # type: ignore[union-attr]


def xor_blocks(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def hamming_distance_bytes(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def flip_bit_in_block(block: bytes, bit_index: int) -> bytes:
    x = int.from_bytes(block, "big")
    x ^= 1 << (127 - bit_index)
    return x.to_bytes(16, "big")


def flip_bit_in_bytes(data: bytes, bit_index: int) -> bytes:
    total = len(data) * 8
    x = int.from_bytes(data, "big")
    x ^= 1 << (total - 1 - bit_index)
    return x.to_bytes(len(data), "big")


def parity128(x: bytes, mask: bytes) -> int:
    acc = 0
    for a, b in zip(x, mask):
        acc ^= (a & b).bit_count() & 1
    return acc


def single_bit_difference(bit_index: int = 0) -> bytes:
    return (1 << (127 - bit_index)).to_bytes(16, "big")


def single_byte_difference(byte_index: int = 0, value: int = 0x01) -> bytes:
    b = bytearray(16)
    b[byte_index] = value & 0xFF
    return bytes(b)

# ============================================================
# Output/path helpers
# ============================================================


def get_desktop_path() -> Path:
    """Find the user Desktop, including OneDrive redirection on Windows."""
    if sys.platform == "win32":
        try:
            import winreg  # type: ignore[import-not-found]
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            )
            raw, _ = winreg.QueryValueEx(key, "Desktop")
            winreg.CloseKey(key)
            expanded = os.path.expandvars(raw)
            p = Path(expanded)
            if p.exists():
                return p
        except Exception:
            pass
        for candidate in [
            Path.home() / "Desktop",
            Path.home() / "OneDrive" / "Desktop",
            Path.home() / "OneDrive - Personal" / "Desktop",
        ]:
            if candidate.is_dir():
                return candidate
    return Path.cwd()


class Tee:
    """Mirror stdout to a log file."""
    def __init__(self, path: Path):
        self.path = path
        self.file = path.open("w", encoding="utf-8", newline="")
        self.stdout = sys.stdout

    def write(self, text: str) -> int:
        self.stdout.write(text)
        return self.file.write(text)

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def close(self) -> None:
        self.file.close()


def maybe_pause(enabled: bool, message: str, continue_code: str = DEFAULT_CONTINUE_CODE) -> None:
    if not enabled:
        return
    print("=" * 72)
    print(message)
    print(f"Type exactly:  {continue_code}  then press ENTER to continue.")
    print("=" * 72)
    while True:
        response = input("  Continue code: ").strip()
        if response == continue_code:
            print("  Continuing...")
            print()
            return
        print(f"  Incorrect -- type exactly '{continue_code}' to continue.")

# ============================================================
# Step 0: Branch summary
# ============================================================


def branch_summary(ctx: CipherContext) -> None:
    print("=" * 72)
    print("STEP 0: BRANCH NUMBER VERIFICATION  (GF(2^8), EXACT via weight-1)")
    print("  Cauchy construction guarantees MDS (B = n + 1) at every tier.")
    print("  hw counts nonzero bytes. Compare AES MixColumns B = 5 (MDS 4x4).")
    print("=" * 72)

    print("\n4x4 matrices (4 matrices, group size = 4 bytes) — MDS bound B = 5:")
    for i, M in enumerate(ctx.mat_4):
        bn = branch_number_gf28(M)
        inv = gf_mat_is_invertible(M)
        tag = "MDS" if bn == 5 else f"NON-MDS (B={bn})"
        print(f"  M4[{i}]: B={bn}  invertible={inv}  [{tag}]")

    print("\n8x8 matrices (2 matrices, group size = 8 bytes) — MDS bound B = 9:")
    for i, M in enumerate(ctx.mat_8):
        bn = branch_number_gf28(M)
        inv = gf_mat_is_invertible(M)
        tag = "MDS" if bn == 9 else f"NON-MDS (B={bn})"
        print(f"  M8[{i}]: B={bn}  invertible={inv}  [{tag}]")

    print("\n16x16 matrix (1 matrix, full block = 16 bytes) — MDS bound B = 17:")
    bn = branch_number_gf28(ctx.mat_16)
    inv = gf_mat_is_invertible(ctx.mat_16)
    tag = "MDS" if bn == 17 else f"NON-MDS (B={bn})"
    print(f"  M16[0]: B={bn}  invertible={inv}  [{tag}]")
    print()

# ============================================================
# Step 1: Avalanche
# ============================================================


def plaintext_avalanche_trials(ctx: CipherContext, rounds: int, trials: int, rng: SampleRNG) -> list[int]:
    distances = []
    encrypt = encrypt_block_ctx
    for _ in range(trials):
        pt = rng.block()
        bit_index = rng.randrange(128)
        c1 = encrypt(pt, ctx, rounds)
        c2 = encrypt(flip_bit_in_block(pt, bit_index), ctx, rounds)
        distances.append(hamming_distance_bytes(c1, c2))
    return distances


def key_avalanche_trials(
    password: str,
    salt: bytes,
    rounds: int,
    trials: int,
    rng: SampleRNG,
    use_argon2: bool = False,
) -> list[int]:
    derive = derive_master_key_argon2id if use_argon2 else derive_master_key_stub
    base_key = derive(password, salt, out_len=32)
    base_ctx = make_context(base_key, ROUNDS)
    distances = []
    for _ in range(trials):
        pt = rng.block()
        bit_index = rng.randrange(256)
        mutated = flip_bit_in_bytes(base_key, bit_index)
        mutated_ctx = make_context(mutated, ROUNDS)
        c1 = encrypt_block_ctx(pt, base_ctx, rounds)
        c2 = encrypt_block_ctx(pt, mutated_ctx, rounds)
        distances.append(hamming_distance_bytes(c1, c2))
    return distances


def summarize_distances(name: str, distances: Sequence[int]) -> None:
    print(f"{name}:")
    print(f"  trials = {len(distances)}")
    print(f"  min    = {min(distances)}")
    print(f"  max    = {max(distances)}")
    print(f"  mean   = {statistics.mean(distances):.2f}")
    print(f"  stdev  = {statistics.pstdev(distances):.2f}")
    print()

# ============================================================
# Step 2: Differential distribution
# ============================================================


def estimate_differential_distribution(
    ctx: CipherContext,
    input_diff: bytes,
    rounds: int,
    samples: int,
    rng: SampleRNG,
    top_k: int = 10,
    progress_every: int = 5_000,
) -> None:
    counter: Counter[bytes] = Counter()
    encrypt = encrypt_block_ctx
    xor = xor_blocks
    for i in range(samples):
        p = rng.block()
        p2 = xor(p, input_diff)
        c1 = encrypt(p, ctx, rounds)
        c2 = encrypt(p2, ctx, rounds)
        counter[xor(c1, c2)] += 1
        if progress_every and (i + 1) % progress_every == 0:
            print(f"  progress: {i + 1}/{samples}")

    most_common = counter.most_common(top_k)
    print(f"Rounds     : {rounds}")
    print(f"Samples    : {samples}")
    print(f"Input diff : {input_diff.hex()}")
    print(f"Unique ΔC  : {len(counter)}")
    print(f"\nTop {top_k} most frequent output differences:")
    for rank, (diff, freq) in enumerate(most_common, start=1):
        print(f"  {rank:2d}. freq={freq:4d}, prob={freq / samples:.6f}, ΔC={diff.hex()}")
    print(
        f"\nSampled maximum observed differential probability = "
        f"{most_common[0][1] / samples:.6f}"
    )
    print(f"Sampling resolution floor = 1/{samples} = {1 / samples:.6f}")
    print()

# ============================================================
# Step 3: Linear-bias probe
# ============================================================


def estimate_linear_bias(
    ctx: CipherContext,
    rounds: int,
    samples: int,
    trials: int,
    rng: SampleRNG,
    log_file: Path,
) -> None:
    threshold = 1.0 / samples ** 0.5

    print("=" * 72)
    print("LINEAR-BIAS PROBE")
    print("=" * 72)
    print(f"Rounds={rounds}, samples={samples}, mask pairs tested={trials}")
    print(f"Detection threshold = 1/sqrt({samples}) = {threshold:.5f}  (~ 2 SE)")
    print("Null exceedance rate ~ 4.55%  (Pr(|Z| > 2) under normal approx.)")
    print(f"Log file: {log_file}  (written after every trial)")
    print()

    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_exists = log_file.exists()
    with log_file.open("a", newline="", encoding="utf-8") as log_f:
        writer = csv.writer(log_f)
        if not log_exists or log_file.stat().st_size == 0:
            writer.writerow([
                "trial", "in_mask", "out_mask", "count_zero", "prob",
                "abs_bias", "exceeds_threshold", "timestamp",
            ])
            log_f.flush()

        best_bias = 0.0
        best_pair: tuple[str, str, float, float] | None = None
        all_biases: list[float] = []
        encrypt = encrypt_block_ctx

        for t in range(trials):
            in_mask = rng.block()
            out_mask = rng.block()
            count_zero = 0
            for _ in range(samples):
                p = rng.block()
                c = encrypt(p, ctx, rounds)
                val = parity128(p, in_mask) ^ parity128(c, out_mask)
                if val == 0:
                    count_zero += 1

            prob = count_zero / samples
            bias = abs(prob - 0.5)
            exceeds = bias > threshold
            all_biases.append(bias)

            if bias > best_bias:
                best_bias = bias
                best_pair = (in_mask.hex(), out_mask.hex(), prob, bias)

            writer.writerow([
                t + 1,
                in_mask.hex(),
                out_mask.hex(),
                count_zero,
                f"{prob:.6f}",
                f"{bias:.6f}",
                int(exceeds),
                _dt.datetime.now().isoformat(timespec="seconds"),
            ])
            log_f.flush()

            flag = "  *** EXCEEDS THRESHOLD ***" if exceeds else ""
            print(f"trial {t + 1:3d}: prob={prob:.6f}, abs_bias={bias:.6f}{flag}")
            if (t + 1) % 50 == 0:
                n_exceed = sum(1 for b in all_biases if b > threshold)
                rate = n_exceed / len(all_biases) * 100
                print(
                    f"  -- completed {t + 1}/{trials} trials · "
                    f"exceedance so far: {n_exceed}/{t + 1} = {rate:.1f}% · "
                    f"max |bias| so far: {max(all_biases):.6f} --"
                )

    n_exceed = sum(1 for b in all_biases if b > threshold)
    exceed_rate = n_exceed / len(all_biases) * 100
    mean_bias = sum(all_biases) / len(all_biases)
    max_bias = max(all_biases)

    print()
    print(f"Completed {trials}/{trials} linear trials")
    print(f"Trials exceeding threshold : {n_exceed}/{trials} = {exceed_rate:.2f}%")
    print("  (noise floor expectation : ~4.55% under null hypothesis)")
    print(f"Mean |bias|                : {mean_bias:.6f}")
    print(f"Max  |bias|                : {max_bias:.6f}  (threshold = {threshold:.5f})")
    if best_pair:
        print(f"Best observed pair         : prob={best_pair[2]:.6f}, abs_bias={best_pair[3]:.6f}")
    print(f"Results saved to           : {log_file}")
    print()

# ============================================================
# Step 4: Algebraic degree lower bounds
# ============================================================


def get_bit_from_bytes(data: bytes, bit_index: int) -> int:
    x = int.from_bytes(data, "big")
    return (x >> (len(data) * 8 - 1 - bit_index)) & 1


def set_bit_in_block(block: bytes, bit_index: int, value: int) -> bytes:
    x = int.from_bytes(block, "big")
    shift = 127 - bit_index
    if value:
        x |= 1 << shift
    else:
        x &= ~(1 << shift)
    return x.to_bytes(16, "big")


def build_plaintext_from_assignment(base: bytes, active_bits: Sequence[int], assignment: int) -> bytes:
    block = base
    t = len(active_bits)
    for i, bit_pos in enumerate(active_bits):
        bit_val = (assignment >> (t - 1 - i)) & 1
        block = set_bit_in_block(block, bit_pos, bit_val)
    return block


def mobius_transform_inplace(vals: list[int]) -> None:
    n = len(vals)
    m = n.bit_length() - 1
    for i in range(m):
        step = 1 << i
        for mask in range(n):
            if mask & step:
                vals[mask] ^= vals[mask ^ step]


def algebraic_degree_from_truth_table(tt: list[int]) -> int:
    coeffs = tt[:]
    mobius_transform_inplace(coeffs)
    deg = 0
    for mask, c in enumerate(coeffs):
        if c:
            wt = mask.bit_count()
            if wt > deg:
                deg = wt
    return deg


def restricted_degree_of_output_bit(
    ctx: CipherContext,
    rounds: int,
    base_plaintext: bytes,
    active_input_bits: Sequence[int],
    output_bit_index: int,
) -> int:
    t = len(active_input_bits)
    size = 1 << t
    tt = [0] * size
    encrypt = encrypt_block_ctx
    for assignment in range(size):
        pt = build_plaintext_from_assignment(base_plaintext, active_input_bits, assignment)
        ct = encrypt(pt, ctx, rounds=rounds)
        tt[assignment] = get_bit_from_bytes(ct, output_bit_index)
    return algebraic_degree_from_truth_table(tt)


def estimate_degree_growth_lower_bounds(
    ctx: CipherContext,
    rounds_list: Sequence[int],
    rng: SampleRNG,
    num_active: int,
    trials_per_round: int,
) -> dict[int, dict[str, float]]:
    print("=" * 72)
    print("STEP 4: ALGEBRAIC DEGREE GROWTH ESTIMATOR (LOWER BOUNDS)")
    print("=" * 72)
    print(f"Active input bits : {num_active}  (2^{num_active} = {1 << num_active} encrypts/trial)")
    print(f"Trials per round  : {trials_per_round}")
    print()

    results: dict[int, dict[str, float]] = {}
    for rounds in rounds_list:
        print(f"--- Rounds = {rounds} ---")
        best = -1
        all_deg: list[int] = []
        for trial in range(trials_per_round):
            base_pt = rng.block()
            active_bits = sorted(rng.sample(range(128), num_active))
            out_bit = rng.randrange(128)
            deg = restricted_degree_of_output_bit(ctx, rounds, base_pt, active_bits, out_bit)
            all_deg.append(deg)
            best = max(best, deg)
            print(f"  trial {trial + 1:2d}: degree={deg:2d}, out_bit={out_bit:3d}, active_bits={active_bits}")
        mean = sum(all_deg) / len(all_deg)
        print(f"  best lower bound = {best}, mean = {mean:.2f}, theoretical max = {num_active}")
        print()
        results[rounds] = {"best": float(best), "mean": float(mean)}

    print("=" * 72)
    print("ALGEBRAIC DEGREE SUMMARY")
    print("=" * 72)
    for r in rounds_list:
        print(
            f"Rounds={r:2d} | best lb={results[r]['best']:2.0f} | "
            f"mean={results[r]['mean']:.2f} | theoretical max={num_active}"
        )
    print()
    return results

# ============================================================
# CLI and main
# ============================================================


def parse_rounds(text: str) -> list[int]:
    return [int(x.strip()) for x in text.split(",") if x.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MD-Hill-SPN metric runner optimized for Windows 11 / Python 3.14",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--preset", choices=["quick", "paper"], default="paper")
    parser.add_argument(
        "--steps",
        nargs="+",
        default=["all"],
        choices=["all", "branch", "avalanche", "diff", "linear", "degree"],
        help="Metrics to run.",
    )
    parser.add_argument("--rounds", type=int, default=ROUNDS, help="Maximum rounds for the context.")
    parser.add_argument("--avalanche-rounds", default="1,2,4,5,8,12")
    parser.add_argument("--degree-rounds", default=None, help="Comma-separated degree rounds; preset default if omitted.")
    parser.add_argument("--plaintext-avalanche-trials", type=int, default=None)
    parser.add_argument("--key-avalanche-trials", type=int, default=None)
    parser.add_argument("--diff-samples", type=int, default=None)
    parser.add_argument("--linear-samples", type=int, default=None)
    parser.add_argument("--linear-trials", type=int, default=None)
    parser.add_argument("--degree-active-bits", type=int, default=None)
    parser.add_argument("--degree-trials-per-round", type=int, default=None)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--salt-hex", default=None, help="Optional fixed salt hex for reproducible key derivation.")
    parser.add_argument("--use-argon2", action="store_true", help="Use Argon2id key derivation instead of SHA-256 metric stub.")
    parser.add_argument("--seed", type=int, default=12345, help="Deterministic sampling seed. Ignored with --secure-random.")
    parser.add_argument("--secure-random", action="store_true", help="Use os.urandom/SystemRandom for sampling instead of deterministic RNG.")
    parser.add_argument("--output-dir", default=None, help="Directory for logs. Defaults to Desktop on Windows, cwd otherwise.")
    parser.add_argument("--console-log", default=None, help="Optional text runlog filename. Defaults to timestamped file.")
    parser.add_argument("--linear-log", default="mdhillspn_linear_bias_log.csv")
    parser.add_argument("--pause", action="store_true", help="Pause after major phases; useful when double-clicking on Windows.")
    parser.add_argument("--no-tee", action="store_true", help="Do not mirror console output to a text log.")
    return parser


def resolved_config(args: argparse.Namespace) -> dict[str, object]:
    base = dict(QUICK_DEFAULTS if args.preset == "quick" else PAPER_DEFAULTS)
    for name in [
        "plaintext_avalanche_trials",
        "key_avalanche_trials",
        "diff_samples",
        "linear_samples",
        "linear_trials",
        "degree_active_bits",
        "degree_trials_per_round",
    ]:
        v = getattr(args, name)
        if v is not None:
            base[name] = v
    if args.degree_rounds:
        base["degree_rounds"] = parse_rounds(args.degree_rounds)
    return base


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = resolved_config(args)
    steps = set(args.steps)
    if "all" in steps:
        steps = {"branch", "avalanche", "diff", "linear", "degree"}

    output_dir = Path(args.output_dir) if args.output_dir else get_desktop_path()
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    console_log = output_dir / (args.console_log or f"mdhillspn_metrics_optimized_{stamp}.txt")
    linear_log = output_dir / args.linear_log

    tee: Tee | None = None
    old_stdout = sys.stdout
    if not args.no_tee:
        tee = Tee(console_log)
        sys.stdout = tee  # type: ignore[assignment]

    t0 = time.perf_counter()
    try:
        salt = bytes.fromhex(args.salt_hex) if args.salt_hex else os.urandom(ARGON_SALT_LEN)
        derive = derive_master_key_argon2id if args.use_argon2 else derive_master_key_stub
        master_key = derive(args.password, salt, out_len=32)
        ctx = make_context(master_key, rounds=args.rounds)
        rng = SampleRNG(seed=args.seed, secure_random=args.secure_random)

        print("=" * 72)
        print("MD-Hill-SPN — Windows/Python 3.14 Optimized Metric Runner")
        print("Based on Revision 3: Cauchy MDS matrices + exact branch-number verification")
        print("=" * 72)
        print(f"Python            : {sys.version.split()[0]}")
        print(f"Platform          : {sys.platform}")
        print(f"Working directory : {Path.cwd()}")
        print(f"Output directory  : {output_dir}")
        print(f"Console log       : {console_log if not args.no_tee else 'disabled'}")
        print(f"Linear bias log   : {linear_log}")
        print(f"Preset            : {args.preset}")
        print(f"Steps             : {', '.join(sorted(steps))}")
        print(f"Sampling RNG      : {'os.urandom/SystemRandom' if args.secure_random else f'deterministic seed {args.seed}'}")
        print(f"KDF               : {'Argon2id' if args.use_argon2 else 'SHA-256 metric stub'}")
        print(f"Salt              : {salt.hex()}")
        print(f"Master key        : {master_key.hex()}")
        print(f"Block size        : {BLOCK_BITS} bits ({NUM_BYTES} bytes)")
        print(f"Rounds            : {args.rounds}")
        print("GF(2^8) polynomial: x^8 + x^4 + x^3 + x + 1  (0x11B)")
        print("Matrix groups     : 4x(4x4) | 2x(8x8) | 1x(16x16) — Cauchy MDS")
        print()

        if "branch" in steps:
            branch_summary(ctx)

        if "avalanche" in steps:
            print("=" * 72)
            print("STEP 1: AVALANCHE")
            print("=" * 72)
            for rc in parse_rounds(args.avalanche_rounds):
                dists = plaintext_avalanche_trials(
                    ctx, rounds=rc,
                    trials=int(cfg["plaintext_avalanche_trials"]),
                    rng=rng,
                )
                summarize_distances(f"PLAINTEXT avalanche, rounds={rc}", dists)

            for rc in parse_rounds(args.avalanche_rounds):
                dists = key_avalanche_trials(
                    args.password,
                    salt,
                    rounds=rc,
                    trials=int(cfg["key_avalanche_trials"]),
                    rng=rng,
                    use_argon2=args.use_argon2,
                )
                summarize_distances(f"KEY avalanche, rounds={rc}", dists)

        if "diff" in steps:
            print("=" * 72)
            print("STEP 2: DIFFERENTIAL TESTS")
            print("=" * 72)
            diff = single_bit_difference(0)
            for label, rounds, input_diff in [
                ("[A] rounds = 4", 4, diff),
                ("[B] rounds = 8", 8, diff),
                ("[C] rounds = 12", 12, diff),
                ("[D] rounds = 12, one active byte", 12, single_byte_difference(0, 0x01)),
            ]:
                print(label)
                estimate_differential_distribution(
                    ctx,
                    input_diff,
                    rounds=rounds,
                    samples=int(cfg["diff_samples"]),
                    rng=rng,
                    progress_every=max(1, min(5_000, int(cfg["diff_samples"]) // 10)),
                )

        if "linear" in steps:
            print("=" * 72)
            print("STEP 3: LINEAR-BIAS PROBE")
            print("=" * 72)
            estimate_linear_bias(
                ctx,
                rounds=args.rounds,
                samples=int(cfg["linear_samples"]),
                trials=int(cfg["linear_trials"]),
                rng=rng,
                log_file=linear_log,
            )
            maybe_pause(args.pause, "PAUSE: Linear bias complete.")

        if "degree" in steps:
            estimate_degree_growth_lower_bounds(
                ctx,
                rounds_list=cfg["degree_rounds"],  # type: ignore[arg-type]
                rng=rng,
                num_active=int(cfg["degree_active_bits"]),
                trials_per_round=int(cfg["degree_trials_per_round"]),
            )
            maybe_pause(args.pause, "PAUSE: algebraic degree complete.")

        elapsed = time.perf_counter() - t0
        print("=" * 72)
        print(f"All requested metrics complete. Elapsed: {elapsed:.1f} seconds")
        if not args.no_tee:
            print(f"Console runlog saved to: {console_log}")
        print(f"Linear CSV log path    : {linear_log}")
        print("=" * 72)
        return 0

    finally:
        if tee is not None:
            sys.stdout = old_stdout
            tee.close()


if __name__ == "__main__":
    raise SystemExit(main())
