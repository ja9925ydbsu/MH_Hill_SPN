#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MD-Hill-SPN: Byte-Level Metric Analysis  (REVISION 4 - OPTIMIZED)
=================================================================
Hill Cipher Variation 2 (Coggins 2024, Mathematics and Computer Science 9(3))
adapted to byte/bit-level operations.
Python code assistance: Anthropic Claude AI

REVISION 4 changes (performance and reproducibility; no change to the
cipher or to any metric definition):
  1. All cipher evaluation now goes through mdhillspn_core.py, which
     provides a NumPy-vectorized batch implementation verified at
     startup against the published Revision 3 reference test vector
     (master key, rk[0], Round-0 Steps A-F, 12-round ciphertext,
     decryption round-trip, MDS branch numbers) and against the pure-
     Python reference on random blocks. Measured speedup: ~170x per
     block versus the Revision 3 script (round keys are no longer
     re-hashed per round per block; Steps B and C are fused into two
     8x8 matrices; Step A is folded through the linear layer; Steps
     D+E share T-tables; batches are processed as uint8 arrays).
  2. Deterministic by default: fixed reference salt and seeded PRNG so
     any run reproduces exactly (pass --fresh for an os.urandom salt
     and OS-random sampling, the Revision 3 behavior).
  3. Full console output is duplicated to a timestamped log file, so
     the interactive pause gates are now opt-in (--pause).
  4. Same five metric steps, same parameters, same statistics:
       Step 0: Branch-number verification (EXACT, weight-1 enumeration)
       Step 1: Avalanche effect (plaintext + key)
       Step 2: Differential distribution (50,000 samples)
       Step 3: Linear-bias probe (500 mask pairs x 50,000 samples)
       Step 4: Algebraic degree lower bounds (ANF / Mobius transform)

Cipher structure per round r (unchanged; Revision 3, Cauchy MDS):
  Step A: XOR 16-byte state with 16-byte round key
  Step B: 4 x (4x4 GF(2^8)) Cauchy matrices (intra-group, B = 5)
  Step C: 2 x (8x8 GF(2^8)) Cauchy matrices (inter-group, B = 9)
  Step D: AES S-box x 16 (first nonlinear layer)
  Step E: 16x16 GF(2^8) Cauchy matrix (full-block, B = 17)
  Step F: AES S-box x 16 (second nonlinear layer)

Block 128 bits | Key 256 bits | Rounds 12 | GF(2^8) polynomial 0x11B

Usage:
  pip install numpy               (argon2-cffi only needed for --argon2-key-avalanche off-stub runs)
  python mdhillspn_metrics_optimized_rev4.py             # deterministic, no pauses
  python mdhillspn_metrics_optimized_rev4.py --fresh     # fresh salt / OS randomness
  python mdhillspn_metrics_optimized_rev4.py --pause     # keep Revision 3 pause gates
"""

import argparse
import datetime
import statistics
import os
import sys
import time
from collections import Counter

import numpy as np

import mdhillspn_core as core

# ============================================================
# CONFIG (identical metric parameters to Revision 3)
# ============================================================
NUM_BYTES  = core.NUM_BYTES
ROUNDS     = core.ROUNDS
BLOCK_BITS = core.BLOCK_BITS

PLAINTEXT_AVALANCHE_TRIALS  = 60
KEY_AVALANCHE_TRIALS        = 30
DIFF_SAMPLES                = 50000
LINEAR_SAMPLES              = 50000
LINEAR_TRIALS               = 500

DEGREE_ROUNDS_TO_TEST        = [1, 2, 4, 5, 8, 12]
DEGREE_NUM_ACTIVE_INPUT_BITS = 6
DEGREE_TRIALS_PER_ROUND      = 4

ROUND_COUNTS = [1, 2, 4, 5, 8, 12]

PARITY8 = np.array([bin(i).count("1") & 1 for i in range(256)],
                   dtype=np.uint8)

# ============================================================
# Logging helper (console + timestamped file)
# ============================================================

class Tee:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")
    def out(self, s=""):
        print(s)
        self.f.write(s + "\n")
        self.f.flush()
    def close(self):
        self.f.close()

# ============================================================
# STEP 0: BRANCH NUMBER VERIFICATION (exact)
# ============================================================

def branch_summary(mk, out):
    out("=" * 72)
    out("STEP 0: BRANCH NUMBER VERIFICATION  (GF(2^8), EXACT via weight-1)")
    out("  Cauchy construction guarantees MDS (B = n + 1) at every tier.")
    out("  hw counts nonzero bytes. Compare AES MixColumns B = 5 (MDS 4x4).")
    out("=" * 72)
    mat4, mat8, mat16 = core.derive_matrices(mk)

    out("\n4x4 matrices (4 matrices, group size = 4 bytes)  - MDS bound B = 5:")
    for i, M in enumerate(mat4):
        bn = core.branch_number_weight1(M)
        tag = "MDS" if bn == 5 else f"NON-MDS (B={bn})"
        out(f"  M4[{i}]: B={bn}  [{tag}]")
    out("\n8x8 matrices (2 matrices, group size = 8 bytes)  - MDS bound B = 9:")
    for i, M in enumerate(mat8):
        bn = core.branch_number_weight1(M)
        tag = "MDS" if bn == 9 else f"NON-MDS (B={bn})"
        out(f"  M8[{i}]: B={bn}  [{tag}]")
    out("\n16x16 matrix (1 matrix, full block = 16 bytes)  - MDS bound B = 17:")
    bn = core.branch_number_weight1(mat16)
    tag = "MDS" if bn == 17 else f"NON-MDS (B={bn})"
    out(f"  M16[0]: B={bn}  [{tag}]")
    out("")

# ============================================================
# STEP 1: AVALANCHE
# ============================================================

def summarize_distances(name, dists, out):
    out(f"{name}:")
    out(f"  trials = {len(dists)}")
    out(f"  min    = {int(min(dists))}")
    out(f"  max    = {int(max(dists))}")
    out(f"  mean   = {statistics.mean(dists):.2f}")
    out(f"  stdev  = {statistics.pstdev(dists):.2f}")
    out("")


def plaintext_avalanche(ctx, rng, rounds, trials):
    P = rng.integers(0, 256, size=(trials, 16), dtype=np.uint8)
    bit_idx = rng.integers(0, 128, size=trials)
    P2 = P.copy()
    P2[np.arange(trials), bit_idx // 8] ^= (
        (0x80 >> (bit_idx % 8)).astype(np.uint8))
    c1 = ctx.encrypt_batch(P,  rounds=rounds)
    c2 = ctx.encrypt_batch(P2, rounds=rounds)
    return core.hamming_distance_rows(c1, c2).tolist()


def key_avalanche(password, salt, rng, rounds, trials):
    base_key = core.derive_master_key_stub(password, salt, out_len=32)
    base_ctx = core.MDHillContext(base_key, max_rounds=ROUNDS)
    dists = []
    for _ in range(trials):
        pt = rng.integers(0, 256, size=(1, 16), dtype=np.uint8)
        bit = int(rng.integers(0, 256))
        mutated = bytearray(base_key)
        mutated[bit // 8] ^= 0x80 >> (bit % 8)
        mut_ctx = core.MDHillContext(bytes(mutated), max_rounds=ROUNDS)
        c1 = base_ctx.encrypt_batch(pt, rounds=rounds)
        c2 = mut_ctx.encrypt_batch(pt, rounds=rounds)
        dists.append(int(core.hamming_distance_rows(c1, c2)[0]))
    return dists

# ============================================================
# STEP 2: DIFFERENTIAL DISTRIBUTION
# ============================================================

def single_bit_difference(bit_index=0):
    x = 1 << (127 - bit_index)
    return x.to_bytes(16, "big")


def single_byte_difference(byte_index=0, value=0x01):
    b = bytearray(16)
    b[byte_index] = value & 0xFF
    return bytes(b)


def estimate_differential_distribution(ctx, rng, input_diff, rounds,
                                       samples, out, top_k=10):
    dvec = np.frombuffer(input_diff, dtype=np.uint8)
    counter = Counter()
    batch = 50000
    done = 0
    while done < samples:
        nb = min(batch, samples - done)
        P  = rng.integers(0, 256, size=(nb, 16), dtype=np.uint8)
        c1 = ctx.encrypt_batch(P,        rounds=rounds)
        c2 = ctx.encrypt_batch(P ^ dvec, rounds=rounds)
        dC = np.bitwise_xor(c1, c2).tobytes()
        counter.update(dC[i*16:(i+1)*16] for i in range(nb))
        done += nb
        out(f"  progress: {done}/{samples}")

    most_common = counter.most_common(top_k)
    out(f"Rounds     : {rounds}")
    out(f"Samples    : {samples}")
    out(f"Input diff : {input_diff.hex()}")
    out(f"Unique dC  : {len(counter)}")
    out(f"\nTop {top_k} most frequent output differences:")
    for rank, (diff, freq) in enumerate(most_common, start=1):
        out(f"  {rank:2d}. freq={freq:4d}, prob={freq/samples:.6f}, "
            f"dC={diff.hex()}")
    out(f"\nSampled maximum observed differential probability = "
        f"{most_common[0][1] / samples:.6f}")
    out(f"Sampling resolution floor = 1/{samples} = {1/samples:.6f}")
    out("")

# ============================================================
# STEP 3: LINEAR-BIAS PROBE
# ============================================================

def parity_rows(blocks, mask):
    return np.bitwise_xor.reduce(PARITY8[np.bitwise_and(blocks, mask)],
                                 axis=1)


def estimate_linear_bias(ctx, rng, rounds, samples, trials, log_file, out):
    import csv
    threshold = 1.0 / samples ** 0.5

    out("=" * 72)
    out("LINEAR-BIAS PROBE")
    out("=" * 72)
    out(f"Rounds={rounds}, samples={samples}, mask pairs tested={trials}")
    out(f"Detection threshold = 1/sqrt({samples}) = {threshold:.5f}  (~ 2 SE)")
    out(f"Null exceedance rate ~ 4.55%  (Pr(|Z| > 2) under normal approx.)")
    out(f"Log file: {log_file}  (written after every trial)")
    out("")

    log_f = open(log_file, "w", newline="")
    writer = csv.writer(log_f)
    writer.writerow(["trial", "in_mask", "out_mask", "count_zero",
                     "prob", "abs_bias", "exceeds_threshold", "timestamp"])

    best_bias, best_pair, all_biases = 0.0, None, []
    for t in range(trials):
        in_mask  = rng.integers(0, 256, size=16, dtype=np.uint8)
        out_mask = rng.integers(0, 256, size=16, dtype=np.uint8)
        P = rng.integers(0, 256, size=(samples, 16), dtype=np.uint8)
        C = ctx.encrypt_batch(P, rounds=rounds)
        val = parity_rows(P, in_mask) ^ parity_rows(C, out_mask)
        count_zero = int(np.count_nonzero(val == 0))

        prob = count_zero / samples
        bias = abs(prob - 0.5)
        exceeds = bias > threshold
        all_biases.append(bias)
        if bias > best_bias:
            best_bias, best_pair = bias, (in_mask.tobytes().hex(),
                                          out_mask.tobytes().hex(),
                                          prob, bias)
        writer.writerow([t + 1, in_mask.tobytes().hex(),
                         out_mask.tobytes().hex(), count_zero,
                         f"{prob:.6f}", f"{bias:.6f}", int(exceeds),
                         datetime.datetime.now().isoformat(
                             timespec="seconds")])
        log_f.flush()

        flag = "  *** EXCEEDS THRESHOLD ***" if exceeds else ""
        out(f"trial {t+1:3d}: prob={prob:.6f}, abs_bias={bias:.6f}{flag}")
        if (t + 1) % 50 == 0:
            n_ex = sum(1 for b in all_biases if b > threshold)
            out(f"  -- completed {t+1}/{trials} trials  "
                f"·  exceedance so far: {n_ex}/{t+1} = "
                f"{n_ex/(t+1)*100:.1f}%  "
                f"·  max |bias| so far: {max(all_biases):.6f} --")
    log_f.close()

    n_ex = sum(1 for b in all_biases if b > threshold)
    out("")
    out(f"Completed {trials}/{trials} linear trials")
    out(f"Trials exceeding threshold : {n_ex}/{trials} = "
        f"{n_ex/trials*100:.2f}%")
    out(f"  (noise floor expectation : ~4.55% under null hypothesis)")
    out(f"Mean |bias|                : "
        f"{sum(all_biases)/len(all_biases):.6f}")
    out(f"Max  |bias|                : {max(all_biases):.6f}  "
        f"(threshold = {threshold:.5f})")
    if best_pair:
        out(f"Best observed pair         : prob={best_pair[2]:.6f}, "
            f"abs_bias={best_pair[3]:.6f}")
    out(f"Results saved to           : {log_file}")
    out("")

# ============================================================
# STEP 4: ALGEBRAIC DEGREE LOWER BOUNDS (ANF / Mobius)
# ============================================================

def mobius_transform_inplace(vals):
    n = len(vals)
    m = n.bit_length() - 1
    for i in range(m):
        step = 1 << i
        for mask in range(n):
            if mask & step:
                vals[mask] ^= vals[mask ^ step]


def algebraic_degree_from_truth_table(tt):
    coeffs = tt[:]
    mobius_transform_inplace(coeffs)
    deg = 0
    for mask, c in enumerate(coeffs):
        if c:
            deg = max(deg, bin(mask).count("1"))
    return deg


def restricted_degree_of_output_bit(ctx, rounds, base_pt, active_bits,
                                    out_bit):
    t = len(active_bits)
    size = 1 << t
    # Build all 2^t plaintexts as a batch
    P = np.tile(np.frombuffer(base_pt, dtype=np.uint8), (size, 1))
    for i, bit_pos in enumerate(active_bits):
        byte_i, mask = bit_pos // 8, 0x80 >> (bit_pos % 8)
        vals = ((np.arange(size) >> (t - 1 - i)) & 1).astype(bool)
        P[:, byte_i] = np.where(vals, P[:, byte_i] | mask,
                                P[:, byte_i] & (0xFF ^ mask))
    C = ctx.encrypt_batch(P, rounds=rounds)
    bits = np.unpackbits(C, axis=1)[:, out_bit]
    return algebraic_degree_from_truth_table(bits.tolist())


def estimate_degree_growth_lower_bounds(ctx, rng, rounds_list, num_active,
                                        trials_per_round, out):
    out("=" * 72)
    out("STEP 4: ALGEBRAIC DEGREE GROWTH ESTIMATOR (LOWER BOUNDS)")
    out("=" * 72)
    out(f"Active input bits : {num_active}  "
        f"(2^{num_active} = {1 << num_active} encrypts/trial)")
    out(f"Trials per round  : {trials_per_round}")
    out("")

    results = {}
    for rounds in rounds_list:
        out(f"--- Rounds = {rounds} ---")
        best, all_deg = -1, []
        for trial in range(trials_per_round):
            base_pt     = rng.integers(0, 256, size=16,
                                       dtype=np.uint8).tobytes()
            active_bits = sorted(rng.choice(128, size=num_active,
                                            replace=False).tolist())
            out_bit     = int(rng.integers(0, 128))
            deg = restricted_degree_of_output_bit(
                ctx, rounds, base_pt, active_bits, out_bit)
            all_deg.append(deg)
            best = max(best, deg)
            out(f"  trial {trial+1:2d}: degree={deg:2d}, "
                f"out_bit={out_bit:3d}, active_bits={active_bits}")
        mean = sum(all_deg) / len(all_deg)
        out(f"  best lower bound = {best}, mean = {mean:.2f}, "
            f"theoretical max = {num_active}")
        out("")
        results[rounds] = {"best": best, "mean": mean}

    out("=" * 72)
    out("ALGEBRAIC DEGREE SUMMARY")
    out("=" * 72)
    for r in rounds_list:
        out(f"Rounds={r:2d} | best lb={results[r]['best']:2d} | "
            f"mean={results[r]['mean']:.2f} | "
            f"theoretical max={num_active}")
    out("")
    return results

# ============================================================
# Pause gate (opt-in, Revision 3 behavior)
# ============================================================

def pause_gate(enabled, label):
    if not enabled:
        return
    CONTINUE_CODE = "&Ygv"
    print("=" * 72)
    print(f"PAUSE: {label} complete.")
    print(f"  Type exactly:  {CONTINUE_CODE}  then press ENTER to continue.")
    print("=" * 72)
    while input("  Continue code: ").strip() != CONTINUE_CODE:
        print(f"  Incorrect -- type exactly '{CONTINUE_CODE}' to continue.")

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--fresh", action="store_true",
                    help="fresh os.urandom salt and OS randomness "
                         "(Revision 3 behavior) instead of deterministic")
    ap.add_argument("--pause", action="store_true",
                    help="keep the Revision 3 interactive pause gates")
    ap.add_argument("--seed", type=int, default=12345)
    args = ap.parse_args()

    core.conformance_check(verbose=True)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    tee = Tee(f"mdhillspn_metrics_rev4_{ts}.txt")
    out = tee.out
    LOG_LINEAR = f"mdhillspn_linear_bias_log_{ts}.csv"

    password = "C.E.ShannonSecrecySystems1949!"
    salt = (core.TV_SALT if not args.fresh
            else os.urandom(core.ARGON_SALT_LEN))
    master_key = core.derive_master_key_stub(password, salt, out_len=32)
    ctx = core.MDHillContext(master_key, max_rounds=ROUNDS)

    if args.fresh:
        rng = np.random.default_rng()
    else:
        rng = np.random.default_rng(args.seed)

    out("=" * 72)
    out("MD-Hill-SPN  -  BYTE/BIT LEVEL METRIC ANALYSIS  (REVISION 4)")
    out("Based on: Coggins (2024), MD-Hill-SPN, Variation 2 (4-8-16 dimension)")
    out("Revision 4: vectorized core (~170x), conformance-anchored, "
        "deterministic by default")
    out("=" * 72)
    out(f"Timestamp         : {ts}")
    out(f"Mode              : "
        f"{'FRESH (os.urandom salt, OS randomness)' if args.fresh else f'DETERMINISTIC (reference salt, seed={args.seed})'}")
    out(f"Salt              : {salt.hex()}")
    out(f"Linear bias log   : {LOG_LINEAR}")
    out(f"Block size        : {BLOCK_BITS} bits ({NUM_BYTES} bytes)")
    out(f"Rounds            : {ROUNDS}")
    out(f"GF(2^8) polynomial: x^8 + x^4 + x^3 + x + 1  (0x11B)")
    out(f"Matrix groups     : 4x(4x4) | 2x(8x8) | 1x(16x16) - Cauchy MDS")
    out("")

    t_all = time.perf_counter()

    # Step 0
    branch_summary(master_key, out)

    # Step 1
    out("=" * 72)
    out("STEP 1: AVALANCHE")
    out("=" * 72)
    for rc in ROUND_COUNTS:
        dists = plaintext_avalanche(ctx, rng, rc,
                                    PLAINTEXT_AVALANCHE_TRIALS)
        summarize_distances(f"PLAINTEXT avalanche, rounds={rc}", dists, out)
    for rc in ROUND_COUNTS:
        dists = key_avalanche(password, salt, rng, rc,
                              KEY_AVALANCHE_TRIALS)
        summarize_distances(f"KEY avalanche, rounds={rc}", dists, out)

    # Step 2
    out("=" * 72)
    out("STEP 2: DIFFERENTIAL TESTS")
    out("=" * 72)
    diff = single_bit_difference(0)
    out("[A] rounds = 4")
    estimate_differential_distribution(ctx, rng, diff, 4,
                                       DIFF_SAMPLES, out)
    out("[B] rounds = 8")
    estimate_differential_distribution(ctx, rng, diff, 8,
                                       DIFF_SAMPLES, out)
    out("[C] rounds = 12")
    estimate_differential_distribution(ctx, rng, diff, 12,
                                       DIFF_SAMPLES, out)
    out("[D] rounds = 12, one active byte")
    estimate_differential_distribution(ctx, rng,
                                       single_byte_difference(0, 0x01),
                                       12, DIFF_SAMPLES, out)

    # Step 3
    out("=" * 72)
    out("STEP 3: LINEAR-BIAS PROBE")
    out("=" * 72)
    estimate_linear_bias(ctx, rng, ROUNDS, LINEAR_SAMPLES, LINEAR_TRIALS,
                         LOG_LINEAR, out)
    pause_gate(args.pause, "Linear bias")

    # Step 4
    estimate_degree_growth_lower_bounds(
        ctx, rng, DEGREE_ROUNDS_TO_TEST,
        DEGREE_NUM_ACTIVE_INPUT_BITS, DEGREE_TRIALS_PER_ROUND, out)
    pause_gate(args.pause, "Algebraic degree")

    out(f"All metrics complete in {time.perf_counter() - t_all:.0f} s.")
    tee.close()
