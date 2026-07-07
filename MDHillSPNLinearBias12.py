#!/usr/bin/env python3
# ============================================================
# MDHillSPNLinearBias12.py
#
# MD-Hill-SPN linear-bias probe, 12-round final parameterization
# (Revision 3, Cauchy MDS matrices), Argon2id production key
# derivation.
#
# Purpose: fully logged, per-session linear-bias runs for the
# MD-Hill-SPN manuscript, structurally parallel to
# HESPNv4LinearBias16.py. Each invocation is one independent
# session: it generates a fresh password and a fresh 16-byte
# salt via os.urandom, derives the master key with Argon2id
# (t=3, m=65536 KiB, p=2, l=32), runs the probe, and writes a
# timestamped log (.txt) plus per-trial data (.csv) so the
# session parameters are durably recorded. Run the script twice
# for two independent sessions (Run 1 and Run 2) with distinct
# passwords and salts.
#
# Statistics: for each of --trials random (input mask, output
# mask) pairs, estimate over --samples random plaintexts
#   p_hat = Pr[ <a,P> XOR <b,C> = 0 ],   bias = |p_hat - 1/2|.
# Under the null (zero true bias) the standard error is
# SE = 1/(2 sqrt(N)); the reporting threshold 1/sqrt(N) = 2 SE,
# so ~4.55% of null trials exceed it (Pr(|Z| > 2)). The summary
# reports the exceedance rate, mean/max |bias|, and max |z|.
#
# CONFORMANCE: verifies mdhillspn_core against the published
# Revision 3 test vector at startup (master key, rk[0], Round-0
# Steps A-F, 12-round ciphertext, decryption round-trip, MDS
# branch numbers, reference-vs-vectorized equivalence). Refuses
# to run on any mismatch.
#
# Usage:
#   pip install argon2-cffi numpy
#   python MDHillSPNLinearBias12.py                    # one session, paper defaults
#   python MDHillSPNLinearBias12.py --trials 500 --samples 50000 --rounds 12
#   python MDHillSPNLinearBias12.py --stub             # deterministic stub key
# ============================================================

import argparse
import csv
import datetime
import os
import platform
import sys
import time

import numpy as np

import mdhillspn_core as core

# byte -> parity(popcount) lookup
PARITY8 = np.array([bin(i).count("1") & 1 for i in range(256)],
                   dtype=np.uint8)


def parity_rows(blocks: np.ndarray, mask: np.ndarray) -> np.ndarray:
    """Parity of <mask, row> over GF(2) for each row of (B, 16) uint8."""
    x = np.bitwise_and(blocks, mask)
    p = PARITY8[x]
    return np.bitwise_xor.reduce(p, axis=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials",  type=int, default=500)
    ap.add_argument("--samples", type=int, default=50000)
    ap.add_argument("--rounds",  type=int, default=12)
    ap.add_argument("--stub", action="store_true",
                    help="deterministic SHA-256 stub key (reference "
                         "password/salt) instead of a fresh Argon2id session")
    args = ap.parse_args()

    core.conformance_check(verbose=True)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = f"mdhill_linear_r{args.rounds}_{ts}.txt"
    csv_path = f"mdhill_linear_r{args.rounds}_{ts}.csv"
    log = open(log_path, "w", encoding="utf-8")

    def out(s=""):
        print(s)
        log.write(s + "\n")
        log.flush()

    if args.stub:
        mk = core.derive_master_key_stub(core.TV_PASSWORD, core.TV_SALT)
        key_desc = ("deterministic SHA-256 stub key "
                    "(reference test-vector password/salt)")
    else:
        password = os.urandom(24).hex()
        salt     = os.urandom(core.ARGON_SALT_LEN)
        mk = core.derive_master_key_argon2id(password, salt)
        key_desc = (f"Argon2id (t={core.ARGON_TIME_COST}, "
                    f"m={core.ARGON_MEMORY_COST} KiB, "
                    f"p={core.ARGON_PARALLELISM}, l=32)\n"
                    f"password  : {password}\n"
                    f"salt      : {salt.hex()}")

    ctx = core.MDHillContext(mk, max_rounds=args.rounds)
    threshold = 1.0 / args.samples ** 0.5
    se        = 0.5 / args.samples ** 0.5

    out("=" * 72)
    out("MD-Hill-SPN LINEAR-BIAS PROBE  (Revision 3, Cauchy MDS)")
    out("=" * 72)
    out(f"Timestamp  : {ts}")
    out(f"Platform   : {platform.platform()}  Python {platform.python_version()}")
    out(f"Rounds     : {args.rounds}")
    out(f"Trials     : {args.trials} random mask pairs")
    out(f"Samples    : {args.samples} plaintexts per trial")
    out(f"Threshold  : 1/sqrt(N) = {threshold:.5f}  (= 2 SE; "
        f"null exceedance ~4.55%)")
    out(f"Key        : {key_desc}")
    out(f"Log file   : {log_path}")
    out(f"CSV file   : {csv_path}")
    out()

    csv_f = open(csv_path, "w", newline="")
    writer = csv.writer(csv_f)
    writer.writerow(["trial", "in_mask", "out_mask", "count_zero",
                     "prob", "abs_bias", "z", "exceeds_threshold",
                     "timestamp"])

    all_biases, all_z = [], []
    best = (0.0, None)
    t0 = time.perf_counter()

    for t in range(args.trials):
        in_mask  = np.frombuffer(os.urandom(16), dtype=np.uint8)
        out_mask = np.frombuffer(os.urandom(16), dtype=np.uint8)

        P = np.frombuffer(os.urandom(args.samples * 16),
                          dtype=np.uint8).reshape(-1, 16)
        C = ctx.encrypt_batch(P, rounds=args.rounds)
        val = parity_rows(P, in_mask) ^ parity_rows(C, out_mask)
        count_zero = int(np.count_nonzero(val == 0))

        prob = count_zero / args.samples
        bias = abs(prob - 0.5)
        z    = (prob - 0.5) / se
        exceeds = bias > threshold
        all_biases.append(bias)
        all_z.append(abs(z))
        if bias > best[0]:
            best = (bias, (in_mask.tobytes().hex(),
                           out_mask.tobytes().hex(), prob, z))

        writer.writerow([t + 1, in_mask.tobytes().hex(),
                         out_mask.tobytes().hex(), count_zero,
                         f"{prob:.6f}", f"{bias:.6f}", f"{z:+.3f}",
                         int(exceeds),
                         datetime.datetime.now().isoformat(
                             timespec="seconds")])
        csv_f.flush()

        flag = "  *** EXCEEDS THRESHOLD ***" if exceeds else ""
        out(f"trial {t+1:3d}: prob={prob:.6f}  abs_bias={bias:.6f}  "
            f"z={z:+6.2f}{flag}")
        if (t + 1) % 50 == 0:
            n_ex = sum(1 for b in all_biases if b > threshold)
            out(f"  -- {t+1}/{args.trials} trials · exceedance "
                f"{n_ex}/{t+1} = {n_ex/(t+1)*100:.1f}% · "
                f"max |bias| {max(all_biases):.6f} --")

    csv_f.close()
    t1 = time.perf_counter()

    n_ex = sum(1 for b in all_biases if b > threshold)
    out()
    out("=" * 72)
    out("SESSION SUMMARY")
    out("=" * 72)
    out(f"Trials exceeding threshold : {n_ex}/{args.trials} = "
        f"{n_ex/args.trials*100:.2f}%   (null expectation ~4.55%)")
    out(f"Mean |bias|                : "
        f"{sum(all_biases)/len(all_biases):.6f}")
    out(f"Max  |bias|                : {max(all_biases):.6f}   "
        f"(threshold {threshold:.5f})")
    out(f"Max  |z|                   : {max(all_z):.2f}")
    if best[1]:
        im, om, prob, z = best[1]
        out(f"Best observed pair         : prob={prob:.6f}  z={z:+.2f}")
        out(f"  in_mask  = {im}")
        out(f"  out_mask = {om}")
    out(f"Elapsed                    : {t1 - t0:.1f} s")
    log.close()
    print(f"\nSession log written to {log_path}")
    print(f"Per-trial CSV written to {csv_path}")


if __name__ == "__main__":
    main()
