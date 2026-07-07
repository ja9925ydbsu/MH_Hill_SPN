#!/usr/bin/env python3
# ============================================================
# MDHillSPNDifferential12.py
#
# MD-Hill-SPN differential-distribution probe, 12-round final
# parameterization (Revision 3, Cauchy MDS matrices).
#
# Purpose: full-round (12-round) differential confirmation for
# the MD-Hill-SPN manuscript, structurally parallel to the
# HESPN probe HESPNv4Differential16.py so that the two ciphers
# report directly comparable statistics: chosen low-weight
# structured input differences across byte positions, checked
# for output-difference clustering.
#
# Method:
#   For a fixed input difference delta, draw N random plaintext
#   pairs (P, P XOR delta), encrypt both under the full 12-round
#   cipher, and count DISTINCT output differences among the N
#   pairs. N distinct out of N means no two pairs produced the
#   same output difference at the sample-size resolution limit
#   (1/N ~ 2e-5 at N = 50,000); fewer indicates collisions. The
#   maximum multiplicity of any single output difference is also
#   reported (the empirical max differential count), which is
#   the direct clustering statistic.
#
# Input differences tested:
#   - single-bit deltas at several bit positions (bytes 0/7/15),
#   - single-byte deltas at several byte positions,
#   - low-weight multi-byte deltas,
# so that clustering across byte positions is exercised, not
# just one representative delta.
#
# CONFORMANCE: at startup this script verifies the shared core
# (mdhillspn_core) against the published Revision 3 reference
# test vector: master key, rk[0], all Round-0 intermediate
# states, the 12-round ciphertext, the decryption round-trip,
# MDS branch numbers, and reference-vs-vectorized equivalence
# on random blocks. It refuses to run if any check fails.
#
# KEYS: deterministic SHA-256 stub key by default (exactly
# reproducible); pass --argon2 for a fresh Argon2id session
# key (independent-key variant; requires argon2-cffi).
#
# Usage:
#   pip install numpy            (argon2-cffi only for --argon2)
#   python MDHillSPNDifferential12.py
#   python MDHillSPNDifferential12.py --samples 50000 --rounds 12
# ============================================================

import argparse
import datetime
import os
import sys
import time

import numpy as np

import mdhillspn_core as core


def make_deltas():
    """Structured low-weight input differences (16-byte each)."""
    deltas = []

    def d(name, pos_val_pairs):
        b = bytearray(16)
        for pos, val in pos_val_pairs:
            b[pos] = val
        deltas.append((name, bytes(b)))

    # single-bit (MSB of byte 0; LSB of byte 7; bit 3 of byte 15)
    d("bit   0        (byte  0, 0x80)", [(0, 0x80)])
    d("bit  63        (byte  7, 0x01)", [(7, 0x01)])
    d("bit 124        (byte 15, 0x08)", [(15, 0x08)])
    # single-byte
    d("byte  0 = 0x01               ", [(0, 0x01)])
    d("byte  7 = 0xFF               ", [(7, 0xFF)])
    d("byte 15 = 0x01               ", [(15, 0x01)])
    # low-weight multi-byte
    d("bytes 0,15 = 0x01            ", [(0, 0x01), (15, 0x01)])
    d("bytes 3,7,11 = 0x80          ", [(3, 0x80), (7, 0x80), (11, 0x80)])
    d("bytes 0,4,8,12 = 0x01 (col)  ", [(0, 0x01), (4, 0x01),
                                        (8, 0x01), (12, 0x01)])
    return deltas


def run_delta(ctx, rng, delta: bytes, samples: int, rounds: int,
              batch: int = 50000):
    """Return (distinct, max_mult, top5) for one input difference."""
    dvec = np.frombuffer(delta, dtype=np.uint8)
    from collections import Counter
    counter = Counter()
    done = 0
    while done < samples:
        nb = min(batch, samples - done)
        P  = rng.integers(0, 256, size=(nb, 16), dtype=np.uint8)
        C1 = ctx.encrypt_batch(P, rounds=rounds)
        C2 = ctx.encrypt_batch(P ^ dvec, rounds=rounds)
        dC = np.bitwise_xor(C1, C2)
        counter.update(dC.tobytes()[i*16:(i+1)*16] for i in range(nb))
        done += nb
    top = counter.most_common(5)
    return len(counter), top[0][1], top


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=50000)
    ap.add_argument("--rounds",  type=int, default=12)
    ap.add_argument("--argon2",  action="store_true",
                    help="fresh Argon2id session key instead of the "
                         "deterministic stub key")
    ap.add_argument("--seed",    type=int, default=20260707,
                    help="PRNG seed for plaintext sampling (deterministic "
                         "runs; ignored meaningfully only if you also want "
                         "fresh keys)")
    args = ap.parse_args()

    core.conformance_check(verbose=True)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = f"mdhill_diff_r{args.rounds}_{ts}.txt"
    log = open(log_path, "w", encoding="utf-8")

    def out(s=""):
        print(s)
        log.write(s + "\n")
        log.flush()

    if args.argon2:
        password = os.urandom(24).hex()
        salt     = os.urandom(core.ARGON_SALT_LEN)
        mk = core.derive_master_key_argon2id(password, salt)
        key_desc = (f"Argon2id session key  (t={core.ARGON_TIME_COST}, "
                    f"m={core.ARGON_MEMORY_COST} KiB, "
                    f"p={core.ARGON_PARALLELISM})\n"
                    f"password = {password}\nsalt     = {salt.hex()}")
    else:
        mk = core.derive_master_key_stub(core.TV_PASSWORD, core.TV_SALT)
        key_desc = ("deterministic SHA-256 stub key "
                    "(reference test-vector password/salt)")

    ctx = core.MDHillContext(mk, max_rounds=args.rounds)
    rng = np.random.default_rng(args.seed)

    out("=" * 72)
    out("MD-Hill-SPN DIFFERENTIAL PROBE  (Revision 3, Cauchy MDS)")
    out("=" * 72)
    out(f"Timestamp : {ts}")
    out(f"Rounds    : {args.rounds}")
    out(f"Samples   : {args.samples} pairs per input difference")
    out(f"Resolution: 1/N = {1/args.samples:.2e}")
    out(f"Key       : {key_desc}")
    out(f"Seed      : {args.seed}")
    out(f"Log file  : {log_path}")
    out()
    out(f"{'input difference':<34}{'distinct dC':>12}{'max mult':>10}"
        f"{'max p_hat':>12}")
    out("-" * 72)

    t0 = time.perf_counter()
    worst_mult = 0
    for name, delta in make_deltas():
        distinct, max_mult, top = run_delta(
            ctx, rng, delta, args.samples, args.rounds)
        worst_mult = max(worst_mult, max_mult)
        out(f"{name:<34}{distinct:>12}{max_mult:>10}"
            f"{max_mult/args.samples:>12.2e}")
        if max_mult > 1:
            for rank, (dc, freq) in enumerate(top, 1):
                if freq > 1:
                    out(f"    collision {rank}: mult={freq}  dC={dc.hex()}")
    t1 = time.perf_counter()

    out("-" * 72)
    out(f"Worst-case multiplicity over all deltas : {worst_mult}")
    out(f"Sampled max differential probability    : "
        f"{worst_mult/args.samples:.2e}")
    out(f"(N distinct out of N pairs = no repeated output difference at "
        f"the 1/N resolution limit.)")
    out(f"Elapsed: {t1 - t0:.1f} s")
    log.close()
    print(f"\nLog written to {log_path}")


if __name__ == "__main__":
    main()
