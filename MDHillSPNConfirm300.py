#!/usr/bin/env python3
# ============================================================
# MDHillSPNConfirm300.py
#
# MD-Hill-SPN 300-sequence NIST SP 800-22 core-battery
# confirmation run at the final 12-round parameterization
# (Revision 3, Cauchy MDS matrices). Structurally parallel to
# HESPNv4Confirm300.py so the two ciphers report directly
# comparable keystream statistics.
#
# Method:
#   Counter-mode keystream = concatenation of encryptions of
#   sequential 128-bit big-endian counter blocks 0, 1, 2, ...,
#   partitioned into SEQUENCES sequences of 10^6 bits. Each
#   sequence is assessed under the seven-test / nine-p-value
#   core battery (frequency, block frequency, runs, longest run
#   of ones, cumulative sums forward and backward, serial m=2,
#   approximate entropy m=2; nist_core_battery.py, validated at
#   import against the SP 800-22 worked examples). A test
#   "fails" for a sequence when its p-value < alpha (0.01).
#   Per-test pass proportions are compared against the
#   three-sigma acceptance region; the total failing-test count
#   is compared against its expectation
#   (alpha x SEQUENCES x 9 p-values).
#
# KEYS: the confirmation key is derived deterministically
# (fixed reference password/salt via the SHA-256 stub) so the
# run reproduces bit-for-bit; pass --argon2 for a fresh random
# Argon2id key (independent-key variant).
#
# CONFORMANCE: verifies mdhillspn_core against the published
# Revision 3 test vector, and the NIST battery against the
# SP 800-22 worked examples (import-time validation inside
# nist_core_battery), at startup. Refuses to run on mismatch.
#
# Requires: numpy; nist_core_battery.py and mdhillspn_core.py
# in the same directory.
#   pip install numpy argon2-cffi
#   python MDHillSPNConfirm300.py                  # 300 seq, deterministic key
#   python MDHillSPNConfirm300.py --sequences 20   # quick core run
#   python MDHillSPNConfirm300.py --argon2         # independent random key
# ============================================================

import argparse
import datetime
import math
import os
import sys
import time

import numpy as np

import mdhillspn_core as core
import nist_core_battery as nist   # validates itself at import

ALPHA        = 0.01
BITS_PER_SEQ = 1_000_000
TEST_NAMES   = ["frequency", "block_frequency", "runs", "longest_run",
                "cusum_fwd", "cusum_bwd", "serial_1", "serial_2",
                "approx_entropy"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sequences", type=int, default=300)
    ap.add_argument("--rounds",    type=int, default=12)
    ap.add_argument("--argon2",    action="store_true",
                    help="fresh Argon2id key instead of the deterministic "
                         "confirmation key")
    args = ap.parse_args()

    core.conformance_check(verbose=True)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = (f"mdhill_nist_confirm_{args.sequences}seq_"
                f"r{args.rounds}_{ts}.txt")
    log = open(log_path, "w", encoding="utf-8")

    def out(s=""):
        print(s)
        log.write(s + "\n")
        log.flush()

    if args.argon2:
        password = os.urandom(24).hex()
        salt     = os.urandom(core.ARGON_SALT_LEN)
        mk = core.derive_master_key_argon2id(password, salt)
        key_desc = (f"Argon2id independent key\npassword = {password}\n"
                    f"salt     = {salt.hex()}")
    else:
        mk = core.derive_master_key_stub(core.TV_PASSWORD, core.TV_SALT)
        key_desc = ("deterministic confirmation key (SHA-256 stub, "
                    "reference password/salt) - reproduces bit-for-bit")

    ctx = core.MDHillContext(mk, max_rounds=args.rounds)

    S = args.sequences
    total_pv   = S * len(TEST_NAMES)
    expect     = ALPHA * total_pv
    p_hat_lo   = (1 - ALPHA) - 3 * math.sqrt(ALPHA * (1 - ALPHA) / S)

    out("=" * 72)
    out(f"MD-Hill-SPN {S}-SEQUENCE NIST SP 800-22 CORE-BATTERY CONFIRMATION")
    out(f"(Revision 3, Cauchy MDS, {args.rounds} rounds)")
    out("=" * 72)
    out(f"Timestamp        : {ts}")
    out(f"Sequences        : {S} x {BITS_PER_SEQ:,} bits "
        f"({S * BITS_PER_SEQ / 8 / 1e6:.0f} MB keystream)")
    out(f"Battery          : 7 tests / 9 p-values (nist_core_battery, "
        f"validated at import)")
    out(f"alpha            : {ALPHA}")
    out(f"Expected failures: {expect:.0f} of {total_pv}")
    out(f"3-sigma pass-proportion cutoff (n={S}): {p_hat_lo:.4f}")
    out(f"Key              : {key_desc}")
    out(f"Keystream        : counter mode, 128-bit big-endian counters "
        f"from 0")
    out(f"Log file         : {log_path}")
    out()

    fails_per_test = {t: 0 for t in TEST_NAMES}
    total_fail = 0
    runs_family_pass = 0
    blocks_per_seq = BITS_PER_SEQ // core.BLOCK_BITS
    t0 = time.perf_counter()

    for s in range(S):
        bits_np = ctx.keystream_bits(s * blocks_per_seq, BITS_PER_SEQ,
                                     rounds=args.rounds)
        bits_list = bits_np.tolist()
        pv = nist.battery_pvalues_fast(bits_list, bits_np)
        seq_fail = [t for t in TEST_NAMES if pv[t] < ALPHA]
        for t in seq_fail:
            fails_per_test[t] += 1
        total_fail += len(seq_fail)
        if pv["runs"] >= ALPHA:
            runs_family_pass += 1
        if seq_fail:
            out(f"  seq {s+1:3d}: FAIL {', '.join(seq_fail)}  "
                f"({ {t: round(pv[t], 5) for t in seq_fail} })")
        if (s + 1) % 25 == 0:
            el = time.perf_counter() - t0
            out(f"  -- {s+1}/{S} sequences · failing so far {total_fail} · "
                f"{el:.0f} s elapsed --")

    t1 = time.perf_counter()

    out()
    out("=" * 72)
    out("CONFIRMATION SUMMARY")
    out("=" * 72)
    out(f"{'test':<18}{'fails':>6}{'pass prop':>12}{'3-sigma cutoff':>16}"
        f"{'verdict':>10}")
    out("-" * 62)
    all_ok = True
    for t in TEST_NAMES:
        f = fails_per_test[t]
        prop = (S - f) / S
        ok = prop >= p_hat_lo
        all_ok &= ok
        out(f"{t:<18}{f:>6}{prop:>12.4f}{p_hat_lo:>16.4f}"
            f"{'ok' if ok else 'LOW':>10}")
    out("-" * 62)
    out(f"Total failing tests : {total_fail} of {total_pv} "
        f"(expectation {expect:.0f})")
    out(f"Runs family         : {runs_family_pass}/{S} = "
        f"{runs_family_pass/S:.3f}")
    out(f"All per-test proportions inside 3-sigma region: "
        f"{'YES' if all_ok else 'NO'}")
    out(f"Elapsed             : {t1 - t0:.0f} s")
    log.close()
    print(f"\nLog written to {log_path}")


if __name__ == "__main__":
    main()
