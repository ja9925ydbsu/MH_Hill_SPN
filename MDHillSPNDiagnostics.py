#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MDHillSPNDiagnostics.py
=======================
MD-Hill-SPN keystream and round-count characterization, structurally
parallel to HESPNv4Diagnostics.py so the two ciphers report directly
comparable diagnostics. Run:

    python MDHillSPNDiagnostics.py > mdhill_diagnostics_output.txt

Parts (toggle with the RUN_* flags below):

  A. Controls
     A1: os.urandom keystream through the same core battery (must pass;
         validates the battery itself).
     A2: full-round MD-Hill-SPN encrypting *independent random
         plaintexts* (must pass; separates structured-input effects
         from marginal nonuniformity of the permutation).

  B. Stride Hamming-distance distinguisher
     Mean HD( Enc(i), Enc(i+stride) ) over counter inputs, for several
     strides, with z-scores against the ideal mean 64.0 and standard
     deviation sqrt(32) for a 128-bit block. |z| < 3 at the tested
     sample size is consistent with random behavior.

  C. NIST rounds sweep
     NUM_SEQ sequences x 10^6 bits of counter-mode keystream per round
     count, nine p-values each. Reports failing counts per round count
     so the round-count margin of the final 12-round parameterization
     is visible (the analogue of the HESPN 12/14/16/20 sweep).

Determinism: keys derive from the fixed reference password/salt via
the SHA-256 stub so reruns reproduce exactly. Set DETERMINISTIC =
False for fresh os.urandom-keyed Argon2id runs.

CONFORMANCE: verifies mdhillspn_core against the published Revision 3
test vector at startup; nist_core_battery validates itself at import
against the SP 800-22 worked examples. Refuses to run on mismatch.

Requires: numpy; mdhillspn_core.py and nist_core_battery.py alongside.
"""

import builtins
import datetime
import math
import os
import time

import numpy as np

import mdhillspn_core as core
import nist_core_battery as nist

# ---------------- log file (console output is duplicated) ----------------
# All print() output below is teed to a timestamped .txt so IDLE runs
# (no shell redirection) still produce a durable artifact.
_LOG_PATH = ("mdhill_diagnostics_"
             + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt")
_LOG_FILE = None

def print(*args, **kwargs):            # shadows builtins.print below
    builtins.print(*args, **kwargs)
    if _LOG_FILE is not None:
        kw = {k: v for k, v in kwargs.items() if k in ("sep", "end")}
        builtins.print(*args, **kw, file=_LOG_FILE)
        _LOG_FILE.flush()

# ---------------- configuration ----------------
RUN_A_CONTROLS     = True
RUN_B_STRIDE_HD    = True
RUN_C_ROUNDS_SWEEP = True

DETERMINISTIC = True

ALPHA        = 0.01
BITS_PER_SEQ = 1_000_000
NUM_SEQ      = 20                  # sequences per configuration
SWEEP_ROUNDS = [2, 4, 6, 8, 10, 12]
STRIDES      = [1, 2, 16, 256, 4096]
STRIDE_PAIRS = 20000

TEST_NAMES = ["frequency", "block_frequency", "runs", "longest_run",
              "cusum_fwd", "cusum_bwd", "serial_1", "serial_2",
              "approx_entropy"]


def make_key(label: str) -> bytes:
    if DETERMINISTIC:
        return core.derive_master_key_stub(
            core.TV_PASSWORD + ":" + label, core.TV_SALT)
    password = os.urandom(24).hex()
    salt     = os.urandom(core.ARGON_SALT_LEN)
    print(f"  [fresh Argon2id key for part {label}: password={password} "
          f"salt={salt.hex()}]")
    return core.derive_master_key_argon2id(password, salt)


def battery_failing(bits_np) -> list:
    pv = nist.battery_pvalues_fast(bits_np.tolist(), bits_np)
    return [t for t in TEST_NAMES if pv[t] < ALPHA]


def battery_over_sequences(bit_source, num_seq: int, label: str) -> int:
    """bit_source(s) -> uint8 bit array of BITS_PER_SEQ for sequence s."""
    total_fail = 0
    t0 = time.perf_counter()
    for s in range(num_seq):
        fails = battery_failing(bit_source(s))
        total_fail += len(fails)
        if fails:
            print(f"    seq {s+1:3d}: FAIL {', '.join(fails)}")
    el = time.perf_counter() - t0
    exp = ALPHA * num_seq * len(TEST_NAMES)
    print(f"  {label}: {total_fail} failing of "
          f"{num_seq * len(TEST_NAMES)} p-values "
          f"(expectation {exp:.1f})  [{el:.0f} s]")
    return total_fail


# ---------------- Part A: controls ----------------

def part_A():
    print("=" * 72)
    print("PART A: CONTROLS")
    print("=" * 72)

    print(f"\nA1: os.urandom keystream, {NUM_SEQ} x {BITS_PER_SEQ:,} bits "
          f"(battery validity control)")
    def urandom_bits(_s):
        raw = np.frombuffer(os.urandom(BITS_PER_SEQ // 8), dtype=np.uint8)
        return np.unpackbits(raw)
    battery_over_sequences(urandom_bits, NUM_SEQ, "A1 urandom")

    print(f"\nA2: 12-round MD-Hill-SPN on independent random plaintexts, "
          f"{NUM_SEQ} x {BITS_PER_SEQ:,} bits")
    ctx = core.MDHillContext(make_key("A2"), max_rounds=core.ROUNDS)
    blocks_per_seq = BITS_PER_SEQ // core.BLOCK_BITS
    rng = np.random.default_rng(0xA2 if DETERMINISTIC else None)
    def rand_pt_bits(_s):
        P = rng.integers(0, 256, size=(blocks_per_seq, 16), dtype=np.uint8)
        C = ctx.encrypt_batch(P)
        return np.unpackbits(C, axis=1).reshape(-1)
    battery_over_sequences(rand_pt_bits, NUM_SEQ, "A2 random-plaintext")
    print()


# ---------------- Part B: stride Hamming-distance distinguisher --------

def part_B():
    print("=" * 72)
    print("PART B: STRIDE HAMMING-DISTANCE DISTINGUISHER")
    print("=" * 72)
    print(f"Mean HD( Enc(i), Enc(i+stride) ) over {STRIDE_PAIRS:,} counter "
          f"pairs per (rounds, stride).")
    print(f"Ideal mean 64.0, sd per pair sqrt(32); "
          f"z = (mean - 64) / (sqrt(32 / n_pairs)).  |z| < 3 nominal.\n")

    mk  = make_key("B")
    ctx = core.MDHillContext(mk, max_rounds=core.ROUNDS)
    sd_mean = math.sqrt(32.0 / STRIDE_PAIRS)

    print(f"{'rounds':>7}{'stride':>8}{'mean HD':>10}{'z':>9}")
    print("-" * 36)
    for rounds in SWEEP_ROUNDS:
        for stride in STRIDES:
            base  = core._counters_to_blocks(0, STRIDE_PAIRS)
            other = core._counters_to_blocks(stride, STRIDE_PAIRS)
            c1 = ctx.encrypt_batch(base,  rounds=rounds)
            c2 = ctx.encrypt_batch(other, rounds=rounds)
            hd = core.hamming_distance_rows(c1, c2)
            mean = float(hd.mean())
            z = (mean - 64.0) / sd_mean
            flag = "" if abs(z) < 3 else "   <-- |z| >= 3"
            print(f"{rounds:>7}{stride:>8}{mean:>10.3f}{z:>9.2f}{flag}")
        print("-" * 36)
    print()


# ---------------- Part C: NIST rounds sweep ----------------

def part_C():
    print("=" * 72)
    print("PART C: NIST ROUNDS SWEEP (counter-mode keystream)")
    print("=" * 72)
    print(f"{NUM_SEQ} sequences x {BITS_PER_SEQ:,} bits per round count; "
          f"nine p-values per sequence "
          f"({NUM_SEQ * len(TEST_NAMES)} tests per configuration); "
          f"alpha = {ALPHA}.\n")

    mk  = make_key("C")
    ctx = core.MDHillContext(mk, max_rounds=core.ROUNDS)
    blocks_per_seq = BITS_PER_SEQ // core.BLOCK_BITS

    results = {}
    for rounds in SWEEP_ROUNDS:
        print(f"--- rounds = {rounds} ---")
        def ks_bits(s, _r=rounds):
            return ctx.keystream_bits(s * blocks_per_seq, BITS_PER_SEQ,
                                      rounds=_r)
        results[rounds] = battery_over_sequences(
            ks_bits, NUM_SEQ, f"rounds={rounds}")
        print()

    print("ROUNDS SWEEP SUMMARY")
    print(f"{'rounds':>7}{'failing':>9}{'of':>6}")
    for rounds in SWEEP_ROUNDS:
        print(f"{rounds:>7}{results[rounds]:>9}"
              f"{NUM_SEQ * len(TEST_NAMES):>6}")
    print()


if __name__ == "__main__":
    core.conformance_check(verbose=True)
    _LOG_FILE = open(_LOG_PATH, "w", encoding="utf-8")
    print(f"Log file: {_LOG_PATH}")
    print()
    t0 = time.perf_counter()
    if RUN_A_CONTROLS:
        part_A()
    if RUN_B_STRIDE_HD:
        part_B()
    if RUN_C_ROUNDS_SWEEP:
        part_C()
    print(f"Diagnostics complete in {time.perf_counter() - t0:.0f} s.")
    _LOG_FILE.close()
    builtins.print(f"Log written to {_LOG_PATH}")
