# MD-Hill-SPN Research Code

> **Correction notice (4 September 2026):** The published article's Section 3.9 incompletely specified the Cauchy matrix parameter derivation and some branch-number wording overstated what weight-one enumeration establishes. The repository implementation already uses the pairwise-distinct, index-separated Cauchy derivation that generated the published test vector and metric results. See [`CORRECTION.md`](CORRECTION.md) for the corrected specification, provenance, and branch-number rationale.

This repository contains Python research code related to the paper **"Multidimensional Hill Cipher Substitution-Permutation Network"** by Porter E. Coggins III (*Journal of Cybersecurity and Privacy*, 2026; DOI: [10.3390/jcp6030104](https://doi.org/10.3390/jcp6030104)).

MD-Hill-SPN is a prototype cryptographic construction developed for experimental and manuscript-support purposes. MD-Hill-SPN is a 128-bit, 12-round substitution-permutation network based on Hill Cipher Variation 2 (Coggins 2024, *Mathematics and Computer Science* 9(3)) adapted to byte/bit-level operations, with layered Cauchy MDS diffusion over GF(2^8) (branch numbers B = 5 / 9 / 17 at the 4x4 / 8x8 / 16x16 tiers) and two AES S-box substitution layers per round.

The code supports rerunning and checking the computational experiments associated with the MD-Hill-SPN manuscript, including branch-number consistency checks, avalanche testing, differential and linear-bias probes, algebraic-degree estimation, NIST SP 800-22 style keystream evaluation, round-count diagnostics, and reference test-vector generation.

## Repository contents

| File                                     | Purpose                                                                                                     |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `CORRECTION.md`                          | Correction notice for the Cauchy parameter derivation and branch-number rationale, including provenance of the April 20, 2026 Revision 3 implementation. |
| `mdhillspn_core.py`                      | Shared core module: pure-Python reference implementation, NumPy-vectorized batch implementation (~170x), key derivation, pairwise-distinct/index-separated Cauchy MDS matrix derivation, counter-mode keystream, and the startup conformance check used by every script. |
| `mdhillspn_metrics_optimized_rev4.py`    | Main metric suite (Revision 4, optimized): branch-number consistency checks, avalanche, differential distribution, linear-bias probe, algebraic-degree lower bounds. Deterministic by default. |
| `MDHillSPNDifferential12.py`             | Full-round (12-round) differential clustering probe over structured low-weight input differences across byte positions. |
| `MDHillSPNLinearBias12.py`               | Per-session linear-bias probe with fresh Argon2id key derivation and per-trial CSV logging; run twice for two independent sessions. |
| `MDHillSPNConfirm300.py`                 | 300-sequence NIST SP 800-22 core-battery confirmation on counter-mode keystream (deterministic confirmation key; reproduces bit-for-bit). |
| `MDHillSPNDiagnostics.py`                | Characterization diagnostics: battery-validity controls, stride Hamming-distance distinguisher, and NIST rounds sweep (rounds 2/4/6/8/10/12). |
| `MD-Hill-SPN_test_vector_rev3_20260420.py` | Historical Revision 3 reference test-vector generator: Round-0 intermediate states, 12-round ciphertext, decryption round-trip, and weight-one implementation consistency checks. Preserved unchanged for provenance; see `CORRECTION.md` for corrected terminology. |
| `mdhillspn_metrics_corrected_2026_04_20.py` | Historical Revision 3 metric analysis and script of record for the published metric results. Preserved unchanged for provenance; superseded for new runs by Revision 4 and by the terminology in `CORRECTION.md`. |
| `nist_core_battery.py`                   | Seven-test / nine-p-value core subset of NIST SP 800-22 (shared with the HESPN repository; validates itself at import against SP 800-22 worked examples). |
| `mdhillspn_metrics_rev4_*.txt`           | Archived full run log of the Revision 4 metric suite (deterministic mode).                                  |
| `mdhill_keystream_sample_first1000.txt`  | First 1,000 bits of counter-mode keystream under the deterministic confirmation key, for independent verification. |
| `README.md`                              | Overview and usage instructions for this repository.                                                        |
| `LICENSE`                                | MIT License for this repository.                                                                             |
| `CITATION.cff`                           | Citation metadata for users who wish to cite this software.                                                  |

## Requirements

This project is written in Python. Use Python 3.10 or later.

Required for all metric scripts:

```bash
pip install numpy
```

Required only for Argon2id session keys (the default mode of `MDHillSPNLinearBias12.py`, and the `--argon2` options elsewhere):

```bash
pip install argon2-cffi
```

The reference test-vector generator uses the standard library only.

## How to run

Clone the repository:

```bash
git clone https://github.com/ja9925ydbsu/MH_Hill_SPN.git
cd MH_Hill_SPN
```

Verify the environment (conformance check only, a few seconds):

```bash
python mdhillspn_core.py
```

Every script in this repository verifies the implementation against the published Revision 3 reference test vector at startup (master key, rk[0], Round-0 Steps A-F, 12-round ciphertext, decryption round-trip, expected Cauchy MDS branch-number values, and reference-vs-vectorized equivalence) and refuses to run on any mismatch. The values B = 5 / 9 / 17 follow mathematically from the pairwise-distinct Cauchy MDS construction; weight-one enumeration in the code is an implementation consistency check rather than an independent proof of the true branch number.

Run the main metric suite (Steps 0-4; a few minutes):

```bash
python mdhillspn_metrics_optimized_rev4.py
```

Run the full-round differential probe:

```bash
python MDHillSPNDifferential12.py
```

Run one independent linear-bias session (repeat for a second session):

```bash
python MDHillSPNLinearBias12.py
```

Run the 300-sequence NIST confirmation:

```bash
python MDHillSPNConfirm300.py
```

Run the diagnostics (controls, stride distinguisher, rounds sweep) and save the output:

```bash
python MDHillSPNDiagnostics.py > mdhill_diagnostics_output.txt
```

Generate the Revision 3 reference test vector:

```bash
python "MD-Hill-SPN_test_vector_rev3_20260420.py"
```

Each metric script also writes its own timestamped `.txt` log (and, where applicable, per-trial `.csv` data), so console output is never the only record of a run.

## Notes on computation time

The metric scripts use a NumPy-vectorized batch implementation of the cipher (approximately 170x faster per block than the straightforward reference implementation; the vectorized and reference implementations are verified equivalent at startup). Representative runtimes: the full Revision 4 metric suite runs in roughly 3-5 minutes; the 300-sequence NIST confirmation in roughly 5-10 minutes; the diagnostics in roughly 30-45 minutes, dominated by the rounds sweep. Runtimes vary with the machine.

## Reproducibility

The metric suite, the differential probe, the NIST confirmation, and the diagnostics use deterministic keys and seeded sampling by default, so reruns reproduce exactly. Deterministic-mode output has been verified to reproduce **bit-for-bit across platforms** (Windows / MSC and Linux / GCC builds of CPython, 2026-07-07), including every reported statistic and every logged intermediate value. The linear-bias script is the deliberate exception: each invocation is an independent session with a fresh Argon2id password and salt, both durably logged.

The April 20, 2026 Revision 3 reference implementation uses a single duplicate-rejection set across X and Y for each matrix and includes a two-byte per-matrix index. These are the implementation details corrected in the journal prose and documented in `CORRECTION.md`. No numerical change to the published test vector or empirical metric tables is implied by that specification correction.

## Relationship to the HESPN repository

The metric programs in this repository are structurally parallel to the HESPN v4 suite ([Hill-Enigma-SPN-HESPN-COGGINS](https://github.com/ja9925ydbsu/Hill-Enigma-SPN-HESPN-COGGINS)) and share the same NIST core battery module, so the two constructions report directly comparable statistics.

## Project status

This repository is intended for research, manuscript review, and reproducibility support. It should be treated as experimental research code, not production cryptographic software.

## Citation

If you use this software in academic work, please cite the associated paper (Coggins, "Multidimensional Hill Cipher Substitution-Permutation Network," *Journal of Cybersecurity and Privacy*, 2026, DOI 10.3390/jcp6030104) and the repository, using the metadata in the `CITATION.cff` file included in this repository. For the corrected Section 3.9 derivation and branch-number rationale, also consult `CORRECTION.md` and, once published, the journal's formal correction/version-of-record update.

GitHub may also display a **Cite this repository** option when the `CITATION.cff` file is present in the repository root.

## Author / concept

Concept: Porter Coggins
Repository: `ja9925ydbsu/MH_Hill_SPN`
Python code assistance: Anthropic Claude AI

## License

This repository is licensed under the MIT License. See the `LICENSE` file for details.

## Disclaimer

This code is provided for research and reproducibility purposes. It has not been independently audited for production cryptographic use.
