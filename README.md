# MD-Hill-SPN Research Code

This repository contains Python research code related to the paper **"Multidimensional Hill Cipher Substitution-Permutation Network"** by Porter E. Coggins III (*Journal of Cybersecurity and Privacy*, 2026; DOI: [10.3390/jcp6030104](https://doi.org/10.3390/jcp6030104)).

> **Specification correction (30 August 2026).** The published prose in Section 3.9 omitted two details present in the implementation used to generate the reported test vectors and metric results: the requirement that all `2n` Cauchy parameters be pairwise distinct, and the per-matrix index that distinguishes multiple matrices of the same dimension. A literal implementation of the published wording can therefore produce a singular matrix and would derive identical matrices within repeated dimensions. The April 20, 2026 Revision 3 reference implementation, meaning the third software revision of the test-vector and supporting metric code used in preparing the article, already uses global duplicate rejection across `X` and `Y` together with an explicit matrix index. Under the standard random-output model for SHA-256, the analytically confirmed lower bound for singularity of the literal published `16 x 16` procedure is 0.61878098; the Appendix A key is a concrete deterministic instance. See [`ERRATUM.md`](ERRATUM.md) for the corrected derivation, provenance, and branch-number clarification. No cryptographic algorithm change is made by this repository correction.

MD-Hill-SPN is a prototype cryptographic construction developed for experimental and manuscript-support purposes. MD-Hill-SPN is a 128-bit, 12-round substitution-permutation network based on Hill Cipher Variation 2 (Coggins 2024, *Mathematics and Computer Science* 9(3)) adapted to byte/bit-level operations, with layered Cauchy MDS diffusion over GF(2^8) (branch numbers B = 5 / 9 / 17 at the 4x4 / 8x8 / 16x16 tiers) and two AES S-box substitution layers per round.

The code supports rerunning and checking the computational experiments associated with the MD-Hill-SPN manuscript, including branch-number consistency checks, avalanche testing, differential and linear-bias probes, algebraic-degree estimation, NIST SP 800-22 style keystream evaluation, round-count diagnostics, and reference test-vector generation.

## Repository contents

| File                                     | Purpose                                                                                                     |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `ERRATUM.md`                             | Specification Correction for Section 3.9: pairwise-distinct Cauchy parameters, per-matrix index, prepublication implementation provenance, and clarification that weight-1 enumeration is a consistency check for the MDS construction. |
| `mdhillspn_core.py`                      | Shared core module: pure-Python reference implementation, NumPy-vectorized batch implementation (~170x), key derivation, Cauchy MDS matrix derivation, counter-mode keystream, and the startup conformance check used by every script. |
| `mdhillspn_metrics_optimized_rev4.py`    | Main metric suite (Revision 4, optimized): branch numbers, avalanche, differential distribution, linear-bias probe, algebraic-degree lower bounds. Deterministic by default. |
| `MDHillSPNDifferential12.py`             | Full-round (12-round) differential clustering probe over structured low-weight input differences across byte positions. |
| `MDHillSPNLinearBias12.py`               | Per-session linear-bias probe with fresh Argon2id key derivation and per-trial CSV logging; run twice for two independent sessions. |
| `MDHillSPNConfirm300.py`                 | 300-sequence NIST SP 800-22 core-battery confirmation on counter-mode keystream (deterministic confirmation key; reproduces bit-for-bit). |
| `MDHillSPNDiagnostics.py`                | Characterization diagnostics: battery-validity controls, stride Hamming-distance distinguisher, and NIST rounds sweep (rounds 2/4/6/8/10/12). |
| `MD-Hill-SPN_test_vector_rev3_20260420.py` | Reference test-vector generator (Revision 3 software revision): Round-0 intermediate states, 12-round ciphertext, decryption round-trip, Cauchy-MDS branch-number consistency checks. |
| `mdhillspn_metrics_corrected_2026_04_20.py` | Revision 3 metric analysis (script of record for the published paper's metric results; superseded for new runs by the Revision 4 optimized suite below, which reproduces the same metric definitions ~170x faster). |
| `nist_core_battery.py`                   | Seven-test / nine-p-value core subset of NIST SP 800-22 (shared with the HESPN repository; validates itself at import against SP 800-22 worked examples). |
| `mdhillspn_metrics_rev4_*.txt`           | Archived full run log of the Revision 4 metric suite (deterministic mode).                                  |
| `mdhill_keystream_sample_first1000.txt`  | First 1,000 bits of counter-mode keystream under the deterministic confirmation key, for independent verification. |
| `README.md`                              | Overview and usage instructions for this repository.                                                        |
| `LICENSE`                                | MIT License for this repository.                                                                             |
| `CITATION.cff`                           | Citation metadata for users who wish to cite this software.                                                  |

## Correct Cauchy parameter derivation

For each `n x n` diffusion matrix, the implementation derives successive SHA-256 blocks from the master key, a **dimension-specific** tag, a two-byte matrix index, and a four-byte counter. The April 20, 2026 Revision 3 reference implementation concatenates these blocks until `max(128, 8n)` candidate bytes have been generated. For the implemented dimensions `n in {4, 8, 16}`, this is a 128-byte candidate stream.

The stream is scanned while rejecting `0x00` and every byte value already selected for that matrix. The first `n` accepted bytes form `X` and the next `n` form `Y`, using one shared duplicate-rejection set across both. If fewer than `2n` acceptable values are obtained, derivation fails closed and no matrix is assembled, preventing construction of a matrix that violates the pairwise-distinctness requirement. Thus every assembled matrix has `2n` pairwise-distinct Cauchy parameters. The implementation additionally excludes `0x00` as a construction convention.

“Revision 3” here is a software/reference-code revision designation, not a third revision of the journal article or manuscript. This is the implementation that generated the repository reference test vector and the Revision 3 metric results. The shorter derivation printed in the published Section 3.9 prose is incomplete; see [`ERRATUM.md`](ERRATUM.md).

For these valid Cauchy matrices, the MDS property establishes `B = n + 1`. The weight-1 branch-number routine is retained as an implementation consistency check; weight-1 enumeration alone is not a general proof of nonsingularity or of the true branch number of an arbitrary matrix.

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

Every script in this repository verifies the implementation against the April 20, 2026 Revision 3 software reference test vector at startup (master key, rk[0], Round-0 Steps A-F, 12-round ciphertext, decryption round-trip, MDS branch-number consistency checks, and reference-vs-vectorized equivalence) and refuses to run on any mismatch.

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

Generate the Revision 3 software reference test vector:

```bash
python "MD-Hill-SPN_test_vector_rev3_20260420.py"
```

Each metric script also writes its own timestamped `.txt` log (and, where applicable, per-trial `.csv` data), so console output is never the only record of a run.

## Notes on computation time

The metric scripts use a NumPy-vectorized batch implementation of the cipher (approximately 170x faster per block than the straightforward reference implementation; the vectorized and reference implementations are verified equivalent at startup). Representative runtimes: the full Revision 4 metric suite runs in roughly 3-5 minutes; the 300-sequence NIST confirmation in roughly 5-10 minutes; the diagnostics in roughly 30-45 minutes, dominated by the rounds sweep. Runtimes vary with the machine.

## Reproducibility

The metric suite, the differential probe, the NIST confirmation, and the diagnostics use deterministic keys and seeded sampling by default, so reruns reproduce exactly. Deterministic-mode output has been verified to reproduce **bit-for-bit across platforms** (Windows / MSC and Linux / GCC builds of CPython, 2026-07-07), including every reported statistic and every logged intermediate value. The linear-bias script is the deliberate exception: each invocation is an independent session with a fresh Argon2id password and salt, both durably logged.

## Relationship to the HESPN repository

The metric programs in this repository are structurally parallel to the HESPN v4 suite ([Hill-Enigma-SPN-HESPN-COGGINS](https://github.com/ja9925ydbsu/Hill-Enigma-SPN-HESPN-COGGINS)) and share the same NIST core battery module, so the two constructions report directly comparable statistics.

## Project status

This repository is intended for research, manuscript review, and reproducibility support. It should be treated as experimental research code, not production cryptographic software.

The historical journal PDF in this repository is intentionally retained unchanged as the published record. The specification discrepancy is documented separately in [`ERRATUM.md`](ERRATUM.md) rather than by silently replacing the article.

No claim is made that the repository Specification Correction addresses broader cryptanalytic questions unrelated to the specification defects discussed there. Its purpose is to document the corrected matrix-derivation procedure and associated branch-number rationale.

## Citation

If you use this software in academic work, please cite the associated paper (Coggins, "Multidimensional Hill Cipher Substitution-Permutation Network," *Journal of Cybersecurity and Privacy*, 2026, DOI 10.3390/jcp6030104) and the repository, using the metadata in the `CITATION.cff` file included in this repository. Readers implementing the construction should also consult [`ERRATUM.md`](ERRATUM.md).

GitHub may also display a **Cite this repository** option when the `CITATION.cff` file is present in the repository root.

## Author / concept

Concept: Porter Coggins
Repository: `ja9925ydbsu/MH_Hill_SPN`
Python code assistance: Anthropic Claude AI

## License

This repository is licensed under the MIT License. See the `LICENSE` file for details.

## Disclaimer

This code is provided for research and reproducibility purposes. It has not been independently audited for production cryptographic use.
