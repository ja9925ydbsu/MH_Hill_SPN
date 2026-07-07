# MD-Hill-SPN Research Code

This repository contains Python research code related to the paper **“Multidimensional Hill Cipher Substitution–Permutation Network”** by Porter E. Coggins III.

- Paper DOI: https://doi.org/10.3390/jcp6030104
- Article link: https://www.mdpi.com/2624-800X/6/3/104
- Repository: https://github.com/ja9925ydbsu/MH_Hill_SPN

## Overview

MD-Hill-SPN is a Hill-cipher-derived substitution–permutation network (SPN) research construction. The code in this repository is intended to support reproducibility for the paper’s reference test vector and byte-level empirical security metric checks.

The repository is provided for research, review, and reproducibility purposes. It is **not** production cryptographic software and has not been independently audited for operational cryptographic deployment.

## Repository contents

| File | Purpose |
| --- | --- |
| `MD-Hill-SPN_test_vector_rev3_20260420.py` | Generates the Revision 3 MD-Hill-SPN reference test vector, including master-key derivation, round keys, round-0 intermediate states, final ciphertext, decryption round-trip verification, and branch-number verification. |
| `mdhillspn_metrics_corrected 2026 04 20.py` | Runs the Revision 3 byte-level metric analysis, including branch-number verification, avalanche testing, differential-distribution sampling, linear-bias probing, and algebraic-degree lower-bound checks. |
| `README.md` | Overview and usage instructions for this repository. |
| `LICENSE` | MIT License for this repository. |
| `CITATION.cff` | Citation metadata for users who wish to cite this software and the associated paper. |

## Requirements

This project is written in Python. Python 3.10 or later is recommended.

The reference test-vector generator uses the Python standard library.

The metric script uses Argon2id key derivation and may require:

```bash
pip install argon2-cffi
```

## How to run

Clone the repository:

```bash
git clone https://github.com/ja9925ydbsu/MH_Hill_SPN.git
cd MH_Hill_SPN
```

Run the reference test-vector generator:

```bash
python "MD-Hill-SPN_test_vector_rev3_20260420.py"
```

Run the metric-analysis script:

```bash
python "mdhillspn_metrics_corrected 2026 04 20.py"
```

To save output to a text file:

```bash
python "MD-Hill-SPN_test_vector_rev3_20260420.py" > mdhillspn_test_vector_output.txt
python "mdhillspn_metrics_corrected 2026 04 20.py" > mdhillspn_metrics_output.txt
```

## Reproducibility notes

The Revision 3 code uses Cauchy MDS matrices over GF(2^8) and performs fail-closed branch-number checks. The test-vector script uses fixed test inputs so that the reference output can be reproduced exactly.

Some metric runs may take noticeable time depending on hardware and Python environment.

## Citation

If you use this repository in academic work, please cite both the repository and the associated paper. Citation metadata is provided in `CITATION.cff`. GitHub may also display a **Cite this repository** option when `CITATION.cff` is present in the repository root.

## License

This repository is licensed under the MIT License. See `LICENSE` for details.

## Disclaimer

This code is provided for research and reproducibility purposes only. It is experimental research code and should not be used as production cryptographic software.
