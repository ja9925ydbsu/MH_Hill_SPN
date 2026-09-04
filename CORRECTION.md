# Correction notice: Cauchy matrix derivation and branch-number rationale

**Repository notice dated 4 September 2026**

This notice documents corrections to the specification in Section 3.9 and to the associated branch-number wording in Porter E. Coggins III, “Multidimensional Hill Cipher Substitution-Permutation Network,” *Journal of Cybersecurity and Privacy* 2026, 6, 104, DOI 10.3390/jcp6030104.

The Journal of Cybersecurity and Privacy editor has permitted correction of the already published manuscript. The specification discrepancy was brought to the author’s attention by Jean-Philippe Aumasson in personal communication on 28 August 2026.

## 1. What was wrong in the published prose

The published Section 3.9 description of Cauchy matrix generation omitted two requirements that are present in the reference implementation:

1. **Pairwise distinctness of all Cauchy parameters.** For an `n x n` Cauchy matrix over `GF(2^8)`, all `2n` values in `X = (x_0, ..., x_{n-1})` and `Y = (y_0, ..., y_{n-1})` must be pairwise distinct. Repetitions within `X` create identical rows; repetitions within `Y` create identical columns. Repairing only `X ∩ Y` is not sufficient.
2. **A per-matrix index.** The four 4 x 4 matrices and two 8 x 8 matrices must be separately derived. The implemented hash input includes a two-byte matrix index in addition to the dimension-specific domain tag.

When the published prose is followed literally, the Appendix A master key yields `x_9 = x_11 = 0x87` for the 16 x 16 derivation, producing two identical rows and a singular matrix of rank 15. Under the standard model in which SHA-256 output bytes are treated as independent and uniformly distributed, the lower bound reported for singularity of the literal 16 x 16 procedure is `0.61878098`. The literal no-index derivation also makes all four 4 x 4 matrices identical to one another and both 8 x 8 matrices identical to one another.

## 2. Correct implemented derivation

For each required diffusion matrix, let `K` be the derived master key, `tag` the dimension-specific domain-separation tag, `index` the matrix index, and `c` a four-byte counter. Successive candidate blocks are

```text
H_c = SHA-256(K || tag || I2OSP_2(index) || I2OSP_4(c)),  c = 0, 1, 2, ...
```

Successive `H_c` values are concatenated until `max(128, 8n)` candidate bytes have been generated. For the implemented dimensions `n ∈ {4, 8, 16}`, this is 128 bytes. The stream is scanned sequentially with one `seen` set for the entire matrix:

- discard `0x00`;
- discard every byte already selected for that matrix;
- accept the first `n` distinct nonzero values as `X`;
- accept the next `n` distinct nonzero values as `Y`;
- if fewer than `2n` acceptable values are available, fail closed and assemble no matrix.

Thus all `2n` Cauchy parameters are pairwise distinct. Matrix entries are

```text
M[i,j] = (x_i XOR y_j)^(-1)
```

with arithmetic in `GF(2^8)` using the AES irreducible polynomial. The dimension tags are `MDHILL_4`, `MDHILL_8`, and `MDHILL_16`. Indices are 0 through 3 for the four 4 x 4 matrices, 0 and 1 for the two 8 x 8 matrices, and 0 for the 16 x 16 matrix.

## 3. Correct branch-number statement

For an arbitrary linear map `M`, weight-one enumeration alone does **not** establish the true branch number and is not an independent proof of nonsingularity or MDS status. It examines column support only and can return `n + 1` even for a singular matrix whose columns all have full support.

For the implemented construction, the branch-number values follow from the Cauchy MDS property. Because all `2n` parameters are pairwise distinct, every square submatrix is nonsingular, so the matrix is MDS and

```text
B(M) = n + 1.
```

Therefore the intended values remain `B(M4) = 5`, `B(M8) = 9`, and `B(M16) = 17`. Weight-one enumeration is an **implementation consistency check** of those theorem-derived values, not an independent exhaustive proof of the branch number.

The active `mdhillspn_core.py` and `mdhillspn_metrics_optimized_rev4.py` files were terminology-aligned with this correction on 4 September 2026. Historical April 20 Revision 3 scripts and archived logs are intentionally preserved unchanged for provenance; any legacy wording in those historical artifacts that describes the branch number as “exact via weight-1 enumeration” is superseded by this notice.

## 4. Effect on the published results

No numerical change is required to the Appendix A test vector or to the reported empirical metric values. The correction aligns the written specification with the collision-free, index-separated implementation that generated the results. It does not change the round function, AES S-box layers, matrix hierarchy, number of rounds, round-key schedule, Appendix A master key, published ciphertext, or published Round-0 intermediate states.

## 5. Repository provenance

The collision-free, index-separated Revision 3 implementation predates publication of the article. The earliest presently visible repository commit containing it is:

```text
32b0b01b92e462346a60f21e7b9f35a648b9eb92
```

committed 22 April 2026 and containing the 20 April 2026 Revision 3 software.

The historical files are intentionally preserved so their provenance remains verifiable:

| File | Git blob identifier |
| --- | --- |
| `MD-Hill-SPN_test_vector_rev3_20260420.py` | `48a53dc11b65bc014f034bc06a9feb1af57509d0` |
| `mdhillspn_metrics_corrected_2026_04_20.py` | `309875decf5f30b2ae7d5f06ac043671911d13e0` |

These blob identifiers match the corresponding files in the 22 April 2026 commit. The repository’s current implementations use the same pairwise-distinct, index-separated Cauchy parameter derivation.

## 6. Published PDF in this repository

The PDF currently stored in this repository is the originally published article. Until a corrected journal version is available, readers should use this notice together with the article and treat the corrected Section 3.9 derivation and branch-number rationale above as controlling.

## Acknowledgment

The author thanks Jean-Philippe Aumasson for identifying the discrepancy between the published matrix-generation description and the requirements for a valid Cauchy MDS matrix. The author independently verified the issue and the corrected rationale summarized here.
