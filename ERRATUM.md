# Specification Correction: Cauchy Matrix Derivation and Branch-Number Wording

This note documents a specification discrepancy in Porter E. Coggins III, **“Multidimensional Hill Cipher Substitution-Permutation Network,”** *Journal of Cybersecurity and Privacy* 2026, 6, 104, DOI 10.3390/jcp6030104.

The correction concerns the prose specification of the Cauchy diffusion-matrix derivation in Section 3.9 and the description of the branch-number check. It does **not** change the implemented MD-Hill-SPN round function or the matrix-generation algorithm used by the April 20, 2026 Revision 3 reference implementation, meaning the third software revision of the test-vector and supporting metric code used in preparing the article.

## 1. Published specification discrepancy

The published Section 3.9 description is incomplete in two independent respects.

### Pairwise distinctness

Section 3.9 describes construction of an `n x n` Cauchy matrix over `GF(2^8)` using sets `X` and `Y` derived from SHA-256 output. It states that zero bytes are replaced and collisions between `X` and `Y` are repaired, but it does not require all `2n` Cauchy parameters to be pairwise distinct.

For a Cauchy matrix

```text
M[i][j] = (x_i XOR y_j)^(-1),
```

the `x_i` values must be mutually distinct, the `y_j` values must be mutually distinct, and `X` and `Y` must be disjoint. Equivalently, all `2n` Cauchy parameters must be pairwise distinct. If `x_i = x_j` for `i != j`, two rows are identical. If `y_i = y_j` for `i != j`, two columns are identical. Either condition makes the matrix singular.

Jean-Philippe Aumasson observed that, when the published Section 3.9 prose is followed literally for the Appendix A test key, the `16 x 16` derivation yields `x_9 = x_11 = 0x87`. The resulting matrix contains two identical rows and is singular; direct elimination over `GF(2^8)` gives rank 15. That observation is correct with respect to the literal published wording.

Under the standard model in which SHA-256 output bytes are treated as independent and uniformly distributed, and accounting for the published `0x00 -> 0x01` substitution, the probability that `n` sampled bytes are pairwise distinct is

```text
p_n = (254)_(n-1) (255 + n) / 256^n,
```

where `(254)_(n-1)` denotes the falling factorial `254 * 253 * ... * (256 - n)`. Internal distinctness of both `X` and `Y` is necessary for nonsingularity, so

```text
Pr[M singular] >= 1 - p_n^2.
```

For `n = 16`, this gives the analytically confirmed lower bound

```text
Pr[M singular] >= 0.61878098.
```

The Appendix A key is therefore a concrete deterministic instance, while the analytic lower bound shows, under the stated random-output model, that the problem is not confined to that test key.

### Missing per-matrix index

The published hash input, `SHA-256(K || domain_tag || 0x00)`, contains one domain tag per matrix dimension but no field distinguishing multiple matrices of the same dimension. Followed literally, the four `4 x 4` matrices would therefore be identical, and the two `8 x 8` matrices would be identical. The implementation includes an explicit two-byte matrix index, so matrices of the same dimension are separately derived.

Both omissions are substantive when the published prose is followed literally.

## 2. Correct implemented derivation

The April 20, 2026 Revision 3 reference implementation uses a collision-safe, index-separated parameter-selection procedure. Here, “Revision 3” is a software/reference-code revision designation, not a revision of the journal article or manuscript.

For each required matrix, successive SHA-256 outputs are generated as

```text
H_c = SHA-256(master_key || tag || uint16(index) || uint32(counter)),
```

where `tag` is the **dimension-specific** domain-separation tag, `index` distinguishes matrices of the same dimension, and `counter` is incremented for successive SHA-256 blocks.

The implementation concatenates successive `H_c` values until `max(128, 8n)` candidate bytes have been generated. For the implemented dimensions `n in {4, 8, 16}`, this quantity is 128 bytes. The candidate stream is then scanned sequentially. A byte is discarded if it is `0x00` or if it has already been selected for that matrix. One duplicate-rejection set is shared across both `X` and `Y`. The first `n` accepted bytes form `X`, and the next `n` accepted bytes form `Y`.

In pseudocode:

```python
X, Y = [], []
seen = set()

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
```

If fewer than `2n` acceptable values are obtained from the candidate stream, derivation fails closed and no matrix is assembled, thereby preventing construction of a matrix that violates the pairwise-distinctness requirement.

Consequently, every assembled matrix uses `2n` pairwise-distinct Cauchy parameters. The implementation additionally excludes `0x00` as a construction convention; excluding zero is not itself required by the Cauchy nonsingularity condition.

The matrix is then formed as

```text
M[i][j] = inverse_GF256(X[i] XOR Y[j]).
```

The dimension-specific tags and indices are:

- `MDHILL_4`, indices 0 through 3;
- `MDHILL_8`, indices 0 and 1;
- `MDHILL_16`, index 0.

This procedure is implemented in `MD-Hill-SPN_test_vector_rev3_20260420.py` and the Revision 3 metric program; the same construction is retained in the later shared core implementation.

## 3. Prepublication provenance

Repository records indicate that the collision-safe, index-separated Revision 3 reference implementation was present in the public repository on 22 April 2026, before publication of the journal article on 17 June 2026 and before the August 2026 critique.

The earliest commit presently visible in the public repository history is:

```text
32b0b01b92e462346a60f21e7b9f35a648b9eb92
```

Permanent commit link:

https://github.com/ja9925ydbsu/MH_Hill_SPN/commit/32b0b01b92e462346a60f21e7b9f35a648b9eb92

The relevant Git blob identifiers are:

```text
MD-Hill-SPN_test_vector_rev3_20260420.py
48a53dc11b65bc014f034bc06a9feb1af57509d0

Revision 3 metric program
309875decf5f30b2ae7d5f06ac043671911d13e0
```

The files were later removed and re-uploaded during repository reorganization, but the matching blob identifiers indicate that the present file contents are identical to the contents recorded in the 22 April 2026 commit.

This chronology indicates that the pairwise-distinct, index-separated construction was present before publication and was not introduced in response to the later criticism. The discrepancy arose between the implemented algorithm and the prose specification that appeared in the published article.

## 4. MDS and branch number

For an arbitrary linear map `M` over `GF(2^8)`, the branch number is

```text
B(M) = min_(a != 0) [ wt(a) + wt(Ma) ],
```

where `wt` denotes the number of nonzero `GF(2^8)` coordinates.

Enumeration restricted to weight-one inputs does not, by itself, establish this minimum for an arbitrary matrix. A singular matrix can have full-support columns and therefore return `n + 1` under weight-one testing while possessing a higher-weight kernel vector that gives a smaller true branch number.

For the singular `16 x 16` matrix produced by the literal Section 3.9 derivation for the Appendix A key, the weight-one procedure returns 17 because every column has full symbol weight. However, a right-kernel vector of symbol weight 16 satisfies `M_16 a = 0`, giving

```text
wt(a) + wt(M_16 a) = 16.
```

Thus the true branch number is at most 16. This example illustrates why weight-one enumeration cannot serve as a stand-alone test of nonsingularity or as an independent proof that an arbitrary matrix is MDS.

For the corrected construction, the mathematical justification is the Cauchy MDS property. Because all `2n` Cauchy parameters are pairwise distinct, every square submatrix is nonsingular and

```text
B(M) = n + 1.
```

Accordingly, the intended diffusion matrices have branch numbers:

```text
4 x 4   -> B = 5
8 x 8   -> B = 9
16 x 16 -> B = 17
```

The weight-one computation is therefore an **implementation consistency check** of the Cauchy MDS construction, not an independent proof of MDS or of the true branch number for an arbitrary matrix.

## 5. Effect on the repository and published results

No cryptographic algorithm change is made by this repository correction. The implementation used to generate the published results already enforces pairwise-distinct, index-separated Cauchy parameters. The published Appendix A test vector, Round-0 intermediate values, 12-round ciphertext, decryption round trip, and metric results correspond to that implementation.

The historical journal PDF is intentionally retained unchanged in this repository as the published record. This note documents the discrepancy rather than silently replacing that record.

No claim is made that this correction addresses broader cryptanalytic questions unrelated to the specification defects discussed here. Its purpose is solely to correct the published matrix-derivation procedure and associated branch-number rationale.

## 6. Corrected specification text

A corrected replacement for the relevant Section 3.9 matrix-generation paragraph is:

> Each diffusion matrix of dimension `n` is constructed as a Cauchy matrix over `GF(2^8)`. For each matrix, a deterministic candidate stream of `max(128, 8n)` bytes is generated by successive evaluations of `H_c = SHA-256(K || tag || I2OSP_2(index) || I2OSP_4(c))`, where `tag` is the dimension-specific domain-separation tag and `c` is an incrementing four-byte counter. For the implemented dimensions `n in {4, 8, 16}`, the candidate stream is 128 bytes. The stream is scanned sequentially, discarding `0x00` and every byte value already selected for that matrix. The first `n` accepted values form `X`, and the next `n` accepted values form `Y`. Thus all `2n` Cauchy parameters are pairwise distinct, which subsumes `X intersect Y = empty`. If fewer than `2n` acceptable values are obtained, derivation fails closed and no matrix is assembled. The two-byte index takes values 0 through 3 for the four `4 x 4` matrices, 0 and 1 for the two `8 x 8` matrices, and 0 for the `16 x 16` matrix, so matrices of the same dimension are separately derived. The matrix entries are `M[i][j] = (x_i XOR y_j)^(-1)`, with arithmetic in `GF(2^8)`. Because all Cauchy parameters are pairwise distinct, every square submatrix has nonzero determinant and the resulting matrix is MDS. Consequently, `B(M) = n + 1`. The implementation additionally checks the expected weight-one value as a consistency check.

The phrase “branch number computed exactly via exhaustive weight-1 enumeration” should correspondingly be replaced by:

> Branch number `B = n + 1` follows from the pairwise-distinct Cauchy MDS construction; weight-one enumeration provides an implementation consistency check and is not, by itself, a test of nonsingularity.

## 7. Acknowledgment

The author thanks Jean-Philippe Aumasson for identifying the discrepancy between the published matrix-generation description and the conditions required for a valid Cauchy MDS matrix. His observation that the literal published derivation produces a repeated Cauchy parameter for the Appendix A test key correctly exposed the specification error, and his analytic lower bound for the resulting singularity probability is confirmed above.

This repository note will be updated with a journal Correction DOI or permanent publication link if and when one becomes available.
