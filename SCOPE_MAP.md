# Scope map — ML-KEM in the pinned postfiatd tree

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55`
(tree: `/home/hatch/workspace/postfiatd-amendment/worktree-0085a1ff`).
The full audit record with exact commands and outputs is vendored at
`fixtures/pinned_tree_audit.json`; check K33 re-verifies it (and re-runs the
primary grep live when the tree is present).

## Step 1 result: there are no ML-KEM call sites to map

| Search | Result |
| --- | --- |
| `grep -ril 'ml-kem\|mlkem\|kyber' .` (whole tree, excl. `.git`) | 0 files |
| `grep -ril 'ml-kem\|mlkem\|kyber' src/` | 0 files |
| `grep -ril 'post.quantum\|postquantum' src/` | 0 files |
| `grep -ril 'x25519\|X25519' src/` | 0 files |
| `grep -rn 'kyber\|ml.kem\|mlkem' src/ docs/` | no matches |

One `pqc` substring hit exists inside a base64-encoded test blob
(`src/test/app/ValidatorSite_test.cpp:47`, a validator-list manifest fixture);
it is test data, not ML-KEM code.

Consequence, stated plainly: steps 1–3 of the assessment (map call sites,
ciphertext validation, error paths, combiner logic) have no in-tree subject.
The mapping below therefore records the absence, the cryptography the tree
does use, and where a KEM would have to attach. Every row is marked honestly
rather than filled with invented call sites.

## What cryptography the tree does use

| Area | Mechanism | Evidence |
| --- | --- | --- |
| Transaction / validation signing | ed25519 and secp256k1 | `src/libxrpl/protocol/PublicKey.cpp` (`KeyType::ed25519`, `ed25519Canonical`), `SecretKey.cpp` |
| Validator identity / manifests | ed25519 signatures over manifests | `src/xrpld/app/misc/detail/ValidatorKeys.cpp`, `Manifest_test.cpp` |
| Key exchange / KEM | none | 0 X25519/ECDH/KEM files in `src/` |

## Where a KEM would integrate (recommendation, not existing code)

| Integration point | What would change | Why it matters |
| --- | --- | --- |
| Peer/validator key exchange | Add an ML-KEM encapsulation step alongside the existing ed25519 validator identity, with a hybrid classical-plus-ML-KEM combiner (see K31/K32 for the combiner behaviour) | Today there is no key-exchange confidentiality layer for a KEM to protect; a KEM added without a defined transcript has nothing to bind to |
| Ciphertext validation | Validate encapsulation-key, ciphertext, and decapsulation-key lengths at the API boundary, and validate decapsulation-key consistency (`H(ek)` recomputation) at import (F-04) | The FIPS 203 math assumes well-formed inputs; the Wycheproof corrupted-key cases show what happens without validation |
| Decapsulation failure handling | Treat every decapsulation output as unauthenticated until key confirmation (F-02, F-06) | Implicit rejection is silent by design; there is no error to branch on |

## FIPS 203 citations used for the mapping

| FIPS 203 reference | Subject |
| --- | --- |
| §6.2, Table 2 | Parameter sets (k, η1, η2, du, dv) and key/ciphertext/shared-secret sizes — verified by K12/K13 and `verify_constants.py` |
| §7.1 (Algorithms 13–15) | K-PKE key generation, encryption, decryption — implemented in `scripts/mlkem_py.py`, validated by K01–K09 |
| §7.2 (Algorithms 16–17) | ML-KEM key generation and encapsulation; encapsulation-key validity is a caller duty |
| §7.3 (Algorithm 18) | ML-KEM decapsulation, implicit rejection (`K = J(z \|\| c)` on re-encryption mismatch), decapsulation-key validation |
| §4.3 (Algorithms 9–11) | NTT, inverse NTT, base-case multiplication — implemented and verified against the direct CRT definition and naive polynomial multiplication |
| §4.4 (Algorithms 7–8) | SamplePolyCBD, SampleNTT — exercised by the CCTV unlucky vectors (K34) |
