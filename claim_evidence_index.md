# Claim-to-evidence index

Every material claim in this pack is mapped to a runnable check or a
primary-source citation. "TESTED" means the harness ran the check;
"SOURCE-DERIVED" means the claim rests on a primary source plus the absence
finding (no code exists to run). Check outputs live in `results/checks/`;
the full log is `results/run_log.txt`.

## Pinned tree

| Claim | Evidence |
| --- | --- |
| The pinned tree (0085a1ff…) contains no ML-KEM/Kyber code | TESTED K33; `fixtures/pinned_tree_audit.json` (exact commands + outputs) |
| The tree's cryptography is ed25519/secp256k1 signing only | TESTED K33; `src/libxrpl/protocol/PublicKey.cpp` |
| No X25519/ECDH/KEM exists in `src/` | TESTED K33 |
| The one `pqc` hit is base64 test-blob data, not code | SOURCE-DERIVED (SCOPE_MAP.md); `src/test/app/ValidatorSite_test.cpp:47` |

## FIPS 203 parameters and sizes

| Claim | Evidence |
| --- | --- |
| ML-KEM-512: k=2, η1=3, η2=2, du=10, dv=4; ek 800, dk 1632, ct 768, ss 32 | TESTED K13 + `verify_constants.py`; FIPS 203 Table 2 |
| ML-KEM-768: k=3, η1=2, η2=2, du=10, dv=4; ek 1184, dk 2400, ct 1088, ss 32 | TESTED K12, K13 + `verify_constants.py`; FIPS 203 Table 2 |
| ML-KEM-1024: k=4, η1=2, η2=2, du=11, dv=5; ek 1568, dk 3168, ct 1568, ss 32 | TESTED K12, K13 + `verify_constants.py`; FIPS 203 Table 2 |
| q=3329, n=256, ζ=17 | TESTED `verify_constants.py`; FIPS 203 §4.1/§8 |

## Implementation correctness (Impl C vs NIST ACVP)

| Claim | Evidence |
| --- | --- |
| Impl C reproduces all 25 keyGen KAT cases per parameter set | TESTED K01, K02, K03 |
| Impl C reproduces all 25 encapsulation KAT cases per set | TESTED K04, K05, K06 |
| Impl C reproduces all 10 decapsulation KAT cases per set | TESTED K07, K08, K09 |
| Impl C reproduces the CCTV unlucky-SampleNTT vectors | TESTED K34 |

## Production implementations

| Claim | Evidence |
| --- | --- |
| Impl A decapsulates the Wycheproof seed-pinned cases for 768/1024, including strcmp and malleable traps | TESTED K10, K11 |
| Impl A sizes match FIPS 203 Table 2; dk stored as the 64-byte seed | TESTED K12 |
| Impl A does not expose ML-KEM-512 in this environment | TESTED K12 (only MLKEM768/1024 classes exist in cryptography 50.0.2) |
| Impl B sizes match Table 2 for all three sets | TESTED K13 |
| Impl B round-trips on fresh keypairs (10 per set) | TESTED K14 |
| Impl B cannot import a seed or an expanded dk | SOURCE-DERIVED (liboqs-python API surface, probed in K29/K30 notes) |

## Cross-implementation agreement

| Claim | Evidence |
| --- | --- |
| B encaps under C keys -> C decaps to the same secret (all sets) | TESTED K15 |
| C encaps under B keys -> B decaps to the same secret (all sets) | TESTED K16 |
| A encaps under C keys -> C decaps to the same secret (768/1024) | TESTED K17 |
| C encaps under A keys -> A decaps to the same secret (768/1024) | TESTED K18 |

## Implicit rejection and oracle behaviour

| Claim | Evidence |
| --- | --- |
| Random invalid ciphertext -> 32-byte secret, no error, != valid secret | TESTED K19 (512), K20 (768), K21 (1024) |
| All-zero ciphertext -> implicit rejection | TESTED K23 |
| Single-bit flip at byte 0/middle/last -> implicit rejection | TESTED K24 |
| Ciphertext from another keypair -> implicit rejection | TESTED K25 |
| Implicit rejection is deterministic: same invalid ct -> same key (`K = J(z \|\| c)`) | TESTED K22; FIPS 203 §7.3 |
| Valid vs invalid decapsulation indistinguishable by type/length/exception | TESTED K26 |
| Timing side-channels were NOT measured | SOURCE-DERIVED (stated limitation, FINDINGS.md) |

## Malformed inputs and corrupted keys

| Claim | Evidence |
| --- | --- |
| Truncated/empty/oversized ct and dk are rejected with an error, never a secret | TESTED K27 |
| Wycheproof malformed-length cases (40 per set) are rejected | TESTED K28 |
| Corrupted dk (bad stored hash / bad embedded ek) is rejected at key validation, even though the corrupted-hash key passes re-encryption | TESTED K30; FIPS 203 §7.3 |
| The bare FIPS 203 pseudocode assumes well-formed inputs; validation is a deployment duty | SOURCE-DERIVED (FIPS 203 Algorithms 16–18 vs §7.2/§7.3 validation) |

## Comparison traps

| Claim | Evidence |
| --- | --- |
| CCTV strcmp trap (difference after a NUL byte) returns the rejection key in all three testable implementations | TESTED K29 |
| Malleable-ciphertext cases (byte-0 modification) return the rejection key | TESTED K29 |
| Re-encryption comparison traps (c1/c2 last byte zeroed) return the rejection key | TESTED K30 |

## Hybrid combiner

| Claim | Evidence |
| --- | --- |
| Concat-KDF hybrid is reproducible; invalid ML-KEM ct or wrong classical peer changes it silently | TESTED K31 |
| Transcript binding changes the hybrid key | TESTED K31 |
| Malformed combiner inputs are rejected | TESTED K31 |
| XOR combiner: hybrid XOR classical recovers the ML-KEM secret exactly | TESTED K32 |

## Findings

| Claim | Evidence |
| --- | --- |
| F-01 (Medium): no ML-KEM in the pinned tree | TESTED K33 |
| F-02 (Low): implicit rejection is silent by design | TESTED K19–K26 |
| F-03 (Low): comparison must cover the full ciphertext | TESTED K29, K24, K30 |
| F-04 (Low): dk validation is a boundary duty | TESTED K27, K28, K30 |
| F-05 (Low): XOR combiner leaks component secrets | TESTED K32 |
| F-06 (Informational): hybrid failure invisible without key confirmation | TESTED K31 |
| No Critical/High finding | TESTED K01–K34 (34 passed, 0 failed) |
