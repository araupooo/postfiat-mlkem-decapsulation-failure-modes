# ML-KEM Decapsulation Failure-Mode Assessment — Findings

Pinned postfiatd commit: `0085a1ff885d6a446369cf73a4430f75af22be55`.
Scope: ML-KEM encapsulation/decapsulation failure modes across ML-KEM-512,
ML-KEM-768 and ML-KEM-1024, tested with local fixtures only against three
independent implementations (pyca/cryptography = Impl A, liboqs = Impl B,
pure-Python FIPS 203 = Impl C). No live-network testing, no mutation of the
pinned tree. Every finding below names the checks that confirm it; the
claim-to-evidence index (`claim_evidence_index.md`) maps every material claim
to a runnable check or a primary-source citation.

Headline: no Critical or High finding. The most consequential result is F-01:
the pinned tree contains no ML-KEM code at all, so there is no ML-KEM attack
surface in-tree — and no ML-KEM capability either. All other findings are
integration risks in code that would consume ML-KEM, confirmed against
reference implementations.

## Failure-mode matrix

<!-- MATRIX-START -->
| ID | Failure mode | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 | Status | Checks |
| --- | --- | --- | --- | --- | --- | --- |
| FM-01 | No ML-KEM code in pinned tree | absent | absent | absent | CONFIRMED | K33 |
| FM-02 | Random invalid ciphertext accepted as valid | rejected (implicit) | rejected (implicit) | rejected (implicit) | CONFIRMED (by design) | K19, K20, K21 |
| FM-03 | All-zero ciphertext accepted as valid | rejected (implicit) | rejected (implicit) | rejected (implicit) | CONFIRMED (by design) | K23 |
| FM-04 | Single-bit-flipped ciphertext accepted as valid | rejected (implicit) | rejected (implicit) | rejected (implicit) | CONFIRMED (by design) | K24 |
| FM-05 | Ciphertext from another keypair accepted | rejected (implicit) | rejected (implicit) | rejected (implicit) | CONFIRMED (by design) | K25 |
| FM-06 | Implicit rejection is deterministic (same invalid ct -> same key) | yes | yes | yes | CONFIRMED | K22 |
| FM-07 | Valid vs invalid decapsulation distinguishable by error/length/type | no signal | no signal | no signal | CONFIRMED | K26 |
| FM-08 | Malformed-length ciphertext accepted | rejected (error) | rejected (error) | rejected (error) | CONFIRMED | K27, K28 |
| FM-09 | Malformed-length decapsulation key accepted | rejected (error) | rejected (error) | rejected (error) | CONFIRMED | K27, K28, K30 |
| FM-10 | Corrupted dk (bad stored hash / bad embedded ek) accepted | rejected (error) | rejected (error) | rejected (error) | CONFIRMED | K30 |
| FM-11 | strcmp-style comparison fooled (difference after NUL byte) | not fooled | not fooled | not fooled | CONFIRMED | K29 |
| FM-12 | Malleable ciphertext (byte-0 modification) missed | detected | detected | detected | CONFIRMED | K29 |
| FM-13 | Re-encryption comparison skips part of c1/c2 | detected | detected | detected | CONFIRMED | K30 |
| FM-14 | Hybrid combiner failure raises an error | no (silent) | no (silent) | no (silent) | CONFIRMED | K31 |
| FM-15 | XOR combiner leaks a component secret | leaks | leaks | leaks | CONFIRMED | K32 |
| FM-16 | Cross-implementation disagreement (KAT / interop) | none found | none found | none found | CONFIRMED | K01–K18, K34 |
<!-- MATRIX-END -->

"Rejected (implicit)" means decapsulation returns a 32-byte pseudorandom
secret different from the valid secret, with no error (FIPS 203 §7.3
implicit rejection). "Rejected (error)" means the checked entry point raises
`ValueError` before returning anything.

## Findings

### F-01 — Medium, CONFIRMED: the pinned tree contains no ML-KEM code

**Checks:** K33.

**Evidence.** `grep -ril 'ml-kem|mlkem|kyber'` over the whole pinned tree
(excluding `.git`) returns 0 files; the same over `src/` returns 0 files.
`grep -ril 'post.quantum|postquantum' src/` returns 0 files and
`grep -ril 'x25519|X25519' src/` returns 0 files. The tree's cryptography is
classical signing only (ed25519/secp256k1, e.g.
`src/libxrpl/protocol/PublicKey.cpp`). One `pqc` substring hit exists inside
a base64 test blob (`src/test/app/ValidatorSite_test.cpp:47`); it is
test-fixture data, not ML-KEM code. The full audit record with exact commands
is vendored at `fixtures/pinned_tree_audit.json`.

**Impact.** Any claim that postfiatd at this commit ships, uses, or has been
audited for ML-KEM is false. There is no ML-KEM attack surface in-tree — but
also no ML-KEM capability: a post-quantum migration has nowhere to attach
today, and the failure modes in this assessment were necessarily confirmed
against reference implementations, not against pinned-tree code.

**Mitigation.** Integrate ML-KEM through a vetted library (liboqs or an
OpenSSL-backed binding) at a defined point — the natural attachment is the
peer/validator key-exchange path, which today has no KEM at all — and add the
NIST ACVP keyGen/encapDecap vectors to CI so the integration is tested
against the standard from day one.

### F-02 — Low, CONFIRMED (by design): implicit rejection is silent

**Checks:** K19, K20, K21, K22, K23, K24, K25, K26.

**Evidence.** Across all three parameter sets and all three implementations,
every invalid ciphertext (random, all-zero, single-bit-flipped, or from
another keypair) decapsulates to a 32-byte secret with no error (K19–K21,
K23–K25). The rejection is deterministic: the same invalid ciphertext always
yields the same pseudorandom secret, `K = J(z || c)` (K22, FIPS 203 §7.3).
Valid and invalid decapsulation are indistinguishable by return type, return
length, and exception behaviour (K26).

**Impact.** This is the specified behaviour (FIPS 203 §7.3), not a bug — but
it is a failure mode for integrators: a caller that treats "decapsulation
returned 32 bytes" as success will accept a rejection key as a session key.
The failure is silent by design, so it cannot be detected at the decapsulation
call site at all.

**Mitigation.** Never treat the decapsulation output as authenticated. Add a
key-confirmation step (e.g. a transcript MAC under the derived key) before
the shared secret is used, and fail closed if confirmation fails. Timing
side-channels were not measured by this harness; a production deployment
should additionally require a constant-time decapsulation implementation.

### F-03 — Low, CONFIRMED (trap cases pass): the ciphertext comparison must cover the full ciphertext

**Checks:** K29, K24, K30.

**Evidence.** All three implementations return the implicit-rejection key
(never the real key) for the CCTV strcmp trap (a ciphertext whose
re-encryption differs only after a `0x00` byte, which a `strcmp()`-based
comparison would judge equal), for the malleable-ciphertext cases (modification
at byte 0), and for the re-encryption comparison traps (last byte of c1/c2
zeroed). Bit flips at bytes 0, middle, and last are all detected (K24).

**Impact.** Low for the implementations tested — they all pass — but the trap
vectors exist precisely because real implementations have failed this way. A
comparison that short-circuits, skips a position, or stops at a NUL byte turns
a modified ciphertext into a valid one and returns the real shared secret.

**Mitigation.** Compare the received ciphertext with the re-encrypted
ciphertext over its full length with a constant-time comparison
(`hmac.compare_digest` / `CRYPTO_memcmp`); never use `strcmp`, `memcmp` with
early exit, or a loop that skips positions. Add the CCTV strcmp, malleable,
and re-encryption vectors to CI.

### F-04 — Low, CONFIRMED: decapsulation-key validation is a boundary duty, not part of the math

**Checks:** K27, K28, K30.

**Evidence.** The bare FIPS 203 pseudocode (Algorithms 16–18) assumes
well-formed inputs and performs no length or key validation. The Wycheproof
semi-expanded cases prove the point: a decapsulation key with a corrupted
stored hash, and one with a corrupted embedded encapsulation key, both have
correct lengths — and the corrupted-hash key even passes the re-encryption
check (`c == c'`) — yet both must be rejected (K30). The checked entry points
in this pack reject them at key validation (FIPS 203 §7.3: recompute `H(ek)`
and compare with the stored hash; compare the embedded ek with the expected
ek). Malformed-length seeds, ciphertexts, and keys are likewise rejected with
`ValueError`, never with a secret (K27, K28).

**Impact.** An integrator that calls the raw decapsulation math without the
validation step silently accepts corrupted keys. The corrupted-hash case is
the sharpest: the key still "works", so nothing downstream notices.

**Mitigation.** Validate at the API boundary, before any decapsulation:
reject wrong-length seeds, keys, and ciphertexts, and validate the
decapsulation key's internal consistency (`H(ek)` recomputation, embedded-ek
match). Ship the validation with the KEM wrapper, not as caller folklore.

### F-05 — Low, CONFIRMED: an XOR combiner leaks component secrets

**Checks:** K32.

**Evidence.** With `hybrid = classical XOR mlkem`, knowledge of the classical
component recovers the ML-KEM component exactly (`hybrid XOR classical ==
mlkem`), demonstrated algebraically in the harness. An invalid ML-KEM
ciphertext also changes the hybrid silently (K32, K31).

**Impact.** If either component is ever attacker-known (e.g. a classical key
compromise, which is exactly the scenario a hybrid is meant to survive), the
XOR combiner hands the attacker the other component. The hybrid then provides
no more security than its weakest component — and fails silently.

**Mitigation.** Use the concat-KDF combiner (HKDF over `classical ||
mlkem`, bound to a transcript, as in K31) with domain separation. Never ship
an XOR combiner where either component may be attacker-known.

### F-06 — Informational, CONFIRMED: hybrid combiner failure is invisible without key confirmation

**Checks:** K31.

**Evidence.** In the concat-KDF combiner, an invalid ML-KEM ciphertext and a
wrong classical peer key both change the hybrid secret with no error at any
layer (K31). Transcript binding works (a different transcript gives a
different key), and malformed combiner inputs are rejected — but no component
failure raises.

**Impact.** A hybrid handshake that skips key confirmation will complete with
a wrong shared secret and only fail later (or never, if the application does
not authenticate the transcript). The failure is silent at the layer where it
happens.

**Mitigation.** Bind the hybrid secret to the transcript and require a key
confirmation (e.g. a MAC over the transcript under the hybrid key) before the
session is used.

### Positive result — three implementations agree byte-for-byte

**Checks:** K01–K18, K34.

The pure-Python FIPS 203 implementation reproduces all 180 NIST ACVP
known-answer cases (75 keyGen, 75 encapsulation, 30 decapsulation) across
ML-KEM-512/768/1024, and the CCTV unlucky-SampleNTT vectors (K34). The
production libraries agree with it: pyca/cryptography reproduces the
Wycheproof seed-pinned cases for ML-KEM-768/1024 (K10, K11), liboqs round-trips
on fresh keypairs (K14), and cross-implementation encapsulation/decapsulation
agrees in both directions for every pair that can exchange keys (K15–K18).
No divergence was found between any two implementations on any valid input.

## Limitations (honest)

- The pinned tree has no ML-KEM code (F-01), so no finding here concerns
  pinned-tree ML-KEM code; the failure modes are confirmed against reference
  implementations and apply to a future integration.
- Impl A (pyca/cryptography) exposes ML-KEM-768/1024 only in this environment;
  ML-KEM-512 coverage comes from Impl B and Impl C.
- Impl B (liboqs Python binding) cannot import a seed or an expanded
  decapsulation key, so it cannot run the seed-pinned Wycheproof cases or the
  semi-expanded cases; its trap behaviour is covered by the bit-flip checks
  (K24) instead.
- The harness measures functional behaviour only. Timing side-channels,
  constant-time properties of the implementations, and fault-injection
  resistance were not measured.
- The pure-Python implementation (Impl C) is a test implementation: it is not
  constant-time and must never protect real data.
