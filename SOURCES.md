# Sources

Primary sources only. Every measured or specification claim in this pack
traces to one of the entries below; the claim-to-evidence index
(`claim_evidence_index.md`) gives the per-claim mapping.

## Standards

- NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism
  Standard", DOI 10.6028/NIST.FIPS.203, 13 August 2024.
  https://csrc.nist.gov/pubs/fips/203/final
  (https://doi.org/10.6028/NIST.FIPS.203).
  Used for: parameter sets and sizes (Table 2, §8); K-PKE and ML-KEM
  algorithms (§7.1–§7.3, Algorithms 7–18); NTT (§4.3); sampling (§4.4);
  implicit rejection (§7.3). The pure-Python implementation
  (`scripts/mlkem_py.py`) was written from this standard and validated
  against the NIST ACVP vectors below.
- NIST FIPS 202 (SHA-3 / SHAKE), used via Python `hashlib` for H, G, J, PRF
  and XOF (§4.1 of FIPS 203).

## Test vectors (vendored in `fixtures/`)

- NIST ACVP ML-KEM keyGen vectors, FIPS203 revision, 75 cases
  (`fixtures/nist_keygen.json.gz`).
  Original source: NIST Automated Cryptographic Validation Protocol (ACVP)
  vector sets, as distributed in the `integritychain/fips203` repository
  (`tests/nist_vectors/ML-KEM-keyGen-FIPS203/internalProjection.json.gz`),
  commit `871fa546c7f3198e23b80cdd451d2ff1f39f4f20`.
  SHA-256: `40bbacc18b53e1a2f657ca5296887bbcd88d3999975bc9486f6e8749ba1c84af`
- NIST ACVP ML-KEM encapDecap vectors, FIPS203 revision, 165 cases
  (`fixtures/nist_encapdecap.json.gz`).
  Same provenance (`tests/nist_vectors/ML-KEM-encapDecap-FIPS203/`).
  SHA-256: `3bf035bbe11ab2c7b31a1ec1544c02bb94425ba74c088c96f37130579bb784e3`
- C2SP / Wycheproof ML-KEM decapsulation vectors
  (`fixtures/wycheproof_{512,768,1024}.json.gz`, 200/201/202 cases each),
  and semi-expanded decapsulation vectors
  (`fixtures/wycheproof_{512,768,1024}_semi.json.gz`, 9 cases each).
  Original source: C2SP Wycheproof ML-KEM test data, as distributed in
  `integritychain/fips203` (`tests/wycheproof/`), same commit as above.
  Groups used: FIPS 203 decaps cases, CCTV/strcmp trap, `007bsd`
  malleable-ciphertext cases, AWS-LC semi-expanded cases (including the
  corrupted-hash / corrupted-embedded-ek cases), `lukaszobernig/reenc`
  re-encryption-comparison traps.
- C2SP CCTV "unlucky" SampleNTT vectors
  (`fixtures/cctv_unlucky_{512,768,1024}.txt`).
  Original source: C2SP CCTV ML-KEM vectors, as distributed in
  `integritychain/fips203` (`tests/cctv_vectors/ML-KEM/unluckysample/`),
  same commit as above. Note (per that repository's `tests/cctv_vectors/main.rs`):
  the file's `(d, z)` do not regenerate `(ek, dk)`; only the
  encaps/decaps relations are asserted.
  SHA-256: 512 `9d4e0ae011978a8f88a49b755ea6996a693428aaea0477c84331580c15b77a9b`,
  768 `fede6f787581dc708e5c3337d7e49de33333d23023470668cd0588b65ad0ba90`,
  1024 `8da6cdb2fb0d4e2223dfa5229ec97d4ded7b93bd8b2202e9a7533850c817b8cd`.

## Implementations tested

- pyca/cryptography 50.0.2 (OpenSSL-backed ML-KEM-768/1024).
  https://cryptography.io/
- liboqs 0.16.0 via liboqs-python 0.16.0.2.
  https://github.com/open-quantum-safe/liboqs
- Pure-Python FIPS 203 implementation in this pack
  (`scripts/mlkem_py.py`), written from FIPS 203; validated against the
  NIST ACVP vectors above (checks K01–K09).

## Pinned tree

- postfiatd, commit `0085a1ff885d6a446369cf73a4430f75af22be55`
  (tree `/home/hatch/workspace/postfiatd-amendment/worktree-0085a1ff`).
  Audit record with exact commands and outputs:
  `fixtures/pinned_tree_audit.json`.

## Not used as sources

- The CCTV modulus and intermediate vectors in the same CCTV collection were
  inspected but not run: the modulus vectors need the CCTV modulus-test
  procedure (out-of-range-coefficient handling), which this pack does not
  implement; the intermediate vectors duplicate the ACVP coverage already
  provided by K01–K09. This is a stated scope boundary, not a claim about
  those vectors.
- No live-network source was consulted for any measured claim.
