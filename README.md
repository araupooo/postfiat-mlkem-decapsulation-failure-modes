# ML-KEM Decapsulation Failure-Mode Assessment

Audit of ML-KEM encapsulation/decapsulation failure modes across ML-KEM-512,
ML-KEM-768 and ML-KEM-1024: implicit rejection, decapsulation-failure oracle
checks, malformed inputs, corrupted keys, comparison traps, and hybrid
classical-plus-ML-KEM combiner behaviour.

## Scope

- Pinned postfiatd commit: `0085a1ff885d6a446369cf73a4430f75af22be55`.
- The pinned tree contains **no ML-KEM code** (verified by grep; see
  `SCOPE_MAP.md` and check K33). The failure modes were therefore confirmed
  against three independent reference implementations, not against pinned-tree
  code. That absence is itself the headline finding (F-01).
- No live-network testing. No mutation of the pinned tree. Local fixtures only.

## Implementations tested

| ID | Implementation | Parameter sets | Notes |
| --- | --- | --- | --- |
| A | pyca/cryptography 50.0.2 (OpenSSL-backed) | ML-KEM-768, ML-KEM-1024 | ML-KEM-512 is not exposed by this build; dk stored as the 64-byte seed |
| B | liboqs 0.16.0 (liboqs-python 0.16.0.2) | ML-KEM-512/768/1024 | Cannot import a seed or an expanded dk |
| C | `scripts/mlkem_py.py` (pure Python, written from FIPS 203) | ML-KEM-512/768/1024 | Validated against all 180 NIST ACVP known-answer cases |

## Results

34 harness checks, 34 passed, 0 failed (see `results/summary.txt`).
Headline numbers: 180 NIST ACVP known-answer cases reproduced exactly;
603 Wycheproof decapsulation cases pass; all cross-implementation interop
checks agree byte-for-byte. No Critical or High finding; highest severity is
Medium (F-01: ML-KEM absent from the pinned tree).

## How to reproduce

```sh
bash run_all.sh
```

Expected: exit 0, byte-identical outputs, clean git status. The script creates
a `.venv` and installs the pinned requirements on first run (needs network
once), then runs the full harness, the constants check, rebuilds the rendered
page, copies the clean-setup logs to `results/outputs/`, and verifies digests.
See `REPRODUCTION.md` for the exact commands and the recorded fresh-clone
result. Verify digests at any time with `bash verify_digests.sh --check`.

## Files

- `FINDINGS.md` — failure-mode matrix, prioritized findings with mitigations
- `SCOPE_MAP.md` — pinned-tree audit and where a KEM would integrate
- `claim_evidence_index.md` — every material claim mapped to a check or source
- `SOURCES.md` — primary sources and fixture provenance
- `REPRODUCTION.md` — fresh-copy reproduction instructions and recorded result
- `scripts/mlkem_py.py` — pure-Python FIPS 203 implementation (test code only:
  not constant-time, never use to protect real data)
- `scripts/run_checks.py` — the harness (34 checks)
- `scripts/verify_constants.py` — FIPS 203 Table 2 constants check
- `scripts/build_derived.py` — builds `docs/index.html`
- `fixtures/` — NIST ACVP vectors, Wycheproof vectors, CCTV unlucky vectors,
  FIPS 203 constants, pinned-tree audit record
- `results/` — run log, summaries, per-check outputs, digests, fresh
  clean-setup logs under `results/outputs/`
- `docs/index.html` — rendered results page
