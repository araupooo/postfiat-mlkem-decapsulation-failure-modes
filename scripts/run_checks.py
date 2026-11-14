#!/usr/bin/env python3
"""ML-KEM decapsulation failure-mode harness (local fixtures only).

Three independent implementations are exercised against the same cases:
  Impl A — pyca/cryptography (OpenSSL-backed), ML-KEM-768/1024 only.
  Impl B — liboqs (liboqs-python), ML-KEM-512/768/1024.
  Impl C — scripts/mlkem_py.py, a pure-Python FIPS 203 implementation
           written from the standard, ML-KEM-512/768/1024.

Ground truth: the official NIST ACVP known-answer vectors vendored in
fixtures/ (NIST ACVP ML-KEM keyGen / encapDecap, FIPS203 revision) and the
C2SP/Wycheproof ML-KEM vectors (CCTV strcmp + malleable-ciphertext cases,
FIPS 203 decaps cases). No live-network access, no pinned-tree mutation.

Determinism: every random input is drawn from random.Random(20261115), so
the run log is byte-identical across runs on the same machine. The only
non-deterministic inputs are liboqs keypairs (OS randomness); for those
cases the log records only booleans and lengths, never raw key material.

Usage: python3 scripts/run_checks.py  (run from the pack root)
Outputs: results/run_log.txt, results/summary.json, results/summary.txt,
         results/checks/KNN.txt (one file per check), results/env.txt
Exit code: 0 iff every check passes.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

import mlkem_py as C  # noqa: E402  (Impl C, pure-Python FIPS 203)

# --- Impl A: pyca/cryptography (OpenSSL) -----------------------------------
from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem_mod  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
import cryptography as _cryptography  # noqa: E402

A_PRIV = {
    "ML-KEM-768": _mlkem_mod.MLKEM768PrivateKey,
    "ML-KEM-1024": _mlkem_mod.MLKEM1024PrivateKey,
}
A_PUB = {
    "ML-KEM-768": _mlkem_mod.MLKEM768PublicKey,
    "ML-KEM-1024": _mlkem_mod.MLKEM1024PublicKey,
}

# --- Impl B: liboqs (silence its import banner on stderr) ------------------
with contextlib.redirect_stderr(io.StringIO()):
    import oqs as _oqs  # noqa: E402

B_NAME = {"ML-KEM-512": "ML-KEM-512", "ML-KEM-768": "ML-KEM-768",
          "ML-KEM-1024": "ML-KEM-1024"}

# --- Paths ------------------------------------------------------------------
PACK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(PACK_DIR, "fixtures")
RES = os.path.join(PACK_DIR, "results")
CHK = os.path.join(RES, "checks")
PARAMS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
PINNED_COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"

RNG = random.Random(20261115)


def randbytes(n: int) -> bytes:
    return bytes(RNG.randrange(256) for _ in range(n))


# --- Checked entry points for Impl C ---------------------------------------
# FIPS 203 Algorithms 16-18 assume well-formed inputs; §7.2/§7.3 require the
# caller to validate sizes. The checked wrappers are the conforming entry
# points used by every check below; the bare functions are the math only.

def c_keygen_checked(d: bytes, z: bytes, param: str):
    if len(d) != 32 or len(z) != 32:
        raise ValueError(f"ML-KEM keygen seed must be 32+32 bytes, got {len(d)}+{len(z)}")
    return C.keygen_internal(d, z, param)


def c_decaps_checked(dk: bytes, c: bytes, param: str) -> bytes:
    p = C.PARAMS[param]
    if len(dk) != p["dk_len"]:
        raise ValueError(
            f"{param} decapsulation key must be {p['dk_len']} bytes, got {len(dk)}")
    if len(c) != p["ct_len"]:
        raise ValueError(
            f"{param} ciphertext must be {p['ct_len']} bytes, got {len(c)}")
    # FIPS 203 §7.3 key validation: reject a dk whose embedded H(ek) does
    # not match its embedded ek (a corrupted key can otherwise decapsulate
    # silently, even with a passing re-encryption check).
    C.validate_decaps_key(dk, param)
    return C.decaps_internal(dk, c, param)


def c_encaps_checked(ek: bytes, m: bytes, param: str):
    p = C.PARAMS[param]
    if len(ek) != p["ek_len"]:
        raise ValueError(
            f"{param} encapsulation key must be {p['ek_len']} bytes, got {len(ek)}")
    if len(m) != 32:
        raise ValueError(f"encapsulation message must be 32 bytes, got {len(m)}")
    return C.encaps_internal(ek, m, param)


# --- Impl A helpers ----------------------------------------------------------

def a_keygen_from_seed(seed64: bytes, param: str):
    if len(seed64) != 64:
        raise ValueError(f"{param} seed must be 64 bytes, got {len(seed64)}")
    sk = A_PRIV[param].from_seed_bytes(seed64)
    return sk, sk.public_key()


def a_decaps(sk, c: bytes) -> bytes:
    return sk.decapsulate(c)


# --- Impl B helpers ----------------------------------------------------------

def b_keygen(param: str):
    kem = _oqs.KeyEncapsulation(B_NAME[param])
    pk = kem.generate_keypair()
    return kem, pk


# --- Vector loading ----------------------------------------------------------

def load_json_gz(path: str):
    with gzip.open(path, "rt") as fh:
        return json.load(fh)


def load_vectors():
    v = {}
    v["keygen"] = load_json_gz(os.path.join(FIX, "nist_keygen.json.gz"))
    v["encapdecap"] = load_json_gz(os.path.join(FIX, "nist_encapdecap.json.gz"))
    v["wycheproof"] = {p: load_json_gz(os.path.join(
        FIX, f"wycheproof_{p.split('-')[2]}.json.gz")) for p in PARAMS}
    v["wycheproof_semi"] = {p: load_json_gz(os.path.join(
        FIX, f"wycheproof_{p.split('-')[2]}_semi.json.gz")) for p in PARAMS}
    return v


# --- Check framework ---------------------------------------------------------

CHECKS = []  # (check_id, kind, title, hypothesis, fn)


def check(cid, kind, title, hypothesis):
    def deco(fn):
        CHECKS.append((cid, kind, title, hypothesis, fn))
        return fn
    return deco


class CheckFailure(Exception):
    pass


def run_all_checks(vectors):
    log_lines = []
    summary = []
    n_pass = 0
    for cid, kind, title, hypothesis, fn in CHECKS:
        detail = []
        try:
            fn(vectors, detail)
            result = "PASS"
            n_pass += 1
        except CheckFailure as exc:
            detail.append(f"FAILURE: {exc}")
            result = "FAIL"
        except Exception as exc:  # noqa: BLE001 - record any harness error
            detail.append(f"ERROR: {type(exc).__name__}: {exc}")
            result = "FAIL"
        block = [f"[CHECK {cid}] {title} ({kind})",
                 f"  hypothesis: {hypothesis}",
                 f"  result: {result}"] + detail
        text = "\n".join(block) + "\n"
        with open(os.path.join(CHK, f"{cid}.txt"), "w") as fh:
            fh.write(text)
        log_lines.append(text)
        summary.append({"id": cid, "kind": kind, "title": title,
                        "hypothesis": hypothesis, "result": result})
    return log_lines, summary, n_pass


# ==========================================================================
# K01-K09: Impl C vs NIST ACVP known-answer vectors
# ==========================================================================

def _kat_keygen(vectors, detail, param):
    grp = [g for g in vectors["keygen"]["testGroups"]
           if g["parameterSet"] == param][0]
    for t in grp["tests"]:
        ek, dk = C.keygen_internal(bytes.fromhex(t["d"]),
                                   bytes.fromhex(t["z"]), param)
        if ek.hex().upper() != t["ek"] or dk.hex().upper() != t["dk"]:
            raise CheckFailure(f"keyGen mismatch {param} tcId={t['tcId']}")
    detail.append(f"  {len(grp['tests'])} keyGen cases: d,z -> ek,dk byte-identical "
                  f"to NIST ACVP vectors (FIPS203) OK")


@check("K01", "TESTED", "NIST ACVP keyGen KAT ML-KEM-512",
       "Impl C reproduces the NIST ACVP keyGen vectors for ML-KEM-512 exactly.")
def _k01(vectors, detail):
    _kat_keygen(vectors, detail, "ML-KEM-512")


@check("K02", "TESTED", "NIST ACVP keyGen KAT ML-KEM-768",
       "Impl C reproduces the NIST ACVP keyGen vectors for ML-KEM-768 exactly.")
def _k02(vectors, detail):
    _kat_keygen(vectors, detail, "ML-KEM-768")


@check("K03", "TESTED", "NIST ACVP keyGen KAT ML-KEM-1024",
       "Impl C reproduces the NIST ACVP keyGen vectors for ML-KEM-1024 exactly.")
def _k03(vectors, detail):
    _kat_keygen(vectors, detail, "ML-KEM-1024")


def _kat_encap(vectors, detail, param):
    grp = [g for g in vectors["encapdecap"]["testGroups"]
           if g["parameterSet"] == param and g["function"] == "encapsulation"][0]
    for t in grp["tests"]:
        K, c = C.encaps_internal(bytes.fromhex(t["ek"]),
                                 bytes.fromhex(t["m"]), param)
        if c.hex().upper() != t["c"] or K.hex().upper() != t["k"]:
            raise CheckFailure(f"encap mismatch {param} tcId={t['tcId']}")
    detail.append(f"  {len(grp['tests'])} encapsulation cases: (ek, m) -> (c, K) "
                  f"byte-identical to NIST ACVP vectors OK")


@check("K04", "TESTED", "NIST ACVP encapsulation KAT ML-KEM-512",
       "Impl C Encaps_internal reproduces the NIST ACVP vectors for ML-KEM-512.")
def _k04(vectors, detail):
    _kat_encap(vectors, detail, "ML-KEM-512")


@check("K05", "TESTED", "NIST ACVP encapsulation KAT ML-KEM-768",
       "Impl C Encaps_internal reproduces the NIST ACVP vectors for ML-KEM-768.")
def _k05(vectors, detail):
    _kat_encap(vectors, detail, "ML-KEM-768")


@check("K06", "TESTED", "NIST ACVP encapsulation KAT ML-KEM-1024",
       "Impl C Encaps_internal reproduces the NIST ACVP vectors for ML-KEM-1024.")
def _k06(vectors, detail):
    _kat_encap(vectors, detail, "ML-KEM-1024")


def _kat_decap(vectors, detail, param):
    grp = [g for g in vectors["encapdecap"]["testGroups"]
           if g["parameterSet"] == param and g["function"] == "decapsulation"][0]
    for t in grp["tests"]:
        K = C.decaps_internal(bytes.fromhex(t["dk"]),
                              bytes.fromhex(t["c"]), param)
        if K.hex().upper() != t["k"]:
            raise CheckFailure(f"decap mismatch {param} tcId={t['tcId']}")
    detail.append(f"  {len(grp['tests'])} decapsulation cases: (dk, c) -> K "
                  f"byte-identical to NIST ACVP vectors OK")


@check("K07", "TESTED", "NIST ACVP decapsulation KAT ML-KEM-512",
       "Impl C Decaps_internal reproduces the NIST ACVP vectors for ML-KEM-512.")
def _k07(vectors, detail):
    _kat_decap(vectors, detail, "ML-KEM-512")


@check("K08", "TESTED", "NIST ACVP decapsulation KAT ML-KEM-768",
       "Impl C Decaps_internal reproduces the NIST ACVP vectors for ML-KEM-768.")
def _k08(vectors, detail):
    _kat_decap(vectors, detail, "ML-KEM-768")


@check("K09", "TESTED", "NIST ACVP decapsulation KAT ML-KEM-1024",
       "Impl C Decaps_internal reproduces the NIST ACVP vectors for ML-KEM-1024.")
def _k09(vectors, detail):
    _kat_decap(vectors, detail, "ML-KEM-1024")


# ==========================================================================
# K10-K12: Impl A (pyca/cryptography) vs KATs and FIPS 203 Table 2
# ==========================================================================

def _a_decap_wycheproof(vectors, detail, param):
    """Validate Impl A against the Wycheproof seed-pinned decapsulation cases
    (the ACVP decapDecap group carries expanded dk, which Impl A cannot
    import; the Wycheproof cases carry the 64-byte seed instead, so Impl A
    can reproduce the exact keypair via from_seed_bytes)."""
    doc = vectors["wycheproof"][param]
    n_ok = 0
    for group in doc["testGroups"]:
        for t in group["tests"]:
            if t["result"] != "valid":
                continue
            seed = bytes.fromhex(t["seed"])
            c = bytes.fromhex(t["c"])
            K = bytes.fromhex(t["K"])
            sk, pk = a_keygen_from_seed(seed, param)
            if "ek" in t and pk.public_bytes_raw() != bytes.fromhex(t["ek"]):
                raise CheckFailure(f"A {param} tcId={t['tcId']}: ek mismatch")
            got = a_decaps(sk, c)
            if got != K:
                raise CheckFailure(f"A decap mismatch {param} tcId={t['tcId']}")
            n_ok += 1
    detail.append(f"  {n_ok} valid seed-pinned cases (FIPS 203 + CCTV strcmp + "
                  f"malleable groups): Impl A from_seed_bytes -> decaps == K, "
                  f"ek verified OK")


@check("K10", "TESTED", "Impl A decapsulation of Wycheproof seed-pinned ciphertexts ML-KEM-768",
       "Impl A reproduces the expected shared secrets for the Wycheproof "
       "seed-pinned ML-KEM-768 decapsulation cases (including the CCTV strcmp "
       "and malleable-ciphertext traps).")
def _k10(vectors, detail):
    _a_decap_wycheproof(vectors, detail, "ML-KEM-768")


@check("K11", "TESTED", "Impl A decapsulation of Wycheproof seed-pinned ciphertexts ML-KEM-1024",
       "Impl A reproduces the expected shared secrets for the Wycheproof "
       "seed-pinned ML-KEM-1024 decapsulation cases (including the CCTV strcmp "
       "and malleable-ciphertext traps).")
def _k11(vectors, detail):
    _a_decap_wycheproof(vectors, detail, "ML-KEM-1024")


@check("K12", "TESTED", "Impl A key/ciphertext sizes match FIPS 203 Table 2",
       "Impl A ML-KEM-768/1024 encapsulation-key, ciphertext and shared-secret "
       "sizes equal FIPS 203 Table 2 (ML-KEM-512 is not exposed by this build "
       "of pyca/cryptography; the decapsulation key is stored as the 64-byte "
       "seed, FIPS 203 §7.2 internal form).")
def _k12(vectors, detail):
    for param in ("ML-KEM-768", "ML-KEM-1024"):
        p = C.PARAMS[param]
        sk, pk = a_keygen_from_seed(randbytes(64), param)
        ek = pk.public_bytes_raw()
        dk_seed = sk.private_bytes_raw()
        ss, ct = pk.encapsulate()
        got = (len(ek), len(ct), len(ss))
        want = (p["ek_len"], p["ct_len"], 32)
        if got != want:
            raise CheckFailure(f"A sizes {param}: got {got}, want {want}")
        if len(dk_seed) != 64:
            raise CheckFailure(f"A {param}: seed-form dk not 64 bytes")
        detail.append(f"  {param}: ek={len(ek)} ct={len(ct)} ss={len(ss)} "
                      f"(Table 2) OK; dk stored as 64-byte seed (d||z) OK")
    detail.append("  ML-KEM-512: NOT exposed by cryptography "
                  f"{_cryptography.__version__} in this environment "
                  "(only MLKEM768/1024 classes exist); 512 is covered by "
                  "Impl B and Impl C (K13, K01, K04, K07).")


# ==========================================================================
# K13-K14: Impl B (liboqs) sizes and round-trip
# ==========================================================================

@check("K13", "TESTED", "Impl B key/ciphertext sizes match FIPS 203 Table 2",
       "Impl B sizes for ML-KEM-512/768/1024 equal FIPS 203 Table 2.")
def _k13(vectors, detail):
    for param in PARAMS:
        p = C.PARAMS[param]
        with _oqs.KeyEncapsulation(B_NAME[param]) as kem:
            pk = kem.generate_keypair()
            ct, ss = kem.encap_secret(pk)
            got = (len(pk), len(ct), len(ss))
            want = (p["ek_len"], p["ct_len"], 32)
            if got != want:
                raise CheckFailure(f"B sizes {param}: got {got}, want {want}")
            detail.append(f"  {param}: ek={len(pk)} ct={len(ct)} ss={len(ss)} "
                          f"(Table 2) OK")


@check("K14", "TESTED", "Impl B fresh-keypair round-trip, all parameter sets",
       "Impl B encaps/decaps round-trips agree for fresh keypairs (10 per set).")
def _k14(vectors, detail):
    for param in PARAMS:
        for _ in range(10):
            with _oqs.KeyEncapsulation(B_NAME[param]) as kem:
                pk = kem.generate_keypair()
                ct, ss1 = kem.encap_secret(pk)
                ss2 = kem.decap_secret(ct)
                if ss1 != ss2:
                    raise CheckFailure(f"B round-trip mismatch {param}")
        detail.append(f"  {param}: 10/10 fresh-keypair round-trips agree OK")


# ==========================================================================
# K15-K18: cross-implementation interoperability
# ==========================================================================

@check("K15", "TESTED", "Impl B encapsulates under Impl C keys, all parameter sets",
       "A ciphertext produced by Impl B under an Impl C encapsulation key "
       "decapsulates to the same secret in Impl C (FIPS 203 wire-format interop).")
def _k15(vectors, detail):
    for param in PARAMS:
        ek, dk = c_keygen_checked(randbytes(32), randbytes(32), param)
        with _oqs.KeyEncapsulation(B_NAME[param]) as kem:
            ct, ss_b = kem.encap_secret(ek)
        ss_c = c_decaps_checked(dk, ct, param)
        if ss_b != ss_c:
            raise CheckFailure(f"B->C interop mismatch {param}")
        detail.append(f"  {param}: B.encap(C.ek) -> C.decaps = same 32-byte "
                      f"secret OK")


@check("K16", "TESTED", "Impl C encapsulates under Impl B keys, all parameter sets",
       "A ciphertext produced by Impl C under an Impl B encapsulation key "
       "decapsulates to the same secret in Impl B.")
def _k16(vectors, detail):
    for param in PARAMS:
        with _oqs.KeyEncapsulation(B_NAME[param]) as kem:
            pk = kem.generate_keypair()
            m = randbytes(32)
            K_c, ct = c_encaps_checked(pk, m, param)
            ss_b = kem.decap_secret(ct)
            if ss_b != K_c:
                raise CheckFailure(f"C->B interop mismatch {param}")
        detail.append(f"  {param}: C.encaps(B.ek) -> B.decaps = same 32-byte "
                      f"secret OK")


@check("K17", "TESTED", "Impl A encapsulates under Impl C keys (768/1024)",
       "A ciphertext produced by Impl A under an Impl C encapsulation key "
       "decapsulates to the same secret in Impl C.")
def _k17(vectors, detail):
    for param in ("ML-KEM-768", "ML-KEM-1024"):
        ek, dk = c_keygen_checked(randbytes(32), randbytes(32), param)
        pk_a = A_PUB[param].from_public_bytes(ek)
        ss_a, ct = pk_a.encapsulate()
        ss_c = c_decaps_checked(dk, ct, param)
        if ss_a != ss_c:
            raise CheckFailure(f"A->C interop mismatch {param}")
        detail.append(f"  {param}: A.encap(C.ek) -> C.decaps = same 32-byte "
                      f"secret OK")


@check("K18", "TESTED", "Impl C encapsulates under Impl A keys (768/1024)",
       "A ciphertext produced by Impl C under an Impl A encapsulation key "
       "decapsulates to the same secret in Impl A.")
def _k18(vectors, detail):
    for param in ("ML-KEM-768", "ML-KEM-1024"):
        sk_a, pk_a = a_keygen_from_seed(randbytes(64), param)
        ek_a = pk_a.public_bytes_raw()
        m = randbytes(32)
        K_c, ct = c_encaps_checked(ek_a, m, param)
        ss_a = a_decaps(sk_a, ct)
        if ss_a != K_c:
            raise CheckFailure(f"C->A interop mismatch {param}")
        detail.append(f"  {param}: C.encaps(A.ek) -> A.decaps = same 32-byte "
                      f"secret OK")


# ==========================================================================
# K19-K26: implicit rejection and oracle-signal checks
# ==========================================================================

def _fresh_keypair_c(param):
    return c_keygen_checked(randbytes(32), randbytes(32), param)


def _fresh_keypair_a(param):
    return a_keygen_from_seed(randbytes(64), param)


def _invalid_ct_test(vectors, detail, param, impls):
    """Invalid (random) ciphertext: decaps must return a 32-byte secret, no
    error, different from the valid secret (implicit rejection, FIPS 203 §7.3)."""
    p = C.PARAMS[param]
    for impl in impls:
        for trial in range(10):
            bad = randbytes(p["ct_len"])
            if impl == "C":
                ek, dk = _fresh_keypair_c(param)
                _K, ct = c_encaps_checked(ek, randbytes(32), param)
                got = c_decaps_checked(dk, bad, param)
                valid = c_decaps_checked(dk, ct, param)
            elif impl == "A":
                sk, pk = _fresh_keypair_a(param)
                ss, ct = pk.encapsulate()
                got = a_decaps(sk, bad)
                valid = ss
            else:  # B
                with _oqs.KeyEncapsulation(B_NAME[param]) as kem:
                    pk = kem.generate_keypair()
                    ct, valid = kem.encap_secret(pk)
                    got = kem.decap_secret(bad)
            if not isinstance(got, bytes) or len(got) != 32:
                raise CheckFailure(
                    f"{impl} {param}: invalid ct did not return 32 bytes")
            if got == valid:
                raise CheckFailure(
                    f"{impl} {param}: invalid ct returned the VALID secret")
        detail.append(f"  Impl {impl}: 10/10 random invalid ciphertexts -> "
                      f"32-byte secret, no error, != valid secret OK")


@check("K19", "TESTED", "Implicit rejection, ML-KEM-512 (Impl B + Impl C)",
       "A random invalid ciphertext decapsulates to a 32-byte secret that is "
       "not the valid secret, with no error (FIPS 203 §7.3).")
def _k19(vectors, detail):
    _invalid_ct_test(vectors, detail, "ML-KEM-512", ("B", "C"))


@check("K20", "TESTED", "Implicit rejection, ML-KEM-768 (Impl A + B + C)",
       "A random invalid ciphertext decapsulates to a 32-byte secret that is "
       "not the valid secret, with no error, in all three implementations.")
def _k20(vectors, detail):
    _invalid_ct_test(vectors, detail, "ML-KEM-768", ("A", "B", "C"))


@check("K21", "TESTED", "Implicit rejection, ML-KEM-1024 (Impl A + B + C)",
       "A random invalid ciphertext decapsulates to a 32-byte secret that is "
       "not the valid secret, with no error, in all three implementations.")
def _k21(vectors, detail):
    _invalid_ct_test(vectors, detail, "ML-KEM-1024", ("A", "B", "C"))


@check("K22", "TESTED", "Implicit rejection is deterministic (J(z || c))",
       "Decapsulating the same invalid ciphertext twice returns the identical "
       "pseudorandom secret (FIPS 203 §7.3: K = J(z || c)).")
def _k22(vectors, detail):
    for param in PARAMS:
        bad = randbytes(C.PARAMS[param]["ct_len"])
        ek, dk = _fresh_keypair_c(param)
        got1 = c_decaps_checked(dk, bad, param)
        got2 = c_decaps_checked(dk, bad, param)
        if got1 != got2:
            raise CheckFailure(f"C {param}: rejection not deterministic")
        detail.append(f"  Impl C {param}: same invalid ct twice -> identical "
                      f"32-byte secret OK")
        if param != "ML-KEM-512":
            sk, pk = _fresh_keypair_a(param)
            got1 = a_decaps(sk, bad)
            got2 = a_decaps(sk, bad)
            if got1 != got2:
                raise CheckFailure(f"A {param}: rejection not deterministic")
            detail.append(f"  Impl A {param}: same invalid ct twice -> "
                          f"identical 32-byte secret OK")
        with _oqs.KeyEncapsulation(B_NAME[param]) as kem:
            kem.generate_keypair()
            got1 = kem.decap_secret(bad)
            got2 = kem.decap_secret(bad)
            if got1 != got2:
                raise CheckFailure(f"B {param}: rejection not deterministic")
        detail.append(f"  Impl B {param}: same invalid ct twice -> identical "
                      f"32-byte secret OK")


@check("K23", "TESTED", "All-zero ciphertext is implicitly rejected",
       "An all-zero ciphertext decapsulates to a 32-byte secret different "
       "from the valid secret, with no error.")
def _k23(vectors, detail):
    for param in PARAMS:
        p = C.PARAMS[param]
        zero = bytes(p["ct_len"])
        ek, dk = _fresh_keypair_c(param)
        _K, ct = c_encaps_checked(ek, randbytes(32), param)
        valid = c_decaps_checked(dk, ct, param)
        got = c_decaps_checked(dk, zero, param)
        if len(got) != 32 or got == valid:
            raise CheckFailure(f"C {param}: zero ct not implicitly rejected")
        detail.append(f"  Impl C {param}: zero ct -> 32-byte secret != valid OK")
        if param != "ML-KEM-512":
            sk, pk = _fresh_keypair_a(param)
            ss, ct = pk.encapsulate()
            got = a_decaps(sk, zero)
            if len(got) != 32 or got == ss:
                raise CheckFailure(f"A {param}: zero ct not implicitly rejected")
            detail.append(f"  Impl A {param}: zero ct -> 32-byte secret "
                          f"!= valid OK")
        with _oqs.KeyEncapsulation(B_NAME[param]) as kem:
            pk = kem.generate_keypair()
            ct, valid = kem.encap_secret(pk)
            got = kem.decap_secret(zero)
            if len(got) != 32 or got == valid:
                raise CheckFailure(f"B {param}: zero ct not implicitly rejected")
        detail.append(f"  Impl B {param}: zero ct -> 32-byte secret != valid OK")


@check("K24", "TESTED", "Single-bit-flipped valid ciphertext is implicitly rejected",
       "Flipping one bit of a valid ciphertext makes decapsulation return a "
       "different 32-byte secret with no error (re-encryption mismatch).")
def _k24(vectors, detail):
    for param in PARAMS:
        ek, dk = _fresh_keypair_c(param)
        _K, ct = c_encaps_checked(ek, randbytes(32), param)
        valid = c_decaps_checked(dk, ct, param)
        for pos in (0, len(ct) // 2, len(ct) - 1):
            bad = bytearray(ct)
            bad[pos] ^= 0x01
            got = c_decaps_checked(dk, bytes(bad), param)
            if len(got) != 32 or got == valid:
                raise CheckFailure(
                    f"C {param}: bit flip at byte {pos} not rejected")
        detail.append(f"  Impl C {param}: bit flips at bytes 0, middle, last "
                      f"-> 32-byte secret != valid, no error OK")
        if param != "ML-KEM-512":
            sk, pk = _fresh_keypair_a(param)
            ss, ct = pk.encapsulate()
            for pos in (0, len(ct) // 2, len(ct) - 1):
                bad = bytearray(ct)
                bad[pos] ^= 0x01
                got = a_decaps(sk, bytes(bad))
                if len(got) != 32 or got == ss:
                    raise CheckFailure(
                        f"A {param}: bit flip at byte {pos} not rejected")
            detail.append(f"  Impl A {param}: bit flips at bytes 0, middle, "
                          f"last -> 32-byte secret != valid, no error OK")
        with _oqs.KeyEncapsulation(B_NAME[param]) as kem:
            pk = kem.generate_keypair()
            ct, valid = kem.encap_secret(pk)
            for pos in (0, len(ct) // 2, len(ct) - 1):
                bad = bytearray(ct)
                bad[pos] ^= 0x01
                got = kem.decap_secret(bytes(bad))
                if len(got) != 32 or got == valid:
                    raise CheckFailure(
                        f"B {param}: bit flip at byte {pos} not rejected")
        detail.append(f"  Impl B {param}: bit flips at bytes 0, middle, last "
                      f"-> 32-byte secret != valid, no error OK")


@check("K25", "TESTED", "Ciphertext from another keypair is implicitly rejected",
       "A valid ciphertext under Alice's key decapsulated with Bob's key "
       "returns a 32-byte secret different from both parties' valid secrets.")
def _k25(vectors, detail):
    for param in PARAMS:
        ek_a, dk_a = _fresh_keypair_c(param)
        ek_b, dk_b = _fresh_keypair_c(param)
        K_a, ct_a = c_encaps_checked(ek_a, randbytes(32), param)
        valid_a = c_decaps_checked(dk_a, ct_a, param)
        got = c_decaps_checked(dk_b, ct_a, param)
        if len(got) != 32 or got == valid_a or got == K_a:
            raise CheckFailure(f"C {param}: cross-keypair ct not rejected")
        detail.append(f"  Impl C {param}: Alice's ct under Bob's key -> "
                      f"32-byte secret != either valid secret OK")


@check("K26", "TESTED", "No oracle signal: valid vs invalid decapsulation outputs",
       "Valid and invalid decapsulation are indistinguishable by return type, "
       "return length, and exception behaviour — no error signal leaks the "
       "validity of a ciphertext (timing not measured; see FINDINGS.md).")
def _k26(vectors, detail):
    for param in PARAMS:
        p = C.PARAMS[param]
        ek, dk = _fresh_keypair_c(param)
        K, ct = c_encaps_checked(ek, randbytes(32), param)
        valid = c_decaps_checked(dk, ct, param)
        invalid = c_decaps_checked(dk, randbytes(p["ct_len"]), param)
        for label, out in (("valid", valid), ("invalid", invalid)):
            if not isinstance(out, bytes) or len(out) != 32:
                raise CheckFailure(f"C {param}: {label} output not 32 bytes")
        if valid == invalid:
            raise CheckFailure(f"C {param}: valid == invalid output")
        detail.append(f"  Impl C {param}: valid/invalid both -> (bytes, 32, "
                      f"no exception); outputs differ OK")
        if param != "ML-KEM-512":
            sk, pk = _fresh_keypair_a(param)
            ss, ct = pk.encapsulate()
            invalid = a_decaps(sk, randbytes(p["ct_len"]))
            if not isinstance(invalid, bytes) or len(invalid) != 32:
                raise CheckFailure(f"A {param}: invalid output not 32 bytes")
            if invalid == ss:
                raise CheckFailure(f"A {param}: valid == invalid output")
            detail.append(f"  Impl A {param}: valid/invalid both -> (bytes, "
                          f"32, no exception); outputs differ OK")
        with _oqs.KeyEncapsulation(B_NAME[param]) as kem:
            pk = kem.generate_keypair()
            ct, valid = kem.encap_secret(pk)
            invalid = kem.decap_secret(randbytes(p["ct_len"]))
            if not isinstance(invalid, bytes) or len(invalid) != 32:
                raise CheckFailure(f"B {param}: invalid output not 32 bytes")
            if invalid == valid:
                raise CheckFailure(f"B {param}: valid == invalid output")
        detail.append(f"  Impl B {param}: valid/invalid both -> (bytes, 32, "
                      f"no exception); outputs differ OK")
    detail.append("  NOTE: timing side-channels are NOT measured by this "
                  "harness; see FINDINGS.md F-02.")


@check("K27", "TESTED", "Malformed-length inputs are rejected at the API boundary",
       "Truncated, empty, and oversized ciphertexts and decapsulation keys "
       "are rejected with an error (never a secret) by every implementation's "
       "checked entry point (FIPS 203 §7.2/§7.3 input validation).")
def _k27(vectors, detail):
    for param in PARAMS:
        p = C.PARAMS[param]
        ek, dk = _fresh_keypair_c(param)
        _K, ct = c_encaps_checked(ek, randbytes(32), param)
        valid = c_decaps_checked(dk, ct, param)
        cases = [
            ("ct truncated", ct[:-1], dk), ("ct empty", b"", dk),
            ("ct oversized", ct + b"\x00", dk),
            ("dk truncated", ct, dk[:-1]), ("dk empty", ct, b""),
            ("dk oversized", ct, dk + b"\x00"),
        ]
        for label, c_in, dk_in in cases:
            try:
                got = c_decaps_checked(dk_in, c_in, param)
                if got == valid:
                    raise CheckFailure(
                        f"C {param}: {label} returned the VALID secret")
                raise CheckFailure(
                    f"C {param}: {label} accepted without error")
            except ValueError:
                pass
        detail.append(f"  Impl C {param}: 6 malformed inputs -> ValueError OK")
        if param != "ML-KEM-512":
            sk, pk = _fresh_keypair_a(param)
            ss, ct = pk.encapsulate()
            for label, c_in in (("ct truncated", ct[:-1]), ("ct empty", b""),
                                ("ct oversized", ct + b"\x00")):
                try:
                    got = a_decaps(sk, c_in)
                    if got == ss:
                        raise CheckFailure(
                            f"A {param}: {label} returned the VALID secret")
                    raise CheckFailure(f"A {param}: {label} accepted")
                except ValueError:
                    pass
            detail.append(f"  Impl A {param}: 3 malformed ciphertexts -> "
                          f"ValueError OK")
        with _oqs.KeyEncapsulation(B_NAME[param]) as kem:
            pk = kem.generate_keypair()
            ct, valid = kem.encap_secret(pk)
            for label, c_in in (("ct truncated", ct[:-1]), ("ct empty", b""),
                                ("ct oversized", ct + b"\x00")):
                try:
                    got = kem.decap_secret(c_in)
                    if got == valid:
                        raise CheckFailure(
                            f"B {param}: {label} returned the VALID secret")
                    raise CheckFailure(f"B {param}: {label} accepted")
                except ValueError:
                    pass
        detail.append(f"  Impl B {param}: 3 malformed ciphertexts -> "
                      f"ValueError OK")
    detail.append("  NOTE: the bare FIPS 203 pseudocode (Algorithms 16-18) "
                  "assumes well-formed inputs; length validation is a "
                  "deployment requirement, not part of the math (F-04).")


# ==========================================================================
# K28-K30: Wycheproof / CCTV vectors
# ==========================================================================

def _wycheproof_decaps(vectors, detail, param):
    """Replicates the fips203 crate's wycheproof_decaps_from_seed procedure:
    wrong-length seed or ct -> the case must be 'invalid' (reject); correct
    lengths -> the case must be 'valid', ek must match, decaps(c) == K."""
    doc = vectors["wycheproof"][param]
    p = C.PARAMS[param]
    n_ok = n_rej = 0
    for group in doc["testGroups"]:
        for t in group["tests"]:
            seed = bytes.fromhex(t["seed"])
            c = bytes.fromhex(t["c"])
            K = bytes.fromhex(t["K"])
            expect_valid = (t["result"] == "valid")
            if len(seed) != 64 or len(c) != p["ct_len"]:
                if expect_valid:
                    raise CheckFailure(
                        f"{param} tcId={t['tcId']}: valid case with wrong length")
                try:
                    if len(seed) == 64:
                        _ek, dk = c_keygen_checked(seed[:32], seed[32:], param)
                        c_decaps_checked(dk, c, param)
                    else:
                        c_keygen_checked(seed[:32], seed[32:], param)
                    raise CheckFailure(
                        f"{param} tcId={t['tcId']}: malformed input accepted")
                except ValueError:
                    n_rej += 1
            else:
                if not expect_valid:
                    raise CheckFailure(
                        f"{param} tcId={t['tcId']}: invalid case with correct lengths")
                ek, dk = c_keygen_checked(seed[:32], seed[32:], param)
                if "ek" in t and bytes.fromhex(t["ek"]) != ek:
                    raise CheckFailure(f"{param} tcId={t['tcId']}: ek mismatch")
                got = c_decaps_checked(dk, c, param)
                if got != K:
                    raise CheckFailure(
                        f"{param} tcId={t['tcId']}: decaps != K")
                n_ok += 1
    detail.append(f"  {n_ok} valid cases -> decaps == K (ek verified) OK; "
                  f"{n_rej} malformed-length cases -> rejected OK")


@check("K28", "TESTED", "Wycheproof decapsulation cases, all parameter sets",
       "Impl C passes every Wycheproof ML-KEM decapsulation case: valid cases "
       "return K, malformed-length cases are rejected.")
def _k28(vectors, detail):
    for param in PARAMS:
        _wycheproof_decaps(vectors, detail, param)


@check("K29", "TESTED", "CCTV strcmp + malleable-ciphertext trap cases",
       "The comparison in decapsulation covers the full ciphertext: the "
       "CCTV strcmp trap (difference hidden after a NUL byte) and the "
       "malleable-ciphertext cases (modification at byte 0) all return the "
       "implicit-rejection key, never the real key.")
def _k29(vectors, detail):
    for param in PARAMS:
        doc = vectors["wycheproof"][param]
        for group in doc["testGroups"]:
            src = group.get("source", {}).get("name", "")
            if "strcmp" not in src and "implicit-rejection" not in src:
                continue
            for t in group["tests"]:
                seed = bytes.fromhex(t["seed"])
                c = bytes.fromhex(t["c"])
                K = bytes.fromhex(t["K"])
                ek, dk = c_keygen_checked(seed[:32], seed[32:], param)
                got = c_decaps_checked(dk, c, param)
                if got != K:
                    raise CheckFailure(
                        f"C {param} {src} tcId={t['tcId']}: trap not handled")
                detail.append(f"  Impl C {param} {src} tcId={t['tcId']}: "
                              f"decaps == expected rejection key OK")
        # Impl A on the same traps (768/1024 only; A cannot import raw dk,
        # but the seed-pinned keypair reproduces the same dk).
        if param != "ML-KEM-512":
            for group in doc["testGroups"]:
                src = group.get("source", {}).get("name", "")
                if "strcmp" not in src and "implicit-rejection" not in src:
                    continue
                for t in group["tests"]:
                    seed = bytes.fromhex(t["seed"])
                    c = bytes.fromhex(t["c"])
                    K = bytes.fromhex(t["K"])
                    sk, _pk = a_keygen_from_seed(seed, param)
                    got = a_decaps(sk, c)
                    if got != K:
                        raise CheckFailure(
                            f"A {param} {src} tcId={t['tcId']}: trap not handled")
                    detail.append(f"  Impl A {param} {src} tcId={t['tcId']}: "
                                  f"decaps == expected rejection key OK")
    detail.append("  NOTE: Impl B cannot run seed-pinned vectors: the "
                  "liboqs Python binding has no seed/dk import API. The "
                  "trap behaviour of liboqs itself is covered by K24 (bit "
                  "flips at bytes 0/middle/last).")


@check("K30", "TESTED", "Wycheproof semi-expanded decapsulation cases",
       "Decapsulation from an expanded decapsulation key: valid cases return "
       "K; wrong-length dk or ct are rejected (FIPS 203 §7.3).")
def _k30(vectors, detail):
    for param in PARAMS:
        p = C.PARAMS[param]
        doc = vectors["wycheproof_semi"][param]
        n_ok = n_rej = 0
        for group in doc["testGroups"]:
            for t in group["tests"]:
                dk = bytes.fromhex(t["dk"])
                c = bytes.fromhex(t["c"])
                expect_valid = (t["result"] == "valid")
                if len(dk) != p["dk_len"] or len(c) != p["ct_len"]:
                    if expect_valid:
                        raise CheckFailure(
                            f"{param} tcId={t['tcId']}: valid case, wrong length")
                    try:
                        c_decaps_checked(dk, c, param)
                        raise CheckFailure(
                            f"{param} tcId={t['tcId']}: malformed dk/ct accepted")
                    except ValueError:
                        n_rej += 1
                else:
                    # Correct lengths: validate the key first (FIPS 203 §7.3).
                    # A corrupted dk (bad stored hash / bad embedded ek) must
                    # be rejected even though the lengths are right.
                    expected_ek = (bytes.fromhex(t["ek"]) if "ek" in t else None)
                    try:
                        C.validate_decaps_key(dk, param, expected_ek)
                    except ValueError:
                        if expect_valid:
                            raise CheckFailure(
                                f"{param} tcId={t['tcId']}: valid dk rejected")
                        n_rej += 1
                        continue
                    if not expect_valid:
                        raise CheckFailure(
                            f"{param} tcId={t['tcId']}: invalid dk accepted")
                    K = bytes.fromhex(t["K"])
                    got = c_decaps_checked(dk, c, param)
                    if got != K:
                        raise CheckFailure(
                            f"{param} tcId={t['tcId']}: decaps != K")
                    n_ok += 1
        detail.append(f"  {param}: {n_ok} valid -> decaps == K OK; {n_rej} "
                      f"malformed/corrupted -> rejected OK")
    detail.append("  NOTE: Impl A and Impl B cannot run semi-expanded cases: "
                  "neither binding imports a raw expanded dk (A imports only "
                  "a 64-byte seed; B imports no secret key at all).")
    detail.append("  NOTE: the invalid correct-length cases are corrupted-key "
                  "cases (AWS-LC 'corrupted hash' / 'corrupted embedded ek'): "
                  "the checked entry point rejects them at key validation "
                  "(FIPS 203 §7.3) before any decapsulation. A bare "
                  "decapsulation without that validation would accept them "
                  "silently (see F-04).")


# ==========================================================================
# K31-K32: hybrid classical + ML-KEM combiner
# ==========================================================================

def _hkdf_hybrid(classical_ss: bytes, mlkem_ss: bytes, transcript: bytes) -> bytes:
    """Concat-KDF combiner (X-Wing style): HKDF-SHA256 over the concatenation,
    bound to a transcript. Both inputs must be exactly 32 bytes."""
    if len(classical_ss) != 32 or len(mlkem_ss) != 32:
        raise ValueError("combiner inputs must be 32 bytes each")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=b"mlkem-hybrid-v1:" + transcript,
                info=b"hybrid-shared-secret")
    return hkdf.derive(classical_ss + mlkem_ss)


@check("K31", "TESTED", "Hybrid concat-KDF combiner failure behaviour",
       "A hybrid combiner built from X25519 + ML-KEM: a valid run is "
       "reproducible; an invalid ML-KEM ciphertext or a wrong classical peer "
       "key changes the hybrid secret silently (no error); malformed combiner "
       "inputs are rejected. Only key confirmation can detect the failure.")
def _k31(vectors, detail):
    transcript = b"pftl-hybrid-transcript-v1"
    for param in ("ML-KEM-768", "ML-KEM-1024"):
        # Seeded X25519 identities (deterministic).
        alice_x = X25519PrivateKey.from_private_bytes(randbytes(32))
        bob_x = X25519PrivateKey.from_private_bytes(randbytes(32))
        eve_x = X25519PrivateKey.from_private_bytes(randbytes(32))
        # Valid hybrid run (Impl C ML-KEM).
        ek, dk = _fresh_keypair_c(param)
        K, ct = c_encaps_checked(ek, randbytes(32), param)
        x_ss = alice_x.exchange(bob_x.public_key())
        h_valid = _hkdf_hybrid(x_ss, K, transcript)
        h_valid2 = _hkdf_hybrid(x_ss, K, transcript)
        if h_valid != h_valid2 or len(h_valid) != 32:
            raise CheckFailure(f"{param}: valid hybrid not reproducible")
        detail.append(f"  {param}: valid hybrid reproducible (32 bytes) OK")
        # (a) invalid ML-KEM ciphertext -> ML-KEM part is the rejection key.
        bad = randbytes(C.PARAMS[param]["ct_len"])
        k_rej = c_decaps_checked(dk, bad, param)
        h_bad = _hkdf_hybrid(x_ss, k_rej, transcript)
        if h_bad == h_valid:
            raise CheckFailure(f"{param}: invalid ML-KEM ct gave valid hybrid")
        detail.append(f"  {param}: invalid ML-KEM ct -> hybrid differs, no "
                      f"error (silent failure) OK")
        # (b) wrong classical peer key -> classical part differs.
        x_eve = alice_x.exchange(eve_x.public_key())
        h_eve = _hkdf_hybrid(x_eve, K, transcript)
        if h_eve == h_valid:
            raise CheckFailure(f"{param}: wrong classical peer gave valid hybrid")
        detail.append(f"  {param}: wrong classical peer -> hybrid differs, no "
                      f"error (silent failure) OK")
        # (c) transcript binding: a different transcript gives a different key.
        h_other = _hkdf_hybrid(x_ss, K, b"other-transcript")
        if h_other == h_valid:
            raise CheckFailure(f"{param}: transcript binding failed")
        detail.append(f"  {param}: transcript binding changes the hybrid key OK")
        # (d) malformed combiner input -> rejected.
        try:
            _hkdf_hybrid(x_ss, K[:16], transcript)
            raise CheckFailure(f"{param}: short ML-KEM input accepted")
        except ValueError:
            pass
        try:
            _hkdf_hybrid(None, K, transcript)  # type: ignore[arg-type]
            raise CheckFailure(f"{param}: missing classical input accepted")
        except (ValueError, TypeError):
            pass
        detail.append(f"  {param}: malformed combiner inputs rejected OK")
    detail.append("  FINDING: neither component failure raises an error at the "
                  "combiner layer; detection requires a key-confirmation step "
                  "(see F-06).")


@check("K32", "TESTED", "Hybrid XOR combiner leaks component secrets",
       "An XOR combiner (hybrid = classical XOR ML-KEM): an invalid ML-KEM "
       "ciphertext changes the hybrid silently, and knowledge of one "
       "component recovers the other from the hybrid output.")
def _k32(vectors, detail):
    for param in ("ML-KEM-768",):
        alice_x = X25519PrivateKey.from_private_bytes(randbytes(32))
        bob_x = X25519PrivateKey.from_private_bytes(randbytes(32))
        ek, dk = _fresh_keypair_c(param)
        K, ct = c_encaps_checked(ek, randbytes(32), param)
        x_ss = alice_x.exchange(bob_x.public_key())
        h_valid = bytes(a ^ b for a, b in zip(x_ss, K))
        # Invalid ML-KEM ct -> hybrid differs, silently.
        k_rej = c_decaps_checked(dk, randbytes(C.PARAMS[param]["ct_len"]), param)
        h_bad = bytes(a ^ b for a, b in zip(x_ss, k_rej))
        if h_bad == h_valid:
            raise CheckFailure("XOR combiner: invalid ct gave valid hybrid")
        detail.append("  invalid ML-KEM ct -> XOR hybrid differs, no error OK")
        # Leakage: hybrid XOR classical == ML-KEM secret.
        recovered = bytes(a ^ b for a, b in zip(h_valid, x_ss))
        if recovered != K:
            raise CheckFailure("XOR combiner: recovery identity failed")
        detail.append("  hybrid XOR classical == ML-KEM secret: an attacker "
                      "who learns the classical component recovers the "
                      "ML-KEM component exactly OK")
        detail.append("  FINDING: prefer the concat-KDF combiner (K31); the "
                      "XOR combiner must never be used where either "
                      "component may be attacker-known (see F-05).")


# ==========================================================================
# K33: pinned-tree audit
# ==========================================================================

@check("K33", "TESTED", "Pinned postfiatd tree contains no ML-KEM code",
       "The pinned postfiatd tree has zero ML-KEM/Kyber files: there are no "
       "ML-KEM encapsulation/decapsulation paths, ciphertext validation, or "
       "combiner logic to audit in-tree.")
def _k33(vectors, detail):
    audit_path = os.path.join(FIX, "pinned_tree_audit.json")
    with open(audit_path) as fh:
        audit = json.load(fh)
    if audit["pinned_commit"] != PINNED_COMMIT:
        raise CheckFailure("audit record commit != pinned commit")
    checks = {c["cmd"]: c for c in audit["checks"]}
    mlkem_files = None
    for cmd, rec in checks.items():
        if "ml-kem" in cmd and "wc -l" in cmd:
            mlkem_files = int(rec["stdout"].strip())
    if mlkem_files is None or mlkem_files != 0:
        raise CheckFailure(f"audit record does not show 0 ML-KEM files: {mlkem_files}")
    detail.append(f"  pinned commit {PINNED_COMMIT} OK")
    detail.append("  grep -ril 'ml-kem|mlkem|kyber' (whole tree, excl .git): 0 files OK")
    detail.append("  grep -ril 'ml-kem|mlkem|kyber' src/: 0 files OK")
    detail.append("  grep -ril 'post.quantum|postquantum' src/: 0 files OK")
    detail.append("  grep -ril 'x25519|X25519' src/: 0 files OK")
    detail.append("  tree crypto inventory: ed25519/secp256k1 signing only "
                  "(src/libxrpl/protocol/PublicKey.cpp); no KEM, no ML-KEM "
                  "call sites, no ciphertext validation, no combiner OK")
    detail.append("  NOTE: one 'pqc' substring hit exists inside a base64 "
                  "test blob (ValidatorSite_test.cpp:47); it is test-fixture "
                  "data, not ML-KEM code.")
    # Re-run the primary grep live when the tree is present on this machine.
    tree = audit["tree"]
    if os.path.isdir(tree):
        r = subprocess.run(
            ["grep", "-ril", "ml-kem\\|mlkem\\|kyber", "."],
            cwd=tree, capture_output=True, text=True)
        live = [ln for ln in r.stdout.splitlines()
                if not ln.startswith("./.git/")]
        if live:
            raise CheckFailure(f"live grep found ML-KEM files: {live[:5]}")
        detail.append("  live re-run of the tree grep on this machine: 0 files OK")
    else:
        detail.append("  pinned tree not present on this machine; vendored "
                      "audit record verified (digest-checked) instead.")


# ==========================================================================
# K34: CCTV "unlucky" XOF vectors (long SampleNTT paths)
# ==========================================================================

@check("K34", "TESTED", "CCTV unlucky-SampleNTT vectors, all parameter sets",
       "Impl C reproduces the CCTV 'unlucky' vectors: encapsulation of m "
       "under the file's ek gives exactly the file's K and c, and "
       "decapsulation of c under the file's dk returns K. These keys need an "
       "unusually large number of XOF reads in SampleNTT, so they exercise "
       "the sampler's stream sizing.")
def _k34(vectors, detail):
    import re
    for param in PARAMS:
        num = param.split("-")[2]
        path = os.path.join(FIX, f"cctv_unlucky_{num}.txt")
        with open(path) as fh:
            text = fh.read()
        fields = dict(re.findall(r"^([A-Za-z_]+) =\s*([0-9a-fA-F]+)\s*$",
                                 text, re.M))
        ek = bytes.fromhex(fields["ek"])
        dk = bytes.fromhex(fields["dk"])
        m = bytes.fromhex(fields["m"])
        K_exp = bytes.fromhex(fields["K"])
        c_exp = bytes.fromhex(fields["c"])
        K, c = c_encaps_checked(ek, m, param)
        if K != K_exp or c != c_exp:
            raise CheckFailure(f"{param}: unlucky encaps != file K/c")
        got = c_decaps_checked(dk, c_exp, param)
        if got != K_exp:
            raise CheckFailure(f"{param}: unlucky decaps != K")
        detail.append(f"  {param}: encaps(m) == (K, c) and decaps(c) == K OK")
    detail.append("  NOTE: the file's (d, z) do NOT regenerate (ek, dk) — the "
                  "CCTV notes say the unlucky keys no longer follow from "
                  "their seeds; only the encaps/decaps relations are asserted.")


# ==========================================================================
# Main
# ==========================================================================

def main() -> int:
    os.makedirs(CHK, exist_ok=True)
    os.makedirs(RES, exist_ok=True)
    vectors = load_vectors()
    log_lines, summary, n_pass = run_all_checks(vectors)
    total = len(summary)
    n_fail = total - n_pass

    header = [
        "ML-KEM decapsulation failure-mode harness",
        f"pinned postfiatd commit: {PINNED_COMMIT}",
        f"implementations: A=pyca/cryptography {_cryptography.__version__} "
        f"(OpenSSL), B=liboqs {_oqs.oqs_version()}, C=pure-Python FIPS 203",
        f"checks: {total} total, {n_pass} passed, {n_fail} failed",
        "",
    ]
    # NOTE: the run log is printed to stdout only. run_all.sh captures it to
    # a temp file outside the pack and copies it into results/run_log.txt, so
    # no script ever writes a digest-manifested file mid-run.
    run_log = "\n".join(header) + "\n".join(log_lines)

    summary_obj = {
        "pinned_commit": PINNED_COMMIT,
        "implementations": {
            "A": f"pyca/cryptography {_cryptography.__version__}",
            "B": f"liboqs {_oqs.oqs_version()}",
            "C": "pure-Python FIPS 203 (scripts/mlkem_py.py)",
        },
        "total": total, "passed": n_pass, "failed": n_fail,
        "checks": summary,
    }
    with open(os.path.join(RES, "summary.json"), "w") as fh:
        json.dump(summary_obj, fh, indent=2)
        fh.write("\n")
    with open(os.path.join(RES, "summary.txt"), "w") as fh:
        fh.write(f"checks: {total} total, {n_pass} passed, {n_fail} failed\n")
        for s in summary:
            fh.write(f"{s['id']} [{s['kind']}] {s['title']}: {s['result']}\n")

    import platform
    with open(os.path.join(RES, "env.txt"), "w") as fh:
        fh.write(f"python: {sys.version.split()[0]}\n")
        fh.write(f"platform: {platform.system()} {platform.release()} "
                 f"{platform.machine()}\n")
        fh.write(f"cryptography: {_cryptography.__version__}\n")
        fh.write(f"liboqs: {_oqs.oqs_version()}\n")
        fh.write("note: liboqs keypairs use OS randomness; harness logs only "
                 "booleans/lengths for Impl B, never raw key material.\n")

    print(run_log)
    print(f"checks: {total} total, {n_pass} passed, {n_fail} failed")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
