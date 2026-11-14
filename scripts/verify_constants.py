#!/usr/bin/env python3
"""Verify the FIPS 203 constants vendored in fixtures/constants.json against
the implementation (scripts/mlkem_py.py) and the NIST ACVP vector files.

Usage: python3 scripts/verify_constants.py   (run from the pack root)
Exit code: 0 iff every constant matches.
"""

from __future__ import annotations

import gzip
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

import mlkem_py as C  # noqa: E402

PACK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(PACK_DIR, "fixtures")


def main() -> int:
    with open(os.path.join(FIX, "constants.json")) as fh:
        consts = json.load(fh)
    n_ok = 0
    n_total = 0

    def check(label, got, want):
        nonlocal n_ok, n_total
        n_total += 1
        if got != want:
            print(f"FAIL {label}: got {got!r}, want {want!r}")
            return
        n_ok += 1
        print(f"OK {label}: {got!r}")

    for param, want in consts["parameter_sets"].items():
        p = C.PARAMS[param]
        for key in ("k", "eta1", "eta2", "du", "dv",
                    "ek_len", "dk_len", "ct_len"):
            check(f"{param}.{key}", p[key], want[key])
        check(f"{param}.ss_len", C.SS_LEN, consts["shared_secret_len"])
    check("q", C.Q, consts["q"])
    check("n", C.N, consts["n"])
    check("zeta", C.ZETA, consts["zeta"])

    # Vector byte-lengths agree with Table 2.
    with gzip.open(os.path.join(FIX, "nist_keygen.json.gz"), "rt") as fh:
        kg = json.load(fh)
    for group in kg["testGroups"]:
        t = group["tests"][0]
        param = group["parameterSet"]
        p = C.PARAMS[param]
        check(f"ACVP {param} ek bytes", len(bytes.fromhex(t["ek"])), p["ek_len"])
        check(f"ACVP {param} dk bytes", len(bytes.fromhex(t["dk"])), p["dk_len"])

    print(f"constants: {n_ok}/{n_total} OK")
    return 0 if n_ok == n_total else 1


if __name__ == "__main__":
    sys.exit(main())
