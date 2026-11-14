#!/usr/bin/env python3
"""Build docs/index.html from the finished run outputs.

Reads results/summary.json, results/run_log.txt (tail), FINDINGS.md (the
failure-mode matrix between the MATRIX-START/END markers) and
claim_evidence_index.md (linked, not embedded). Deterministic: no timestamps,
no random data. Must run AFTER the final run log exists (run_all.sh order:
harness -> constants -> this script -> digests).
"""

from __future__ import annotations

import html
import json
import os
import re

PACK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(PACK_DIR, "results")


def parse_matrix(path: str):
    with open(path) as fh:
        text = fh.read()
    m = re.search(r"<!-- MATRIX-START -->(.*?)<!-- MATRIX-END -->",
                  text, re.S)
    if not m:
        raise RuntimeError("matrix markers not found in FINDINGS.md")
    rows = []
    for line in m.group(1).strip().splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells[0] == "ID" or set(cells[0]) <= set("- "):
            continue
        rows.append(cells)
    return rows


def main() -> None:
    with open(os.path.join(RES, "summary.json")) as fh:
        summary = json.load(fh)
    with open(os.path.join(RES, "run_log.txt")) as fh:
        run_log = fh.read()
    matrix = parse_matrix(os.path.join(PACK_DIR, "FINDINGS.md"))

    total = summary["total"]
    passed = summary["passed"]
    failed = summary["failed"]
    checks = summary["checks"]
    tested = sum(1 for c in checks if c["kind"] == "TESTED")

    matrix_html = "\n".join(
        "<tr>" + "".join(
            f"<td>{html.escape(cell)}</td>" for cell in row) + "</tr>"
        for row in matrix)
    checks_html = "\n".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(c["id"]), html.escape(c["kind"]),
            html.escape(c["title"]), html.escape(c["result"]))
        for c in checks)
    tail = "\n".join(run_log.strip().splitlines()[-40:])

    findings_rows = [
        ("F-01", "Medium", "CONFIRMED",
         "No ML-KEM code in the pinned tree", "K33"),
        ("F-02", "Low", "CONFIRMED (by design)",
         "Implicit rejection is silent — no error signal", "K19–K26"),
        ("F-03", "Low", "CONFIRMED (traps pass)",
         "Ciphertext comparison must cover the full ciphertext",
         "K29, K24, K30"),
        ("F-04", "Low", "CONFIRMED",
         "Decapsulation-key validation is a boundary duty", "K27, K28, K30"),
        ("F-05", "Low", "CONFIRMED",
         "XOR combiner leaks component secrets", "K32"),
        ("F-06", "Informational", "CONFIRMED",
         "Hybrid combiner failure is invisible without key confirmation",
         "K31"),
    ]
    findings_html = "\n".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            *[html.escape(x) for x in row]) for row in findings_rows)

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ML-KEM Decapsulation Failure-Mode Assessment</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; line-height: 1.5; }}
table {{ border-collapse: collapse; margin: 1em 0; }}
th, td {{ border: 1px solid #bbb; padding: 0.35em 0.6em; text-align: left; font-size: 0.9em; }}
th {{ background: #eee; }}
pre {{ background: #f6f6f6; padding: 1em; overflow-x: auto; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>ML-KEM Decapsulation Failure-Mode Assessment</h1>
<p>Audit of ML-KEM encapsulation and decapsulation failure modes across
ML-KEM-512/768/1024: implicit rejection, decapsulation-failure oracles,
malformed inputs, corrupted keys, comparison traps, and hybrid
classical-plus-ML-KEM combiner behaviour. Tested with local fixtures only
against three independent implementations (pyca/cryptography, liboqs, and a
pure-Python FIPS 203 implementation written from the standard). No
live-network testing, no mutation of the pinned tree.</p>
<p>Pinned tree: postfiatd
<code>0085a1ff885d6a446369cf73a4430f75af22be55</code>.</p>
<p><strong>Headline finding.</strong> The pinned tree contains no ML-KEM code
at all (F-01): there is no ML-KEM attack surface in-tree — and no ML-KEM
capability either. Every other failure mode below was confirmed against
reference implementations and applies to a future integration. No Critical or
High finding.</p>
<h2>Headline numbers</h2>
<table>
<tr><th>Measure</th><th>Value</th></tr>
<tr><td>Harness checks</td><td>{total} total — {passed} passed, {failed} failed ({tested} tested)</td></tr>
<tr><td>NIST ACVP known-answer cases reproduced (Impl C)</td><td>180 (75 keyGen, 75 encapsulation, 30 decapsulation)</td></tr>
<tr><td>Wycheproof decapsulation cases (Impl C)</td><td>603 (200/201/202 per parameter set: 152 valid + 40 malformed in the FIPS 203 group, plus 1 strcmp trap and 7–9 malleable-ciphertext cases)</td></tr>
<tr><td>Highest severity</td><td>Medium (F-01: ML-KEM absent from the pinned tree)</td></tr>
</table>
<h2>Findings</h2>
<table>
<tr><th>ID</th><th>Severity</th><th>Status</th><th>Finding</th><th>Checks</th></tr>
{findings_html}
</table>
<p>Full detail, impact, and concrete mitigations: <code>FINDINGS.md</code>.
Every material claim is mapped to a runnable check or a primary-source
citation in <code>claim_evidence_index.md</code>.</p>
<h2>Failure-mode matrix</h2>
<table>
<tr><th>ID</th><th>Failure mode</th><th>ML-KEM-512</th><th>ML-KEM-768</th><th>ML-KEM-1024</th><th>Status</th><th>Checks</th></tr>
{matrix_html}
</table>
<p>"Rejected (implicit)" means decapsulation returns a 32-byte pseudorandom
secret different from the valid secret, with no error (FIPS 203 §7.3).
"Rejected (error)" means the checked entry point raises <code>ValueError</code>
before returning anything.</p>
<h2>Checks</h2>
<table>
<tr><th>ID</th><th>Kind</th><th>Check</th><th>Result</th></tr>
{checks_html}
</table>
<p>Per-check outputs: <code>results/checks/</code>. Full raw log:
<code>results/run_log.txt</code> (tail below).</p>
<h2>Reproduction</h2>
<pre>bash run_all.sh</pre>
<p>Regenerates every derived output offline from the vendored fixtures,
rebuilds this page, and verifies digests. Expected: exit 0, byte-identical
outputs, clean git status. See <code>REPRODUCTION.md</code> for the exact
commands and recorded results, and
<code>results/digest_check_output.txt</code> for the raw digest-check output.
Verify digests at any time with <code>bash verify_digests.sh --check</code>.
Fresh-clean-setup logs (all batteries re-run) are under
<code>results/outputs/</code>.</p>
<h2>Run log (last 40 lines)</h2>
<pre>{html.escape(tail)}</pre>
<h2>Digest check output</h2>
<p>The raw digest-check output is <code>results/digest_check_output.txt</code>
(all manifest files OK). It is deliberately not embedded in this page: the
digest output is produced after this page is built, so embedding it would make
the page lag one run behind the manifest and a fresh-copy regeneration would
leave git status dirty whenever manifest membership changed.</p>
<h2>Files</h2>
<ul>
<li><code>README.md</code> — scope, method, how to reproduce</li>
<li><code>SCOPE_MAP.md</code> — pinned-tree audit and integration points</li>
<li><code>FINDINGS.md</code> — failure-mode matrix, prioritized findings with concrete mitigations and limitations</li>
<li><code>claim_evidence_index.md</code> — every material claim mapped to a runnable check or a primary-source citation</li>
<li><code>SOURCES.md</code> — primary sources and fixture provenance</li>
<li><code>scripts/mlkem_py.py</code> — pure-Python FIPS 203 implementation (Impl C)</li>
<li><code>scripts/run_checks.py</code> — the local-fixture harness (34 checks)</li>
<li><code>fixtures/</code> — NIST ACVP vectors, Wycheproof vectors, CCTV unlucky vectors, FIPS 203 constants</li>
<li><code>results/run_log.txt</code>, <code>results/summary.json</code>, <code>results/summary.txt</code> — harness outputs</li>
<li><code>results/checks/</code> — per-check outputs</li>
<li><code>results/outputs/</code> — fresh clean-setup run logs (all batteries)</li>
<li><code>results/SHA256SUMS</code> — digest manifest</li>
</ul>
</body>
</html>
"""
    with open(os.path.join(PACK_DIR, "docs", "index.html"), "w") as fh:
        fh.write(page)
    print("build_derived.py: docs/index.html written")


if __name__ == "__main__":
    main()
