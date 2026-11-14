#!/bin/sh
# Regenerate every derived output of this pack from scratch (offline except
# for the one-time dependency install).
#   1. scripts/run_checks.py   -> results/run_log.txt, results/summary.json,
#                                 results/summary.txt, results/checks/*.txt,
#                                 results/env.txt (local fixtures only; no
#                                 network access, no pinned tree needed)
#   2. scripts/verify_constants.py -> constants check (stdout only)
#   3. scripts/build_derived.py -> docs/index.html
#   4. results/outputs/          -> clean-setup copies of the run log,
#                                 summary and per-check outputs
#   5. verify_digests.sh       -> results/SHA256SUMS, then --check output
#                                 -> results/digest_check_output.txt
# Run logs are captured outside the pack first, then copied in, so no
# script ever writes into a file its own digest manifest covers mid-run.
set -eu
PACK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$PACK_DIR"

# --- dependencies -----------------------------------------------------------
# Prefer an existing venv; else the system interpreter if it has the imports;
# else create .venv and install the pinned requirements (needs network once).
if [ -x .venv/bin/python3 ]; then
    PY=.venv/bin/python3
elif python3 -c "import cryptography.hazmat.primitives.asymmetric.mlkem, oqs" 2>/dev/null; then
    PY=python3
else
    python3 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt
    PY=.venv/bin/python3
fi

TMP_LOG=$(mktemp)
TMP_ERR=$(mktemp)
TMP_CONST=$(mktemp)
TMP_DIGEST=$(mktemp)
trap 'rm -f "$TMP_LOG" "$TMP_ERR" "$TMP_CONST" "$TMP_DIGEST"' EXIT INT TERM

set +e
"$PY" scripts/run_checks.py > "$TMP_LOG" 2> "$TMP_ERR"
RC=$?
set -e
cat "$TMP_LOG"
if [ "$RC" -ne 0 ]; then
    echo "run_checks.py failed with exit $RC" >&2
    cat "$TMP_ERR" >&2
    exit "$RC"
fi
cp "$TMP_LOG" results/run_log.txt

"$PY" scripts/verify_constants.py > "$TMP_CONST" 2>&1
cat "$TMP_CONST"
cp "$TMP_CONST" results/constants_verification.txt

"$PY" scripts/build_derived.py

rm -rf results/outputs
mkdir -p results/outputs/checks
cp results/run_log.txt results/outputs/run_log.txt
cp results/summary.json results/outputs/summary.json
cp results/summary.txt results/outputs/summary.txt
cp results/checks/*.txt results/outputs/checks/

bash verify_digests.sh
bash verify_digests.sh --check > "$TMP_DIGEST" 2>&1
cat "$TMP_DIGEST"
cp "$TMP_DIGEST" results/digest_check_output.txt

echo "run_all.sh: OK"
