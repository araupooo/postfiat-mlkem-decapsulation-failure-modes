#!/bin/sh
# Regenerate or verify the SHA-256 digest manifest for this pack.
#   bash verify_digests.sh          regenerates results/SHA256SUMS
#   bash verify_digests.sh --check  verifies every listed file and prints
#                                   "N files OK" (exit 0) or failures (exit 1)
# Excluded from the manifest: .git, .venv, __pycache__, results/SHA256SUMS
# itself, results/digest_check_output.txt (written after the check) and
# results/reproduction_log.txt (written after the fresh-clone reproduction).
set -eu
PACK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$PACK_DIR"

if [ "${1:-}" = "--check" ]; then
    cd "$PACK_DIR"
    OUT=$(sha256sum -c results/SHA256SUMS 2>&1) || {
        printf '%s\n' "$OUT"
        exit 1
    }
    N_OK=$(printf '%s\n' "$OUT" | grep -c ': OK$' || true)
    N_FAIL=$(printf '%s\n' "$OUT" | grep -vc ': OK$' || true)
    printf '%s\n' "$OUT"
    echo "verify_digests.sh: $N_OK files OK, $N_FAIL failed"
    [ "$N_FAIL" -eq 0 ]
    exit 0
fi

find . \( -path './.git' -o -path './.venv' -o -path '*/__pycache__' \) -prune \
    -o -type f ! -name 'SHA256SUMS' ! -name 'digest_check_output.txt' \
    ! -name 'reproduction_log.txt' -print \
    | LC_ALL=C sort | xargs sha256sum > results/SHA256SUMS
N=$(wc -l < results/SHA256SUMS)
echo "verify_digests.sh: SHA256SUMS regenerated ($N files)"
