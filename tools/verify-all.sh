#!/usr/bin/env bash
# Run every verified PoC and store the machine-readable summary in _wip/.
# Exit code mirrors the orchestrator: non-zero if any verified PoC failed.
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p _wip
out="_wip/verify-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 i-explorar.py --all --json > "$out"
status=$?
echo "wrote $out (orchestrator exit code: $status)"
exit "$status"
