#!/usr/bin/env bash
# Run one PoC against the local 2.11.0 lab and print its raw evidence log.
#
# Usage: ./tools/show-evidence.sh <NN|slug>   (e.g. 01 or db-restore-command-injection)
# Target override: IEXPLORAR_TARGET=http://127.0.0.1:8080
set -uo pipefail
cd "$(dirname "$0")/.."

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <NN|slug>" >&2
    exit 2
fi

arg="$1"
dir=""
for candidate in vulns/"${arg}"-* vulns/"${arg}"; do
    if [ -d "$candidate" ]; then
        dir="$candidate"
        break
    fi
done
if [ -z "$dir" ]; then
    echo "vuln not found: $arg" >&2
    exit 1
fi

python3 "$dir/poc.py" --target "${IEXPLORAR_TARGET:-http://127.0.0.1:8080}" --print-evidence
