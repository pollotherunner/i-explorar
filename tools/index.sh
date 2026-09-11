#!/usr/bin/env bash
# Regenerate README.md and RESEARCH-TIMELINE.md from the VULN dicts.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 i-explorar.py --index
