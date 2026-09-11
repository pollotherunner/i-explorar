"""Shared argparse CLI for standalone PoC execution.

Each ``poc.py`` keeps its own ``VULN`` dict and ``run()``; this helper only
provides the identical ``--target/--json/--verbose/--print-evidence`` command
line so every PoC behaves the same standalone and under the orchestrator.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import lab_guard
from .art import BANNER, Colors

ROOT = Path(__file__).resolve().parents[1]


def poc_main(vuln: dict, run_fn, argv: list[str] | None, poc_file: str) -> int:
    parser = argparse.ArgumentParser(
        prog=Path(poc_file).name,
        description=f"{vuln.get('id')} — {vuln.get('title')} (local lab only)",
    )
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:8080",
        help="local lab base URL (127.0.0.1/localhost/::1 only)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable result")
    parser.add_argument("--verbose", action="store_true", help="extra verbosity")
    parser.add_argument(
        "--print-evidence",
        action="store_true",
        help="also print the newest raw evidence log of this PoC",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = parser.parse_args(argv)

    color_enabled = (
        not args.no_color
        and args.json is False
        and sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
    )
    colors = Colors(color_enabled)

    try:
        target = lab_guard.check_target(args.target)
    except lab_guard.LabGuardError as exc:
        print(f"refused target: {exc}", file=sys.stderr)
        return 2

    command = f"python3 {Path(poc_file).resolve().relative_to(ROOT)} --target {target}"
    if args.verbose:
        command += " --verbose"

    if not args.json:
        print(colors.cyan(BANNER))
        print()
        if args.verbose:
            print(f"  {colors.bold('VULN ' + str(vuln.get('id')) + ' — ' + str(vuln.get('title')))}")
            if vuln.get("endpoint"):
                print(f"  {colors.dim(str(vuln['endpoint']))}")
            print()

    try:
        result = run_fn(target, verbose=args.verbose)
    except lab_guard.LabGuardError as exc:
        result = {"vulnerable": False, "evidence": [], "notes": f"lab guard: {exc}"}
    except Exception as exc:  # noqa: BLE001 - surface the real error
        result = {
            "vulnerable": False,
            "evidence": [],
            "notes": f"EXCEPTION {type(exc).__name__}: {exc}",
        }

    result.setdefault("vulnerable", False)
    result.setdefault("evidence", [])
    result.setdefault("notes", "")
    result["id"] = vuln.get("id")
    result["slug"] = vuln.get("slug")
    result["title"] = vuln.get("title")
    result["status"] = vuln.get("status")
    result["command"] = command

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        proof = str(result["notes"]).strip() or (
            "target is vulnerable" if result["vulnerable"] else "not reproduced"
        )
        if result["vulnerable"]:
            print(f"  {colors.green('[+]')} {colors.green(proof)}")
        else:
            print(f"  {colors.red('[-]')} {colors.red(proof)}")

        if args.verbose:
            for path in result["evidence"]:
                try:
                    shown = Path(path).relative_to(ROOT)
                except ValueError:
                    shown = Path(path)
                print(f"      {colors.dim('evidence: ' + str(shown))}")
            print(f"      {colors.dim('command:  ' + command)}")

    if args.print_evidence:
        evidence_dir = Path(poc_file).resolve().parent / "evidence"
        logs = sorted(evidence_dir.glob("run-*.log"), key=lambda item: item.stat().st_mtime)
        stream = sys.stderr if args.json else sys.stdout
        if logs:
            print(file=stream)
            print(f"=================== raw evidence: {logs[-1]} ===================", file=stream)
            print(logs[-1].read_text(encoding="utf-8"), file=stream, end="")
        else:
            print("no evidence log found", file=sys.stderr)

    return 0 if result["vulnerable"] else 1
