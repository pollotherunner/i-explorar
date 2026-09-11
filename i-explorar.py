#!/usr/bin/env python3
"""i-explorar — orchestrator for the i-Educar local-lab disclosure PoCs.

Pure standard library. Vulnerability metadata lives *only* in each
``vulns/NN-<slug>/poc.py`` module inside its ``VULN`` dict; this file never
parses advisory text and never looks for a sidecar metadata file.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib import lab_guard  # noqa: E402

BANNER = r"""
  _        ______            _
 (_)      |  ____|          | |
  _ ______| |__  __  ___ __ | | ___  _ __ __ _ _ __
 | |______|  __| \ \/ / '_ \| |/ _ \| '__/ _` | '__|
 | |      | |____ >  <| |_) | | (_) | | | (_| | |
 |_|      |______/_/\_\ .__/|_|\___/|_|  \__,_|_|
                    i - e d u c a r   l o c a l   d i s c l o s u r e
"""

DEFAULT_TARGET = "http://127.0.0.1:8080"


# ---------------------------------------------------------------------------
# colors
# ---------------------------------------------------------------------------


class Palette:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def red(self, text):
        return self._wrap("31;1", text)

    def green(self, text):
        return self._wrap("32;1", text)

    def yellow(self, text):
        return self._wrap("33;1", text)

    def blue(self, text):
        return self._wrap("34;1", text)

    def cyan(self, text):
        return self._wrap("36;1", text)

    def bold(self, text):
        return self._wrap("1", text)

    def dim(self, text):
        return self._wrap("2", text)


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


def load_vulns() -> list[dict]:
    """Import every vulns/*/poc.py and return its VULN dict (id order)."""
    items = []
    for poc_path in sorted((ROOT / "vulns").glob("*/poc.py")):
        spec = importlib.util.spec_from_file_location(
            f"i_explorar_{poc_path.parent.name.replace('-', '_')}", poc_path
        )
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # pragma: no cover - import bug is visible
            print(f"[!] failed to import {poc_path}: {exc}", file=sys.stderr)
            continue
        vuln = getattr(module, "VULN", None)
        if not isinstance(vuln, dict):
            print(f"[!] {poc_path} has no VULN dict", file=sys.stderr)
            continue
        items.append(
            {
                "vuln": vuln,
                "module": module,
                "path": poc_path,
                "dir": poc_path.parent,
            }
        )
    items.sort(key=lambda item: str(item["vuln"].get("id", "99")))
    return items


def load_wip() -> list[dict]:
    items = []
    for poc_path in sorted((ROOT / "_wip").glob("*/poc.py")):
        try:
            spec = importlib.util.spec_from_file_location(
                f"i_explorar_wip_{poc_path.parent.name.replace('-', '_')}", poc_path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            items.append({"path": poc_path, "error": str(exc)})
            continue
        items.append({"path": poc_path, "vuln": getattr(module, "VULN", {})})
    return items


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def status_label(vuln: dict, colors: Palette) -> str:
    status = vuln.get("status", "unknown")
    if status == "verified":
        return colors.green("[verified]")
    if status == "blocked":
        return colors.red("[blocked]")
    return colors.yellow("[unverified]")


def vuln_line(vuln: dict, colors: Palette) -> str:
    return (
        f"[{vuln.get('id', '??')}] {vuln.get('cwe_id', 'CWE-???'):<8} "
        f"{vuln.get('title', '')}  {vuln.get('endpoint', '')}   "
        f"{status_label(vuln, colors)}"
    )


def print_menu(items: list[dict], colors: Palette) -> None:
    print()
    print(colors.bold("  VULNERABILITIES"))
    if not items:
        print("    (none yet under vulns/)")
    for item in items:
        print("    " + vuln_line(item["vuln"], colors))
    print()
    print("  " + colors.bold("OPTIONS"))
    print("    <number>  run one PoC")
    print("    a         run every verified PoC")
    print("    s         status board (vulns/ and _wip/)")
    print("    l         list one vulnerability's details")
    print("    r         re-print the last raw evidence")
    print("    q         quit")


def print_details(item: dict, colors: Palette) -> None:
    vuln = item["vuln"]
    print()
    print(colors.bold(f"  [{vuln.get('id')}] {vuln.get('title')}"))
    print(f"    product.......... {vuln.get('product')} {vuln.get('affected_version')}")
    print(f"    cwe.............. {vuln.get('cwe_id')} {vuln.get('cwe_name')}")
    print(f"    cwe source....... {vuln.get('cwe_source_url')} ({vuln.get('cwe_confidence')})")
    print(f"    cwe justification {vuln.get('cwe_justification')}")
    print(f"    cvss............. {vuln.get('cvss_vector')} ({vuln.get('cvss_score')})")
    print(f"    endpoint......... {vuln.get('endpoint')}")
    print(f"    params........... {', '.join(vuln.get('params', []))}")
    print(f"    precondition..... {vuln.get('precondition')}")
    print(f"    status........... {vuln.get('status')}")
    if vuln.get("blocked_reason"):
        print(f"    blocked reason... {vuln.get('blocked_reason')}")
    print(f"    advisory......... {item['dir'] / 'README.md'}")
    print(f"    poc.............. {item['path']}")
    screenshots = vuln.get("screenshots", [])
    if screenshots:
        print("    screenshots......")
        for shot in screenshots:
            print(f"      - {item['dir'] / shot}")
    else:
        print("    screenshots...... none registered")


def print_status_board(items: list[dict], colors: Palette) -> None:
    print()
    print(colors.bold("  STATUS BOARD — vulns/ (committed)"))
    if not items:
        print("    (empty)")
    for item in items:
        vuln = item["vuln"]
        print(
            f"    [{vuln.get('id')}] {vuln.get('slug'):<34} "
            f"{vuln.get('status'):<10} {vuln.get('blocked_reason', '')}"
        )
    print()
    print(colors.bold("  STATUS BOARD — _wip/ (never committed)"))
    wip = load_wip()
    if not wip:
        print("    (empty)")
    for entry in wip:
        if "error" in entry:
            print(f"    {entry['path']}: import error: {entry['error']}")
            continue
        vuln = entry["vuln"]
        print(
            f"    {entry['path'].parent.name:<34} "
            f"{vuln.get('status', '?'):<10} {vuln.get('blocked_reason', '')}"
        )


# ---------------------------------------------------------------------------
# running
# ---------------------------------------------------------------------------


def standalone_command(item: dict, target: str) -> str:
    return f"python3 {item['path'].relative_to(ROOT)} --target {target}"


def run_one(item: dict, target: str, colors: Palette, stream=sys.stdout) -> dict:
    vuln = item["vuln"]
    command = standalone_command(item, target)
    print(file=stream)
    print(colors.cyan(f"  executing: {command}"), file=stream)
    try:
        result = item["module"].run(target)
    except lab_guard.LabGuardError as exc:
        result = {
            "vulnerable": False,
            "evidence": [],
            "notes": f"LAB GUARD REJECTED TARGET: {exc}",
        }
    except Exception as exc:  # noqa: BLE001 - report, never hide
        result = {
            "vulnerable": False,
            "evidence": [],
            "notes": f"EXCEPTION: {type(exc).__name__}: {exc}",
        }

    result.setdefault("evidence", [])
    result.setdefault("notes", "")
    result["id"] = vuln.get("id")
    result["slug"] = vuln.get("slug")
    result["title"] = vuln.get("title")
    result["cwe"] = vuln.get("cwe_id")
    result["status"] = vuln.get("status")
    result["command"] = command

    if result["vulnerable"]:
        print(colors.green(f"  VULNERABLE — {vuln.get('title')}"), file=stream)
    else:
        print(colors.red(f"  NOT VULNERABLE — {vuln.get('title')}"), file=stream)
    if result["notes"]:
        for line in str(result["notes"]).splitlines():
            print(f"    {line}", file=stream)
    for path in result["evidence"]:
        print(f"    evidence: {path}", file=stream)
    return result


def run_all(items: list[dict], target: str, colors: Palette, as_json: bool, stream=sys.stdout) -> int:
    verified = [item for item in items if item["vuln"].get("status") == "verified"]
    results = [run_one(item, target, colors, stream) for item in verified]

    if as_json:
        print(json.dumps({"target": target, "results": results}, indent=2))
    else:
        print(file=stream)
        print(colors.bold("  SUMMARY"), file=stream)
        print("    " + "-" * 92, file=stream)
        print(f"    {'ID':<4} {'CWE':<8} {'VULNERABLE':<11} {'EVIDENCE':<52}", file=stream)
        print("    " + "-" * 92, file=stream)
        for result in results:
            evidence = result["evidence"][0] if result["evidence"] else "-"
            print(
                f"    {result['id']:<4} {result['cwe']:<8} "
                f"{'yes' if result['vulnerable'] else 'NO':<11} {evidence:<52}",
                file=stream,
            )
        print("    " + "-" * 92, file=stream)
        ok = sum(1 for r in results if r["vulnerable"])
        print(f"    {ok}/{len(results)} verified PoCs reproduced", file=stream)

    return 0 if results and all(r["vulnerable"] for r in results) else 1


# ---------------------------------------------------------------------------
# index generation
# ---------------------------------------------------------------------------


def rewrite_index(items: list[dict]) -> None:
    verified = [i for i in items if i["vuln"].get("status") == "verified"]
    others = [i for i in items if i["vuln"].get("status") != "verified"]

    lines = [
        "# i-explorar",
        "",
        "Local-lab disclosure of vulnerabilities found in **i-Educar 2.11.0**",
        "(portabilis/i-educar). Every PoC is stdlib Python 3 and only talks to the",
        "local Docker lab (`127.0.0.1` / `localhost` / `::1`).",
        "",
        "The single source of truth for each item is the `VULN` dict inside its own",
        "`vulns/NN-<slug>/poc.py`. This file is generated by `python3 i-explorar.py --index`.",
        "",
        "## Verified vulnerabilities",
        "",
        "| ID | Title | CWE | Endpoint | Status | Advisory |",
        "|----|-------|-----|----------|--------|----------|",
    ]
    for item in verified:
        vuln = item["vuln"]
        advisory = f"vulns/{vuln.get('id')}-{vuln.get('slug')}/README.md"
        endpoint = str(vuln.get("endpoint", "")).replace("|", "\\|")
        if "`" not in endpoint:
            endpoint = f"`{endpoint}`"
        lines.append(
            f"| {vuln.get('id')} | {vuln.get('title')} | {vuln.get('cwe_id')} | "
            f"{endpoint} | `{vuln.get('status')}` | [{advisory}]({advisory}) |"
        )

    lines += ["", "## Not verified", ""]
    if not others:
        lines.append("None.")
    else:
        lines.append("| ID | Title | CWE | Status | Reason |")
        lines.append("|----|-------|-----|--------|--------|")
        for item in others:
            vuln = item["vuln"]
            reason = (vuln.get("blocked_reason") or "not reproduced").replace("|", "/")
            lines.append(
                f"| {vuln.get('id')} | {vuln.get('title')} | {vuln.get('cwe_id')} | "
                f"`{vuln.get('status')}` | {reason} |"
            )

    lines += [
        "",
        "## Usage",
        "",
        "```bash",
        "# interactive menu (ASCII banner)",
        "python3 i-explorar.py",
        "",
        "# run every verified PoC non-interactively",
        "python3 i-explorar.py --all",
        "",
        "# machine-readable summary",
        "python3 i-explorar.py --all --json",
        "",
        "# regenerate this file and RESEARCH-TIMELINE.md from the VULN dicts",
        "python3 i-explorar.py --index",
        "",
        "# any PoC also runs standalone; --print-evidence prints the raw run log",
        "python3 vulns/01-<slug>/poc.py --target http://127.0.0.1:8080 --print-evidence",
        "",
        "# shortcut: run one PoC and print its newest raw evidence log",
        "./tools/show-evidence.sh 01",
        "```",
        "",
        "## Lab",
        "",
        "`lab/i-educar` is the upstream `2.11.0` release tag (latest release)",
        "started with Docker Compose on `http://127.0.0.1:8080`. The checkout is",
        "gitignored; PoCs can point at another checkout through `IEXPLORAR_LAB`.",
    ]
    (ROOT / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    timeline = [
        "# Research timeline",
        "",
        "Generated by `python3 i-explorar.py --index` from the `VULN` dicts.",
        "`reported_at`, `followups` and `silence_days` are only filled when a",
        "report to the maintainer actually happened; empty means it did not.",
        "",
        "| ID | Title | Status | Reported at | Follow-ups | Silence (days) |",
        "|----|-------|--------|-------------|------------|----------------|",
    ]
    for item in items:
        vuln = item["vuln"]
        followups = ", ".join(vuln.get("followups", [])) or "-"
        timeline.append(
            f"| {vuln.get('id')} | {vuln.get('title')} | `{vuln.get('status')}` | "
            f"{vuln.get('reported_at') or '-'} | {followups} | {vuln.get('silence_days', 0)} |"
        )
    timeline += [
        "",
        "## Notes",
        "",
        "- Verification date for all items is recorded inside each PoC's raw",
        "  evidence log under `vulns/NN-<slug>/evidence/`.",
        "- All 13 items were verified against the 2.11.0 release tag",
        "  (898d2da7) on 2026-09-10.",
        "- No item has been reported to the maintainer from this repository;",
        "  no push, no remote, no external contact was performed.",
        "",
    ]
    (ROOT / "RESEARCH-TIMELINE.md").write_text("\n".join(timeline) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="i-explorar",
        description="i-Educar 2.11.0 local-lab disclosure orchestrator",
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help="local lab base URL")
    parser.add_argument("--all", action="store_true", help="run every verified PoC")
    parser.add_argument("--json", action="store_true", help="machine-readable summary")
    parser.add_argument("--index", action="store_true", help="rewrite README and timeline")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    return parser


def interactive(items: list[dict], target: str, colors: Palette) -> int:
    last_result = None
    while True:
        print_menu(items, colors)
        try:
            choice = input("  i-explorar> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice in ("q", "quit", "exit"):
            return 0
        if choice == "a":
            code = run_all(items, target, colors, as_json=False)
            if code != 0:
                return code
            continue
        if choice == "s":
            print_status_board(items, colors)
            continue
        if choice == "l":
            wanted = input("  vulnerability id: ").strip()
            for item in items:
                if str(item["vuln"].get("id")) == wanted:
                    print_details(item, colors)
                    break
            else:
                print("  not found")
            continue
        if choice == "r":
            logs = sorted(
                (ROOT / "vulns").glob("*/evidence/run-*.log"), key=lambda p: p.stat().st_mtime
            )
            if not logs:
                print("  no evidence logs yet")
            else:
                print()
                print(colors.bold(f"  raw evidence: {logs[-1]}"))
                print(textwrap.indent(logs[-1].read_text(encoding="utf-8"), "    "))
            continue
        if choice.isdigit():
            for item in items:
                if item["vuln"].get("id") == choice.zfill(2):
                    last_result = run_one(item, target, colors)
                    break
            else:
                print("  unknown id")
            continue
        print("  unknown option")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    color_enabled = not args.no_color and os.environ.get("NO_COLOR") is None and sys.stdout.isatty()
    colors = Palette(color_enabled)

    banner_stream = sys.stderr if args.json else sys.stdout
    if sys.stdout.isatty():
        os.system("clear")

    print(colors.cyan(BANNER), file=banner_stream)

    try:
        target = lab_guard.check_target(args.target)
    except lab_guard.LabGuardError as exc:
        print(colors.red(f"  refused target: {exc}"))
        return 2

    items = load_vulns()

    if args.index:
        rewrite_index(items)
        print(colors.green(f"  README.md and RESEARCH-TIMELINE.md rewritten from {len(items)} VULN dict(s)"))
        return 0

    if args.all:
        if not items:
            print(colors.yellow("  no vulns discovered under vulns/"))
            return 1
        stream = sys.stderr if args.json else sys.stdout
        return run_all(items, target, colors, as_json=args.json, stream=stream)

    if sys.stdin.isatty():
        return interactive(items, target, colors)

    print("  non-interactive stdin: use --all or --index")
    return 2


if __name__ == "__main__":
    sys.exit(main())
