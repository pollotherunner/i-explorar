"""Read disposable lab credentials from the gitignored lab/CREDENTIALS.md.

Passwords are never committed: they live only in ``lab/CREDENTIALS.md`` (or in
the ``IEXPLORAR_<ROLE>_PASSWORD`` environment variables). This module parses
the markdown table that the lab notes document.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CREDENTIALS_FILE = ROOT / "lab" / "CREDENTIALS.md"

DEFAULT_LOGINS = {
    "admin": "admin",
    "secretary": "secretary",
    "teacher": "teacher",
}


def _from_file(role: str) -> str | None:
    if not CREDENTIALS_FILE.exists():
        return None
    for line in CREDENTIALS_FILE.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        if cells[0].lower() == role.lower():
            return cells[2].strip("`")
    return None


def password(role: str) -> str:
    env = os.environ.get(f"IEXPLORAR_{role.upper()}_PASSWORD")
    if env:
        return env
    value = _from_file(role)
    if value:
        return value
    raise RuntimeError(
        f"no password for role {role!r}: create {CREDENTIALS_FILE} or set "
        f"IEXPLORAR_{role.upper()}_PASSWORD"
    )


def credentials(role: str) -> tuple[str, str]:
    login = DEFAULT_LOGINS.get(role, role)
    return login, password(role)


LOGIN_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")
