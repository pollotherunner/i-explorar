"""Locate the local lab checkout used by PoCs that need psql/docker exec.

The main lab is the upstream checkout at ``lab/i-educar``. A second lab (for
example the 2.11.0 release tag) can be selected with the ``IEXPLORAR_LAB``
environment variable, relative to the repository root or absolute.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def lab_dir() -> Path:
    override = os.environ.get("IEXPLORAR_LAB")
    if override:
        path = Path(override)
        if not path.is_absolute():
            path = ROOT / path
        return path.resolve()
    return ROOT / "lab" / "i-educar"


def compose(lab: Path, *args: str) -> list[str]:
    """Build a `docker compose` command for the given lab checkout.

    The checkout's own `.env` supplies COMPOSE_PROJECT_NAME and ports, so a
    second lab (different project/containers) is selected simply by changing
    `lab_dir()`.
    """
    return [
        "docker",
        "compose",
        "--project-directory",
        str(lab),
        "-f",
        str(lab / "docker-compose.yml"),
        *args,
    ]
