"""Timestamped raw-evidence writer.

Every execution of a PoC appends its raw output to
``vulns/NN-<slug>/evidence/run-<timestamp>.log``. Nothing is invented here:
callers only write real command output, timings and HTTP exchanges.
"""

from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SECRET_KEYS = (
    "APP_KEY",
    "DB_PASSWORD",
    "PGPASSWORD",
    "API_ACCESS_KEY",
    "API_SECRET_KEY",
    "REDIS_PASSWORD",
    "MAIL_PASSWORD",
    "AWS_SECRET_ACCESS_KEY",
)


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def timestamp() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%SZ")


def redact(text: str) -> str:
    """Mask common secret values so evidence can be committed safely."""
    for key in SECRET_KEYS:
        text = re.sub(
            rf"({re.escape(key)}\s*[=:]\s*)(\S+)",
            rf"\1<redacted>",
            text,
        )
    return text


class EvidenceLog:
    """Append-only raw log for one PoC run."""

    def __init__(self, vuln_dir: Path | str, *, prefix: str = "run"):
        self.vuln_dir = Path(vuln_dir)
        self.evidence_dir = self.vuln_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.started = utc_now()
        self.path = self.evidence_dir / f"{prefix}-{timestamp()}.log"
        self._fh = self.path.open("a", encoding="utf-8")
        self.write(f"# i-explorar raw evidence")
        self.write(f"# started_at: {self.started.isoformat()}")
        self.write(f"# host: {self.started.astimezone().strftime('%Z')}")

    def write(self, line: str = "") -> None:
        self._fh.write(redact(line) + "\n")
        self._fh.flush()

    def command(self, command: str) -> None:
        self.write(f"$ {command}")

    def block(self, title: str, content: str) -> None:
        self.write("")
        self.write(f"--- {title} ---")
        for line in content.splitlines() or [""]:
            self.write(line)
        self.write(f"--- end {title} ---")

    def close(self) -> Path:
        self.write(f"# finished_at: {utc_now().isoformat()}")
        self._fh.close()
        return self.path


def screenshot_registry(vuln_dir: Path | str, names: list[str]) -> list[Path]:
    """Return the expected local paths of a vuln's screenshots (may not exist yet)."""
    base = Path(vuln_dir) / "evidence" / "screenshots"
    return [base / name for name in names]
