"""Shared ASCII banner for the standalone PoC CLI and the orchestrator."""

from __future__ import annotations

BANNER = (
    "\n"
    "____     ______           __                     \n"
    "   /  _/    / ____/  ______  / /___  _________ ______\n"
    "   / /_____/ __/ | |/_/ __ \\/ / __ \\/ ___/ __ `/ ___/\n"
    " _/ /_____/ /____>  </ /_/ / / /_/ / /  / /_/ / /    \n"
    "/___/    /_____/_/|_/ .___/_/\\____/_/   \\__,_/_/     \n"
    "                   /_/  "
)


class Colors:
    """ANSI colors, auto-disabled when not writing to a terminal."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def green(self, text: str) -> str:
        return self._wrap("32;1", text)

    def red(self, text: str) -> str:
        return self._wrap("31;1", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33;1", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36;1", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)
