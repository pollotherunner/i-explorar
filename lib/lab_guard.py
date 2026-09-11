"""Hard-coded local-lab target allowlist shared by every PoC and the orchestrator.

Fail closed: anything that is not explicitly the local i-Educar lab raises
LabGuardError before a single byte is sent or a single command is executed.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

ALLOWED_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})

# Containers of the local lab compose project. Used by CLI-level checks.
ALLOWED_CONTAINERS = frozenset(
    {
        "ieducar-php",
        "ieducar-fpm",
        "ieducar-nginx",
        "ieducar-postgres",
        "ieducar-redis",
        "ieducar-horizon",
    }
)


class LabGuardError(RuntimeError):
    """Raised when a target is outside the local lab allowlist."""


def is_allowed_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.strip("[]").lower()
    if host in ALLOWED_HOSTNAMES:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback


def check_target(target: str) -> str:
    """Validate a lab base URL and return it without a trailing slash.

    Only http/https on loopback hosts are accepted. Credentials in the URL,
    unknown schemes and non-loopback hosts are rejected.
    """
    if not target:
        raise LabGuardError("empty target")

    parts = urlsplit(target)
    if parts.scheme not in ("http", "https"):
        raise LabGuardError(f"scheme not allowed: {parts.scheme!r}")
    if parts.username or parts.password:
        raise LabGuardError("credentials in URL are not allowed")
    if not is_allowed_host(parts.hostname):
        raise LabGuardError(f"host not allowed: {parts.hostname!r} (local lab only)")
    if parts.path not in ("", "/"):
        raise LabGuardError(f"target must be a base URL, got path {parts.path!r}")

    return target.rstrip("/")


def check_url(url: str) -> str:
    """Validate an absolute URL opened by lib/http_util. Same allowlist."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise LabGuardError(f"scheme not allowed: {parts.scheme!r}")
    if not is_allowed_host(parts.hostname):
        raise LabGuardError(f"host not allowed: {parts.hostname!r} (local lab only)")
    return url


def check_container(name: str) -> str:
    if name not in ALLOWED_CONTAINERS:
        raise LabGuardError(f"container not allowed: {name!r} (local lab only)")
    return name
