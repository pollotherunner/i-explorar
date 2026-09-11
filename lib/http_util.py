"""Minimal stdlib-only HTTP helpers for the i-explorar PoCs.

No third-party dependencies: urllib + http.cookiejar only. Every request is
routed through lab_guard.check_url before it is sent.
"""

from __future__ import annotations

import http.cookiejar
import http.server
import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import lab_guard

DEFAULT_TIMEOUT = 30.0
DEFAULT_UA = "i-explorar-poc/1.0 (local lab reproduction)"


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.text)

    @property
    def location(self) -> str:
        return self.headers.get("location", "")


class HttpClient:
    """Cookie-aware urllib session with a localhost-only guard."""

    def __init__(self, base_url: str, *, timeout: float = DEFAULT_TIMEOUT, verbose: bool = False):
        self.base_url = lab_guard.check_target(base_url)
        self.timeout = timeout
        self.verbose = verbose
        self._jar = http.cookiejar.CookieJar()
        self._cookie_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar),
        )
        self.last_request_line = ""

    # -- low level ---------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        data: dict | list | None = None,
        raw_data: bytes | None = None,
        headers: dict | None = None,
        timeout: float | None = None,
        follow: bool = False,
    ) -> Response:
        url = path if path.startswith("http") else self.base_url + path
        lab_guard.check_url(url)

        body = raw_data
        if data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode()

        req_headers = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
        if body is not None:
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=body, headers=req_headers, method=method.upper())
        self.last_request_line = f"{method.upper()} {url}"

        if follow:
            opener = self._cookie_opener
        else:
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(self._jar),
                _NoRedirect(),
            )

        try:
            with opener.open(req, timeout=timeout or self.timeout) as resp:
                return Response(
                    status=resp.status,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=resp.read(),
                    url=resp.geturl(),
                )
        except urllib.error.HTTPError as exc:
            return Response(
                status=exc.code,
                headers={k.lower(): v for k, v in exc.headers.items()},
                body=exc.read(),
                url=url,
            )
        except urllib.error.URLError as exc:
            raise ConnectionError(f"request failed: {method} {url}: {exc}") from exc

    def get(self, path: str, **kwargs) -> Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> Response:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> Response:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs) -> Response:
        return self.request("DELETE", path, **kwargs)

    # -- lab helpers -------------------------------------------------------

    def login(self, login: str, password: str) -> Response:
        """Authenticate against the Laravel login form (no CSRF token in this release)."""
        return self.post("/login", data={"login": login, "password": password})

    def logged_in(self) -> bool:
        response = self.get("/intranet/educar_index.php")
        return response.status == 200


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

    def http_error_302(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


@dataclass
class CallbackServer:
    """Tiny HTTP callback server used to prove outbound requests (SSRF)."""

    host: str = "0.0.0.0"
    port: int = 0
    response_content_type: str = "image/gif"
    response_body: bytes = (
        b"GIF89a\x01\x00\x01\x00\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,"
        b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    )
    requests: list = field(default_factory=list)

    def __post_init__(self):
        hits = self.requests
        body = self.response_body
        content_type = self.response_content_type

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                hits.append({"method": "GET", "path": self.path,
                             "headers": dict(self.headers.items())})
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802
                hits.append({"method": "POST", "path": self.path,
                             "headers": dict(self.headers.items())})
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        self._httpd = http.server.ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://host.docker.internal:{self.port}"

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()

    def wait_for_hit(self, timeout: float = 15.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.requests:
                return True
            time.sleep(0.2)
        return bool(self.requests)


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket() as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]
