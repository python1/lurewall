# SPDX-License-Identifier: AGPL-3.0-only
"""The lab test client: plain HTTP requests to the lab site, and nothing else.

Every request goes to one target, which must be an IP address on a private
network or loopback, over plain HTTP. A public address, a hostname, HTTPS or a
redirect elsewhere is refused before any connection is made. Only GET and HEAD
are sent. Nothing is uploaded and no request carries a body.

Requests are written byte for byte on a socket, not through an HTTP library,
so a test can send exactly the path it means (``//.env``, ``/%2eenv``, invalid
UTF-8) without a library normalising it first.

Standard library only: this runs on the Mac and on the Alienware (WSL), which
need no more than Python 3.11 and this package.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_TARGET = "http://192.168.1.160"
USER_AGENT = "lurewall-lab-harness/1 (lab test client; harmless requests only)"
MAX_RESPONSE_BYTES = 1024 * 1024
TIMEOUT_S = 10.0
# Under nginx's limit of 10 requests a second, so only the flood case meets it.
DEFAULT_PAUSE_S = 0.15
METHODS = frozenset({"GET", "HEAD"})

# A canary reference as served on a stamped page: a path, one short query key
# and a 32-hex request ID. Found by shape, so the client needs no canary table.
REFERENCE_RE = re.compile(rb"(/[A-Za-z0-9._~/-]{1,200})\?([a-z]{1,8})=([0-9a-f]{32})(?![0-9a-f])")
_LINK_RE = re.compile(rb"""(?:href|src)\s*=\s*["']([^"'<>\s]{1,300})["']""", re.IGNORECASE)
_PATH_IN_TEXT_RE = re.compile(
    rb"(?:^|[\s:(])(/[A-Za-z0-9._~/-]{1,200}(?:\?[A-Za-z0-9=&._-]{1,100})?)"
)
_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9-]{1,64}")


class TargetError(ValueError):
    """The target is not a lab address this client will talk to."""


@dataclass(frozen=True)
class Target:
    host: str  # an IP address, as text
    port: int

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == 80 else f"{host}:{self.port}"

    def url(self, path: str) -> str:
        return f"http://{self.netloc}{path}"


def parse_target(text: str) -> Target:
    """Accept only ``http://<private or loopback IP>[:port]`` with no path."""
    try:
        parts = urlsplit(text)
        port = parts.port or 80
    except ValueError as exc:
        raise TargetError("target is not a URL") from exc
    if parts.scheme != "http":
        raise TargetError("target must be plain http:// (the lab site has no TLS)")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise TargetError("target is a bare http://address[:port], nothing more")
    try:
        address = ipaddress.ip_address(parts.hostname or "")
    except ValueError as exc:
        raise TargetError("target must be an IP address, not a name") from exc
    if not (address.is_private or address.is_loopback) or address.is_unspecified:
        raise TargetError(f"{address} is not a private or loopback address; refusing")
    if address.is_multicast or address.is_link_local:
        raise TargetError(f"{address} is not a lab host address; refusing")
    return Target(str(address), port)


@dataclass(frozen=True)
class Response:
    status: int  # 0 when no response came back
    headers: tuple[tuple[str, str], ...]
    body: bytes
    error: str | None = None  # a fixed word when the request failed

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((value for key, value in self.headers if key.lower() == name), None)


Sender = Callable[[Target, bytes], Response]


def _clean(value: str) -> bytes:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("header values hold no control characters")
    return value.encode("latin-1")


def build_request(
    target: Target,
    path: bytes | str,
    *,
    method: str = "GET",
    user_agent: bytes | str = USER_AGENT,
    headers: Iterable[tuple[str, str]] = (),
) -> bytes:
    """The request bytes. ``path`` and ``user_agent`` may hold any bytes a test needs
    except CR, LF and NUL, which would end the line and smuggle a second header."""
    if method not in METHODS:
        raise ValueError("the harness sends GET and HEAD only")
    raw_path = path.encode("utf-8", "surrogateescape") if isinstance(path, str) else path
    raw_ua = (
        user_agent.encode("utf-8", "surrogateescape") if isinstance(user_agent, str) else user_agent
    )
    for value in (raw_path, raw_ua):
        if any(byte in value for byte in b"\r\n\x00"):
            raise ValueError("CR, LF and NUL would split the request; refusing")
    if not raw_path.startswith(b"/") or b" " in raw_path:
        raise ValueError("the path starts with / and holds no space")
    lines = [
        method.encode() + b" " + raw_path + b" HTTP/1.1",
        b"Host: " + target.netloc.encode(),
        b"User-Agent: " + raw_ua,
        b"Accept: text/html,*/*;q=0.8",
        b"Connection: close",
    ]
    for name, value in headers:
        if _HEADER_NAME_RE.fullmatch(name) is None:
            raise ValueError("bad header name")
        lines.append(name.encode() + b": " + _clean(value))
    return b"\r\n".join(lines) + b"\r\n\r\n"


def _parse_response(raw: bytes) -> Response:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    match = re.fullmatch(rb"HTTP/1\.[01] (\d{3})(?: .*)?", lines[0] if lines else b"")
    if match is None:
        return Response(0, (), b"", "bad_response")
    headers = []
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if sep:
            headers.append((name.decode("latin-1").strip(), value.decode("latin-1").strip()))
    if any(key.lower() == "transfer-encoding" and "chunked" in value for key, value in headers):
        body = _dechunk(body)
    return Response(int(match.group(1)), tuple(headers), body)


def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    while body:
        size_line, _, rest = body.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        body = rest[size + 2 :]
    return bytes(out)


def socket_sender(target: Target, request: bytes, *, bind: str | None = None) -> Response:
    """Send one request on a fresh connection and read the reply (capped).

    ``bind`` picks the local address to send from, on a machine with several.
    """
    source = (bind, 0) if bind else None
    try:
        with socket.create_connection(
            (target.host, target.port), timeout=TIMEOUT_S, source_address=source
        ) as conn:
            conn.sendall(request)
            chunks, total = [], 0
            while total <= MAX_RESPONSE_BYTES:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
    except TimeoutError:
        return Response(0, (), b"", "timeout")
    except ConnectionRefusedError:
        return Response(0, (), b"", "refused")
    except OSError:
        return Response(0, (), b"", "network_error")
    return _parse_response(b"".join(chunks)[:MAX_RESPONSE_BYTES])


class Client:
    """Requests to one lab target, with a tally of what was sent."""

    def __init__(
        self, target: Target, sender: Sender = socket_sender, *, pause_s: float = DEFAULT_PAUSE_S
    ):
        self.target = target
        self._send = sender
        self.pause_s = pause_s
        self.sent = 0
        self.statuses: dict[int, int] = {}

    def get(self, path: bytes | str, **kwargs) -> Response:
        response = self._send(self.target, build_request(self.target, path, **kwargs))
        self.sent += 1
        self.statuses[response.status] = self.statuses.get(response.status, 0) + 1
        if self.pause_s:
            time.sleep(self.pause_s)
        return response


# -- reading what the site served --------------------------------------------------------


def references(response: Response) -> list[str]:
    """Canary-shaped references (path?key=<request id>) in a body and its headers."""
    text = response.body + b"\n" + b"\n".join(v.encode("latin-1") for _, v in response.headers)
    found = []
    for match in REFERENCE_RE.finditer(text):
        ref = match.group(0).decode("ascii")
        if ref not in found:
            found.append(ref)
    return found


def same_site_paths(target: Target, body: bytes) -> list[str]:
    """Links and bare paths in a page (comments included) that stay on the target."""
    found: list[str] = []
    candidates = [m.group(1) for m in _LINK_RE.finditer(body)]
    candidates += [m.group(1) for m in _PATH_IN_TEXT_RE.finditer(body)]
    for raw in candidates:
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        if text.startswith(("http://", "https://")):
            parts = urlsplit(text)
            if parts.scheme != "http" or parts.netloc != target.netloc:
                continue
            text = parts.path + (f"?{parts.query}" if parts.query else "")
        if not text.startswith("/") or text.startswith("//"):
            continue
        text = text.split("#", 1)[0]
        if text and text not in found:
            found.append(text)
    return found


def robots_paths(body: bytes) -> list[str]:
    paths = []
    for line in body.decode("utf-8", "replace").splitlines():
        key, _, value = line.partition(":")
        value = value.strip()
        if key.strip().lower() in ("allow", "disallow", "sitemap") and value.startswith("/"):
            paths.append(value.split("*")[0].split("$")[0])
    return paths


def crawl(client: Client, *, max_pages: int = 60) -> list[str]:
    """A link-following crawler with no model behind it (test case 9).

    It reads robots.txt as a list of paths to visit, follows every same-site
    path it finds in pages (comments included), and stops at ``max_pages``.
    Returns the paths requested, in order.
    """
    queue: deque[str] = deque(["/", "/robots.txt"])
    seen: set[str] = set()
    visited: list[str] = []
    while queue and len(visited) < max_pages:
        path = queue.popleft()
        if path in seen:
            continue
        seen.add(path)
        response = client.get(path)
        visited.append(path)
        if response.status != 200:
            continue
        new = robots_paths(response.body) if path == "/robots.txt" else []
        new += same_site_paths(client.target, response.body)
        queue.extend(item for item in new if item not in seen)
    return visited


# -- fixed request sets ------------------------------------------------------------------------

# A short, fixed wordlist of the kind any scanner sends (test case 3). Paths only:
# each is a GET that the lab site answers with its 404 page.
WORDLIST = (
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/wp-admin/",
    "/phpmyadmin/",
    "/admin/",
    "/backup.zip",
    "/config.php.bak",
    "/.aws/credentials",
    "/server-status",
    "/.DS_Store",
    "/actuator/env",
)

# Spellings of two attack paths (test case 17). Each must be matched.
PATH_VARIANTS = (
    "/%2eenv",
    "//.env",
    "/.ENV",
    "/.Env",
    "/%2Eenv",
    "/./.env",
    "/%252eenv",
    "//.git//config",
    "/.GIT/Config",
    "/%2egit/config",
)

# Hostile bytes in the path and user agent (test case 16). Nothing here can end
# the request line: CR, LF and NUL are refused by build_request.
HOSTILE = (
    (b"/caf\xc3\xa9.html", USER_AGENT.encode()),
    (b"/bad-\xff\xfe-utf8", USER_AGENT.encode()),
    (b"/quote-%22-and-%5c", b'agent with "quotes" and \\backslashes\\'),
    (b'/raw-quote-"-x', b"\xc0\xaf overlong slash"),
    (b"/ctl-%01-%1b-%7f", b"tab\there and bell\x07 and esc\x1b[31m"),
    (b"/latin1-\xe9t\xe9", b"\xe9t\xe9 not utf-8"),
    (b"/json-%7b%22seq%22:1%7d", b'{"seq":1,"type":"block","detail":{}}'),
    (b"/long-" + b"A" * 3000, b"B" * 3000),
)
