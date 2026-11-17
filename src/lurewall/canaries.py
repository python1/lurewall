# SPDX-License-Identifier: AGPL-3.0-only
"""Canaries: generating them, storing them outside the repo, and looking hits up.

A canary is a short piece of non-rendered page content naming a decoy path. A
client that reads it and acts on it makes one request to that path, which
returns a fixed body holding no data. That request is the whole effect.

What a hit means: a client read non-rendered content and acted on it. It does
not prove the client is an AI, and it does not mean the visitor is hostile.

Design rules enforced here (see the design doc, Component A):

* **Per installation.** Paths, wording, the header name and the decoy bodies
  are drawn at random for each installation and live in a state file outside
  any git repository. The shipped example is refused at load time.
* **No shared fingerprint.** Every decoy has a different first path segment,
  and nothing marks a decoy as a decoy.
* **Two lure types, labelled.** ``instruction`` lures address the reader;
  ``bait`` lures only offer something a probing agent wants. Each canary
  carries its label so the two are measured apart.
* **Never a real route.** A decoy that collides with a real site path is an
  error, checked at generation and again on every site build.
* **Never real data.** Bodies come from a fixed word bank. The generator is
  never given site content, so it has nothing real to copy.
* **Rotation only on leak.** Nothing here rotates on a schedule; an unchanged
  state file always yields the same canaries.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes

from lurewall import wordbank as bank

STATE_VERSION = 1

INSTRUCTION = "instruction"
BAIT = "bait"

# The v1 placements: id -> (where it goes, lure type). The id names the lure
# that worked when a hit is looked up.
PLACEMENTS: dict[str, tuple[str, str]] = {
    "html_comment.instruction": ("html_comment", INSTRUCTION),
    "html_comment.bait": ("html_comment", BAIT),
    "hidden_element.instruction": ("hidden_element", INSTRUCTION),
    "robots_comment.instruction": ("robots_comment", INSTRUCTION),
    "api_doc.bait": ("api_doc", BAIT),
    "error_page.bait": ("error_page", BAIT),
    "response_header.instruction": ("response_header", INSTRUCTION),
}

# Marks the shipped example. It can never pass the path rules, and the loader
# also names it, so a copied example fails with a clear message.
EXAMPLE_MARKER = "EXAMPLE-NOT-A-REAL-CANARY"

# Segments a decoy must never contain: a bait request has to stay a canary hit
# and never look like a sensitive-path probe. The per-site attack-path list
# arrives with the signals; these are the names no site should use as a decoy.
RESERVED_SEGMENTS = frozenset(
    {
        "admin", "administrator", "wp-admin", "wp-login.php", "wp-content", "wp-includes",
        "phpmyadmin", "pma", "cgi-bin", "xmlrpc.php", "server-status", "server-info",
        "actuator", "login", "shell", "passwd", "etc",
    }
)  # fmt: skip

# Header names that mean something to browsers, crawlers or nginx itself. The
# canary header must be a made-up one.
REAL_HEADERS = frozenset(
    {
        "x-robots-tag", "x-frame-options", "x-content-type-options", "x-xss-protection",
        "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
        "x-request-id", "x-powered-by", "x-accel-redirect", "x-accel-buffering",
        "x-accel-expires", "x-accel-limit-rate", "x-accel-charset", "x-ua-compatible",
        "x-dns-prefetch-control", "x-csrf-token", "x-api-key", "x-cache-status",
    }
)  # fmt: skip

MAX_BODY_BYTES = 512
_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}", re.ASCII)
_PLACEHOLDER_RE = _REQUEST_ID_RE
_PATH_RE = re.compile(r"(?:/[a-z0-9][a-z0-9._-]{0,63}){2,5}", re.ASCII)
_PARAM_RE = re.compile(r"[a-z]{1,8}", re.ASCII)
_HEADER_RE = re.compile(r"X-[A-Z][a-z]{1,15}-[A-Z][a-z]{1,15}", re.ASCII)
_CLASS_RE = re.compile(r"[a-z][a-z-]{2,31}", re.ASCII)
_TEXT_RE = re.compile(r"[A-Za-z0-9 .,:()/_{}-]{1,200}", re.ASCII)
_BODY_RE = re.compile(r'[A-Za-z0-9 .,:<>/="{}\n-]{1,512}', re.ASCII)
_CONTENT_TYPES = frozenset({"application/json", "text/plain", "text/html"})
_FORMS = frozenset({"plain", "link", "api_row"})
_REF = "{ref}"


class CanaryError(ValueError):
    """A canary set that must not be used."""


class CollisionError(CanaryError):
    """A decoy path collides with a real site path. The site build must fail."""


@dataclass(frozen=True)
class Canary:
    id: str
    placement: str
    lure: str  # "instruction" or "bait"
    path: str  # the decoy path
    param: str  # query key that carries the serving request's ID
    text: str  # lure wording; holds "{ref}" where the reference goes, for form "plain"
    form: str  # how the text is rendered: "plain", "link" or "api_row"
    body: str  # the fixed decoy body
    content_type: str

    def reference(self, request_id: str) -> str:
        """The canary reference as it appears on a page: path plus the request ID."""
        return f"{self.path}?{self.param}={request_id}"


@dataclass(frozen=True)
class CanaryHit:
    canary: Canary
    request_id: str | None  # None when the request carried no well-formed ID


@dataclass(frozen=True)
class CanarySet:
    version: int
    created_ms: int
    # The text nginx's sub_filter replaces with $request_id. Random, and shaped
    # like a request ID, so a page served unstamped by mistake shows nothing odd.
    placeholder: str
    header_name: str
    hidden_class: str
    canaries: tuple[Canary, ...]

    def by_id(self, canary_id: str) -> Canary:
        for canary in self.canaries:
            if canary.id == canary_id:
                return canary
        raise KeyError(canary_id)

    def lookup_path(self, path: str) -> Canary | None:
        """The canary a decoy path belongs to, or None. Exact match only."""
        for canary in self.canaries:
            if canary.path == path:
                return canary
        return None

    def lookup_uri(self, uri: str) -> CanaryHit | None:
        """Match a logged request URI against the table.

        The path is normalized the way nginx normalizes it before choosing a
        location (one percent-decode, merged slashes, resolved dot segments),
        so a hit here is a request nginx answered with the decoy body. The URI
        is attacker-controlled; this never raises.
        """
        raw_path, _, query = uri.partition("?")
        path = nginx_normalize(raw_path)
        canary = self.lookup_path(path) if path is not None else None
        if canary is None:
            return None
        request_id = None
        for pair in query.split("&"):
            key, _, value = pair.partition("=")
            if key == canary.param:
                request_id = value if _REQUEST_ID_RE.fullmatch(value) else None
                break
        return CanaryHit(canary=canary, request_id=request_id)

    def lure_counts(self) -> dict[str, int]:
        counts = {INSTRUCTION: 0, BAIT: 0}
        for canary in self.canaries:
            counts[canary.lure] += 1
        return counts


# -- path handling ---------------------------------------------------------------


def _resolve_segments(path: str) -> str | None:
    out: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not out:
                return None  # climbs above the root: nginx answers 400
            out.pop()
            continue
        out.append(segment)
    return "/" + "/".join(out)


def nginx_normalize(raw_path: str) -> str | None:
    """Normalize a request path as nginx does before matching a location."""
    if not raw_path.startswith("/"):
        return None
    try:
        decoded = unquote_to_bytes(raw_path).decode("utf-8", errors="replace")
    except (ValueError, UnicodeError):  # pragma: no cover - unquote_to_bytes is lenient
        return None
    if "\x00" in decoded:
        return None
    resolved = _resolve_segments(decoded)
    if resolved is not None and decoded.endswith("/") and resolved != "/":
        resolved += "/"  # a trailing slash is a different location to nginx
    return resolved


def collision_key(path: str) -> str:
    """A deliberately loose form for comparing a decoy with real routes.

    Looser than nginx: case is folded and a trailing slash ignored, so a decoy
    is rejected even when it would only collide on a case-insensitive
    filesystem or after a redirect.
    """
    decoded = unquote_to_bytes(path.partition("?")[0]).decode("utf-8", errors="replace")
    resolved = _resolve_segments(decoded) or "/"
    return resolved.lower()


def find_collisions(canary_set: CanarySet, real_paths: Iterable[str]) -> list[tuple[str, str]]:
    """Every (canary id, real path) pair that collides."""
    real = {collision_key(path) for path in real_paths}
    found = []
    for canary in canary_set.canaries:
        decoy = collision_key(canary.path)
        for route in sorted(real):
            if route == "/":
                continue
            if (
                decoy == route
                or route.startswith(decoy + "/")  # the decoy is a real directory
                or decoy.startswith(route + "/")  # the decoy sits under a real file or folder
            ):
                found.append((canary.id, route))
    return found


def check_collisions(canary_set: CanarySet, real_paths: Iterable[str]) -> None:
    """Raise CollisionError if any decoy path collides with a real site path."""
    found = find_collisions(canary_set, real_paths)
    if found:
        detail = "; ".join(f"{canary_id} collides with {route}" for canary_id, route in found)
        raise CollisionError(
            f"decoy path collides with a real site path: {detail}. "
            "Rotate that canary (`lurewall canaries rotate`) and rebuild."
        )


# -- validation ---------------------------------------------------------------------


def _validate_canary(canary: Canary, placeholder: str) -> None:
    def bad(what: str) -> CanaryError:
        return CanaryError(f"canary {canary.id!r}: {what}")

    if canary.id not in PLACEMENTS:
        raise CanaryError("unknown canary id")
    if (canary.placement, canary.lure) != PLACEMENTS[canary.id]:
        raise bad("placement or lure type does not match its id")
    if EXAMPLE_MARKER.lower() in canary.path.lower():
        raise bad("this is the shipped example, not a real canary. Generate your own.")
    if _PATH_RE.fullmatch(canary.path) is None or "--" in canary.path or ".." in canary.path:
        raise bad("decoy path is not in the allowed form")
    segments = canary.path.strip("/").split("/")
    if any(segment in RESERVED_SEGMENTS or segment.startswith(".") for segment in segments):
        raise bad("decoy path contains a reserved (attack-path) name")
    if _PARAM_RE.fullmatch(canary.param) is None:
        raise bad("query key is not in the allowed form")
    if canary.form not in _FORMS:
        raise bad("unknown text form")
    if _TEXT_RE.fullmatch(canary.text) is None or "--" in canary.text:
        raise bad("lure text is not in the allowed form")
    wants_ref = 1 if canary.form == "plain" else 0
    if canary.text.count(_REF) != wants_ref or canary.text.replace(_REF, "").count("{"):
        raise bad("lure text must hold exactly one {ref} for form 'plain' and none otherwise")
    if "}" in canary.text.replace(_REF, ""):
        raise bad("lure text holds a stray brace")
    if canary.content_type not in _CONTENT_TYPES:
        raise bad("unknown content type")
    if _BODY_RE.fullmatch(canary.body) is None or len(canary.body.encode()) > MAX_BODY_BYTES:
        raise bad("decoy body is not in the allowed form")
    if placeholder in canary.body or canary.path in canary.body:
        raise bad("decoy body must not hold a request ID or a decoy path")


def validate(canary_set: CanarySet) -> None:
    """Raise CanaryError unless the set is safe to build a site and an nginx config from.

    Everything in the set is later written into HTML and an nginx config, so
    each field is held to a narrow character set here, whoever wrote the file.
    """
    if canary_set.version != STATE_VERSION:
        raise CanaryError("unsupported canary state version")
    if type(canary_set.created_ms) is not int or canary_set.created_ms < 0:
        raise CanaryError("bad creation time")
    if _PLACEHOLDER_RE.fullmatch(canary_set.placeholder) is None:
        raise CanaryError("placeholder is not 32 hex characters")
    if _HEADER_RE.fullmatch(canary_set.header_name) is None:
        raise CanaryError("header name is not in the allowed form")
    if canary_set.header_name.lower() in REAL_HEADERS:
        raise CanaryError("header name is a real header; the canary header must be made up")
    if _CLASS_RE.fullmatch(canary_set.hidden_class) is None:
        raise CanaryError("hidden class name is not in the allowed form")
    ids = [canary.id for canary in canary_set.canaries]
    if sorted(ids) != sorted(PLACEMENTS):
        raise CanaryError("the set must hold exactly one canary per placement")
    for canary in canary_set.canaries:
        _validate_canary(canary, canary_set.placeholder)
    paths = [canary.path for canary in canary_set.canaries]
    if len({collision_key(path) for path in paths}) != len(paths):
        raise CanaryError("two canaries share a decoy path")
    firsts = [path.split("/")[1] for path in paths]
    if len(set(firsts)) != len(firsts):
        raise CanaryError("two decoy paths share a first segment (a shared prefix)")


# -- generation ----------------------------------------------------------------------


def _date(rng: Any) -> str:
    year, month, day = rng.randint(2019, 2025), rng.randint(1, 12), rng.randint(1, 28)
    style = rng.randrange(4)
    if style == 0:
        return f"{year}{month:02d}{day:02d}"
    if style == 1:
        return f"{year}-{month:02d}-{day:02d}"
    if style == 2:
        return f"{year}_{month:02d}_{day:02d}"
    return f"{year}{month:02d}"


def _tail(canary_id: str, rng: Any) -> str:
    """Everything after the first segment, in a shape that suits the placement."""
    first, second = rng.choice(bank.GENERIC), rng.choice(bank.GENERIC)
    number = rng.randint(2, 4095)
    if canary_id == "html_comment.instruction":
        return f"{rng.choice(bank.VERIFY)}-{first}/{second}-{number}"
    if canary_id == "html_comment.bait":
        stem, ext = rng.choice(bank.BACKUP_STEMS), rng.choice(bank.BACKUP_EXTENSIONS)
        return f"{first}/{stem}-{_date(rng)}.{ext}"
    if canary_id == "hidden_element.instruction":
        return f"{rng.choice(bank.VERIFY)}/{first}-{second}-{number}"
    if canary_id == "robots_comment.instruction":
        return f"{rng.choice(bank.HEALTH)}/{first}-{number}"
    if canary_id == "api_doc.bait":
        return f"v{rng.randint(1, 4)}/{rng.choice(bank.DEBUG)}/{first}-{number}"
    if canary_id == "error_page.bait":
        return f"{rng.choice(bank.DEBUG)}/{first}-{second}-{number}"
    return f"{rng.choice(bank.VERIFY)}-{first}-{number}"  # response_header.instruction


def path_space(canary_id: str) -> int:
    """How many different paths the generator can produce for one placement.

    The space is finite and the banks are public, so a determined attacker can
    enumerate it. What stops a guessed path from counting is the request-ID
    binding, not secrecy of the path alone.
    """
    generic, number, dirs = len(bank.GENERIC), 4094, len(bank.DIRS)
    tails = {
        "html_comment.instruction": len(bank.VERIFY) * generic * generic * number,
        "html_comment.bait": generic
        * len(bank.BACKUP_STEMS)
        * len(bank.BACKUP_EXTENSIONS)
        * (7 * 12 * 28 * 3 + 7 * 12),
        "hidden_element.instruction": len(bank.VERIFY) * generic * generic * number,
        "robots_comment.instruction": len(bank.HEALTH) * generic * number,
        "api_doc.bait": 4 * len(bank.DEBUG) * generic * number,
        "error_page.bait": len(bank.DEBUG) * generic * generic * number,
        "response_header.instruction": len(bank.VERIFY) * generic * number,
    }
    return dirs * tails[canary_id]


def _instruction_text(rng: Any) -> str:
    opener = rng.choice(bank.INSTRUCTION_OPENERS)
    action = rng.choice(bank.INSTRUCTION_ACTIONS)
    return f"{opener}: {action}{rng.choice(bank.INSTRUCTION_CLOSERS)}."


def _wording(canary_id: str, rng: Any) -> tuple[str, str]:
    """(text, form) for a placement."""
    if canary_id in ("html_comment.instruction", "hidden_element.instruction"):
        return _instruction_text(rng), "plain"
    if canary_id == "html_comment.bait":
        if rng.random() < 0.5:
            return rng.choice(bank.BAIT_LINK_LABELS), "link"
        return rng.choice(bank.BAIT_NOTES), "plain"
    if canary_id == "robots_comment.instruction":
        return f"{rng.choice(bank.ROBOTS_OPENERS)}: {_REF}", "plain"
    if canary_id == "api_doc.bait":
        return rng.choice(bank.API_DESCRIPTIONS), "api_row"
    if canary_id == "error_page.bait":
        return rng.choice(bank.ERROR_NOTES), "plain"
    return rng.choice(bank.HEADER_PHRASES), "plain"  # response_header.instruction


def _body(canary_id: str, rng: Any) -> tuple[str, str]:
    """(body, content type). Drawn from the bank alone: there is no site input to copy."""
    if canary_id == "html_comment.bait":
        title = rng.choice(bank.BODY_HTML_TITLES)
        message = rng.choice(bank.BODY_HTML_MESSAGES)
        html = f"<html><head><title>{title}</title></head><body><p>{message}</p></body></html>\n"
        return html, "text/html"
    plain_ok = canary_id in ("robots_comment.instruction", "response_header.instruction")
    if plain_ok and rng.random() < 0.5:
        return rng.choice(bank.BODY_TEXT) + "\n", "text/plain"
    key, value = rng.choice(bank.BODY_JSON_KEYS), rng.choice(bank.BODY_JSON_VALUES)
    return f'{{"{key}":"{value}"}}\n', "application/json"


def _make_canary(canary_id: str, directory: str, real_paths: frozenset[str], rng: Any) -> Canary:
    placement, lure = PLACEMENTS[canary_id]
    text, form = _wording(canary_id, rng)
    body, content_type = _body(canary_id, rng)
    for _ in range(200):
        path = f"/{directory}/{_tail(canary_id, rng)}"
        candidate = Canary(
            id=canary_id,
            placement=placement,
            lure=lure,
            path=path,
            param=rng.choice(bank.ID_PARAMS),
            text=text,
            form=form,
            body=body,
            content_type=content_type,
        )
        probe = CanarySet(STATE_VERSION, 0, "0" * 32, "X-A-B", "x", (candidate,))
        if not find_collisions(probe, real_paths):
            return candidate
    raise CanaryError(f"could not find a decoy path for {canary_id} that avoids the site's routes")


def _free_directories(real_paths: Iterable[str], taken: Iterable[str]) -> list[str]:
    """First segments a new decoy may use: not a real top-level name, not already a decoy's."""
    used = {collision_key(path).split("/")[1] for path in real_paths if collision_key(path) != "/"}
    used.update(taken)
    return [name for name in bank.DIRS if name not in used and name not in RESERVED_SEGMENTS]


def generate(real_paths: Iterable[str], *, rng: Any = None, now_ms: int | None = None) -> CanarySet:
    """Draw a fresh canary set for a site whose real routes are ``real_paths``.

    ``rng`` defaults to the operating system's secure source. Tests pass a
    seeded ``random.Random``.
    """
    rng = secrets.SystemRandom() if rng is None else rng
    real = frozenset(real_paths)
    directories = _free_directories(real, ())
    if len(directories) < len(PLACEMENTS):
        raise CanaryError("the site uses too many of the generator's top-level names")
    chosen = rng.sample(directories, len(PLACEMENTS))
    canaries = tuple(
        _make_canary(canary_id, directory, real, rng)
        for canary_id, directory in zip(PLACEMENTS, chosen, strict=True)
    )
    canary_set = CanarySet(
        version=STATE_VERSION,
        created_ms=time.time_ns() // 1_000_000 if now_ms is None else now_ms,
        placeholder=f"{rng.getrandbits(128):032x}",
        header_name=f"X-{rng.choice(bank.HEADER_FIRST)}-{rng.choice(bank.HEADER_SECOND)}",
        hidden_class=rng.choice(bank.HIDDEN_CLASSES),
        canaries=canaries,
    )
    validate(canary_set)
    check_collisions(canary_set, real)
    return canary_set


def rotate(
    canary_set: CanarySet, ids: Iterable[str], real_paths: Iterable[str], *, rng: Any = None
) -> CanarySet:
    """Replace the named canaries after a suspected leak. The rest are left exactly as they are."""
    rng = secrets.SystemRandom() if rng is None else rng
    wanted = set(ids)
    unknown = wanted - set(PLACEMENTS)
    if unknown:
        raise CanaryError(f"unknown canary id: {sorted(unknown)[0]}")
    real = frozenset(real_paths)
    kept_firsts = [c.path.split("/")[1] for c in canary_set.canaries]
    directories = _free_directories(real, kept_firsts)
    if len(directories) < len(wanted):
        raise CanaryError("no unused top-level names left to rotate into")
    fresh = iter(rng.sample(directories, len(wanted)))
    canaries = tuple(
        _make_canary(c.id, next(fresh), real, rng) if c.id in wanted else c
        for c in canary_set.canaries
    )
    rotated = replace(canary_set, canaries=canaries)
    validate(rotated)
    check_collisions(rotated, real)
    return rotated


# -- state file ------------------------------------------------------------------------


def inside_git_work_tree(path: Path) -> Path | None:
    """The enclosing git work tree, if ``path`` is inside one."""
    resolved = path.resolve()
    for folder in (resolved, *resolved.parents):
        if (folder / ".git").exists():
            return folder
    return None


def refuse_git_work_tree(path: Path, what: str) -> None:
    tree = inside_git_work_tree(path)
    if tree is not None:
        raise CanaryError(
            f"{what} {path} is inside the git repository at {tree}. Generated canaries must "
            "live outside any repository, so they can never be committed."
        )


def save_state(canary_set: CanarySet, path: str | Path) -> None:
    """Write the set to ``path`` atomically at mode 0600. Refuses any git work tree."""
    target = Path(path)
    validate(canary_set)
    refuse_git_work_tree(target.parent, "state file location")
    data = (json.dumps(asdict(canary_set), indent=2, sort_keys=True) + "\n").encode("ascii")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(dir=target.parent, prefix=".canaries-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:  # mkstemp creates the file 0600
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
    except BaseException:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
        raise


def parse_state(raw: bytes | str) -> CanarySet:
    """Parse and validate a state document. Refuses the shipped example."""
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise CanaryError("canary state is not valid JSON") from exc
    if type(document) is not dict:
        raise CanaryError("canary state is not a JSON object")
    if document.get("example") is not None or EXAMPLE_MARKER in json.dumps(document):
        raise CanaryError(
            "this is the shipped example canary set. It is public, so it is refused. "
            "Generate a set for this installation."
        )
    try:
        entries = document["canaries"]
        if type(entries) is not list or not all(type(entry) is dict for entry in entries):
            raise CanaryError("canary state: 'canaries' must be a list of objects")
        canaries = tuple(Canary(**entry) for entry in entries)
        if not all(type(value) is str for canary in canaries for value in asdict(canary).values()):
            raise CanaryError("canary state: every canary field must be a string")
        canary_set = CanarySet(
            version=document["version"],
            created_ms=document["created_ms"],
            placeholder=document["placeholder"],
            header_name=document["header_name"],
            hidden_class=document["hidden_class"],
            canaries=canaries,
        )
        extra = set(document) - set(asdict(canary_set))
        if extra:
            raise CanaryError("canary state has unexpected fields")
        for name in ("placeholder", "header_name", "hidden_class"):
            if type(document[name]) is not str:
                raise CanaryError(f"canary state: {name} must be a string")
    except (KeyError, TypeError) as exc:
        raise CanaryError("canary state is missing fields or has unexpected ones") from exc
    validate(canary_set)
    return canary_set


def load_state(path: str | Path) -> CanarySet:
    """Load an installation's canaries. Refuses a file inside a git work tree."""
    source = Path(path)
    refuse_git_work_tree(source.parent, "state file location")
    with open(source, "rb") as handle:
        raw = handle.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise CanaryError("canary state file is too large")
    return parse_state(raw)
