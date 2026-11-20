# SPDX-License-Identifier: AGPL-3.0-only
"""Compile a private, per-vhost njs profile from operator-owned public content."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from lurewall import canaries, labsite
from lurewall.natural_runtime import JAVASCRIPT

PLACEMENTS = {
    "footer": ("index.html", "footer_comment.quiet"),
    "robots": ("robots.txt", "robots_disallow.quiet"),
    "security": (".well-known/security.txt", "security_txt.quiet"),
}
MAX_BODY = 524288
WORD = re.compile(r"[a-z]{3,24}")
EXTENSIONS = {"html", "htm", "txt", "xml", "pdf", "csv", "json"}
EXCLUDE = EXTENSIONS | {"index", "robots", "well", "known", "security", "sitemap"}
LOG_FORMAT = """log_format lurewall_natural escape=json
  '{"ts":"$msec","ip":"$realip_remote_addr","method":"$request_method",'
  '"request":"$request","uri":"$request_uri","status":"$status",'
  '"ua":"$http_user_agent","lang":"$http_accept_language","referer":"$http_referer",'
  '"sec_fetch_site":"$http_sec_fetch_site","request_id":"$request_id",'
  '"forwarded_for":"$http_x_forwarded_for","lw_source":"$remote_addr",'
  '"lw_placement":"$lw_placement","lw_path":"$lw_path","lw_until":"$lw_until"}';
"""


def _path(path: Path) -> str:
    value = str(path)
    if not re.fullmatch(r"/[a-zA-Z0-9_./-]+", value) or ".." in path.parts:
        raise labsite.BuildError("nginx paths require plain absolute filesystem names")
    return value


def _public_file(root: Path, route: str) -> Path | None:
    path = root / route
    if path.resolve() != path or not path.is_file() or path.stat().st_size > MAX_BODY:
        return None
    return path


def _style(route: str) -> str | None:
    if not canaries.is_natural_path(route):
        return None
    stem, dot, ext = route.rpartition(".")
    suffix = dot + ext if dot and ext in EXTENSIONS else ""
    text = stem if suffix else route
    text = re.sub(r"(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)", "D", text)
    text = re.sub(r"/\d{4}/\d{2}/\d{2}(?=/|$)", "/Y/M/T", text)
    text = re.sub(r"(?<=/)v\d+(?=/|$)", "vV", text)
    text = re.sub(r"[a-z]+", lambda m: "v" if text[m.end() :].startswith("V") else "W", text)
    if not re.fullmatch(r"[/WvVDYMT._-]+", text) or "W" not in text or text.count("W") > 6:
        return None
    if text.count("W") == 1 and not any(c in text for c in "VDY"):
        text = text.replace("W", "W-W")
    return text + suffix


def _inputs(root: Path, host: str, wordlist: Path | None):
    words: set[str] = set()
    routes: set[str] = set()
    styles: Counter[str] = Counter()

    def add(route: str):
        if route in routes or len(route) > 220:
            return
        routes.add(route)
        if len(routes) > 20000:
            raise labsite.BuildError("site route inventory exceeds 20000 entries")
        if route in {"/index.html", "/robots.txt", "/.well-known/security.txt", "/sitemap.xml"}:
            return
        words.update(WORD.findall(route.lower()))
        style = _style(route)
        if style:
            styles[style] += 1

    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(
            d for d in dirs if not d.startswith(".") and not (Path(folder) / d).is_symlink()
        )
        for name in sorted(files):
            if not name.startswith("."):
                add("/" + (Path(folder) / name).relative_to(root).as_posix())
    sitemap = _public_file(root, "sitemap.xml")
    if sitemap:
        from xml.parsers import expat

        values: list[str] = []
        parts: list[str] = []
        in_loc = False

        def start(name, _attrs):
            nonlocal in_loc
            in_loc = name.rsplit(":", 1)[-1] == "loc"
            parts.clear()

        def end(_name):
            nonlocal in_loc
            if in_loc:
                values.append("".join(parts).strip())
            in_loc = False

        def reject_doctype(*_args):
            raise labsite.BuildError("sitemap must not declare entities")

        parser = expat.ParserCreate()
        parser.StartElementHandler, parser.EndElementHandler = start, end
        parser.CharacterDataHandler = lambda s: parts.append(s) if in_loc else None
        parser.StartDoctypeDeclHandler = reject_doctype
        try:
            parser.Parse(sitemap.read_bytes(), True)
        except expat.ExpatError as exc:
            raise labsite.BuildError("invalid local sitemap XML") from exc
        for value in values:
            url = urlsplit(value)
            if url.hostname == host.lower() and url.scheme in {"http", "https"}:
                add(url.path)
    if wordlist:
        if wordlist.stat().st_size > MAX_BODY:
            raise labsite.BuildError("wordlist exceeds size limit")
        for line in wordlist.read_text(encoding="utf-8").splitlines():
            words.update(WORD.findall(line.partition("#")[0].lower()))
    words.difference_update(EXCLUDE | canaries.RESERVED_SEGMENTS)
    words = {word for word in words if not re.fullmatch("[a-f]+", word)}
    return sorted(words)[:512], routes, [s for s, _ in styles.most_common()]


def _security_expiry(text: str) -> int | None:
    """Only extend a conservative subset of unsigned, valid security.txt files."""
    contacts = []
    dates = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*):[ \t]+([^\x00-\x1f]+)", line)
        if not match:
            return None
        field, value = match[1].lower(), match[2].strip()
        if field == "contact":
            contacts.append(value)
        if field == "expires":
            dates.append(value)
    if (
        not contacts
        or len(dates) != 1
        or not re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", dates[0]
        )
    ):
        return None
    if any(
        not re.fullmatch(
            r"(?:https://[^\s/]+(?:/[^\s]*)?|mailto:[^\s@]+@[^\s@]+|tel:\+?[\d()-]+)", c
        )
        for c in contacts
    ):
        return None
    try:
        expires = datetime.fromisoformat(dates[0])
    except ValueError:
        return None
    return int(expires.timestamp()) if expires > datetime.now(UTC) else None


def _carrier(name, root):
    filename, placement = PLACEMENTS[name]
    path = _public_file(root, filename)
    if not path:
        return None
    raw = path.read_bytes()
    try:
        body = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    nl = "\r\n" if "\r\n" in body else "\n"
    expiry = None
    if name == "footer":
        end = re.search(r"</(?:footer|body)\s*>", body, re.I)
        if not end:
            return None
        before, after = body[: end.start()] + "<!-- ", " -->" + nl + body[end.start() :]
    elif name == "robots":
        # Insert in an existing wildcard group and follow its directive spelling.
        wildcard = False
        pos = 0
        for line in body.splitlines(keepends=True):
            text = line.partition("#")[0].strip()
            key, _, value = text.partition(":")
            if key.strip().lower() == "user-agent":
                wildcard = value.strip() == "*"
            match = re.match(r"^(\s*)(Allow|Disallow)([ \t]*:[ \t]*)", line, re.I)
            pos += len(line)
            if wildcard and match:
                directive = "disallow" if match[2].islower() else "Disallow"
                before = (
                    body[:pos]
                    + ("" if line.endswith("\n") else nl)
                    + match[1]
                    + directive
                    + match[3]
                )
                after = nl + body[pos:]
                break
        else:
            return None
    else:
        expiry = _security_expiry(body)
        if expiry is None:
            return None
        comment = re.search(r"^(#[ \t]*)", body, re.M)
        before = body + ("" if body.endswith("\n") else nl) + (comment[1] if comment else "# ")
        after = nl
    return {
        "id": placement,
        "before": before,
        "after": after,
        "file": str(path),
        "expires": expiry,
        "hash": hashlib.sha256(raw).hexdigest(),
        "type": "text/html" if name == "footer" else "text/plain; charset=utf-8",
        "fallback": "@lw_static_" + name,
    }


def build(
    *,
    state: Path,
    site_root: Path,
    out: Path,
    host: str,
    listen: str,
    wordlist: Path | None,
    placements: str,
    deploy_root: str | None,
    checkpoint: str | None,
):
    root, out = site_root.resolve(), out.resolve()
    dest = _path(Path(deploy_root or out))
    _path(root)
    if (
        not root.is_dir()
        or root.is_relative_to(out)
        or out.is_relative_to(root)
        or state.resolve().is_relative_to(root)
    ):
        raise labsite.BuildError("keep private output and state separate from the public site root")
    if (
        not host
        or "." not in host
        or len(host) > 253
        or not all(labsite._HOST_LABEL_RE.fullmatch(s) for s in host.split("."))
    ):
        raise labsite.BuildError("natural vhost requires an exact hostname")
    if not labsite._LISTEN_RE.fullmatch(listen) or " " in listen:
        raise labsite.BuildError("invalid nginx listen address")
    canaries.refuse_git_work_tree(out, "natural site output")
    names = placements.split(",")
    if len(names) != len(set(names)) or not all(n in PLACEMENTS for n in names):
        raise labsite.BuildError("placements must be selected from footer,robots,security")
    if out.exists() and any(out.iterdir()):
        raise labsite.BuildError(
            "build into a fresh directory; keep the previous vhost for rollback"
        )
    words, routes, styles = _inputs(root, host, wordlist)
    carriers = {}
    used_endings = set()
    for name in names:
        c = _carrier(name, root)
        if not c:
            continue
        # When too few styles exist on the site, use different local word constructions.
        for style in [*styles, "/W-W/W", "/W/W-W/", "/W/vV/W", "/W/D/W-W"]:
            ending = style[style.rfind(".") :] if "." in style else style[-2:]
            if ending not in used_endings:
                break
        used_endings.add(ending)
        c.update(style=style, slot=len(carriers))
        carriers["/" + PLACEMENTS[name][0]] = c
    if not carriers:
        raise labsite.BuildError("no eligible existing carriers for the selected placements")
    count = len(carriers)
    if len(words) < count * max(4, max(c["style"].count("W") for c in carriers.values())):
        raise labsite.BuildError("insufficient local route vocabulary; supply --wordlist")
    if state.exists():
        canaries.load_state(state)
    sidecar = canaries.natural_state_path(state)
    key = canaries.load_state(sidecar) if sidecar.exists() else canaries.natural_state()
    if key.version != canaries.NATURAL_VERSION:
        raise labsite.BuildError("invalid natural issuance state")
    if "/index.html" in carriers:
        carriers["/"] = carriers["/index.html"]
    profile = {
        "root": str(root),
        "leases": dest + "/leases",
        "key": key.placeholder,
        "words": words,
        "count": count,
        "routes": dict.fromkeys((p.rstrip("/") for p in routes), True),
        "carriers": carriers,
    }
    fmt = f"js_import lurewall from {dest}/nginx/natural.js;\n"
    fmt += "js_var $lw_placement;\njs_var $lw_path;\njs_var $lw_until;\n" + LOG_FORMAT
    locations = [f"location = {route} {{ js_content lurewall.serve; }}" for route in carriers]
    for name in names:
        filename = PLACEMENTS[name][0]
        if "/" + filename in carriers:
            locations.append(f"location @lw_static_{name} {{ try_files /{filename} =404; }}")
    if checkpoint:
        locations.append(
            f"location = {labsite.CHECKPOINT_ROUTE} {{ alias {_path(Path(checkpoint))}; }}"
        )
    conf = f"""server {{
    listen {listen};
    server_name {host};
    root {root};
    access_log /var/log/lurewall/access.jsonl lurewall_natural;
    include {dest}/nginx/lurewall-natural-locations.conf;
    location / {{ try_files $uri $uri/ =404; }}
}}
"""
    directory = out / "nginx"
    directory.mkdir(parents=True)
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise labsite.BuildError("expected private nginx output directory")
    # A root nginx master compiles the module at config load. Never put it below root.
    for name, data in {
        "natural.js": "const PROFILE = "
        + json.dumps(profile, ensure_ascii=True)
        + ";\n"
        + JAVASCRIPT,
        "lurewall-natural-format.conf": fmt,
        "lurewall-natural-locations.conf": "\n".join(locations) + "\n",
        "lurewall-site.conf": conf,
    }.items():
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as tmp:
            tmp.write(data.encode())
        os.replace(tmp.name, directory / name)
    (out / "leases").mkdir(mode=0o700)
    # Commit the activation sidecar only after the entire vhost has been generated.
    if not state.exists():
        canaries.save_state(canaries.generate(labsite.site_routes()), state)
    if not sidecar.exists():
        canaries.save_state(key, sidecar)
    return directory / "lurewall-site.conf"
