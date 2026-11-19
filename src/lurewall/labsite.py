# SPDX-License-Identifier: AGPL-3.0-only
"""The throwaway lab site: static pages with every canary placement, and its nginx config.

The site is a small fictional one, served by nginx on a private network for
the lab tests only. Its pages are public (they are in this file); the canaries
woven into them come from an installation's state file and are not.

Building does three things every time, so they hold whenever the site changes:

1. checks every decoy path against the site's real routes, and fails on any
   collision;
2. writes the pages with each canary reference carrying a placeholder that
   nginx's ``sub_filter`` replaces with that request's ``$request_id``;
3. writes an nginx ``server`` block that answers each decoy path, and only
   those paths, with its fixed body.

v2 quiet canaries (when the installation has them): B is an HTML comment in
every content page's footer, A one ``Disallow`` line in robots.txt, and C a
comment in a valid ``/.well-known/security.txt``. No quiet decoy has an nginx
location: a request for one gets the site's ordinary 404, byte for byte, and
every 404 carries ``X-Robots-Tag: noindex``. Which pages carry which quiet
canary is ``quiet_carriers``; the engine uses it to bind a hit to the source
that was served the carrier.

Accessibility rule: no canary is read aloud to a screen-reader user. Canaries
are either HTML comments (not in the DOM at all) or elements carrying
``aria-hidden="true"`` with nothing focusable inside.

Text-mode browsers are the exception, and HTML cannot hide anything from them.
Lynx 2.9.3 prints the text of an element hidden by CSS, by the ``hidden``
attribute, by ``display: none`` and inside ``<template>`` alike; only comments
and attribute values stay out. That is the same reason the hidden-element
placement works at all: an agent that turns a page into text sees what a text
browser shows. So hidden canary text is not hidden from those readers. It
starts with ``TEXT_MODE_NOTICE`` instead, which tells a person reading it that
the line is not meant for them (lab test case 5).

The output holds an installation's canaries in clear, so it is refused inside
any git work tree.
"""

from __future__ import annotations

import html
import re
import shutil
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lurewall import canaries as canary_mod
from lurewall.canaries import Canary, CanaryError, CanarySet

SITE_NAME = "Lab Tool Library"
MARKER_FILE = ".lurewall-lab-site"

_DEPLOY_ROOT_RE = re.compile(r"/[A-Za-z0-9._/-]{1,200}", re.ASCII)
_LISTEN_RE = re.compile(r"[0-9A-Za-z.:\[\]_ -]{1,80}", re.ASCII)
_HOST_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII | re.IGNORECASE)
_ROUTE_RE = re.compile(r"/[A-Za-z0-9._/-]{0,200}", re.ASCII)


class BuildError(CanaryError):
    """The site could not be built."""


@dataclass(frozen=True)
class BuildResult:
    out_dir: Path
    web_root: Path
    nginx_conf: Path
    routes: frozenset[str]


# -- the site's own content (public, not canaries) ---------------------------------

_NAV = (
    ("/", "Home"),
    ("/about.html", "About"),
    ("/services.html", "Borrowing"),
    ("/docs/", "Guides"),
    ("/contact.html", "Contact"),
)

_PAGES: dict[str, tuple[str, str]] = {
    "/index.html": (
        "Home",
        "<h1>Lab Tool Library</h1>\n"
        "<p>A neighbourhood shelf of shared tools. Borrow a drill for the weekend, bring it"
        " back on Monday, and leave the storage problem to us.</p>\n"
        '<p><a href="/services.html">See how borrowing works</a> or read the'
        ' <a href="/docs/">guides</a>.</p>',
    ),
    "/about.html": (
        "About",
        "<h1>About</h1>\n"
        "<p>This is a fictional organisation used as a test site. Nothing here is a real"
        " service, and no real person or business is described.</p>\n"
        "<p>The shelf holds hand tools, a few power tools and one very popular ladder.</p>",
    ),
    "/services.html": (
        "Borrowing",
        "<h1>Borrowing</h1>\n"
        "<ul>\n<li>Pick a tool from the shelf list.</li>\n<li>Keep it for up to seven days.</li>\n"
        "<li>Return it clean and tell us if anything broke.</li>\n</ul>",
    ),
    "/contact.html": (
        "Contact",
        "<h1>Contact</h1>\n"
        "<p>This test site has no inbox. In a real library this page would list opening"
        " hours and a way to reach a volunteer.</p>",
    ),
    "/docs/index.html": (
        "Guides",
        "<h1>Guides</h1>\n"
        '<ul>\n<li><a href="/docs/getting-started.html">Getting started</a></li>\n</ul>',
    ),
    "/docs/getting-started.html": (
        "Getting started",
        "<h1>Getting started</h1>\n"
        "<p>Check the tool before you leave, wear eye protection, and read the label on"
        " anything with a blade.</p>",
    ),
}

_API_PAGE = "/developers/api.html"

# Test case 19: one page that carries three fixed markers and no canary, so an
# agent's answer shows which parts its fetch tool passed on. Not linked from
# anywhere and not in the sitemap. The markers are public and mean nothing.
FETCH_CHECK_PAGE = "/lab/fetch-check.html"
MARKER_COMMENT = "marker-comment-kestrel"
MARKER_HIDDEN = "marker-hidden-heron"
# Leads every hidden canary, for a person on a text-mode browser who sees it.
TEXT_MODE_NOTICE = (
    "Text-mode note: the rest of this line is hidden on the normal page"
    " and is not meant for people."
)
MARKER_HEADER = "marker-header-plover"
MARKER_HEADER_NAME = "X-Lab-Marker"

# The signed checkpoint, served so test machine A can pull it (runbook, Phase 4).
CHECKPOINT_ROUTE = "/lurewall-checkpoint.json"

# RFC 9116. Carries canary C when the installation has the quiet canaries.
SECURITY_TXT = "/.well-known/security.txt"
SECURITY_CONTACT = "mailto:security@lab-tool-library.invalid"
SECURITY_EXPIRES_DAYS = 180
_ERROR_PAGES = {
    "/errors/404.html": ("Page not found", "We could not find that page."),
    "/errors/403.html": ("Not allowed", "You do not have access to that page."),
}

_LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" role="img"'
    ' aria-label="Lab Tool Library">'
    '<rect width="32" height="32" rx="6" fill="#2f5d50"/>'
    '<path d="M9 22l9-9m0 0l2-5 4 4-5 2" stroke="#fff" stroke-width="2.5" fill="none"'
    ' stroke-linecap="round"/></svg>\n'
)

_CSS = """\
body { font-family: system-ui, sans-serif; line-height: 1.5; margin: 0; color: #1d2b27; }
header, main, footer { max-width: 44rem; margin: 0 auto; padding: 1rem; }
nav a { margin-right: 1rem; }
footer { color: #51615c; font-size: 0.9rem; border-top: 1px solid #d5ddd9; }
table { border-collapse: collapse; }
td, th { border: 1px solid #d5ddd9; padding: 0.3rem 0.6rem; text-align: left; }
"""

# Takes the element out of view and out of layout. Together with aria-hidden it
# is hidden from sighted users and from screen readers.
_HIDDEN_RULE = (
    ".{name} {{ position: absolute; left: -10000px; top: auto; width: 1px; height: 1px;"
    " overflow: hidden; clip-path: inset(50%); white-space: nowrap; }}\n"
)

_STATIC_ROUTES = frozenset(
    {
        "/",
        "/assets/",
        "/assets/site.css",
        "/assets/logo.svg",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/docs/",
        "/developers/",
        "/errors/",
        "/staff/",
        "/lab/",
        "/.well-known/",
        SECURITY_TXT,
        FETCH_CHECK_PAGE,
        CHECKPOINT_ROUTE,
        _API_PAGE,
        *_PAGES,
        *_ERROR_PAGES,
    }
)


def site_routes(extra_pages: Mapping[str, str] | None = None) -> frozenset[str]:
    """Every real path of the lab site. Decoys are checked against these."""
    return _STATIC_ROUTES | frozenset(extra_pages or ())


def quiet_carriers(
    canary_set: CanarySet, extra_pages: Mapping[str, str] | None = None
) -> dict[str, tuple[str, ...]]:
    """Normalized, lowercased path -> the quiet canaries a 200 response to it carries.

    B is in the footer of every content page (and so of each directory index
    that serves one), A in robots.txt, C in security.txt. Error pages, the API
    page and the fetch-check page carry none.
    """
    present = {canary.id for canary in canary_set.canaries if canary.quiet}
    carriers: dict[str, tuple[str, ...]] = {}
    if "footer_comment.quiet" in present:
        pages = {*_PAGES, *(extra_pages or ())}
        for page in pages:
            carriers[page.lower()] = ("footer_comment.quiet",)
            if page.endswith("/index.html"):
                carriers[page[: -len("index.html")].lower()] = ("footer_comment.quiet",)
    if "robots_disallow.quiet" in present:
        carriers["/robots.txt"] = ("robots_disallow.quiet",)
    if "security_txt.quiet" in present:
        carriers[SECURITY_TXT] = ("security_txt.quiet",)
    return carriers


def _quiet(canary_set: CanarySet, canary_id: str) -> Canary | None:
    return next((c for c in canary_set.canaries if c.id == canary_id), None)


# -- rendering canaries ----------------------------------------------------------------


def _text(canary: Canary, placeholder: str) -> str:
    return canary.text.replace("{ref}", canary.reference(placeholder))


def _comment(canary: Canary, placeholder: str) -> str:
    if canary.form == "link":
        ref = html.escape(canary.reference(placeholder), quote=True)
        return f'<!-- <a href="{ref}">{html.escape(canary.text)}</a> -->'
    return f"<!-- {_text(canary, placeholder)} -->"


def _hidden(canary: Canary, canary_set: CanarySet) -> str:
    text = html.escape(f"{TEXT_MODE_NOTICE} {_text(canary, canary_set.placeholder)}")
    return f'<p class="{canary_set.hidden_class}" aria-hidden="true">{text}</p>'


def _layout(title: str, main: str, *, head: str = "", after_main: str = "", foot: str = "") -> str:
    nav = "\n".join(f'<a href="{href}">{label}</a>' for href, label in _NAV)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(title)} - {SITE_NAME}</title>\n"
        '<link rel="stylesheet" href="/assets/site.css">\n'
        '<link rel="icon" href="/assets/logo.svg" type="image/svg+xml">\n'
        f"{head}</head>\n<body>\n"
        f'<header>\n<a href="/"><img src="/assets/logo.svg" alt="{SITE_NAME} home"'
        ' width="32" height="32"></a>\n'
        f"<nav>\n{nav}\n</nav>\n</header>\n"
        f"<main>\n{main}\n{after_main}</main>\n"
        f"<footer>\n<p>{SITE_NAME}: a fictional test site.</p>\n{foot}</footer>\n"
        "</body>\n</html>\n"
    )


def _content_page(title: str, body: str, canary_set: CanarySet) -> str:
    placeholder = canary_set.placeholder
    foot = _comment(canary_set.by_id("html_comment.bait"), placeholder) + "\n"
    quiet = _quiet(canary_set, "footer_comment.quiet")
    if quiet is not None:
        # Canary B: a destination, no instruction. Comments are not rendered,
        # not read by screen readers and not shown by text-mode browsers.
        foot += f"<!-- {_text(quiet, placeholder)} -->\n"
    return _layout(
        title,
        body,
        head=_comment(canary_set.by_id("html_comment.instruction"), placeholder) + "\n",
        after_main=_hidden(canary_set.by_id("hidden_element.instruction"), canary_set) + "\n",
        foot=foot,
    )


def _api_page(canary_set: CanarySet) -> str:
    bait = canary_set.by_id("api_doc.bait")
    root = "/".join(bait.path.split("/")[:3])  # the bait sits among endpoints of the same root
    ref = html.escape(bait.reference(canary_set.placeholder))
    ordinary = [
        ("GET", f"{root}/tools", "List tools on the shelf"),
        ("GET", f"{root}/tools/{{id}}", "One tool"),
        ("GET", f"{root}/hours", "Opening hours"),
        ("POST", f"{root}/reservations", "Reserve a tool"),
    ]
    rows = [
        f"<tr><td>{method}</td><td><code>{html.escape(path)}</code></td><td>{text}</td></tr>"
        for method, path, text in ordinary
    ]
    # Hidden from assistive technology like every other canary, and not a link.
    rows.insert(
        2,
        f'<tr aria-hidden="true"><td>GET</td><td><code>{ref}</code></td>'
        f"<td>{html.escape(bait.text)}</td></tr>",
    )
    table = (
        "<h1>API reference</h1>\n<p>Endpoints for partner integrations.</p>\n<table>\n"
        "<tr><th>Method</th><th>Path</th><th>Description</th></tr>\n"
        + "\n".join(rows)
        + "\n</table>"
    )
    return _layout("API reference", table, head='<meta name="robots" content="noindex">\n')


def _error_page(title: str, message: str, canary_set: CanarySet) -> str:
    body = (
        f'<h1>{html.escape(title)}</h1>\n<p>{html.escape(message)}</p>\n<p><a href="/">Home</a></p>'
    )
    return _layout(
        title, body, foot=_hidden(canary_set.by_id("error_page.bait"), canary_set) + "\n"
    )


def _fetch_check_page(canary_set: CanarySet) -> str:
    """Markers only. The page is built without _layout's canaries on purpose."""
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f"<title>Fetch check - {SITE_NAME}</title>\n"
        '<link rel="stylesheet" href="/assets/site.css">\n'
        f"<!-- {MARKER_COMMENT} -->\n</head>\n<body>\n<main>\n"
        "<h1>Fetch check</h1>\n<p>marker-visible-wren</p>\n"
        f'<p class="{canary_set.hidden_class}" aria-hidden="true">{MARKER_HIDDEN}</p>\n'
        "</main>\n</body>\n</html>\n"
    )


def _robots(canary_set: CanarySet) -> str:
    # One Disallow line names a decoy, and only canary A's (v2, a recon signal:
    # ordinary scanners read robots.txt too). No other decoy is listed.
    lure = _text(canary_set.by_id("robots_comment.instruction"), canary_set.placeholder)
    quiet = _quiet(canary_set, "robots_disallow.quiet")
    disallow = f"{_text(quiet, canary_set.placeholder)}\n" if quiet is not None else ""
    return f"User-agent: *\n{disallow}Allow: /\n# {lure}\nSitemap: /sitemap.xml\n"


def _security_txt(canary_set: CanarySet, now_ms: int) -> str:
    """A valid RFC 9116 file for the fictional site. C is a comment line in it."""
    expires = datetime.fromtimestamp(now_ms / 1000, UTC).date() + timedelta(
        days=SECURITY_EXPIRES_DAYS
    )
    lines = [
        f"Contact: {SECURITY_CONTACT}",
        f"Expires: {expires.isoformat()}T00:00:00.000Z",
        "Preferred-Languages: en",
    ]
    quiet = _quiet(canary_set, "security_txt.quiet")
    if quiet is not None:
        lines.append(f"# {_text(quiet, canary_set.placeholder)}")
    return "\n".join(lines) + "\n"


def _sitemap() -> str:
    urls = ["/", *sorted(path for path in _PAGES if path != "/index.html")]
    items = "".join(f"<url><loc>{html.escape(path)}</loc></url>\n" for path in urls)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + items + "</urlset>\n"
    )


def render_files(
    canary_set: CanarySet,
    extra_pages: Mapping[str, str] | None = None,
    *,
    now_ms: int | None = None,
) -> dict[str, str]:
    """Every file under the web root, keyed by URL path."""
    now_ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    files = {path: _content_page(title, body, canary_set) for path, (title, body) in _PAGES.items()}
    for path, body in (extra_pages or {}).items():
        files[path] = _content_page("Page", body, canary_set)
    files[_API_PAGE] = _api_page(canary_set)
    for path, (title, message) in _ERROR_PAGES.items():
        files[path] = _error_page(title, message, canary_set)
    files[FETCH_CHECK_PAGE] = _fetch_check_page(canary_set)
    files["/robots.txt"] = _robots(canary_set)
    files[SECURITY_TXT] = _security_txt(canary_set, now_ms)
    files["/sitemap.xml"] = _sitemap()
    files["/assets/site.css"] = _CSS + _HIDDEN_RULE.format(name=canary_set.hidden_class)
    files["/assets/logo.svg"] = _LOGO_SVG
    return files


# -- nginx ---------------------------------------------------------------------------


def nginx_config(
    canary_set: CanarySet,
    deploy_root: str,
    listen: str = "80",
    checkpoint_file: str | None = None,
    *,
    server_name: str | None = None,
) -> str:
    """The ``server`` block for the lab site. Meant for nginx's ``http`` context.

    Everything written here comes from a validated canary set, whose fields
    are held to character sets with no quote, backslash, ``$``, ``;`` or brace
    in them, so nothing in the state file can add a directive.
    """
    canary_mod.validate(canary_set)
    if _DEPLOY_ROOT_RE.fullmatch(deploy_root) is None or ".." in deploy_root:
        raise BuildError("deploy root must be an absolute path of letters, digits and . _ / -")
    if _LISTEN_RE.fullmatch(listen) is None:
        raise BuildError("listen value is not in the allowed form")
    if server_name is not None and (
        len(server_name) > 253
        or "." not in server_name
        or not all(_HOST_LABEL_RE.fullmatch(label) for label in server_name.split("."))
        or " " in listen
    ):
        raise BuildError("operator vhost requires an exact DNS name and a listen address or port")
    if checkpoint_file is not None and (
        _DEPLOY_ROOT_RE.fullmatch(checkpoint_file) is None or ".." in checkpoint_file
    ):
        raise BuildError("checkpoint file must be an absolute path of letters, digits and . _ / -")
    root = deploy_root.rstrip("/")
    header = canary_set.by_id("response_header.instruction")
    header_ref = f"{header.path}?{header.param}=${{request_id}}"
    header_value = header.text.replace("{ref}", header_ref)

    # Page stamping: each canary reference on a served page carries that
    # request's ID, so a later hit can be tied to the page that carried it.
    # It is set per location, and only where pages are served: decoy bodies
    # and assets go out untouched, as ordinary static files.
    stamp = [
        f"        sub_filter '{canary_set.placeholder}' '$request_id';",
        "        sub_filter_once off;",
        "        sub_filter_types text/plain;",
    ]
    # add_header in a location replaces the server's, so the error pages
    # repeat the server's headers and add X-Robots-Tag. Every 404, whether for
    # a quiet decoy or any other missing path, is then the same response.
    server_headers = [
        '        add_header Cache-Control "no-store" always;',
        f'        add_header {canary_set.header_name} "{header_value}" always;',
    ]
    lines = [
        "# Generated by `lurewall lab-site build`. Holds this installation's canaries:",
        "# keep it out of any repository.",
        "server {",
        f"    listen {listen};",
        f"    server_name {server_name or '_'};",
        *(
            ["    access_log /var/log/lurewall/access.jsonl lurewall_operator;"]
            if server_name is not None
            else []
        ),
        f"    root {root}/www;",
        "    index index.html;",
        "    charset utf-8;",
        "    server_tokens off;",
        "",
        "    error_page 404 /errors/404.html;",
        "    error_page 403 /errors/403.html;",
        "",
        "    # A stamped page belongs to one request. No cache may hand it to another.",
        '    add_header Cache-Control "no-store" always;',
        f'    add_header {canary_set.header_name} "{header_value}" always;',
        "",
        "    location / {",
        "        try_files $uri $uri/ =404;",
        *stamp,
        "    }",
        "    location /errors/ {",
        "        internal;",
        *server_headers,
        '        add_header X-Robots-Tag "noindex" always;',
        *stamp,
        "    }",
        "    location /staff/ {",
        "        deny all;",
        "    }",
        "    location /assets/ {",
        '        add_header Cache-Control "public, max-age=3600";',
        "    }",
        f"    location = {_API_PAGE} {{",
        '        add_header Cache-Control "no-store" always;',
        '        add_header X-Robots-Tag "noindex" always;',
        *stamp,
        "    }",
        "    # Test case 19. add_header here replaces the server's, so this page",
        "    # carries the marker header and no canary header.",
        f"    location = {FETCH_CHECK_PAGE} {{",
        '        add_header Cache-Control "no-store" always;',
        f'        add_header {MARKER_HEADER_NAME} "{MARKER_HEADER}" always;',
        "    }",
    ]
    if checkpoint_file is not None:
        lines += [
            "    # The signed checkpoint: hashes and a signature, nothing about visitors.",
            f"    location = {CHECKPOINT_ROUTE} {{",
            "        types { }",
            "        default_type application/json;",
            '        add_header Cache-Control "no-store" always;',
            f"        alias {checkpoint_file};",
            "    }",
        ]
    lines += [
        "",
        "    # v1 decoys: exact paths only. Any other missing path gets the normal 404.",
        "    # A fixed 200 body, never a 204, and not announced in robots.txt.",
        "    # v2 quiet decoys have no location: they get the ordinary 404.",
    ]
    for index, canary in enumerate(_served_decoys(canary_set)):
        lines += [
            f"    location = {canary.path} {{",
            "        types { }",
            f"        default_type {canary.content_type};",
            '        add_header X-Robots-Tag "noindex, nofollow" always;',
            f"        alias {root}/decoys/{index}.body;",
            "    }",
        ]
    lines += ["}", ""]
    return "\n".join(lines)


def _served_decoys(canary_set: CanarySet) -> list[Canary]:
    """The decoys nginx answers with a body: v1 only, in a fixed order."""
    return [canary for canary in canary_set.canaries if not canary.quiet]


# -- building ------------------------------------------------------------------------


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(0o644)


def build(
    canary_set: CanarySet,
    out_dir: str | Path,
    *,
    deploy_root: str | None = None,
    listen: str = "80",
    extra_pages: Mapping[str, str] | None = None,
    checkpoint_file: str | None = None,
    now_ms: int | None = None,
    server_name: str | None = None,
) -> BuildResult:
    """Build the site and its nginx config into ``out_dir``.

    Fails with CollisionError if a decoy path collides with a real route. That
    check runs on every build, so it runs again whenever the site changes.
    ``deploy_root`` is where the output will live on the web server, if that
    differs from ``out_dir``.
    """
    out = Path(out_dir)
    canary_mod.validate(canary_set)
    for route in extra_pages or ():
        if _ROUTE_RE.fullmatch(route) is None or ".." in route or not route.endswith(".html"):
            raise BuildError(f"extra page route is not in the allowed form: {route!r}")
    routes = site_routes(extra_pages)
    canary_mod.check_collisions(canary_set, routes)
    root = str(out.resolve()) if deploy_root is None else deploy_root
    config = nginx_config(canary_set, root, listen, checkpoint_file, server_name=server_name)

    canary_mod.refuse_git_work_tree(out, "site output directory")
    if out.exists():
        if not out.is_dir():
            raise BuildError(f"{out} exists and is not a directory")
        if any(out.iterdir()) and not (out / MARKER_FILE).exists():
            raise BuildError(
                f"{out} is not empty and was not built by Lurewall; refusing to use it"
            )
    out.mkdir(parents=True, exist_ok=True, mode=0o755)
    for old in ("www", "decoys", "nginx"):
        if (out / old).exists():
            shutil.rmtree(out / old)
    _write(out / MARKER_FILE, "Built by `lurewall lab-site build`. Safe to delete and rebuild.\n")

    web_root = out / "www"
    for url_path, content in render_files(canary_set, extra_pages, now_ms=now_ms).items():
        _write(web_root / url_path.lstrip("/"), content)
    for name in ("staff",):
        (web_root / name).mkdir(mode=0o755, exist_ok=True)
    for index, canary in enumerate(_served_decoys(canary_set)):
        _write(out / "decoys" / f"{index}.body", canary.body)

    conf = out / "nginx" / "lurewall-site.conf"
    _write(conf, config)
    return BuildResult(out_dir=out, web_root=web_root, nginx_conf=conf, routes=routes)
