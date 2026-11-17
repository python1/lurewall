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

Accessibility rule: no canary is read aloud to a screen-reader user. Canaries
are either HTML comments (not in the DOM at all) or elements carrying
``aria-hidden="true"`` with nothing focusable inside.

The output holds an installation's canaries in clear, so it is refused inside
any git work tree.
"""

from __future__ import annotations

import html
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from lurewall import canaries as canary_mod
from lurewall.canaries import Canary, CanaryError, CanarySet

SITE_NAME = "Lab Tool Library"
MARKER_FILE = ".lurewall-lab-site"

_DEPLOY_ROOT_RE = re.compile(r"/[A-Za-z0-9._/-]{1,200}", re.ASCII)
_LISTEN_RE = re.compile(r"[0-9A-Za-z.:\[\]_ -]{1,80}", re.ASCII)
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
        _API_PAGE,
        *_PAGES,
        *_ERROR_PAGES,
    }
)


def site_routes(extra_pages: Mapping[str, str] | None = None) -> frozenset[str]:
    """Every real path of the lab site. Decoys are checked against these."""
    return _STATIC_ROUTES | frozenset(extra_pages or ())


# -- rendering canaries ----------------------------------------------------------------


def _text(canary: Canary, placeholder: str) -> str:
    return canary.text.replace("{ref}", canary.reference(placeholder))


def _comment(canary: Canary, placeholder: str) -> str:
    if canary.form == "link":
        ref = html.escape(canary.reference(placeholder), quote=True)
        return f'<!-- <a href="{ref}">{html.escape(canary.text)}</a> -->'
    return f"<!-- {_text(canary, placeholder)} -->"


def _hidden(canary: Canary, canary_set: CanarySet) -> str:
    text = html.escape(_text(canary, canary_set.placeholder))
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
        f'<header>\n<a href="/"><img src="/assets/logo.svg" alt="" width="32" height="32"></a>\n'
        f"<nav>\n{nav}\n</nav>\n</header>\n"
        f"<main>\n{main}\n{after_main}</main>\n"
        f"<footer>\n<p>{SITE_NAME}: a fictional test site.</p>\n{foot}</footer>\n"
        "</body>\n</html>\n"
    )


def _content_page(title: str, body: str, canary_set: CanarySet) -> str:
    placeholder = canary_set.placeholder
    return _layout(
        title,
        body,
        head=_comment(canary_set.by_id("html_comment.instruction"), placeholder) + "\n",
        after_main=_hidden(canary_set.by_id("hidden_element.instruction"), canary_set) + "\n",
        foot=_comment(canary_set.by_id("html_comment.bait"), placeholder) + "\n",
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


def _robots(canary_set: CanarySet) -> str:
    # No Disallow line names a decoy: that would publish the list of them.
    lure = _text(canary_set.by_id("robots_comment.instruction"), canary_set.placeholder)
    return f"User-agent: *\nAllow: /\n# {lure}\nSitemap: /sitemap.xml\n"


def _sitemap() -> str:
    urls = ["/", *sorted(path for path in _PAGES if path != "/index.html")]
    items = "".join(f"<url><loc>{html.escape(path)}</loc></url>\n" for path in urls)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + items + "</urlset>\n"
    )


def render_files(
    canary_set: CanarySet, extra_pages: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Every file under the web root, keyed by URL path."""
    files = {path: _content_page(title, body, canary_set) for path, (title, body) in _PAGES.items()}
    for path, body in (extra_pages or {}).items():
        files[path] = _content_page("Page", body, canary_set)
    files[_API_PAGE] = _api_page(canary_set)
    for path, (title, message) in _ERROR_PAGES.items():
        files[path] = _error_page(title, message, canary_set)
    files["/robots.txt"] = _robots(canary_set)
    files["/sitemap.xml"] = _sitemap()
    files["/assets/site.css"] = _CSS + _HIDDEN_RULE.format(name=canary_set.hidden_class)
    files["/assets/logo.svg"] = _LOGO_SVG
    return files


# -- nginx ---------------------------------------------------------------------------


def nginx_config(canary_set: CanarySet, deploy_root: str, listen: str = "80") -> str:
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
    root = deploy_root.rstrip("/")
    header = canary_set.by_id("response_header.instruction")
    header_ref = f"{header.path}?{header.param}=${{request_id}}"
    header_value = header.text.replace("{ref}", header_ref)

    lines = [
        "# Generated by `lurewall lab-site build`. Holds this installation's canaries:",
        "# keep it out of any repository.",
        "server {",
        f"    listen {listen};",
        "    server_name _;",
        f"    root {root}/www;",
        "    index index.html;",
        "    charset utf-8;",
        "    server_tokens off;",
        "",
        "    error_page 404 /errors/404.html;",
        "    error_page 403 /errors/403.html;",
        "",
        "    # Page stamping: each canary reference on a served page carries that",
        "    # request's ID, so a later hit can be tied to the page that carried it.",
        f"    sub_filter '{canary_set.placeholder}' '$request_id';",
        "    sub_filter_once off;",
        "    sub_filter_types text/plain;",
        "",
        "    # A stamped page belongs to one request. No cache may hand it to another.",
        '    add_header Cache-Control "no-store" always;',
        f'    add_header {canary_set.header_name} "{header_value}" always;',
        "",
        "    location / {",
        "        try_files $uri $uri/ =404;",
        "    }",
        "    location /errors/ {",
        "        internal;",
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
        "    }",
        "",
        "    # Decoys: exact paths only. Any other missing path gets the normal 404.",
        "    # A fixed 200 body, never a 204, and not announced in robots.txt.",
    ]
    for index, canary in enumerate(canary_set.canaries):
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
    for url_path, content in render_files(canary_set, extra_pages).items():
        _write(web_root / url_path.lstrip("/"), content)
    for name in ("staff",):
        (web_root / name).mkdir(mode=0o755, exist_ok=True)
    for index, canary in enumerate(canary_set.canaries):
        _write(out / "decoys" / f"{index}.body", canary.body)

    root = str(out.resolve()) if deploy_root is None else deploy_root
    conf = out / "nginx" / "lurewall-site.conf"
    _write(conf, nginx_config(canary_set, root, listen))
    return BuildResult(out_dir=out, web_root=web_root, nginx_conf=conf, routes=routes)
