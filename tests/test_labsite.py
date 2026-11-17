# SPDX-License-Identifier: AGPL-3.0-only
"""The lab site build: placements, stamping, accessibility, collisions, nginx config."""

import random
import re
import stat
from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path

import pytest

from lurewall import canaries, labsite
from lurewall.canaries import PLACEMENTS, CanaryError, CollisionError
from lurewall.cli import main

REPO = Path(__file__).resolve().parents[1]
SEEDS = range(40)
VOID = {"meta", "link", "img", "br", "hr", "input"}
FOCUSABLE = {"a", "button", "input", "select", "textarea", "summary", "iframe", "area"}


def make(seed=1, extra=None):
    return canaries.generate(labsite.site_routes(extra), rng=random.Random(seed), now_ms=1)


@pytest.fixture
def built(tmp_path):
    canary_set = make()
    result = labsite.build(canary_set, tmp_path / "site")
    return canary_set, result


class Page(HTMLParser):
    """Splits a page into what assistive technology is given, and everything else.

    A model of the accessibility tree, good enough to check the markup rule:
    text inside ``aria-hidden="true"`` and inside comments is not exposed.
    A real screen reader is still tested in the lab before any public use.
    """

    def __init__(self, source: str) -> None:
        super().__init__(convert_charrefs=True)
        self.exposed: list[str] = []
        self.hidden: list[str] = []
        self.comments: list[str] = []
        self.links: list[str] = []
        self.hidden_focusable: list[str] = []
        self.hidden_elements: list[dict] = []
        self.meta: dict[str, str] = {}
        self._stack: list[bool] = []
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        inherited = bool(self._stack and self._stack[-1])
        hidden = inherited or attributes.get("aria-hidden") == "true"
        if attributes.get("aria-hidden") == "true":
            self.hidden_elements.append({"tag": tag, **attributes})
        if hidden and (tag in FOCUSABLE or "tabindex" in attributes or "href" in attributes):
            self.hidden_focusable.append(tag)
        if tag == "a" and "href" in attributes:
            self.links.append(attributes["href"])
        if tag == "meta" and "name" in attributes:
            self.meta[attributes["name"]] = attributes.get("content", "")
        for name in ("alt", "title", "aria-label", "placeholder"):
            if attributes.get(name):
                (self.hidden if hidden else self.exposed).append(attributes[name])
        if tag not in VOID:
            self._stack.append(hidden)

    def handle_endtag(self, tag):
        if tag not in VOID and self._stack:
            self._stack.pop()

    def handle_data(self, data):
        (self.hidden if self._stack and self._stack[-1] else self.exposed).append(data)

    def handle_comment(self, data):
        self.comments.append(data)


def read(result, url_path):
    return (result.web_root / url_path.lstrip("/")).read_text()


def html_pages(result):
    return sorted(
        "/" + str(path.relative_to(result.web_root)) for path in result.web_root.rglob("*.html")
    )


# -- the site builds, with every placement ------------------------------------------------


def test_site_builds_with_every_placement(built):
    canary_set, result = built
    placeholder = canary_set.placeholder
    ref = {c.id: c.reference(placeholder) for c in canary_set.canaries}
    home = Page(read(result, "/index.html"))
    assert any(ref["html_comment.instruction"] in comment for comment in home.comments)
    assert any(ref["html_comment.bait"] in comment for comment in home.comments)
    assert any(ref["hidden_element.instruction"] in text for text in home.hidden)
    assert f"# {canary_set.by_id('robots_comment.instruction').text.split('{')[0]}" in read(
        result, "/robots.txt"
    )
    assert ref["robots_comment.instruction"] in read(result, "/robots.txt")
    assert any(
        ref["api_doc.bait"] in text for text in Page(read(result, "/developers/api.html")).hidden
    )
    for error_page in ("/errors/404.html", "/errors/403.html"):
        assert any(ref["error_page.bait"] in text for text in Page(read(result, error_page)).hidden)
    header = canary_set.by_id("response_header.instruction")
    conf = result.nginx_conf.read_text()
    assert f"add_header {canary_set.header_name} " in conf
    assert f"{header.path}?{header.param}=${{request_id}}" in conf


def test_every_content_page_carries_the_page_canaries(built):
    canary_set, result = built
    for url_path in ("/index.html", "/about.html", "/services.html", "/contact.html",
                     "/docs/index.html", "/docs/getting-started.html"):  # fmt: skip
        source = read(result, url_path)
        for canary_id in ("html_comment.instruction", "html_comment.bait",
                          "hidden_element.instruction"):  # fmt: skip
            assert canary_set.by_id(canary_id).path in source, (url_path, canary_id)


def test_each_canary_appears_only_in_its_own_placement(built):
    canary_set, result = built
    where = {c.id: set() for c in canary_set.canaries}
    for path in result.web_root.rglob("*"):
        if path.is_file():
            text = path.read_text()
            for canary in canary_set.canaries:
                if canary.path in text:
                    where[canary.id].add("/" + str(path.relative_to(result.web_root)))
    assert where["robots_comment.instruction"] == {"/robots.txt"}
    assert where["api_doc.bait"] == {"/developers/api.html"}
    assert where["error_page.bait"] == {"/errors/404.html", "/errors/403.html"}
    assert where["response_header.instruction"] == set()  # only ever in a response header
    assert "/developers/api.html" not in where["html_comment.instruction"]


def test_built_files_are_world_readable_for_the_web_server(built):
    _canary_set, result = built
    for path in result.out_dir.rglob("*"):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == (0o755 if path.is_dir() else 0o644), path


def test_the_same_state_builds_the_same_site(tmp_path):
    """No scheduled rotation: two fetches of a page differ only in the request ID."""
    canary_set = make()
    first = labsite.build(canary_set, tmp_path / "a", deploy_root="/srv/lab")
    second = labsite.build(canary_set, tmp_path / "b", deploy_root="/srv/lab")
    files_a = {
        p.relative_to(first.out_dir): p.read_bytes()
        for p in first.out_dir.rglob("*")
        if p.is_file()
    }
    files_b = {
        p.relative_to(second.out_dir): p.read_bytes()
        for p in second.out_dir.rglob("*")
        if p.is_file()
    }
    assert files_a == files_b and len(files_a) > 15
    again = labsite.build(canary_set, tmp_path / "a", deploy_root="/srv/lab")
    assert {
        p.relative_to(again.out_dir): p.read_bytes()
        for p in again.out_dir.rglob("*")
        if p.is_file()
    } == files_a


# -- page stamping --------------------------------------------------------------------------


def test_every_canary_reference_on_a_page_carries_the_request_id_placeholder(built):
    canary_set, result = built
    for path in result.web_root.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text()
        for canary in canary_set.canaries:
            for match in re.finditer(re.escape(canary.path), text):
                tail = text[match.end() : match.end() + 2 + len(canary.param) + 32]
                assert tail == f"?{canary.param}={canary_set.placeholder}", (path, canary.id)


def test_nginx_replaces_the_placeholder_with_the_request_id_everywhere(built):
    canary_set, result = built
    conf = result.nginx_conf.read_text()
    stamp = f"sub_filter '{canary_set.placeholder}' '$request_id';"
    # Pages, error pages and the API page are stamped; decoys and assets are not.
    for location in ("location / {", "location /errors/ {", "location = /developers/api.html {"):
        block = conf.split(location, 1)[1].split("\n    }", 1)[0]
        assert stamp in block and "sub_filter_once off;" in block
        assert "sub_filter_types text/plain;" in block  # robots.txt; text/html is always on
    assert conf.count(stamp) == 3
    for canary in canary_set.canaries:
        block = conf.split(f"location = {canary.path} {{", 1)[1].split("\n    }", 1)[0]
        assert "sub_filter" not in block
    assert 'add_header Cache-Control "no-store" always;' in conf
    assert "proxy_pass" not in conf  # still a static site and a log reader, no proxy


def test_a_stamped_reference_resolves_back_to_its_canary_and_id(built):
    canary_set, result = built
    request_id = "feedfacefeedfacefeedfacefeedface"
    served = read(result, "/index.html").replace(canary_set.placeholder, request_id)
    assert canary_set.placeholder not in served
    refs = re.findall(r"(/[a-z0-9._/-]+\?[a-z]+=[0-9a-f]{32})", served)
    hits = [canary_set.lookup_uri(ref) for ref in refs]
    assert {hit.canary.id for hit in hits} == {
        "html_comment.instruction",
        "html_comment.bait",
        "hidden_element.instruction",
    }
    assert all(hit.request_id == request_id for hit in hits)


def test_the_placeholder_looks_like_a_request_id_and_is_nowhere_else(built):
    canary_set, result = built
    assert re.fullmatch(r"[0-9a-f]{32}", canary_set.placeholder)
    for canary in canary_set.canaries:
        assert canary_set.placeholder not in canary.body
    for index in range(len(canary_set.canaries)):
        assert (
            canary_set.placeholder not in (result.out_dir / "decoys" / f"{index}.body").read_text()
        )


# -- accessibility --------------------------------------------------------------------------


def test_no_canary_is_exposed_to_assistive_technology():
    for seed in SEEDS:
        canary_set = make(seed)
        for url_path, source in labsite.render_files(canary_set).items():
            if not url_path.endswith(".html"):
                continue
            page = Page(source)
            exposed = " ".join(page.exposed)
            for canary in canary_set.canaries:
                assert canary.path not in exposed, (seed, url_path, canary.id)
                wording = canary.text.replace("{ref}", "").strip(" :.")
                if canary.form == "plain" and len(wording) > 10:
                    assert wording not in exposed, (seed, url_path, canary.id)
            assert canary_set.placeholder not in exposed


def test_every_dom_canary_is_aria_hidden_and_holds_nothing_focusable():
    for seed in SEEDS:
        canary_set = make(seed)
        for url_path, source in labsite.render_files(canary_set).items():
            if not url_path.endswith(".html"):
                continue
            page = Page(source)
            assert page.hidden_focusable == [], (seed, url_path)
            in_dom = " ".join(page.exposed + page.hidden)
            in_hidden = " ".join(page.hidden)
            for canary in canary_set.canaries:
                assert in_dom.count(canary.path) == in_hidden.count(canary.path)
            for element in page.hidden_elements:
                assert element["aria-hidden"] == "true"
                assert "href" not in element and "tabindex" not in element


def test_hidden_canaries_are_out_of_sight_as_well(built):
    canary_set, result = built
    css = read(result, "/assets/site.css")
    rule = re.search(r"\." + re.escape(canary_set.hidden_class) + r" \{([^}]*)\}", css)
    assert rule and "position: absolute" in rule.group(1) and "left: -10000px" in rule.group(1)
    assert "display: none" not in rule.group(1)  # text converters should still pass it on
    home = Page(read(result, "/index.html"))
    classes = [e.get("class") for e in home.hidden_elements if e["tag"] == "p"]
    assert classes == [canary_set.hidden_class]


def test_comment_canaries_cannot_end_their_comment_early():
    for seed in SEEDS:
        canary_set = make(seed)
        page = Page(labsite.render_files(canary_set)["/index.html"])
        assert len(page.comments) == 2
        assert all("--" not in comment for comment in page.comments)
        assert "alert" not in "".join(page.exposed)


def test_ordinary_content_is_still_exposed(built):
    _canary_set, result = built
    page = Page(read(result, "/index.html"))
    assert "Lab Tool Library" in " ".join(page.exposed)
    assert 'lang="en"' in read(result, "/index.html")


# -- not announced, not indexed ---------------------------------------------------------------


def test_robots_txt_has_no_disallow_line_and_names_only_its_own_lure(built):
    canary_set, result = built
    robots = read(result, "/robots.txt")
    assert "disallow" not in robots.lower()
    live = [line for line in robots.splitlines() if line and not line.startswith("#")]
    assert live == ["User-agent: *", "Allow: /", "Sitemap: /sitemap.xml"]
    named = [c.id for c in canary_set.canaries if c.path in robots]
    assert named == ["robots_comment.instruction"]


def test_decoys_carry_x_robots_tag_instead(built):
    canary_set, result = built
    conf = result.nginx_conf.read_text()
    for canary in canary_set.canaries:
        block = re.search(r"location = " + re.escape(canary.path) + r" \{(.*?)\n    \}", conf, re.S)
        assert block, canary.id
        assert 'add_header X-Robots-Tag "noindex, nofollow" always;' in block.group(1)


def test_api_doc_page_is_unlinked_and_noindex(built):
    _canary_set, result = built
    api = Page(read(result, "/developers/api.html"))
    assert api.meta.get("robots") == "noindex"
    for url_path in html_pages(result):
        assert "/developers/api.html" not in Page(read(result, url_path)).links
    assert "developers" not in read(result, "/sitemap.xml")
    assert "developers" not in read(result, "/robots.txt")
    conf = result.nginx_conf.read_text()
    block = re.search(r"location = /developers/api\.html \{(.*?)\n    \}", conf, re.S).group(1)
    assert 'add_header X-Robots-Tag "noindex" always;' in block
    assert 'add_header Cache-Control "no-store" always;' in block


def test_sitemap_lists_real_pages_only(built):
    canary_set, result = built
    sitemap = read(result, "/sitemap.xml")
    for canary in canary_set.canaries:
        assert canary.path not in sitemap
    assert "<loc>/about.html</loc>" in sitemap and "errors" not in sitemap


# -- nginx config: decoys and only decoys --------------------------------------------------------


def exact_locations(conf: str) -> list[str]:
    return re.findall(r"^\s*location = (\S+) \{", conf, re.M)


def test_only_table_paths_get_a_decoy_location(built):
    canary_set, result = built
    conf = result.nginx_conf.read_text()
    not_decoys = {"/developers/api.html", labsite.FETCH_CHECK_PAGE, labsite.CHECKPOINT_ROUTE}
    decoy_locations = [path for path in exact_locations(conf) if path not in not_decoys]
    assert decoy_locations == [c.path for c in canary_set.canaries]
    # No prefix or regex location could answer a path outside the table.
    assert re.findall(r"^\s*location (\S+) \{", conf, re.M) == [
        "/",
        "/errors/",
        "/staff/",
        "/assets/",
    ]
    assert "location ~" not in conf
    assert "try_files $uri $uri/ =404;" in conf
    assert "error_page 404 /errors/404.html;" in conf


def test_decoys_answer_200_with_a_fixed_body_never_204(built):
    canary_set, result = built
    conf = result.nginx_conf.read_text()
    directives = [ln for ln in conf.splitlines() if not ln.strip().startswith("#")]
    assert not any(re.search(r"\breturn\b", line) for line in directives)
    for index, canary in enumerate(canary_set.canaries):
        body_file = result.out_dir / "decoys" / f"{index}.body"
        assert body_file.read_text() == canary.body and canary.body
        assert f"alias {result.out_dir.resolve()}/decoys/{index}.body;" in conf
        assert f"default_type {canary.content_type};" in conf
    # Bodies are outside the web root, so no second URL reaches them.
    assert not (result.web_root / "decoys").exists()


def test_config_is_safe_for_any_generated_set():
    structural = re.compile(r"[;{}]")
    for seed in range(150):
        canary_set = make(seed)
        conf = labsite.nginx_config(canary_set, "/srv/lurewall-lab")
        assert conf.count("{") == conf.count("}")
        for line in conf.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # One directive per line: nothing generated adds a second one.
            body = re.sub(r'"[^"]*"|\'[^\']*\'', "", stripped).replace("${request_id}", "")
            assert len(structural.findall(body)) == 1 or body == "types { }", line
            assert "$" not in body.replace("$uri", "").replace("$request_id", ""), line


@pytest.mark.parametrize(
    "deploy_root",
    ["relative/path", "/srv/lab; include /etc/passwd", "/srv/$host", "/srv/a b", "/srv/../etc",
     "/srv/lab'", '/srv/"lab"', "/srv/{lab}", "", "/srv/lab\n"],
)  # fmt: skip
def test_deploy_root_is_held_to_a_plain_path(deploy_root):
    with pytest.raises(labsite.BuildError, match="deploy root"):
        labsite.nginx_config(make(), deploy_root)


@pytest.mark.parametrize("listen", ["80; return 200", "80 {", "$port", "80\nserver {", ""])
def test_listen_value_is_held_to_a_plain_form(listen):
    with pytest.raises(labsite.BuildError, match="listen"):
        labsite.nginx_config(make(), "/srv/lab", listen)
    assert "listen 127.0.0.1:8080;" in labsite.nginx_config(make(), "/srv/lab", "127.0.0.1:8080")


def test_an_invalid_set_never_reaches_the_config_or_the_site(tmp_path):
    canary_set = make()
    bad = replace(canary_set, header_name='X-A-B "x"; add_header Set-Cookie')
    with pytest.raises(CanaryError):
        labsite.nginx_config(bad, "/srv/lab")
    with pytest.raises(CanaryError):
        labsite.build(bad, tmp_path / "site")
    assert not (tmp_path / "site").exists()


# -- hard rule: the build fails on a collision ---------------------------------------------------


def test_build_fails_when_a_decoy_collides_with_a_real_route(tmp_path):
    canary_set = make()
    real = replace(canary_set.by_id("html_comment.bait"), path="/docs/getting-started.html")
    collided = replace(
        canary_set,
        canaries=tuple(real if c.id == real.id else c for c in canary_set.canaries),
    )
    canaries.validate(collided)  # well-formed in itself; only the site makes it wrong
    with pytest.raises(
        CollisionError, match=r"html_comment\.bait collides with /docs/getting-started\.html"
    ):
        labsite.build(collided, tmp_path / "site")
    assert not (tmp_path / "site").exists()


def test_the_check_runs_again_when_the_site_changes(tmp_path):
    canary_set = make()
    out = tmp_path / "site"
    labsite.build(canary_set, out)
    before = (out / "www" / "index.html").read_bytes()
    decoy = canary_set.by_id("hidden_element.instruction").path
    # The site gains a page exactly where a decoy lives.
    new_page = {decoy + ".html": "<h1>New</h1>"}
    labsite.build(canary_set, out, extra_pages=new_page)  # near, but not a collision
    for route in (decoy + "/index.html", decoy.upper() + "/a.html"):
        with pytest.raises(CollisionError):
            labsite.build(canary_set, out, extra_pages={route: "<h1>New</h1>"})
    # A failed build leaves the last good site in place.
    assert (out / "www" / "index.html").read_bytes() == before


def test_new_canaries_avoid_the_changed_site():
    extra = {"/internal/index.html": "<p>x</p>", "/backup/list.html": "<p>y</p>"}
    for seed in SEEDS:
        canary_set = make(seed, extra)
        firsts = {c.path.split("/")[1] for c in canary_set.canaries}
        assert not firsts & {
            "internal",
            "backup",
            "docs",
            "assets",
            "errors",
            "developers",
            "staff",
        }


def test_no_decoy_shares_a_top_level_name_with_the_site():
    tops = {route.split("/")[1] for route in labsite.site_routes() if route != "/"}
    for seed in SEEDS:
        assert not {c.path.split("/")[1] for c in make(seed).canaries} & tops


# -- where the output may go ----------------------------------------------------------------------


def test_output_is_refused_inside_a_git_repository(tmp_path):
    with pytest.raises(CanaryError, match="inside the git repository"):
        labsite.build(make(), REPO / "lab-site")
    assert not (REPO / "lab-site").exists()


def test_a_foreign_non_empty_directory_is_never_overwritten(tmp_path):
    target = tmp_path / "important"
    target.mkdir()
    (target / "thesis.txt").write_text("do not delete")
    (target / "www").mkdir()
    (target / "www" / "mine.html").write_text("mine")
    with pytest.raises(labsite.BuildError, match="not built by Lurewall"):
        labsite.build(make(), target)
    assert (target / "thesis.txt").read_text() == "do not delete"
    assert (target / "www" / "mine.html").read_text() == "mine"
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("x")
    with pytest.raises(labsite.BuildError, match="not a directory"):
        labsite.build(make(), not_a_dir)


@pytest.mark.parametrize(
    "route", ["/../etc/x.html", "relative.html", "/a b.html", "/x.php", "/a/$x.html"]
)
def test_extra_page_routes_are_held_to_a_plain_form(tmp_path, route):
    with pytest.raises(labsite.BuildError, match="extra page route"):
        labsite.build(make(), tmp_path / "site", extra_pages={route: "x"})


# -- command line ----------------------------------------------------------------------------------


def run(capsys, *argv):
    code = main([str(arg) for arg in argv])
    out, err = capsys.readouterr()
    return code, out, err


def test_cli_first_build_creates_private_state_and_later_builds_reuse_it(tmp_path, capsys):
    state, out = tmp_path / "private" / "canaries.json", tmp_path / "site"
    code, text, _err = run(capsys, "lab-site", "build", "--state", state, "--out", out,
                           "--deploy-root", "/srv/lurewall-lab", "--listen", "80")  # fmt: skip
    assert code == 0 and "generated a new canary set" in text
    assert "7 (4 instruction, 3 bait)" in text and "no collisions" in text
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    first = state.read_bytes()
    conf = (out / "nginx" / "lurewall-site.conf").read_text()
    assert "root /srv/lurewall-lab/www;" in conf
    # Nothing printed gives a decoy path away to a shared terminal log.
    canary_set = canaries.load_state(state)
    assert not any(c.path in text for c in canary_set.canaries)

    code, text, _err = run(capsys, "lab-site", "build", "--state", state, "--out", out)
    assert code == 0 and "generated" not in text and state.read_bytes() == first


def test_cli_list_shows_the_table_with_lure_labels(tmp_path, capsys):
    state = tmp_path / "canaries.json"
    canaries.save_state(make(), state)
    code, text, _err = run(capsys, "canaries", "list", "--state", state)
    rows = [line.split("\t") for line in text.splitlines()]
    assert code == 0 and [row[0] for row in rows] == list(PLACEMENTS)
    assert [row[1] for row in rows].count("instruction") == 4
    assert [row[1] for row in rows].count("bait") == 3


def test_cli_rotate_is_explicit_and_scoped(tmp_path, capsys):
    state = tmp_path / "canaries.json"
    canaries.save_state(make(), state)
    before = canaries.load_state(state)
    code, _out, err = run(capsys, "canaries", "rotate", "--state", state, "--id", "bogus")
    assert code == 2 and "unknown canary id" in err and canaries.load_state(state) == before
    code, text, _err = run(capsys, "canaries", "rotate", "--state", state, "--id", "api_doc.bait")
    after = canaries.load_state(state)
    assert code == 0 and "Rebuild" in text
    changed = [a.id for a, b in zip(after.canaries, before.canaries, strict=True) if a != b]
    assert changed == ["api_doc.bait"]
    code, _out, _err = run(capsys, "canaries", "rotate", "--state", state, "--all")
    assert code == 0
    assert not {c.path for c in canaries.load_state(state).canaries} & {
        c.path for c in after.canaries
    }


def test_cli_refuses_the_example_a_repo_path_and_a_broken_state(tmp_path, capsys):
    example = tmp_path / "canaries.json"
    example.write_bytes((REPO / "examples" / "canaries.example.json").read_bytes())
    code, out, err = run(capsys, "lab-site", "build", "--state", example, "--out", tmp_path / "s")
    assert code == 2 and "shipped example" in err and not (tmp_path / "s").exists()

    code, out, err = run(capsys, "lab-site", "build", "--state", REPO / "state" / "canaries.json",
                         "--out", tmp_path / "s")  # fmt: skip
    assert code == 2 and "inside the git repository" in err
    assert not (REPO / "state").exists()

    broken = tmp_path / "broken.json"
    broken.write_text("{")
    code, out, err = run(capsys, "canaries", "list", "--state", broken)
    assert code == 2 and "not valid JSON" in err
    code, out, err = run(capsys, "canaries", "list", "--state", tmp_path / "absent.json")
    assert code == 2 and out == ""


def test_cli_build_failure_on_collision_is_exit_1(tmp_path, capsys):
    canary_set = make()
    real = replace(canary_set.by_id("error_page.bait"), path="/assets/site.css")
    collided = replace(
        canary_set, canaries=tuple(real if c.id == real.id else c for c in canary_set.canaries)
    )
    state = tmp_path / "canaries.json"
    canaries.save_state(collided, state)
    code, _out, err = run(capsys, "lab-site", "build", "--state", state, "--out", tmp_path / "site")
    assert code == 1 and "BUILD FAILED" in err and "collides with /assets/site.css" in err
    assert not (tmp_path / "site").exists()


# -- PR 8: the fetch-check page and the served checkpoint ------------------------------------


def test_the_fetch_check_page_holds_its_markers_and_no_canary():
    canary_set = make()
    page = labsite.render_files(canary_set)[labsite.FETCH_CHECK_PAGE]
    assert f"<!-- {labsite.MARKER_COMMENT} -->" in page
    assert f'aria-hidden="true">{labsite.MARKER_HIDDEN}<' in page
    assert canary_set.placeholder not in page
    for canary in canary_set.canaries:
        assert canary.path not in page
    files = labsite.render_files(canary_set)
    assert not any(labsite.FETCH_CHECK_PAGE in body for body in files.values())  # unlinked


def test_the_fetch_check_page_sends_the_marker_header_and_not_the_canary_header():
    canary_set = make()
    conf = labsite.nginx_config(canary_set, "/srv/lab")
    block = conf.split(f"location = {labsite.FETCH_CHECK_PAGE} {{", 1)[1].split("}", 1)[0]
    assert f'add_header {labsite.MARKER_HEADER_NAME} "{labsite.MARKER_HEADER}" always;' in block
    assert canary_set.header_name not in block


def test_the_checkpoint_is_served_only_when_asked_for():
    canary_set = make()
    assert labsite.CHECKPOINT_ROUTE not in labsite.nginx_config(canary_set, "/srv/lab")
    conf = labsite.nginx_config(
        canary_set, "/srv/lab", checkpoint_file="/srv/lurewall/checkpoint/checkpoint.json"
    )
    block = conf.split(f"location = {labsite.CHECKPOINT_ROUTE} {{", 1)[1].split("    }\n", 1)[0]
    assert "alias /srv/lurewall/checkpoint/checkpoint.json;" in block
    assert "default_type application/json;" in block


@pytest.mark.parametrize(
    "path", ["relative/checkpoint.json", "/srv/../etc/shadow", "/srv/a b", "/srv/x;deny all", ""]
)
def test_a_bad_checkpoint_path_is_refused(path):
    with pytest.raises(labsite.BuildError):
        labsite.nginx_config(make(), "/srv/lab", checkpoint_file=path)


def test_no_canary_can_land_on_the_new_routes():
    routes = labsite.site_routes()
    for route in (labsite.FETCH_CHECK_PAGE, labsite.CHECKPOINT_ROUTE, "/lab/"):
        assert route in routes
