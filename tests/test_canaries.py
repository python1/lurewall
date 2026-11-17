# SPDX-License-Identifier: AGPL-3.0-only
"""The canary generator, its rules, the state file and the lookup table."""

import json
import random
import stat
import subprocess
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from lurewall import canaries, labsite
from lurewall import wordbank as bank
from lurewall.canaries import (
    BAIT,
    EXAMPLE_MARKER,
    INSTRUCTION,
    PLACEMENTS,
    CanaryError,
    CollisionError,
)

REPO = Path(__file__).resolve().parents[1]
ROUTES = labsite.site_routes()
SEEDS = range(150)
RID = "0123456789abcdef0123456789abcdef"


def make(seed=1, routes=ROUTES):
    return canaries.generate(routes, rng=random.Random(seed), now_ms=1)


def with_canary(canary_set, canary_id, **changes):
    swapped = tuple(replace(c, **changes) if c.id == canary_id else c for c in canary_set.canaries)
    return replace(canary_set, canaries=swapped)


# -- the table ---------------------------------------------------------------------


def test_every_decoy_path_maps_to_exactly_one_placement():
    for seed in SEEDS:
        canary_set = make(seed)
        assert [c.id for c in canary_set.canaries] == list(PLACEMENTS)
        paths = [c.path for c in canary_set.canaries]
        assert len(set(paths)) == len(PLACEMENTS)
        for canary in canary_set.canaries:
            assert canary_set.lookup_path(canary.path) is canary
            assert (canary.placement, canary.lure) == PLACEMENTS[canary.id]


def test_both_lure_types_are_present_and_labelled():
    canary_set = make()
    lures = {c.id: c.lure for c in canary_set.canaries}
    assert lures == {
        "html_comment.instruction": INSTRUCTION,
        "html_comment.bait": BAIT,
        "hidden_element.instruction": INSTRUCTION,
        "robots_comment.instruction": INSTRUCTION,
        "api_doc.bait": BAIT,
        "error_page.bait": BAIT,
        "response_header.instruction": INSTRUCTION,
    }
    assert canary_set.lure_counts() == {INSTRUCTION: 4, BAIT: 3}


def test_instruction_lures_address_the_reader_and_bait_lures_do_not():
    imperative = {
        "confirm", "verify", "request", "check", "fetch", "load", "open", "visit",
        "retrieve", "call", "should", "may",
    }  # fmt: skip
    for seed in SEEDS:
        for canary in make(seed).canaries:
            words = set(canary.text.lower().replace(":", " ").replace(".", " ").split())
            if canary.lure == BAIT:
                assert not words & imperative, canary.text
                assert "automated" not in words and "agents" not in words
            elif canary.id in ("html_comment.instruction", "hidden_element.instruction"):
                assert words & imperative, canary.text


# -- no shared fingerprint ------------------------------------------------------------


def test_decoy_paths_share_no_prefix_and_no_marker():
    for seed in SEEDS:
        paths = [c.path for c in make(seed).canaries]
        firsts = [path.split("/")[1] for path in paths]
        assert len(set(firsts)) == len(paths)
        for path in paths:
            assert not path.startswith("/_c/") and "canary" not in path and "lure" not in path
            assert "decoy" not in path and "honey" not in path and "trap" not in path


def test_decoy_paths_look_like_ordinary_site_paths():
    for seed in SEEDS:
        for canary in make(seed).canaries:
            segments = canary.path.strip("/").split("/")
            assert 2 <= len(segments) <= 4
            assert canary.path == canary.path.lower()
            assert all(set(s) <= set("abcdefghijklmnopqrstuvwxyz0123456789.-_") for s in segments)
            assert not any(len(s) > 40 for s in segments)
            assert "--" not in canary.path and ".." not in canary.path


def test_decoy_paths_never_look_like_an_attack_path_probe():
    for seed in SEEDS:
        for canary in make(seed).canaries:
            segments = canary.path.strip("/").split("/")
            assert not set(segments) & canaries.RESERVED_SEGMENTS
            assert not any(s.startswith(".") for s in segments)
            for sensitive in (".env", ".git", "admin", "wp-login", "phpmyadmin", "passwd"):
                assert sensitive not in canary.path
    assert not set(bank.DIRS) & canaries.RESERVED_SEGMENTS


def test_request_id_keys_look_like_cache_busters():
    seen = {c.param for seed in SEEDS for c in make(seed).canaries}
    assert seen <= set(bank.ID_PARAMS) and len(seen) > 3
    assert not seen & {"token", "session", "sid", "key", "auth", "canary"}


# -- per installation ------------------------------------------------------------------


def test_each_installation_gets_different_canaries():
    first, second = make(1), make(2)
    assert first.placeholder != second.placeholder
    assert not {c.path for c in first.canaries} & {c.path for c in second.canaries}
    sets = [make(seed) for seed in SEEDS]
    assert len({s.header_name for s in sets}) > 20
    assert len({s.hidden_class for s in sets}) > 3
    assert len({c.text for s in sets for c in s.canaries}) > 100
    assert len({c.path for s in sets for c in s.canaries}) == len(sets) * len(PLACEMENTS)


def test_generated_header_is_never_a_real_header():
    names = {f"x-{a}-{b}".lower() for a in bank.HEADER_FIRST for b in bank.HEADER_SECOND}
    assert not names & canaries.REAL_HEADERS


def test_default_randomness_is_the_operating_systems_secure_source():
    first, second = canaries.generate(ROUTES), canaries.generate(ROUTES)
    assert first.placeholder != second.placeholder
    assert [c.path for c in first.canaries] != [c.path for c in second.canaries]


def test_path_space_is_large_and_its_size_is_stated():
    for canary_id in PLACEMENTS:
        assert canaries.path_space(canary_id) >= 2**24, canary_id


def test_no_generated_value_is_hardcoded_in_the_repository():
    tracked = subprocess.run(  # noqa: S603
        ["git", "-C", str(REPO), "ls-files", "-z"],  # noqa: S607
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    source = b"".join(
        (REPO / name.decode()).read_bytes()
        for name in tracked
        if name and name.endswith((b".py", b".conf", b".md", b".json", b".toml", b".yml"))
    )
    for seed in range(20):
        canary_set = make(seed)
        assert canary_set.placeholder.encode() not in source
        for canary in canary_set.canaries:
            assert canary.path.encode() not in source


def test_the_same_state_always_gives_the_same_canaries(tmp_path):
    """Rotation only on leak: nothing changes with time or with a reload."""
    canary_set = make()
    path = tmp_path / "state" / "canaries.json"
    canaries.save_state(canary_set, path)
    assert canaries.load_state(path) == canary_set
    assert canaries.load_state(path) == canaries.load_state(path)
    assert not hasattr(canaries, "rotate_due") and "schedule" not in canaries.rotate.__doc__


# -- decoy bodies ----------------------------------------------------------------------


def test_decoy_bodies_come_only_from_the_fixed_bank():
    allowed_json = {
        f'{{"{key}":"{value}"}}\n' for key in bank.BODY_JSON_KEYS for value in bank.BODY_JSON_VALUES
    }
    allowed_text = {word + "\n" for word in bank.BODY_TEXT}
    for seed in SEEDS:
        for canary in make(seed).canaries:
            if canary.content_type == "application/json":
                assert canary.body in allowed_json
            elif canary.content_type == "text/plain":
                assert canary.body in allowed_text
            else:
                assert canary.content_type == "text/html"
                assert any(message in canary.body for message in bank.BODY_HTML_MESSAGES)
            assert 0 < len(canary.body) <= canaries.MAX_BODY_BYTES


def test_decoy_bodies_hold_no_data():
    site_text = " ".join(labsite.render_files(make()).values())
    for seed in SEEDS:
        canary_set = make(seed)
        for canary in canary_set.canaries:
            body = canary.body
            assert not any(ch.isdigit() for ch in body)  # no versions, counts, addresses, dates
            assert canary_set.placeholder not in body and canary.path not in body
            assert labsite.SITE_NAME not in body
            for word in ("password", "secret", "key", "token", "root", "@", "http"):
                assert word not in body.lower()
            for sentence in bank.BODY_HTML_MESSAGES:
                assert sentence not in site_text  # nothing shared with the site's own pages


def test_bodies_cannot_copy_the_site_because_the_generator_never_sees_it():
    """Same seed, very different sites: the bodies are identical."""
    other_site = {"/", "/shop/cart.html", "/blog/2026/post.html", "/secret-plans.html"}
    plain = [c.body for c in make(7, ROUTES).canaries]
    assert [c.body for c in make(7, other_site).canaries] == plain


# -- hard rule: never a real route --------------------------------------------------------


def test_generator_avoids_every_real_route_even_on_a_crowded_site():
    crowded = set(ROUTES)
    for name in bank.DIRS[: len(bank.DIRS) - 12]:
        crowded.add(f"/{name}/index.html")
    for seed in range(40):
        canary_set = make(seed, crowded)
        assert canaries.find_collisions(canary_set, crowded) == []
        firsts = {c.path.split("/")[1] for c in canary_set.canaries}
        assert firsts <= set(bank.DIRS[len(bank.DIRS) - 12 :])


def test_generator_fails_rather_than_collide_when_no_names_are_left():
    full = {f"/{name}/index.html" for name in bank.DIRS}
    with pytest.raises(CanaryError, match="too many"):
        make(1, full)


@pytest.mark.parametrize(
    "real_route",
    [
        "{path}",
        "{upper}",
        "{path}/",
        "{path}/index.html",
        "{parent}",
        "{parent}/",
        "/{first}",
        "{encoded}",
        "/.{path}",
        "//{nolead}",
        "{path}?x=1",
    ],
)
def test_collision_is_detected_in_every_spelling(real_route):
    canary_set = make()
    canary = canary_set.by_id("html_comment.bait")
    route = real_route.format(
        path=canary.path,
        upper=canary.path.upper(),
        parent=canary.path.rsplit("/", 1)[0],
        first=canary.path.split("/")[1],
        encoded=canary.path.replace("a", "%61").replace("e", "%65"),
        nolead=canary.path.lstrip("/"),
    )
    assert canaries.find_collisions(canary_set, {*ROUTES, route})
    with pytest.raises(CollisionError, match=r"html_comment\.bait collides"):
        canaries.check_collisions(canary_set, {*ROUTES, route})


def test_unrelated_routes_do_not_collide():
    canary_set = make()
    canary = canary_set.by_id("html_comment.bait")
    near = {canary.path + "x", canary.path[:-1], "/x" + canary.path, "/"}
    assert canaries.find_collisions(canary_set, ROUTES | near) == []


# -- rotation ----------------------------------------------------------------------------


def test_rotation_replaces_only_the_named_canaries():
    canary_set = make()
    rotated = canaries.rotate(canary_set, ["api_doc.bait"], ROUTES, rng=random.Random(9))
    for before, after in zip(canary_set.canaries, rotated.canaries, strict=True):
        if before.id == "api_doc.bait":
            assert after.path != before.path
            assert after.path.split("/")[1] != before.path.split("/")[1]
        else:
            assert after == before
    assert rotated.placeholder == canary_set.placeholder
    canaries.validate(rotated)


def test_rotating_everything_changes_every_path_and_keeps_the_rules():
    canary_set = make()
    rotated = canaries.rotate(canary_set, list(PLACEMENTS), ROUTES, rng=random.Random(9))
    assert not {c.path for c in rotated.canaries} & {c.path for c in canary_set.canaries}
    old_firsts = {c.path.split("/")[1] for c in canary_set.canaries}
    assert not {c.path.split("/")[1] for c in rotated.canaries} & old_firsts
    canaries.validate(rotated)
    with pytest.raises(CanaryError, match="unknown canary id"):
        canaries.rotate(canary_set, ["nope"], ROUTES)


# -- lookup ---------------------------------------------------------------------------------


def test_lookup_names_the_lure_and_the_request_id():
    canary_set = make()
    for canary in canary_set.canaries:
        hit = canary_set.lookup_uri(canary.reference(RID))
        assert hit.canary is canary and hit.request_id == RID
        assert (hit.canary.placement, hit.canary.lure) == PLACEMENTS[canary.id]
        assert (
            canary_set.lookup_uri(f"{canary.path}?a=b&{canary.param}={RID}&z=1").request_id == RID
        )


def test_lookup_follows_nginx_normalization():
    canary_set = make()
    canary = canary_set.canaries[0]
    first = canary.path.split("/")[1]
    for spelling in (
        canary.path,
        "/" + canary.path,
        canary.path.replace("/", "//"),
        f"/x/..{canary.path}",
        f"/./{canary.path.lstrip('/')}",
        canary.path.replace(first, "".join(f"%{ord(ch):02x}" for ch in first)),
    ):
        assert canary_set.lookup_uri(spelling).canary is canary, spelling


@pytest.mark.parametrize(
    "transform",
    [
        lambda p: p + "x",
        lambda p: p[:-1],
        lambda p: p + "/",
        lambda p: p + "/more",
        lambda p: p.rsplit("/", 1)[0],
        lambda p: p.upper(),
        lambda p: "/x" + p,
        lambda p: p.lstrip("/"),
        lambda p: "/.." + p,
        lambda p: p.replace("/", "%252f"),
        lambda p: p + "%00",
        lambda p: p + "#frag",
        lambda p: "http://lab.example" + p,
    ],
)
def test_a_path_outside_the_table_is_not_a_canary(transform):
    canary_set = make()
    for canary in canary_set.canaries:
        assert canary_set.lookup_uri(transform(canary.path)) is None
    for other in ("/", "/index.html", "/.env", "/random/path-123", "", "?", "*"):
        assert canary_set.lookup_uri(other) is None


@pytest.mark.parametrize(
    "query",
    [
        "",
        "{param}=",
        "{param}",
        "{param}=" + RID[:-1],
        "{param}=" + RID + "0",
        "{param}=" + RID.upper(),
        "{param}=" + "g" * 32,
        "{param}=%30" + RID[1:],
        "{param}= " + RID,
        "other=" + RID,
        "{param}x=" + RID,
        "{param}=bad&{param}=" + RID,  # first value wins; a second cannot rescue it
    ],
)
def test_a_hit_without_a_well_formed_id_is_a_hit_bound_to_nobody(query):
    canary_set = make()
    canary = canary_set.canaries[0]
    hit = canary_set.lookup_uri(f"{canary.path}?{query.format(param=canary.param)}")
    assert hit.canary is canary and hit.request_id is None


def test_lookup_never_raises_on_hostile_uris():
    canary_set = make()
    rng = random.Random(5)
    first = canary_set.canaries[0]
    pieces = [
        "/", "%", "%zz", "%00", "..", "?", "&", "=", "\x00", "\ufffd", "\udc80", "é", " ",
        first.path, first.param, RID, "%2f", "%2e", "A" * 500,
    ]  # fmt: skip
    for _ in range(3000):
        uri = "".join(rng.choice(pieces) for _ in range(rng.randrange(0, 12)))
        result = canary_set.lookup_uri(uri)
        assert result is None or result.canary in canary_set.canaries


# -- state file --------------------------------------------------------------------------------


def test_state_file_is_private_and_round_trips(tmp_path):
    canary_set = make()
    path = tmp_path / "private" / "canaries.json"
    canaries.save_state(canary_set, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert canaries.load_state(path) == canary_set
    assert [p.name for p in path.parent.iterdir()] == ["canaries.json"]


def test_state_is_refused_anywhere_inside_a_git_repository(tmp_path):
    canary_set = make()
    for target in (REPO / "state" / "canaries.json", REPO / "canaries.json"):
        with pytest.raises(CanaryError, match="inside the git repository"):
            canaries.save_state(canary_set, target)
        assert not target.exists()
    work_tree = tmp_path / "someone-elses-repo"
    (work_tree / ".git").mkdir(parents=True)
    with pytest.raises(CanaryError, match="inside the git repository"):
        canaries.save_state(canary_set, work_tree / "deep" / "er" / "canaries.json")
    stray = work_tree / "canaries.json"
    stray.write_text(json.dumps(asdict(canary_set)))
    with pytest.raises(CanaryError, match="inside the git repository"):
        canaries.load_state(stray)


def test_gitignore_covers_canary_state_as_a_second_line_of_defence():
    for name in ("state/canaries.json", "canaries.json", "lab-site/www/index.html"):
        result = subprocess.run(  # noqa: S603
            ["git", "-C", str(REPO), "check-ignore", "-q", name],  # noqa: S607
            check=False,
        )
        assert result.returncode == 0, name


def test_the_shipped_example_is_refused(tmp_path):
    example = (REPO / "examples" / "canaries.example.json").read_bytes()
    assert EXAMPLE_MARKER.encode() in example
    with pytest.raises(CanaryError, match="shipped example"):
        canaries.parse_state(example)
    copied = tmp_path / "canaries.json"
    copied.write_bytes(example)
    with pytest.raises(CanaryError, match="shipped example"):
        canaries.load_state(copied)

    # Stripping the flag does not help: the marker is in the content.
    document = json.loads(example)
    del document["example"]
    with pytest.raises(CanaryError, match="shipped example"):
        canaries.parse_state(json.dumps(document))
    # Nor does renaming the marker: example paths are not valid decoy paths.
    renamed = json.dumps(document).replace(EXAMPLE_MARKER, "Some-Other-Words")
    with pytest.raises(CanaryError):
        canaries.parse_state(renamed)


def test_a_real_set_wearing_the_example_marker_is_refused():
    canary_set = make()
    document = asdict(canary_set)
    document["canaries"][0]["text"] = EXAMPLE_MARKER + " {ref}"
    with pytest.raises(CanaryError, match="shipped example"):
        canaries.parse_state(json.dumps(document))


HOSTILE_FIELDS = [
    ("path", "/a/b;\n    return 301 http://evil.example"),
    ("path", "/a/b {"),
    ("path", "/a/b}"),
    ("path", "/a/$request_uri"),
    ("path", "/a/b'c"),
    ("path", '/a/b"c'),
    ("path", "/a/b c"),
    ("path", "/a/b\\c"),
    ("path", "/a/../b"),
    ("path", "/a//b"),
    ("path", "/a/b--c"),
    ("path", "/a/B"),
    ("path", "/single"),
    ("path", "a/b"),
    ("path", "/a/b?x=1"),
    ("path", "/a/b#x"),
    ("path", "/a/.hidden"),
    ("path", "/admin/panel"),
    ("path", "/a/wp-login.php"),
    ("path", "/a/bé"),
    ("path", "/" + "a" * 80 + "/b"),
    ("param", "v;"),
    ("param", "V"),
    ("param", ""),
    ("param", "v=1&x"),
    ("param", "$arg"),
    ("text", 'x" always; add_header Set-Cookie "a=b {ref}'),
    ("text", "x $host {ref}"),
    ("text", "x --> <script>alert(1)</script> {ref}"),
    ("text", "x -- y {ref}"),
    ("text", "x\ny {ref}"),
    ("text", "x \\ y {ref}"),
    ("text", "no reference at all"),
    ("text", "{ref} twice {ref}"),
    ("text", "{other} {ref}"),
    ("text", "x } {ref}"),
    ("text", "x ; y {ref}"),
    ("text", ""),
    ("text", "a" * 201 + "{ref}"),
    ("form", "raw_html"),
    ("content_type", "text/html; charset=utf-7"),
    ("content_type", "application/x-httpd-php"),
    ("body", ""),
    ("body", "x" * 600),
    ("body", "<script>alert(1)</script>$"),
    ("body", "it's"),
    ("body", "a;b"),
    ("body", "café"),
    ("lure", "bait"),
    ("placement", "error_page"),
]


@pytest.mark.parametrize(("field", "value"), HOSTILE_FIELDS)
def test_a_state_file_cannot_smuggle_anything_into_html_or_nginx(field, value):
    canary_set = make()
    document = asdict(canary_set)
    document["canaries"][0][field] = value
    with pytest.raises(CanaryError):
        canaries.parse_state(json.dumps(document))
    with pytest.raises(CanaryError):
        canaries.validate(with_canary(canary_set, "html_comment.instruction", **{field: value}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("placeholder", "short"),
        ("placeholder", "G" * 32),
        ("placeholder", "0" * 31 + "'"),
        ("header_name", "Set-Cookie"),
        ("header_name", "X-A-B: x\r\nSet-Cookie"),
        ("header_name", "X-Robots-Tag"),
        ("header_name", "x-lower-case"),
        ("hidden_class", 'x" onload="alert(1)'),
        ("hidden_class", "a b"),
        ("hidden_class", "x{}"),
        ("version", 2),
        ("version", "1"),
        ("created_ms", -1),
        ("created_ms", 1.5),
        ("placeholder", 5),
        ("canaries", "none"),
        ("canaries", [1, 2]),
        ("canaries", []),
    ],
)
def test_set_level_fields_are_held_to_narrow_forms(field, value):
    document = asdict(make())
    document[field] = value
    with pytest.raises(CanaryError):
        canaries.parse_state(json.dumps(document))


def test_malformed_state_documents_are_refused():
    good = asdict(make())
    cases = [b"", b"not json", b"[]", b"null", b"{}", b"[" * 100_000]
    cases.append(json.dumps({**good, "extra": 1}).encode())
    missing = dict(good)
    del missing["placeholder"]
    cases.append(json.dumps(missing).encode())
    extra_field = json.loads(json.dumps(good))
    extra_field["canaries"][0]["surprise"] = "x"
    cases.append(json.dumps(extra_field).encode())
    not_string = json.loads(json.dumps(good))
    not_string["canaries"][0]["path"] = 5
    cases.append(json.dumps(not_string).encode())
    duplicate = json.loads(json.dumps(good))
    duplicate["canaries"][1] = dict(duplicate["canaries"][0])
    cases.append(json.dumps(duplicate).encode())
    shared = json.loads(json.dumps(good))
    first = shared["canaries"][0]["path"].split("/")[1]
    tail = shared["canaries"][2]["path"].split("/", 2)[2]
    shared["canaries"][2]["path"] = f"/{first}/{tail}"
    cases.append(json.dumps(shared).encode())
    for raw in cases:
        with pytest.raises(CanaryError):
            canaries.parse_state(raw)
