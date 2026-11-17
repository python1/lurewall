# SPDX-License-Identifier: AGPL-3.0-only
"""The per-site signals config, and its cross-check against the canary table."""

from __future__ import annotations

from dataclasses import replace

import pytest

import sig
from lurewall import canaries, cli, labsite, sigconfig, signals
from lurewall.sigconfig import SignalConfigError

MINIMAL = 'version = 1\n[site]\nhosts = ["lab.lurewall.test"]\n'
SEEDS = range(40)


def with_paths(config, **changes):
    return replace(config, **changes)


def test_shipped_lab_config_loads_and_lists_the_documented_probes():
    config = sig.lab_config()
    for uri in ("/.env", "/.git/config", "/admin", "/wp-login.php", "/phpmyadmin"):
        assert signals.match_attack_paths(config, uri), uri
    assert config.window_ms == 15 * 60_000
    assert config.distinct_attack_signals == 2
    assert set(config.injection_families) == set(sigconfig.INJECTION_FAMILIES)


def test_shipped_lab_config_fits_the_lab_site_for_many_installations():
    config = sig.lab_config()
    for seed in SEEDS:
        sigconfig.check_against_site(config, sig.canary_set(seed), labsite.site_routes())


def test_minimal_config_gets_the_documented_defaults():
    config = sigconfig.parse(MINIMAL)
    assert config.window_ms == 15 * 60_000
    assert config.distinct_attack_signals == 2
    assert config.max_sources == 10_000
    assert not config.exact and not config.tree and not config.segment


@pytest.mark.parametrize("value", [1, 0, -1, 17])
def test_threshold_can_never_be_set_below_two(value):
    with pytest.raises(SignalConfigError, match="distinct_attack_signals"):
        sigconfig.parse(MINIMAL + f"[thresholds]\ndistinct_attack_signals = {value}\n")


def test_threshold_can_be_raised():
    config = sigconfig.parse(MINIMAL + "[thresholds]\ndistinct_attack_signals = 3\n")
    assert config.distinct_attack_signals == 3


@pytest.mark.parametrize(
    "text",
    [
        "",
        "version = 2\n",
        "version = true\n" + MINIMAL.split("\n", 1)[1],
        "version = 1\n[site]\nhosts = []\n",
        "version = 1\n",
        MINIMAL + "surprise = 1\n",
        MINIMAL + "[site2]\n",
        MINIMAL + '[attack_paths]\nbody = ["x"]\n',
        MINIMAL + '[attack_paths]\nexact = "/.env"\n',
        MINIMAL + "[attack_paths]\nexact = [1]\n",
        MINIMAL + '[attack_paths]\nexact = [".env"]\n',
        MINIMAL + '[attack_paths]\nexact = ["/Admin"]\n',
        MINIMAL + '[attack_paths]\nexact = ["/a/../b"]\n',
        MINIMAL + '[attack_paths]\nexact = ["/a//b"]\n',
        MINIMAL + '[attack_paths]\nexact = ["/a?b"]\n',
        MINIMAL + '[attack_paths]\nexact = ["/a", "/a"]\n',
        MINIMAL + '[attack_paths]\ntree = ["/"]\n',
        MINIMAL + '[attack_paths]\nsegment = ["a/b"]\n',
        MINIMAL + '[attack_paths]\nsegment = [".."]\n',
        MINIMAL + '[injection]\nfamilies = ["body"]\n',
        MINIMAL + '[injection]\nfamilies = "sqli"\n',
        MINIMAL + '[methods]\nabuse = ["GET"]\n',
        MINIMAL + '[methods]\nabuse = ["POST"]\n',
        MINIMAL + '[methods]\nabuse = ["trace"]\n',
        MINIMAL + "[thresholds]\nwindow_minutes = 0\n",
        MINIMAL + "[thresholds]\nwindow_minutes = 1.5\n",
        MINIMAL + "[thresholds]\nmax_sources = 0\n",
        MINIMAL + "[thresholds]\nspeed_alone = true\n",
        "not toml at all [",
    ],
)
def test_malformed_config_is_refused(text):
    with pytest.raises(SignalConfigError):
        sigconfig.parse(text)


def test_config_has_no_key_for_body_or_speed_signals():
    # The schema is closed: there is nowhere to switch on a body-based signal
    # or to make a timing signal count.
    for table, key in [("injection", "body"), ("thresholds", "speed"), ("methods", "body")]:
        with pytest.raises(SignalConfigError, match="unknown keys"):
            sigconfig.parse(MINIMAL + f"[{table}]\n{key} = true\n")


def test_bytes_that_are_not_utf8_or_too_large_are_refused():
    with pytest.raises(SignalConfigError, match="UTF-8"):
        sigconfig.parse(b"\xff\xfe")
    with pytest.raises(SignalConfigError, match="too large"):
        sigconfig.parse(b"#" * (sigconfig.MAX_CONFIG_BYTES + 1))


def test_missing_file_is_a_config_error(tmp_path):
    with pytest.raises(SignalConfigError, match="cannot read"):
        sigconfig.load(tmp_path / "absent.toml")


# -- the cross-check against the canary table -------------------------------------


@pytest.mark.parametrize("kind", ["exact", "tree", "segment"])
def test_a_decoy_path_on_the_attack_list_fails_the_check(kind):
    config = sig.lab_config()
    canary_set = sig.canary_set()
    for canary in canary_set.canaries:
        if kind == "exact":
            bad = with_paths(config, exact=config.exact | {canary.path})
        elif kind == "tree":
            bad = with_paths(config, tree=(*config.tree, "/" + canary.path.split("/")[1]))
        else:
            bad = with_paths(config, segment=config.segment | {canary.path.split("/")[-1]})
        with pytest.raises(SignalConfigError, match=f"decoy {canary.id}"):
            sigconfig.check_against_site(bad, canary_set, labsite.site_routes())


def test_a_rule_underneath_a_decoy_fails_the_check():
    config = sig.lab_config()
    canary_set = sig.canary_set()
    decoy = canary_set.canaries[0]
    bad = with_paths(config, exact=config.exact | {decoy.path + "/config"})
    with pytest.raises(SignalConfigError, match="sits on decoy"):
        sigconfig.check_against_site(bad, canary_set, labsite.site_routes())


def test_a_decoy_holding_an_attack_segment_fails_the_check():
    config = sig.lab_config()
    canary_set = sig.canary_set()
    first = canary_set.canaries[0]
    for path in ("/files/.git/notes.txt", "/admin/notes.txt", "/files/.env"):
        swapped = replace(
            canary_set, canaries=(replace(first, path=path), *canary_set.canaries[1:])
        )
        with pytest.raises(SignalConfigError, match=f"decoy {first.id}"):
            sigconfig.check_against_site(config, swapped, labsite.site_routes())


def test_a_canary_whose_planted_request_looks_like_injection_fails_the_check():
    config = sig.lab_config()
    canary_set = sig.canary_set()
    first = canary_set.canaries[0]
    swapped = replace(
        canary_set,
        canaries=(replace(first, path="/files/union select/x"), *canary_set.canaries[1:]),
    )
    with pytest.raises(SignalConfigError, match="would raise injection:sqli"):
        sigconfig.check_against_site(config, swapped, labsite.site_routes())


@pytest.mark.parametrize("route", ["/docs/", "/assets/site.css", "/robots.txt", "/index.html"])
def test_a_real_site_path_on_the_attack_list_fails_the_check(route):
    config = sig.lab_config()
    trimmed = route.rstrip("/")
    bad = with_paths(config, tree=(*config.tree, trimmed))
    with pytest.raises(SignalConfigError, match="real site path"):
        sigconfig.check_against_site(bad, sig.canary_set(), labsite.site_routes())


def test_a_classifier_cannot_be_built_from_a_config_that_fails_the_check():
    config = sig.lab_config()
    canary_set = sig.canary_set()
    bad = with_paths(config, exact=config.exact | {canary_set.canaries[3].path})
    with pytest.raises(SignalConfigError):
        signals.Classifier(bad, canary_set, labsite.site_routes())


def test_every_problem_is_reported_at_once():
    config = sig.lab_config()
    canary_set = sig.canary_set()
    bad = with_paths(config, exact=config.exact | {c.path for c in canary_set.canaries[:2]})
    with pytest.raises(SignalConfigError) as caught:
        sigconfig.check_against_site(bad, canary_set, labsite.site_routes())
    for canary in canary_set.canaries[:2]:
        assert f"decoy {canary.id}" in str(caught.value)


# -- the command --------------------------------------------------------------------


def _state(tmp_path):
    state = tmp_path / "canaries.json"
    canaries.save_state(sig.canary_set(), state)
    return state


def test_signals_check_passes_for_the_shipped_config(tmp_path, capsys):
    code = cli.main(
        ["signals", "check", "--config", str(sig.LAB_CONFIG), "--state", str(_state(tmp_path))]
    )
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "7 decoys" in out and "2 distinct attack signals" in out


def test_signals_check_exits_1_when_a_decoy_is_an_attack_path(tmp_path, capsys):
    state = _state(tmp_path)
    decoy = canaries.load_state(state).canaries[0]
    config = tmp_path / "signals.toml"
    config.write_text(MINIMAL + f'[attack_paths]\nexact = ["{decoy.path}"]\n')
    code = cli.main(["signals", "check", "--config", str(config), "--state", str(state)])
    assert code == cli.EXIT_FAIL
    assert "CHECK FAILED" in capsys.readouterr().err


def test_signals_check_exits_2_for_an_unreadable_config(tmp_path, capsys):
    config = tmp_path / "signals.toml"
    config.write_text("version = 9\n")
    code = cli.main(["signals", "check", "--config", str(config), "--state", str(_state(tmp_path))])
    assert code == cli.EXIT_USAGE
    assert "version" in capsys.readouterr().err
