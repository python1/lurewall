# SPDX-License-Identifier: AGPL-3.0-only
"""Natural placements refuse to start without the opt-in njs module package."""

from __future__ import annotations

import subprocess

import pytest

from lurewall import cli, natural_runtime, operator


def host(status="installed", version="0.8.9-1", newer=True):
    def run(argv):
        if argv[0].endswith("dpkg-query"):
            if status is None:
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="no packages")
            return subprocess.CompletedProcess(argv, 0, stdout=f"{status} {version}", stderr="")
        assert argv[1:] == ["--compare-versions", version, "ge", natural_runtime.NJS_MINIMUM]
        return subprocess.CompletedProcess(argv, 0 if newer else 1, stdout="", stderr="")

    return run


def test_an_installed_new_enough_module_passes(tmp_path):
    module = tmp_path / "ngx_http_js_module.so"
    module.write_bytes(b"fixture")
    assert natural_runtime.njs_problem(host(), module) is None


@pytest.mark.parametrize(
    ("run", "words"),
    [
        (host(status=None), "is not installed"),
        (host(status="config-files"), "is not installed"),
        (host(version="0.7.12-1", newer=False), "0.7.12-1 is too old"),
    ],
)
def test_missing_or_old_module_names_the_package_and_the_fix(tmp_path, run, words):
    problem = natural_runtime.njs_problem(run, tmp_path / "absent.so")
    assert words in problem
    assert "sudo apt install libnginx-mod-http-js" in problem
    assert "0.8.2 or newer" in problem


def test_missing_module_file_or_dpkg_is_refused(tmp_path):
    assert "is missing" in natural_runtime.njs_problem(host(), tmp_path / "absent.so")

    def no_dpkg(argv):
        raise FileNotFoundError(argv[0])

    assert "Could not confirm" in natural_runtime.njs_problem(no_dpkg, tmp_path / "absent.so")


def test_natural_build_refuses_before_writing_anything(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(natural_runtime, "njs_problem", lambda: "njs missing fixture")
    root = tmp_path / "public"
    root.mkdir()
    out = tmp_path / "private"
    status = cli.main(
        [
            "lab-site",
            "build",
            "--state",
            str(tmp_path / "canaries.json"),
            "--out",
            str(out),
            "--site-root",
            str(root),
            "--server-name",
            "static.example.test",
        ]
    )
    assert status == cli.EXIT_USAGE
    assert "njs missing fixture" in capsys.readouterr().err
    assert not out.exists() and not (tmp_path / "canaries.json").exists()


def test_doctor_natural_checks_fail_without_njs_and_always_warn_about_rollback():
    good = operator.natural_checks(lambda: None)
    assert [(c.name, c.level) for c in good] == [("njs module", "pass"), ("rollback", "warn")]
    assert "restore the previous vhost" in good[1].detail
    bad = operator.natural_checks(lambda: "njs missing fixture")
    assert (bad[0].level, bad[0].detail) == ("fail", "njs missing fixture")
