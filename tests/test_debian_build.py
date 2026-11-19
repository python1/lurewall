# SPDX-License-Identifier: AGPL-3.0-only
"""Check package staging without apt, a running systemd, or a root user."""

from __future__ import annotations

import runpy
import shutil
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BUILDER = runpy.run_path(str(REPO / "deploy/debian/build"))
VERSION = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]


def test_staged_payload_uses_source_git_and_ships_observe_only_defaults(tmp_path):
    commit = BUILDER["source_commit"](REPO, None)
    BUILDER["stage"](REPO, commit, tmp_path, "0.1.0~test1", "0.1.0")
    assert (tmp_path / "usr/share/doc/lurewall/source-commit").read_text() == f"{commit}\n"
    cli = BUILDER["blob"](REPO, commit, "src/lurewall/cli.py")
    assert (tmp_path / "usr/lib/lurewall/lurewall/cli.py").read_bytes() == cli
    crypto, license_text = BUILDER["signing_source"](REPO, commit)
    assert (tmp_path / "usr/lib/lurewall/crypto.py").read_bytes() == crypto
    assert (tmp_path / "usr/share/doc/lurewall/copyright.eureka").read_bytes() == license_text

    engine = (tmp_path / "etc/lurewall/engine.toml").read_text()
    assert "dry_run = true" in engine
    assert 'adapter = "log-only"' in engine
    assert "Architecture: all" in (tmp_path / "DEBIAN/control").read_text()
    declared = (tmp_path / "DEBIAN/conffiles").read_text().splitlines()
    assert declared == sorted(
        "/" + str(path.relative_to(tmp_path))
        for path in (tmp_path / "etc").rglob("*")
        if path.is_file()
    )
    units = tmp_path / "usr/lib/systemd/system"
    for service in units.glob("*.service"):
        content = service.read_text()
        assert "ExecStart=/usr/bin/lurewall " in content
        assert "/opt/lurewall/" not in content
    launcher = tmp_path / "usr/bin/lurewall"
    assert stat.S_IMODE(launcher.stat().st_mode) == 0o755
    assert "/usr/sbin/runuser -u lurewall" in launcher.read_text()
    assert "/usr/bin/python3 -I -S" in launcher.read_text()
    assert "pip install" not in launcher.read_text()


def test_signing_source_rejects_bytes_outside_the_committed_pin(monkeypatch):
    read_blob = BUILDER["blob"]

    def tampered(repository, commit, name):
        content = read_blob(repository, commit, name)
        return content + b"\n" if name == BUILDER["CRYPTO"] else content

    monkeypatch.setitem(BUILDER["signing_source"].__globals__, "blob", tampered)
    commit = BUILDER["source_commit"](REPO, None)
    with pytest.raises(BUILDER["BuildError"], match="signing source"):
        BUILDER["signing_source"](REPO, commit)


def test_build_uses_root_owned_archive_explicit_xz_and_source_timestamp(tmp_path, monkeypatch):
    invoke = subprocess.run
    which = shutil.which
    dpkg = "/mock/dpkg-deb"
    seen = []

    def command(arguments, **kwargs):
        if arguments[0] != dpkg:
            return invoke(arguments, **kwargs)
        root = Path(arguments[-2])
        (mode, owner) = (root.stat().st_mode, arguments[1])
        assert stat.S_IMODE(mode) == 0o755
        assert owner == "--root-owner-group"
        assert "-Zxz" in arguments
        assert (root / "DEBIAN/control").is_file()
        assert kwargs["env"]["SOURCE_DATE_EPOCH"] == str(int(root.stat().st_mtime))
        package = Path(arguments[-1])
        package.write_bytes(b"mock package evidence\n")
        seen.append(package.name)
        return None

    monkeypatch.setattr(shutil, "which", lambda name: dpkg if name == "dpkg-deb" else which(name))
    monkeypatch.setattr(subprocess, "run", command)
    commit = BUILDER["source_commit"](REPO, None)
    package = BUILDER["build"](REPO, commit, None, tmp_path)
    assert seen == [f"lurewall_{VERSION}~deb1+g{commit[:12]}_all.deb"]
    assert package.read_bytes() == b"mock package evidence\n"
    assert list(tmp_path.iterdir()) == [package]


@pytest.mark.parametrize("requested", ["HEAD", "main", "f45dd27", "--output=unexpected"])
def test_source_override_must_be_a_full_commit_id(requested):
    with pytest.raises(BUILDER["BuildError"], match="full Git commit ID"):
        BUILDER["source_commit"](REPO, requested)
