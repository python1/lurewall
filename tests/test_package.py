# SPDX-License-Identifier: AGPL-3.0-only
"""The scaffold's only promise: the package installs and imports."""

import re

import lurewall


def test_package_imports_with_a_version():
    assert re.match(r"^\d+\.\d+", lurewall.__version__)


def test_package_is_installed_not_just_on_the_path():
    # CI installs the package; an uninstalled tree reports the fallback version.
    assert lurewall.__version__ != "0.0.0+unknown"
