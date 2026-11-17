# SPDX-License-Identifier: AGPL-3.0-only
"""Lurewall: defensive, lab-only AI-agent canaries and detector.

Created by Paul Charydczak.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("lurewall")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
