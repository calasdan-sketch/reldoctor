"""reldoctor — audit a Python release end-to-end before you upload it."""

from .doctor import CHECKS, Finding, diagnose, diagnose_dist_dir

__version__ = "0.3.0"
__author__ = "Calas Automations Inc."
__all__ = ["diagnose", "diagnose_dist_dir", "Finding", "CHECKS", "__version__", "__author__"]
