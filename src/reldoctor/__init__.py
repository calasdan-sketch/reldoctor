"""reldoctor — audit a Python release end-to-end before you upload it."""

from .doctor import CHECKS, Finding, diagnose, diagnose_dist_dir

__version__ = "0.2.0"
__all__ = ["diagnose", "diagnose_dist_dir", "Finding", "CHECKS", "__version__"]
