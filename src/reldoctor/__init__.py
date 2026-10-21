"""reldoctor — audit a Python release end-to-end before you upload it."""

from .doctor import Finding, diagnose_dist_dir

__version__ = "0.1.0"
__all__ = ["diagnose_dist_dir", "Finding", "__version__"]
