"""Regenerate src/reldoctor/data/* from upstream sources.

Needs (dev only): pip install trove-classifiers packaging
Network is used only for the popular-projects list (hugovk/top-pypi-packages).
Usage: python tools/refresh_data.py [--top N]
"""
import json
import os
import re
import sys
import urllib.request
from importlib.metadata import version

OUT = os.path.join(os.path.dirname(__file__), "..", "src", "reldoctor", "data")


def main(top: int = 1500) -> None:
    import trove_classifiers as tc
    from packaging.licenses import _spdx

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "trove_classifiers.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# trove-classifiers {version('trove-classifiers')} (Apache-2.0)."
                 " '! old => new | new' marks a deprecated classifier.\n")
        for c in sorted(tc.classifiers):
            fh.write(c + "\n")
        for c, repl in sorted(tc.deprecated_classifiers.items()):
            fh.write(f"! {c} => {' | '.join(repl)}\n")
    with open(os.path.join(OUT, "spdx_licenses.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# SPDX license ids (L) and exceptions (E) as shipped in packaging {version('packaging')}.\n")
        for v in sorted(x["id"] for x in _spdx.LICENSES.values()):
            fh.write(f"L {v}\n")
        for v in sorted(x["id"] for x in _spdx.EXCEPTIONS.values()):
            fh.write(f"E {v}\n")
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 - fixed https URL
        data = json.load(r)
    names = [re.sub(r"[-_.]+", "-", row["project"]).lower() for row in data["rows"][:top]]
    with open(os.path.join(OUT, "popular_projects.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# top {top} PyPI projects by downloads, {data['last_update']}"
                 " (hugovk/top-pypi-packages). Names only, normalized.\n")
        fh.write("\n".join(names) + "\n")


if __name__ == "__main__":
    main(int(sys.argv[sys.argv.index("--top") + 1]) if "--top" in sys.argv else 1500)
