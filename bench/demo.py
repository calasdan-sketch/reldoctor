"""Build the broken demo release shown in the README, so its output can be reproduced.

    python -m bench.demo OUTDIR            # writes OUTDIR/dist (broken) and OUTDIR/prev (last release)
    reldoctor OUTDIR/dist --against OUTDIR/prev

Everything is synthetic; the fake credential is assembled at runtime and is not a real key.
"""
from __future__ import annotations

import os
import sys

from .build import Mutator, build_sdist, build_wheel, elf, frag

TAG = "cp312-cp312-manylinux2014_x86_64"


def main(out: str) -> int:
    dist, prev = os.path.join(out, "dist"), os.path.join(out, "prev")
    native = elf(machine=183, glibc="GLIBC_2.34") + b"/home/jsmith/build/src/_speed.c\0"
    secret = frag("STRIPE_KEY = '", "sk_", "live_", "q8Zk2mT7vXw4Nd9Rb3Hs6YpL", "'\n").encode()
    build_wheel(dist, tag=TAG, wheel_tags=[TAG], purelib=False,
                files={"acme_widgets/_speed.cpython-312-x86_64-linux-gnu.so": native,
                       "acme_widgets/settings.py": secret},
                meta=Mutator(add=[("Classifier", "Topic :: Software Development :: Widgets")]),
                body="# Acme Widgets\n\n![logo](docs/logo.png)\n")
    build_sdist(dist)
    build_wheel(prev, version="0.9.0", tag=TAG, wheel_tags=[TAG], purelib=False,
                files={"acme_widgets/_speed.cpython-312-x86_64-linux-gnu.so": elf()})
    build_sdist(prev, version="0.9.0")
    print(f"wrote {dist} and {prev}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "demo"))
