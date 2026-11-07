"""Look inside archives that are bundled in a release (a `data.zip`, a vendored
`.tar.gz`, a `.whl` of test fixtures) for credentials.

Hostile or merely large input is expected: everything is bounded (depth, member
count, bytes read after decompression), nothing is extracted to disk, and what
cannot be inspected is counted so the caller can say so instead of passing
silently.
"""
from __future__ import annotations

import bz2
import io
import lzma
import tarfile
import zipfile
import zlib
from typing import Iterator, Optional, Tuple

from .safety import StreamScanner, sensitive_file_kind

MAX_DEPTH = 2                      # an archive inside an archive inside the artifact
MAX_NESTED_BYTES = 64 * 1024 * 1024    # largest nested archive read into memory
MAX_UNPACKED_BYTES = 256 * 1024 * 1024  # decompressed bytes examined per outer file
MAX_NESTED_MEMBERS = 10_000        # per archive
MAX_TOTAL_MEMBERS = 50_000         # across everything nested in one artifact
CHUNK = 1024 * 1024

_ERRORS = (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError, RuntimeError,
           NotImplementedError, zlib.error, lzma.LZMAError, UnicodeError, OverflowError)


def archive_kind(head: bytes, name: str = "") -> Optional[str]:
    """'zip', 'gzip', 'bzip2', 'xz' or 'tar' from magic bytes, else None."""
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh") and head[3:4].isdigit():
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head[257:262] == b"ustar":
        return "tar"
    return None


class Limits:
    def __init__(self):
        self.left = MAX_UNPACKED_BYTES
        self.members = MAX_TOTAL_MEMBERS
        self.skipped = 0       # nested archives or members not inspected (too big, too deep, too many)


def _decompress(kind: str, data: bytes, limits: Limits) -> Optional[bytearray]:
    """Whole decompressed stream, or None when it would exceed the budget (a
    compression bomb never gets expanded past `limits.left` bytes)."""
    cap = limits.left
    out = bytearray()
    try:
        if kind == "gzip":
            d = zlib.decompressobj(31)
            buf = data
            while True:
                out += d.decompress(buf, cap - len(out) + 1)
                if len(out) > cap:
                    limits.skipped += 1
                    return None
                buf = d.unconsumed_tail
                if d.eof:
                    buf = d.unused_data
                    if not buf:
                        break
                    d = zlib.decompressobj(31)     # concatenated gzip members
                elif not buf:
                    break
        else:
            d = bz2.BZ2Decompressor() if kind == "bzip2" else lzma.LZMADecompressor()
            buf = data
            while True:
                piece = d.decompress(buf, cap - len(out) + 1)
                buf = b""
                out += piece
                if len(out) > cap:
                    limits.skipped += 1
                    return None
                if d.eof or (not piece and d.needs_input):
                    break
    except _ERRORS:
        if not out:
            return None          # not actually compressed data
    limits.left -= len(out)
    return out


def _scan(fp, name: str) -> StreamScanner:
    sc = StreamScanner(name)
    while True:
        chunk = fp.read(CHUNK)
        if not chunk:
            break
        sc.feed(chunk)
    return sc


def inspect(data: bytes, outer: str, limits: Limits, depth: int = 1
            ) -> Iterator[Tuple[str, int, StreamScanner, Optional[str]]]:
    """Yield (display name, size, scanner, credential-file kind) for each file inside
    the archive in `data`. Names read `outer!/inner`."""
    kind = archive_kind(data[:512], outer)
    if kind is None:
        return
    try:
        if kind in ("gzip", "bzip2", "xz"):
            raw = _decompress(kind, data, limits)
            if raw is None:
                return
            if archive_kind(raw[:512]) == "tar":
                yield from inspect(raw, outer, limits, depth)
                return
            inner_name = outer.rsplit("/", 1)[-1]
            for suf in (".gz", ".bz2", ".xz", ".tgz"):
                if inner_name.endswith(suf):
                    inner_name = inner_name[:-len(suf)]
            yield from _leaf(raw, f"{outer}!/{inner_name}", limits, depth)
            return
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()
                if len(infos) > MAX_NESTED_MEMBERS:
                    limits.skipped += 1
                    return
                for info in infos:
                    if info.is_dir():
                        continue
                    if info.flag_bits & 0x1:          # encrypted: cannot be read, so say so
                        limits.skipped += 1
                        continue
                    if info.file_size > limits.left:
                        limits.skipped += 1
                        continue
                    limits.left -= info.file_size
                    try:
                        with zf.open(info) as fp:
                            blob = fp.read(info.file_size)
                    except _ERRORS:
                        continue
                    yield from _leaf(blob, f"{outer}!/{info.filename}", limits, depth)
        else:   # tar
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
                count = 0
                for mem in tf:
                    count += 1
                    if count > MAX_NESTED_MEMBERS:
                        limits.skipped += 1
                        return
                    if not mem.isfile():
                        continue
                    if mem.size > limits.left:
                        limits.skipped += 1
                        continue
                    limits.left -= mem.size
                    fp = tf.extractfile(mem)
                    if fp is None:
                        continue
                    yield from _leaf(fp.read(mem.size), f"{outer}!/{mem.name}", limits, depth)
    except _ERRORS:
        return


def _leaf(blob: bytes, display: str, limits: Limits, depth: int):
    if limits.members <= 0:
        limits.skipped += 1
        return
    limits.members -= 1
    sc = _scan(io.BytesIO(blob), display)
    yield display, len(blob), sc, sensitive_file_kind(display.rsplit("!/", 1)[-1])
    inner_kind = archive_kind(sc.head, display)
    if inner_kind:
        if depth >= MAX_DEPTH or len(blob) > MAX_NESTED_BYTES:
            limits.skipped += 1
        else:
            yield from inspect(blob, display, limits, depth + 1)
