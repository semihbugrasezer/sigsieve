#!/usr/bin/env python3
"""Package a release archive deterministically.

Usage: package-release.py NAME

Writes dist/NAME.tar.gz containing NAME/sigsieve (from target/release), the
LICENSE*/THIRD_PARTY_LICENSES* files, README.md and CHANGELOG.md. Entry order,
modes, owners and mtimes (SOURCE_DATE_EPOCH) are fixed and the gzip header has
no name or time, so the same inputs give byte-identical archives. Used by
release.yml and release-rehearsal.yml.
"""

import gzip, io, os, sys, tarfile
name, mtime = sys.argv[1], int(os.environ["SOURCE_DATE_EPOCH"])
files = [("target/release/sigsieve", "sigsieve", 0o755)] + [
    (f, f, 0o644)
    for f in sorted(os.listdir("."))
    if f.startswith(("LICENSE", "THIRD_PARTY_LICENSES"))
] + [("README.md", "README.md", 0o644), ("CHANGELOG.md", "CHANGELOG.md", 0o644)]
if not any(f[1].startswith("LICENSE") for f in files):
    sys.exit("no LICENSE file")
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
    for src, arc, mode in files:
        data = open(src, "rb").read()
        info = tarfile.TarInfo(f"{name}/{arc}")
        info.size, info.mode, info.mtime = len(data), mode, mtime
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        tar.addfile(info, io.BytesIO(data))
with open(f"dist/{name}.tar.gz", "wb") as out:
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
        gz.write(buf.getvalue())
