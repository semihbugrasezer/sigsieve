#!/usr/bin/env python3
"""Check package documentation links and reproducibility with synthetic inputs."""

import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

packager = Path(__file__).with_name("package-release.py").resolve()
for name in ("README.md", "CHANGELOG.md"):
    body = (packager.parent.parent / name).read_text()
    assert not re.search(r"^\s{0,3}\[[^]]+\]:", body, re.M), f"{name}: extend packaging for reference-style links"
    assert not re.search(r"\]\([<\s]", body), f"{name}: extend packaging for this link syntax"

with tempfile.TemporaryDirectory(prefix="sigsieve-package-") as temporary:
    root = Path(temporary)
    (root / "target/release").mkdir(parents=True)
    (root / "dist").mkdir()
    readme = (
        "[Usage](docs/USAGE.md)\n"
        "[Security](docs/SECURITY_MODEL.md#two-modes)\n"
        "[License](LICENSE)\n"
        "[Section](#install)\n"
        "[Website](https://example.invalid/guide)\n"
        "[External](//example.invalid/guide)\n"
        "[Contact](mailto:report@example.invalid)\n"
    )
    fixtures = {
        "target/release/sigsieve": b"synthetic executable\x00\xff",
        "LICENSE": b"synthetic license\n",
        "THIRD_PARTY_LICENSES.txt": b"synthetic third-party notices\n",
        "README.md": readme.encode(),
        "CHANGELOG.md": b"[Limits](docs/LIMITATIONS.md)\n",
    }
    for path, content in fixtures.items():
        (root / path).write_bytes(content)

    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, SOURCE_DATE_EPOCH="1")
    subprocess.run(["git", "init", "-q"], cwd=root, env=env, check=True)
    subprocess.run(["git", "add", "."], cwd=root, env=env, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Packaging test", "-c", "user.email=test@example.invalid",
         "-c", "commit.gpgsign=false", "commit", "-qm", "synthetic package fixture"],
        cwd=root, env=env, check=True,
    )
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, env=env, text=True).strip()
    archive = root / "dist/sigsieve-test.tar.gz"
    subprocess.run([sys.executable, packager, "sigsieve-test"], cwd=root, env=env, check=True)
    first = archive.read_bytes()
    subprocess.run([sys.executable, packager, "sigsieve-test"], cwd=root, env=env, check=True)
    assert archive.read_bytes() == first, "packaging changed with identical inputs"

    base = f"https://github.com/semihbugrasezer/sigsieve/blob/{revision}/"
    with tarfile.open(fileobj=io.BytesIO(first)) as packaged:
        members = packaged.getmembers()
        assert {m.name for m in members} == {
            f"sigsieve-test/{name}"
            for name in ("sigsieve", "LICENSE", "THIRD_PARTY_LICENSES.txt", "README.md", "CHANGELOG.md")
        }
        for member in members:
            assert member.isfile() and member.uid == member.gid == 0 and member.mtime == 1
            assert member.mode == (0o755 if member.name.endswith("/sigsieve") else 0o644)
        text = packaged.extractfile("sigsieve-test/README.md").read().decode()
        assert f"[Usage]({base}docs/USAGE.md)" in text
        assert f"[Security]({base}docs/SECURITY_MODEL.md#two-modes)" in text
        assert f"[License]({base}LICENSE)" in text
        for line in readme.splitlines()[3:]:
            assert line in text, f"external URL or local anchor changed: {line}"
        assert packaged.extractfile("sigsieve-test/CHANGELOG.md").read().decode() == f"[Limits]({base}docs/LIMITATIONS.md)\n"
        for name in ("LICENSE", "THIRD_PARTY_LICENSES.txt", "sigsieve"):
            source = "target/release/sigsieve" if name == "sigsieve" else name
            assert packaged.extractfile(f"sigsieve-test/{name}").read() == fixtures[source]
    assert (root / "README.md").read_text() == readme, "source README was modified"

print("PASS: immutable documentation links, preserved payloads/metadata and byte-identical packaging")
