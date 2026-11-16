#!/usr/bin/env python3
"""Refresh vendor/ to the pinned versions (tech.md §3).

Downloads each pinned wheel from PyPI, checks its sha256, unpacks the package
and its licence into vendor/ and rewrites vendor/VERSIONS. Development only:
the runtime never downloads anything.
"""

from __future__ import annotations

import hashlib
import io
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor"

# name, version, top-level package, wheel URL, sha256
PINNED = [
    (
        "rich",
        "15.0.0",
        "rich",
        "https://files.pythonhosted.org/packages/82/3b/"
        "64d4899d73f91ba49a8c18a8ff3f0ea8f1c1d75481760df8c68ef5235bf5/"
        "rich-15.0.0-py3-none-any.whl",
        "33bd4ef74232fb73fe9279a257718407f169c09b78a87ad3d296f548e27de0bb",
    ),
]

NOT_VENDORED = """\
# Not vendored: pygments, markdown-it-py, mdurl, typing_extensions.
# Rich 15 needs pygments only for rich.syntax and rich.traceback and
# markdown-it-py (with mdurl) only for rich.markdown; it needs no
# typing_extensions on Python 3.9+. KERBEROS imports none of these modules,
# and tests run the app under `python3 -I -S` with vendor/ alone.
"""


def fetch(url: str, sha256: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as resp:
        data = resp.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha256:
        raise SystemExit(f"sha256 mismatch for {url}: {digest}")
    return data


def _is_license(filename: str) -> bool:
    return filename.upper().startswith(("LICENSE", "COPYING"))


def unpack(data: bytes, package: str, name: str) -> None:
    target = VENDOR / package
    if target.exists():
        shutil.rmtree(target)
    licenses = VENDOR / "licenses"
    licenses.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as wheel:
        for info in wheel.infolist():
            path = info.filename
            if path.startswith(package + "/"):
                if "__pycache__" in path or path.endswith(".pyc"):
                    continue
                out = VENDOR / path
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(wheel.read(info))
            elif ".dist-info/" in path and _is_license(Path(path).name):
                (licenses / f"{name}-{Path(path).name}").write_bytes(wheel.read(info))


def main() -> int:
    VENDOR.mkdir(exist_ok=True)
    lines = ["# Vendored by tools/vendor.py; do not edit by hand.", ""]
    for name, version, package, url, sha256 in PINNED:
        print(f"{name} {version}")
        unpack(fetch(url, sha256), package, name)
        lines.append(f"{name}=={version} sha256={sha256}")
    lines += ["", NOT_VENDORED.rstrip()]
    (VENDOR / "VERSIONS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
