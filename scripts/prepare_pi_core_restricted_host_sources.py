"""Return only the reviewed repository-code portion of the coordinator host profile.

The pins are from signed fb49c72, not discovered from a developer tree or a VM.
Reading the projection does not import projected Python or the wrapper.
The independent full host profile and retained Linux host-export checks still apply.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import stat

from scripts.build_pi_core_linux import regular_bytes, sha256

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "packaging/pi-core/restricted-host-sources-v1.json"
MANIFEST_SHA256 = "c823ab144d076ff69136ddf61651607112c83a92f185b6d3a0e678bef598ad10"
REVISION = "fb49c72f9381aee050cc51547fb4ff180db9f7c2"
TREE = "342e75c58ae5386b4c4cbe9f16117159b8de4bd8"
WRAPPER = "/opt/aragorn/bin/coordinator.py"


def _identity(path):
    st = path.lstat()
    if path.resolve(strict=True) != path or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ValueError("linked or nonregular host source: " + str(path))
    return st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _release(root):
    path = root / MANIFEST
    before = _identity(path)
    raw = regular_bytes(path, 65536)
    if _identity(path) != before or sha256(raw) != MANIFEST_SHA256:
        raise ValueError("unapproved host source manifest")
    release = json.loads(raw)
    if (release["schema"], release["revision"], release["tree"]) != (
            "aragorn/pi-core-restricted-host-sources/v1", REVISION, TREE):
        raise ValueError("host source release differs")
    return release["files"]


def prepare_host_sources(root=ROOT):
    """Return sorted host `files` rows without claiming host/installed custody."""
    root = Path(root).absolute()
    rows = _release(root)
    held = {}
    # The raw manifest pin fixes the complete ordered paths, sizes and hashes,
    # including the four wrapper entrypoints and the dynamically installed loader.
    for row in rows:
        dest = row["path"]
        if dest == WRAPPER:
            path = root / "packaging/pi-core/coordinator.py"
        elif re.fullmatch(r"/opt/aragorn/src/aragorn/(?:[A-Za-z_]\w*/)*[A-Za-z_]\w*\.py", dest, re.ASCII):
            path = root / dest.removeprefix("/opt/aragorn/")
        else:
            raise ValueError("not a protected host source path")
        if path in held:
            raise ValueError("duplicate host source")
        held[path] = _identity(path)
        raw = regular_bytes(path, 4 << 20)
        if len(raw) != row["size"] or "sha256:" + sha256(raw) != row["digest"]:
            raise ValueError("host source differs from release: " + row["path"])
    if any(_identity(path) != before for path, before in held.items()):
        raise ValueError("host source changed during preparation")
    return rows


def require_host_source_projection(approved_host_files, *, root=ROOT):
    """Compare an approved full profile to the release; never read its export."""
    expected = _release(Path(root).absolute())
    if type(approved_host_files) is not list or len(approved_host_files) > 4096:
        raise ValueError("invalid host file inventory")
    actual = []
    for row in approved_host_files:
        if type(row) is not dict or type(row.get("path")) is not str:
            raise ValueError("invalid host file row")
        if row["path"].startswith(("/opt/aragorn/src/", "/opt/aragorn/bin/")):
            if set(row) != {"path", "size", "digest"} or type(row["size"]) is not int:
                raise ValueError("invalid host code row")
            actual.append(row)
    if actual != expected:
        raise ValueError("host profile code projection differs")


def prepare_restricted_coordinator_host(expected_profile_raw, *, expected_profile_digest, retained_root, root=ROOT):
    """Authenticate one full profile before applying both checks to those same bytes."""
    if (type(expected_profile_raw) is not bytes or not 0 < len(expected_profile_raw) <= 2 << 20
            or type(expected_profile_digest) is not str or "sha256:" + sha256(expected_profile_raw) != expected_profile_digest):
        raise ValueError("independent bounded full host profile and pin required")
    profile = json.loads(expected_profile_raw)
    if type(profile) is not dict:
        raise ValueError("full host profile required")
    require_host_source_projection(profile.get("files"), root=root)
    # Keep the historical full verifier and its canonical parsing and export
    # custody intact. Loading its developer-side helpers is not profile discovery.
    from scripts.prepare_pi_core_coordinator_host import prepare_pi_coordinator_host_profile
    return prepare_pi_coordinator_host_profile(expected_profile_raw, expected_profile_digest=expected_profile_digest,
                                               retained_root=retained_root)
