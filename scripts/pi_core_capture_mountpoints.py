"""Immutable guest placeholders. Nothing here creates a release, mounts a volume, or grants access."""
import json
from pathlib import PurePosixPath

from scripts.build_pi_core_linux import ROOT, regular_bytes, require, sha256


MOUNTPOINTS = {
    "/etc/aragorn/approvals": 0o700,
    "/var/lib/aragorn/admitted": 0o755,
    "/var/lib/aragorn-capture-claims": 0o700,
    "/var/lib/aragorn-runtime-action": 0o755,
    "/var/lib/aragorn-runtime-provider": 0o700,
}
WORKER_ROOTS = ("/var/lib/aragorn/pi-os", "/var/lib/aragorn/pi-runtime")
_INVENTORY = (ROOT / ".aragorn/host-preflight/build-b41/image" /
              "59122196cb507ab4182468b525cde753482c3429407ca457585fed6c832af806/inventory.jsonl")
_PIN = "421801ead2c04324f04ab7c7d4d0d7e8f093cfc7fedf82b96d769558e6bf1208"


def _check(entries, original):
    roots = {**MOUNTPOINTS, **dict.fromkeys(WORKER_ROOTS, 0o755)}
    parents = {str(p) for key in roots for p in PurePosixPath(key).parents}
    existing = set()
    for row in original:
        path = row["path"]
        require(not any(path == target or path.startswith(target + "/") for target in roots),
                "refusing to replace or conceal existing guest contents")
        if path in parents:
            require(path not in existing and row["type"] == "D" and row["uid"] == row["gid"] == 0 and
                    row["mode"] == 0o755 and row["xattrs"] == [], "unexpected guest ancestor")
            existing.add(path)
    require("/" in existing, "base guest root not observed")
    seen = {}
    for row in entries:
        path = row["path"]
        require(path not in seen and not any(path.startswith(p + "/") for p in MOUNTPOINTS),
                "duplicate payload path or nonempty protected mountpoint")
        seen[path] = row
    for path, mode in (roots | dict.fromkeys(parents - {"/"}, 0o755)).items():
        if path not in seen and path in existing:
            continue
        require(seen.get(path) == dict(path=path, type="dir", uid=0, gid=0, mode=mode),
                "missing or misplaced protected directory: " + path)


def verify_guest_layout(entries):
    # The payload manifest alone cannot establish that a mount would not conceal files in the base OS.
    raw = regular_bytes(_INVENTORY, 64 << 20)
    require(sha256(raw) == _PIN, "unreviewed original guest inventory")
    _check(entries, (json.loads(line) for line in raw.splitlines()))
