"""Prepare the complete immutable-image input tree. No mounts, image builds, state or release."""
import json
import os
from pathlib import Path
import stat

from scripts import pi_core_capture_mountpoints as mounts
from scripts import prepare_pi_core_immutable_payload as image
from scripts import prepare_pi_core_split_worker_payload as worker
from scripts.build_pi_core_linux import canonical, require, sha256


PRIOR = Path.home() / "Library/Application Support/Aragorn-B63-Offline"
OUT = PRIOR.parent / "Aragorn-B64-Offline"
REVIEW = image.ROOT / "packaging/pi-core/split-guest-payload-b64.json"
B63_OUTCOME = "94e8986251e8d0035e501b66d3e67e448e3d81a0126e90301097aa88e5770204"
WORKER_ROOTS = tuple(map(Path, mounts.WORKER_ROOTS))
SCHEMA = "aragorn/pi-core-immutable-payload/v1"


def _index(rows):
    indexed = {}
    for row in rows:
        name = row["path"]
        path = Path(name)
        require(str(path) == name and path.anchor == "/" and name != "/" and ".." not in path.parts
                and name not in indexed and row["uid"] == row["gid"] == 0, "ambiguous payload identity")
        if row["type"] == "file":
            require(row["mode"] in (0o400, 0o444, 0o555), "invalid immutable file mode")
        else:
            require(row["type"] == "dir" and row["mode"] in (0o555, 0o700, 0o755), "invalid immutable directory")
        indexed[name] = row
    return indexed


def _dir(path, mode):
    return dict(path=str(path), type="dir", mode=mode, uid=0, gid=0)


def compose(host, split, mountpoints):
    require(host["schema"] == SCHEMA, "unexpected host payload")
    rows, add = _index(host["entries"]), _index(split["entries"])
    require(not (rows.keys() & add.keys()) and all(any(Path(p).is_relative_to(r) for r in WORKER_ROOTS)
            for p in add) and all(add.get(str(r)) == _dir(r, 0o755) for r in WORKER_ROOTS),
            "worker roots incomplete, outside placement or shadow host")
    rows.update(add)
    for dest, mode in mountpoints.items():
        require(not any(Path(p).is_relative_to(dest) for p in rows) and
                not any(Path(dest).is_relative_to(r) for r in WORKER_ROOTS),
                "mountpoint would shadow a payload object or enter the worker")
        rows[dest] = _dir(dest, mode)
    # Fill only the outer placement paths; a missing directory within a worker
    # or host projection is not permission to silently manufacture a new one.
    for name in (*WORKER_ROOTS, *mountpoints):
        for parent in Path(name).parents:
            if parent != Path("/"):
                rows.setdefault(str(parent), _dir(parent, 0o755))
    for name in rows:
        parent = Path(name).parent
        require(parent == Path("/") or rows.get(str(parent), {}).get("type") == "dir",
                "payload parent missing or is a file")
    return {"schema": SCHEMA, "entries": [rows[name] for name in sorted(rows)]}


def _host_bytes(row, base):
    name = row["path"]
    root = image.WORK / "root" if base.get(name) == row else PRIOR / "changed-files"
    src = root / name[1:]
    require(src.resolve(strict=True) == src, "linked physical source path")
    before = src.lstat()
    require(before.st_nlink == 1 and stat.S_ISREG(before.st_mode) and
            stat.S_IMODE(before.st_mode) == row["mode"], "not a single physical source file with expected mode")
    # _stage hashes these exact bytes against the independently committed row before copying.
    raw = image.regular_bytes(src, row["size"])
    after = src.lstat()
    require(len(raw) == row["size"] and (before.st_dev, before.st_ino, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_ctime_ns), "physical source changed")
    return raw


def _stage(root, manifest, file_bytes):
    root.mkdir(mode=0o700)
    dirs = []
    for row in manifest["entries"]:
        target = root / row["path"][1:]
        if row["type"] == "dir":
            target.mkdir(mode=0o700)
            dirs.append((target, row["mode"]))
        else:
            data = file_bytes(row)
            require(len(data) == row["size"] and sha256(data) == row["sha256"], "copied bytes differ from commitment")
            image.new(target, data, row["mode"])
    for d, mode in reversed(dirs):
        d.chmod(mode)
    image.check_physical(root, manifest)


def prepare():
    require(not os.path.lexists(OUT), "output already present; do not resume or replace it")
    receipt = json.loads(image.read(PRIOR / "outcome.json", B63_OUTCOME, 8192))
    pins = receipt["retained_files"]
    base = _index(json.loads(image.read(image.WORK / "payload.json", receipt["base_manifest_sha256"],
                                        2 << 20))["entries"])
    host = json.loads(image.read(PRIOR / "payload.json", pins["payload.json"], 2 << 20))
    profile = image.read(PRIOR / "coordinator-host.json", pins["coordinator-host.json"], 2 << 20)
    plan = image.read(PRIOR / "worker-source-plan.json", pins["worker-source-plan.json"], 65536)
    split, raw_worker, binding = worker.prepare(profile, plan)
    require(set(raw_worker) == {r["path"] for r in split["entries"] if r["type"] == "file"},
            "worker bytes do not cover precisely the split manifest")
    manifest = compose(host, split, mounts.MOUNTPOINTS)
    mounts.verify_guest_layout(manifest["entries"])
    encoded = canonical(manifest)
    manifest_pin = sha256(encoded)
    review = json.loads(image.regular_bytes(REVIEW, 8192))
    require(review["schema"] == "aragorn/pi-core-split-guest-payload-inputs/v1" and
            review["payload_sha256"] == manifest_pin, "complete payload differs from independent commitment")
    parent = OUT.parent
    require(parent.resolve(strict=True) == parent and parent.stat().st_uid == os.geteuid()
            and not parent.stat().st_mode & 0o022, "unsafe private staging parent")
    OUT.mkdir(mode=0o700)
    _stage(OUT / "root", manifest, lambda r: raw_worker[r["path"]] if r["path"] in raw_worker else _host_bytes(r, base))
    files = [r for r in manifest["entries"] if r["type"] == "file"]
    result = dict(schema="aragorn/pi-core-split-guest-payload/v1", payload_sha256=manifest_pin,
                  base_manifest_sha256=receipt["base_manifest_sha256"], b63_outcome_sha256=B63_OUTCOME,
                  host_profile_sha256=pins["coordinator-host.json"], worker_plan_sha256=pins["worker-source-plan.json"],
                  worker_binding=binding, entries=len(manifest["entries"]), files=len(files),
                  bytes=sum(r["size"] for r in files), image_assembled=False, installed_identity_verified=False,
                  phase3_exit_eligible=False)
    for name, raw in (("payload.json", encoded), ("outcome.json", canonical(result))):
        image.new(OUT / name, raw)
        require(image.read(OUT / name, sha256(raw), len(raw)) == raw, "public metadata differs on readback")
    return result
