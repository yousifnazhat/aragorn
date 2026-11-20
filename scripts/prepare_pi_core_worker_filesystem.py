"""Package retained worker bytes and a separate empty service-state seed. No mount or extraction."""
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile

from scripts import prepare_pi_core_restricted_runtime as storage
from scripts.build_pi_core_linux import ROOT, require, sha256
from scripts.prepare_pi_core_worker_state import state_seed
from scripts.prepare_pi_core_worker_view import worker_members


OUT = Path.home() / "Library/Application Support/Aragorn-B53-Offline"
MEDIA = "packaging/pi-core/immutable-host-b44/media-output.json"
MEDIA_SHA = "0ebd47b2380dcba15e60d9dfb1dd42838f613733d62ac8128a679cd1ec19e892"
LIMIT = 160 << 20


def _entries(directories, files):
    names = directories.keys() | files.keys()
    require(0 < len(names) <= 128 and not directories.keys() & files.keys(), "archive member collision or limit")
    for name in sorted(names):
        require(type(name) is str and len(name) <= 100 and
                all(re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9.+_-]*", part) for part in name.split("/")),
                "noncanonical archive member")
        parent = str(PurePosixPath(name).parent)
        require(parent == "." or parent in directories, "archive parent absent")
        info = tarfile.TarInfo(name)
        if name in directories:
            info.type = tarfile.DIRTYPE
            info.mode = directories[name]
            require(info.mode in ((0o555,) if files else (0o555, 0o755)), "invalid directory mode")
            data = b""
        else:
            data, info.mode = files[name]
            require(type(data) is bytes and 0 < len(data) <= 128 << 20 and info.mode in (0o444, 0o555),
                    "invalid worker file bytes or mode")
            info.size = len(data)
        yield info, data


def write_archive(path, directories, files):
    entries = list(_entries(directories, files))
    storage.plain(path.parent)
    with path.open("xb") as out:
        os.fchmod(out.fileno(), 0o400)
        with tarfile.open(fileobj=out, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
            for info, data in entries:
                archive.addfile(info, io.BytesIO(data) if info.isfile() else None)
        out.flush()
        os.fsync(out.fileno())


def verify_archive(path, directories, files):
    """Check the entire on-disk USTAR stream against the inputs; do not extract or trust member paths."""
    raw = storage.read(path, LIMIT)
    view = memoryview(raw)
    pos = 0
    for info, data in _entries(directories, files):
        require(view[pos:pos+512] == info.tobuf(tarfile.USTAR_FORMAT), "archive header or namespace differs")
        pos += 512
        require(view[pos:pos+len(data)] == data, "archived member bytes differ")
        pos += len(data)
        pad = -pos % 512
        require(view[pos:pos+pad] == bytes(pad), "invalid member padding")
        pos += pad
    size = pos + 1024
    require(len(raw) == size + (-size % tarfile.RECORDSIZE) and not any(view[pos:]),
            "missing archive terminator or unexpected trailing data")
    return sha256(raw)


def prepare(root=ROOT):
    """Produce one private, fresh batch directory; preserve partial output on failure."""
    require(root == ROOT, "fixed workspace required")
    raw = storage.read(root / MEDIA, 32768)
    require(sha256(raw) == MEDIA_SHA, "B44 catalog differs from reviewed candidate")
    media = json.loads(raw)
    directories, files, plan = worker_members(root)
    seed, state = state_seed()
    # B46 custody boundary: keep new artifacts outside the managed Documents checkout.
    work = OUT
    parent = storage.plain(work.parent).stat()
    require(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022, "unprotected local staging parent")
    work.mkdir(mode=0o700)  # Exclusive; never adopt an earlier/partial directory.
    archives = {}
    for name, dirs, members in (("worker-view.tar", dict.fromkeys(directories, 0o555), files),
                                ("writable-state.tar", seed, {})):
        target = work / name
        write_archive(target, dirs, members)
        archives[name] = verify_archive(target, dirs, members)
    storage.write(work / "worker-source-plan.json", plan)
    require(storage.read(work / "worker-source-plan.json") == plan, "retained source plan readback differs")
    outcome = {"schema": "aragorn/pi-core-offline-worker-filesystem/v1", "disk_sha256": media["disk_sha256"],
               "media_pins_sha256": MEDIA_SHA, "archives": archives, "source_plan_sha256": sha256(plan),
               "runtime_digest": storage.fixed.RUNTIME_DIGEST, "worker_files": len(files),
               "worker_directories": len(directories), "state": state, "installed_view_observed": False,
               "target_executed": False, "phase3_exit_eligible": False}
    storage.record(work / "outcome.json", outcome)
    require(json.loads(storage.read(work / "outcome.json")) == outcome, "preparation receipt readback differs")
    return outcome
