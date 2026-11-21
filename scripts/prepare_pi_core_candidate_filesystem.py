"""Prepare one offline worker-view archive from B53 and B83. Never extract, mount or launch it."""
import io
import os
from pathlib import Path
import stat
import tarfile

from scripts import prepare_pi_core_worker_filesystem as b53
from scripts import prepare_pi_core_worker_view_runtime as b83
from scripts.prepare_pi_core_restricted_worker_inventory import _document, fixed, retained
from scripts.prepare_pi_core_worker_view import candidate_content_inventory


ROOT = b53.ROOT
PREVIOUS = b53.OUT / "worker-view.tar"
OUT = Path.home() / "Library/Application Support/Aragorn-B86-Offline"
B53_RECEIPT = "packaging/pi-core/worker-filesystem-b53.json"
B53_RECEIPT_SHA = "97a7339d3b1d5bce33b5398df8ef7ffee7fe1a193cd042aed018218810c02ca7"
B53_ARCHIVE_SHA = "95ca2d28a2f5b5cf85b01f1f5772066188fe05dd63e3723327c0adc0144d058e"
B53_ARCHIVE_BYTES = 129320960
MEMBER = fixed.GATE_PATH.lstrip("/")
SCHEMA = "aragorn/pi-core-worker-filesystem-candidate/v1"
require = retained.require


def _original_members(raw):
    # B53 pins the complete, canonical USTAR stream. Read only regular members, never extract to disk.
    require(len(raw) == B53_ARCHIVE_BYTES and retained.sha(raw) == B53_ARCHIVE_SHA, "different B53 worker archive")
    directories, files = {}, {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = member.name
            require(name not in directories and name not in files and len(directories) + len(files) < 35,
                    "duplicate or extra B53 member")
            if member.type == tarfile.DIRTYPE:
                require(member.mode == 0o555 and member.size == 0, "wrong B53 directory metadata")
                directories[name] = member.mode
            else:
                require(member.type == tarfile.REGTYPE and member.mode in (0o444, 0o555)
                        and 0 < member.size <= 128 << 20, "invalid B53 regular file")
                with archive.extractfile(member) as stream:
                    files[name] = (stream.read(member.size), member.mode)
                require(len(files[name][0]) == member.size, "short B53 member")
    require((len(directories), len(files)) == (22, 13), "incomplete B53 namespace")
    return directories, files


def replace_gate(directories, files, gate, inventory):
    """Verify the one replacement and the complete candidate projection without mutating the predecessor."""
    require(inventory["schema"] == "aragorn/pi-core-worker-view-content-candidate/v1" and
            all(inventory[k] is False for k in ("installed_view_observed", "target_executed", "launch_authorized",
                                               "phase3_exit_eligible")), "not an unactivated content candidate")
    old, mode = files[MEMBER]
    require(mode == 0o555 and len(old) == fixed.GATE_BYTES and retained.sha(old) == fixed.GATE_SHA256 and
            type(gate) is bytes and len(gate) == 4232 and old != gate, "invalid predecessor or replacement gate")
    successor = files | {MEMBER: (gate, mode)}
    runtime, loaders = inventory["runtime_files"], inventory["node_loaders"]
    require(type(runtime) is list and len(runtime) == 4 and type(loaders) is list and len(loaders) == 8 and
            {r["path"] for r in runtime} == {fixed.PREFIX + r["path"] for r in fixed.expected_files()} and
            {r["path"] for r in loaders} == {"/" + name for name in files if name.startswith("lib/")},
            "candidate runtime or loader namespace differs")
    checked = set()
    for row in runtime + loaders:
        name = row["path"][1:]
        require(set(row) == {"path", "digest", "size", "mode"} and name in successor and name not in checked,
                "missing or duplicate candidate member")
        data, file_mode = successor[name]
        require(type(row["size"]) is type(row["mode"]) is int and (len(data), file_mode, "sha256:" + retained.sha(data)) ==
                (row["size"], row["mode"], row["digest"]), "candidate content or mode differs")
        checked.add(name)
    require(checked | {"usr/bin/env"} == files.keys() and not directories.keys() & files.keys(),
            "unexpected unchecked worker member")
    return successor


def candidate_members(root=ROOT):
    require(root == ROOT, "fixed workspace required")
    previous = _document(root / B53_RECEIPT, B53_RECEIPT_SHA)
    require(previous["archives"]["worker-view.tar"] == B53_ARCHIVE_SHA and
            previous["runtime_digest"] == fixed.RUNTIME_DIGEST, "unrecognized B53 receipt")
    original = retained.plain(PREVIOUS).stat()
    require(original.st_uid == os.geteuid() and stat.S_ISREG(original.st_mode) and stat.S_IMODE(original.st_mode) == 0o400,
            "unexpected predecessor file ownership or mode")
    directories, files = _original_members(retained.read(PREVIOUS, B53_ARCHIVE_BYTES))
    inventory = candidate_content_inventory(root=root)
    path = root / b83.OUTPUT / "deployment" / b83.MEMBER
    s = retained.plain(path).lstat()
    require(s.st_uid == os.geteuid() and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o555,
            "unexpected B83 gate ownership or mode")
    gate = retained.read(path, 4232)
    after = path.lstat()
    require((s.st_dev, s.st_ino, s.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_ctime_ns),
            "B83 gate changed during intake")
    return directories, replace_gate(directories, files, gate, inventory), inventory


def prepare(root=ROOT):
    require(root == ROOT, "fixed workspace required")
    parent = retained.plain(OUT.parent).stat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o022,
            "unprotected staging parent")
    OUT.mkdir(mode=0o700)  # Exclusive even after a failed partial attempt. No retries, adoption, or deletion.
    directories, files, inventory = candidate_members(root)
    target = OUT / "worker-view.tar"
    b53.write_archive(target, directories, files)
    archive_pin = b53.verify_archive(target, directories, files)
    result = dict(schema=SCHEMA, predecessor_archive_sha256=B53_ARCHIVE_SHA, candidate_inventory_digest=fixed.digest(inventory),
                  candidate_tree_digest=inventory["candidate_tree_digest"], replaced_member=MEMBER,
                  archives={target.name: archive_pin}, worker_files=len(files), worker_directories=len(directories),
                  installed_view_observed=False, target_executed=False, launch_authorized=False, phase3_exit_eligible=False)
    retained.record(OUT / "outcome.json", result)
    require(retained.read(OUT / "outcome.json", 8192) == fixed.canonical(result) + b"\n", "candidate receipt readback differs")
    return result
