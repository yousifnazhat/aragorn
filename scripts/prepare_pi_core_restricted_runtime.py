"""Offline custody of one restricted reproduction and one four-file assembly; no target execution."""
import hashlib
import json
import os
from pathlib import Path
import stat

from aragorn import pi_core_restricted_profile as fixed
from aragorn.acquire import inventory_open_directory
from scripts import build_pi_core_source_gate as gate
from scripts import verify_pi_core_worker_bundle as audit

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(".aragorn/pi-core-build")
ORIGINAL = BASE / "d2-worker-bundle-qyr6cefv/original"
COPY = BASE / "worker-reproduction-b36"
REVIEW = BASE / "worker-reproduction-evidence-b36"
ASSEMBLY = BASE / "restricted-runtime-b36"
GATE = BASE / "gate-batch-36"
PREVIOUS = BASE / "d2-73e34727a1f04044a7b74381e5bbb32d"
CHECKPOINT = Path("packaging/pi-core/worker-reproduction-b36.json")
V3_CHECKPOINT = Path("packaging/pi-core/compiled-artifact-v3.json")
V3_CHECKPOINT_SHA = "bdb3e4c1645199b3161468a7f26cde4c0314801f93119e53eb3de09134f22b17"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def plain(path):
    require(path.resolve(strict=True) == path, "linked input or ancestor: " + str(path))
    return path


def read(path, limit=16 << 20):
    require(plain(path).lstat().st_nlink == 1, "multiply linked input")
    return audit._read(path, limit)


def write(path, raw, mode=0o400):
    plain(path.parent)
    with path.open("xb") as f:
        f.write(raw)
        f.flush()
        os.fchmod(f.fileno(), mode)
        os.fsync(f.fileno())


def record(path, value):
    raw = fixed.canonical(value) + b"\n"
    write(path, raw)
    return sha(raw)


def fresh(root, name):
    base = plain(root / BASE)
    require(base.is_dir() and base.stat().st_uid == os.geteuid() and not base.stat().st_mode & 0o022,
            "unowned or writable build root")
    dest = root / name
    require(dest.parent == base, "not a fixed build-root child")
    dest.mkdir(mode=0o700)  # exclusive; never adopt an existing or partial attempt
    return dest


def gate_input(root):
    location = root / GATE
    binary, receipt = (plain(location / n) for n in ("source-gate", "build-receipt.json"))
    require(binary.lstat().st_nlink == receipt.lstat().st_nlink == 1, "linked gate input")
    plain(root / "packaging/pi-core" / gate.RESTRICTED_SOURCE)
    elf, build = gate.restricted_gate_input(root, binary, receipt, "sha256:" + fixed.GATE_RECEIPT_SHA256)
    fixed.validate_gate(build)
    require(sha(elf) == fixed.GATE_SHA256 and len(elf) == fixed.GATE_BYTES, "restricted gate ELF differs")
    return elf, build


def products(root, where):
    folder = plain(root / where)
    pins = {"entrypoint.js": fixed.BUNDLE_SHA256, "meta.json": fixed.META_SHA256,
            "receipt.json": fixed.BUNDLE_RECEIPT_SHA256}
    require({p.name for p in folder.iterdir()} == set(pins), "unexpected retained bundle files")
    for name, pin in pins.items():
        require(sha(read(folder / name)) == pin, "retained bundle product differs: " + name)
    return pins


def outcome(build, pins, first, second):
    require(first == second and first["status"] == "INSPECTED_RESTRICTED_NOT_DEPLOYED" and
            first["node_argv"] == list(fixed.NODE_ARGV) and first["gate_receipt_digest"] == build["receipt_digest"] and
            first["restricted_gate_elf_sha256"] == fixed.GATE_SHA256 and first["build_receipt_sha256"] == pins["receipt.json"] and
            all(first[k] is False for k in ("target_executed", "phase3_exit_eligible", "runtime_enforcement_observed")),
            "independent inspections differ or exceed offline scope")
    return {"schema":"aragorn/pi-core-worker-reproduction/v1", "status":"REPRODUCED_RESTRICTED_NOT_DEPLOYED",
            "original":str(ORIGINAL), "reproduction":str(COPY), "products":pins,
            "verification_sha256":sha(fixed.canonical(first) + b"\n"), "node_argv":list(fixed.NODE_ARGV),
            "gate_receipt_digest":build["receipt_digest"], "gate_elf_sha256":fixed.GATE_SHA256,
            "target_executed":False, "phase3_exit_eligible":False}


def reproduce(*, root=ROOT):
    from scripts import build_pi_core_worker_bundle as builder

    work = fresh(root, REVIEW)
    phase = "original"
    try:
        require(not os.path.lexists(root / COPY), "prior reproduction or indeterminate output exists")
        _, build = gate_input(root)
        products(root, ORIGINAL)
        first = audit.verify_restricted(root / ORIGINAL, build, fixed.NODE_ARGV, root=root)
        record(work / "original-review.json", first)
        phase = "sole-independent-emission"
        builder.build(root / COPY, root=root)
        phase = "reproduction-readback"
        second = audit.verify_restricted(root / COPY, build, fixed.NODE_ARGV, root=root)
        record(work / "reproduction-review.json", second)
        pins = products(root, ORIGINAL)
        require(not (root / COPY).samefile(root / ORIGINAL) and products(root, COPY) == pins,
                "reproduction and retained original disagree")
        require(gate_input(root)[1] == build, "gate changed during reproduction")
        require(products_pins(first) == pins, "review differs from bundle readback")
        result = outcome(build, pins, first, second)
        pin = record(work / "outcome.json", result)
        return result, pin
    except Exception as e:
        record(work / "refusal.json", {"phase":phase, "reason":str(e)[:8192], "target_executed":False})
        raise


def products_pins(report):
    return {"entrypoint.js":report["outputs"]["entrypoint.js"]["sha256"],
            "meta.json":report["outputs"]["meta.json"]["sha256"], "receipt.json":report["build_receipt_sha256"]}


def reviewed_copy(root, build):
    checkpoint = audit._json(read(root / CHECKPOINT, 4096))
    require(type(checkpoint) is dict and set(checkpoint) == {"schema", "outcome_sha256"} and
            checkpoint["schema"] == "aragorn/pi-core-worker-reproduction-checkpoint/v1", "invalid reproduction checkpoint")
    work = plain(root / REVIEW)
    raw = read(work / "outcome.json", 16384)
    require(sha(raw) == checkpoint["outcome_sha256"], "unapproved reproduction outcome")
    a, b = (read(work / (x + "-review.json"), 65536) for x in ("original", "reproduction"))
    require(a == b and (root / COPY).resolve(strict=True) != (root / ORIGINAL).resolve(strict=True),
            "missing independent reproduction evidence")
    pins = products(root, ORIGINAL)
    require(products(root, COPY) == pins, "retained reproduction changed")
    first, second = audit._json(a), audit._json(b)
    expected = outcome(build, pins, first, second)
    require(products_pins(first) == pins and sha(a) == expected["verification_sha256"] and raw == fixed.canonical(expected) + b"\n",
            "outcome does not bind both inspections")
    return sha(raw)


def predecessor(root):
    checkpoint = read(root / V3_CHECKPOINT, 32768)
    require(sha(checkpoint) == V3_CHECKPOINT_SHA, "unapproved v3 checkpoint")
    row = audit._json(checkpoint)
    raw = read(root / PREVIOUS / "build-receipt.json", 4 << 20)
    require(row["receipt_local_path"] == str(PREVIOUS / "build-receipt.json") and
            sha(raw) == row["receipt_file_sha256"] == audit.V3, "v3 build receipt differs")
    wanted = {"node/bin/node":fixed.NODE_SHA256, "pi-core/package.json":fixed.PACKAGE_SHA256}
    rows = [r for r in audit._json(raw)["deployment_inventory"] if r["path"] in wanted]
    require(len(rows) == 2 and {r["path"]:r["sha256"] for r in rows} == wanted and all(r["kind"] == "file" for r in rows),
            "v3 runtime input inventory differs")
    result = {}
    for r in rows:
        data = read(root / PREVIOUS / "deployment" / r["path"], 128 << 20)
        require(len(data) == r["bytes"] and sha(data) == wanted[r["path"]], "v3 runtime member differs")
        result[r["path"]] = data
    return result


def materialize(deployment, sources, expected):
    require(set(sources) == {r["path"] for r in expected}, "runtime file set differs")
    deployment.mkdir(mode=0o700)
    directories = {deployment}
    for row in expected:
        name = row["path"]
        dest = deployment / name
        require(not Path(name).is_absolute() and ".." not in Path(name).parts, "unsafe runtime member")
        raw = sources[name]
        require(len(raw) == row["size"] and "sha256:" + sha(raw) == row["digest"], "unapproved runtime member: " + name)
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        directories.update(d for d in dest.parents if d.is_relative_to(deployment))
        write(dest, raw, 0o555 if row["executable"] else 0o444)
    for d in sorted(directories, key=lambda p:-len(p.parts)):
        d.chmod(0o555)
    fd = os.open(plain(deployment), os.O_NOFOLLOW | os.O_DIRECTORY | os.O_RDONLY)
    try:
        manifest, actual_dirs = inventory_open_directory(fd, max_depth=4, max_files=len(expected) + len(directories) - 1, max_file_size=128<<20,
                                                        max_total_bytes=160<<20)
        require(set(actual_dirs) == {str(d.relative_to(deployment)) for d in directories if d != deployment}
                and manifest["files"] == expected, "assembled inventory differs")
        for d in directories:
            require(stat.S_IMODE(plain(d).lstat().st_mode) == 0o555, "assembled directory mode differs")
        for row in expected:
            st = plain(deployment / row["path"]).lstat()
            require(st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == (0o555 if row["executable"] else 0o444),
                    "assembled member mode or link count differs")
        return manifest
    finally:
        os.close(fd)


def assemble(*, root=ROOT):
    work = fresh(root, ASSEMBLY)
    phase = "approved-input-custody"
    try:
        elf, build = gate_input(root)
        result_pin = reviewed_copy(root, build)
        sources = predecessor(root)
        sources["observer/source-gate"] = elf
        sources["pi-core/entrypoint.js"] = read(root / ORIGINAL / "entrypoint.js")
        phase = "exclusive-four-file-assembly"
        manifest = materialize(work / "deployment", sources, fixed.expected_files())
        receipt = fixed.runtime_receipt(build)
        tree = fixed.validate_runtime(receipt, manifest, fixed.digest(receipt))
        record(work / "manifest.json", manifest)
        receipt_pin = record(work / "build-receipt.json", receipt)
        evidence = {"schema":"aragorn/pi-core-restricted-assembly/v1", "status":receipt["status"],
                    "reproduction_outcome_sha256":result_pin, "source_worker":str(ORIGINAL / "entrypoint.js"),
                    "runtime_receipt_sha256":receipt_pin, "runtime_tree_digest":tree,
                    "installed":False, "target_executed":False, "phase3_exit_eligible":False}
        record(work / "outcome.json", evidence)
        return evidence
    except Exception as e:
        record(work / "refusal.json", {"phase":phase, "reason":str(e)[:8192], "target_executed":False})
        raise
