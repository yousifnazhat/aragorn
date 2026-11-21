"""Local byte custody for an owned sensor snapshot; not a storage, health or run verdict."""
from contextlib import ExitStack
from io import BytesIO
import os
from pathlib import Path
import re
import time

from . import pi_core_mask_custody as custody
from . import pi_core_stopped_mask_view as kernel
from .cas import CAS
from .oci_worker_protocol import canonical_json
from .phase3_exit_gate_manifest import load_phase3_exit_gate_manifest_bytes
from .pi_core_state_mounts import direct_mount_inventory


BASE = Path("/run/aragorn-sensor-state-evidence")
STORE, RECEIPTS = BASE / "cas", BASE / "receipts"
SCHEMA = "aragorn/pi-core-sensor-state-local-custody/v1"
_LIMITS = {"record": 65535, "manager": 1 << 20, "sensor": 1 << 20}
_need, _digest = custody._need, custody._digest


def _name(attempt):
    _need(type(attempt) is str and re.fullmatch(r"[0-9a-f]{32}", attempt) and int(attempt, 16),
          "missing sensor capture identity")
    return "sensor-state-" + attempt + ".json"


def _record(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= _LIMITS["record"], "incomplete sensor record")
    doc = load_phase3_exit_gate_manifest_bytes(raw + b"\n")
    _need(doc.get("schema") == "aragorn/pi-core-sensor-state-record/v1", "wrong sensor custody record")
    return doc, _name(doc.get("attempt_id"))


def _members(record, manager, sensor):
    doc, name = _record(record)
    for role, buf in (("manager", manager), ("sensor", sensor)):
        _need(type(buf) is bytes and 0 < len(buf) <= _LIMITS[role] and buf.endswith(b"\n") and
              b"\0" not in buf and doc.get(role + "_mountinfo_digest") == _digest(buf),
              "sensor record does not bind both original mount streams")
    return doc, name, {"record": record, "manager": manager, "sensor": sensor}


def _fixed(store, receipt_directory):
    _need((store, receipt_directory) == (STORE, RECEIPTS), "not the fixed sensor evidence directories")


def _require_absent(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise FileExistsError("sensor capture attempt already has a receipt")


def check_sensor_destinations(*, store, receipt_directory, deadline, attempt_id):
    _fixed(store, receipt_directory)
    with custody._roots(store, receipt_directory, deadline) as (fd, guard, roots):
        CAS(store, read_only=True)
        _require_absent(fd, _name(attempt_id))
        guard()
        return roots


def sensor_evidence_mount(manager_raw, sensor_raw, storage):
    """Check captured namespace topology, not the devices used to store a later exported copy."""
    # The state mount may be wrong: preserve that negative if the *evidence* mount is safe.
    manager, sensor = map(direct_mount_inventory, (manager_raw, sensor_raw))
    p = str(BASE)
    row, run = manager.get(p), manager.get(str(BASE.parent))
    _need(row and run and (run.root, run.filesystem) == ("/", b"tmpfs") and row.parent == run.mount_id and
          row.root == "/" and row.filesystem in (b"ext4", b"xfs") and row.no_optional_fields and
          {b"rw", b"nodev", b"noexec", b"nosuid"} <= row.options and b"rw" in row.super_options,
          "private durable sensor evidence mount required")
    dev, source = row.device, row.source
    _need(not dev.startswith("0:") and dev not in (storage["device"], *storage["backing_devices"]),
          "sensor evidence medium is shared with state")
    for path, other in manager.items():
        _need(path == p or (other.device != dev and other.source != source and not path.startswith(p + "/")),
              "aliased or shadowed sensor evidence")
    _need(all(other.device != dev and other.source != source and path != p and not path.startswith(p + "/")
              for path, other in sensor.items()), "sensor can see the evidence mount")
    return row


def _replay(reader, fd, capture_digest, receipt_digest, guard):
    guard()
    record = reader.read(capture_digest, max_bytes=_LIMITS["record"])
    doc, name = _record(record)
    receipt = custody._receipt(fd, name, receipt_digest)
    expected = {"record": capture_digest, **{r: custody._pin(doc[r + "_mountinfo_digest"]) for r in ("manager", "sensor")}}
    _need(receipt == canonical_json(dict(schema=SCHEMA, members=expected)), "foreign sensor receipt")
    raw = {r: reader.read(expected[r], max_bytes=_LIMITS[r]) for r in ("manager", "sensor")}
    _members(record, **raw)
    _need(custody._receipt(fd, name, receipt_digest) == receipt, "sensor receipt changed")
    guard()
    return {"record": record, **raw}


def replay_sensor_observation(*, store, receipt_directory, capture_digest, receipt_digest):
    """Allow a read-only exported private copy; require independent pins and the external receipt."""
    custody._pin(capture_digest)
    custody._pin(receipt_digest)
    with custody._roots(store, receipt_directory, time.monotonic() + 30) as (fd, guard, _):
        return _replay(CAS(store, read_only=True), fd, capture_digest, receipt_digest, guard)


def retain_sensor_observation(*, store, receipt_directory, expected_roots, record_raw, manager_raw,
                              sensor_raw, deadline, storage, topology_guard):
    _fixed(store, receipt_directory)
    doc, name, members = _members(record_raw, manager_raw, sensor_raw)
    _need(doc.get("storage") == storage, "sensor storage binding differs")
    with custody._roots(store, receipt_directory, deadline) as (fd, path_guard, roots), ExitStack() as owners:
        _need(roots == expected_roots, "sensor evidence directories changed")
        row = sensor_evidence_mount(manager_raw, sensor_raw, storage)
        _need(all(row.device == f"{os.major(r[0])}:{os.minor(r[0])}" for r in roots),
              "sensor evidence medium differs from held roots")
        parent = custody.held._open_chain(BASE, deadline)
        owners.callback(custody.held.provision._close_all, list(reversed(parent)))
        base = parent[-1]
        def opened(stack, parent_fd, name):
            f = os.open(name, custody.held.provision._DIRECTORY, dir_fd=parent_fd)
            stack.callback(os.close, f)
            return f
        cas_dir = opened(owners, base, store.name)
        def statx(f):
            custody.held.provision._owner(f, 0o700, directory=True)
            s = kernel._stat(f, owner=True)
            _need((s["mnt_id"], s["dev"]) == (row.mount_id, row.device), "different evidence mount identity")
            return s
        held = [statx(f) for f in (base, cas_dir, fd)]
        _need([custody.files._directory_identity(os.fstat(f)) for f in (cas_dir, fd)] == list(roots),
              "different evidence directories")
        def guard():
            # Re-sample the owned roles, then compare the held and currently named objects.
            # These are sampled boundaries, not a lock against a privileged concurrent mount writer.
            topology_guard()
            path_guard()
            with ExitStack() as edge:
                named = opened(edge, parent[-2], BASE.name)
                _need(held == [statx(f) for f in (base, cas_dir, fd)] ==
                      [statx(f) for f in (named, opened(edge, named, store.name),
                                         opened(edge, named, receipt_directory.name))], "evidence path changed")
        guard()
        _require_absent(fd, name)
        reader, writer = CAS(store, read_only=True), CAS(store)
        pins = {}
        for k, raw in members.items():
            guard()
            pins[k] = writer.put_expected(BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw))
            _need(reader.read(pins[k], max_bytes=len(raw)) == raw, "sensor capture member readback differs")
        receipt = canonical_json(dict(schema=SCHEMA, members=pins))
        guard()
        pin = writer.put_expected(BytesIO(receipt), expected_digest=_digest(receipt), max_bytes=len(receipt))
        guard()
        reader.materialize(pin, receipt_directory / name, root=receipt_directory)
        os.fsync(fd)
        _need(_replay(reader, fd, pins["record"], pin, guard) == members, "sensor final readback differs")
        return pin
