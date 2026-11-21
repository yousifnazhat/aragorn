"""Local immutable retention for an independently acquired mask observation.

The operator supplies two pre-existing private directories and an initialized
CAS. A matching readback authenticates bytes, not the collector or its kernel
claims. It is not an off-host witness, a rollback fence, or permission to start.
"""
from contextlib import ExitStack, contextmanager
import hashlib
from io import BytesIO
import os
from pathlib import Path
import re
import stat
import time

from . import pi_core_service_provision as held
from . import runtime_action_broker as files
from .cas import CAS
from .oci_worker_protocol import canonical_json
from .phase3_exit_gate_manifest import load_phase3_exit_gate_manifest_bytes


_SCHEMA = "aragorn/pi-core-mask-local-custody/v1"
_SPINE_SCHEMA = "aragorn/pi-core-mask-local-custody/v2"
_LIMITS = dict(bindings=65535, manager=1 << 20, worker=1 << 20, vantage=65535, proof=65535)
_SPINE_LIMITS = dict(_LIMITS, worker_spine=65535)
_DOCS = {"bindings", "vantage", "proof", "worker_spine"}
_PIN = re.compile(r"sha256:[0-9a-f]{64}")


def _need(ok, message):
    if not ok:
        raise ValueError("mask custody: " + message)


def _pin(value):
    _need(type(value) is str and _PIN.fullmatch(value), "invalid digest")
    return value


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate(key, raw):
    _need(type(raw) is bytes and 0 < len(raw) <= _SPINE_LIMITS[key], "missing or oversized " + key)
    if key in _DOCS:
        # Reuse the strict canonical integer-only parser. The supplied blob,
        # unlike the parser envelope, has no trailing LF. Do not reserialize it.
        load_phase3_exit_gate_manifest_bytes(raw + b"\n")
    else:
        _need(raw.endswith(b"\n") and b"\x00" not in raw, "incomplete raw mountinfo")


@contextmanager
def _roots(store, receipt_directory, deadline, *, mount_ids=None):
    paths = (store, receipt_directory)
    for p in paths:
        _need(isinstance(p, Path) and p.is_absolute() and p.anchor == "/" and p != Path("/")
              and ".." not in p.parts, "explicit absolute private path required")
    _need(not any(x.is_relative_to(y) for x, y in (paths, paths[::-1])), "directories must be disjoint")
    with ExitStack() as owned:
        roots = []
        for path in paths:
            chain = held._open_chain(path, deadline)
            owned.callback(held.provision._close_all, list(reversed(chain)))
            roots.append((path, chain, [files._directory_identity(os.fstat(fd)) for fd in chain]))
        for _, chain, _ in roots:
            held.provision._owner(chain[-1], 0o700, directory=True)
        store_ids, receipt_ids = [[ident[:2] for ident in ids] for _, _, ids in roots]
        _need(store_ids[-1] not in receipt_ids and receipt_ids[-1] not in store_ids, "directory alias")

        if mount_ids is not None:
            _need(type(mount_ids) is tuple and len(mount_ids) == 2 and
                  all(type(i) is int and 0 < i < (1 << 64) for i in mount_ids), "invalid evidence mount pins")

        def guard():
            # Parent timestamps legitimately change during publication; pin all
            # named and held devices, inodes, types, ownership and modes instead.
            for path, chain, identities in roots:
                for i, fd in enumerate(chain):
                    held.provision._deadline(deadline)
                    held._ancestor(fd)
                    named = os.lstat("/") if i == 0 else os.stat(path.parts[i], dir_fd=chain[i-1],
                                                               follow_symlinks=False)
                    _need(identities[i] == files._directory_identity(os.fstat(fd)) ==
                          files._directory_identity(named), "private ancestry changed")
            if mount_ids is not None:
                for (path, chain, identities), mid in zip(roots, mount_ids, strict=True):
                    # An alias of the same directory can have identical st_dev and inode while
                    # sitting on a different mount. Re-open from /, not an old parent fd.
                    current = held._open_chain(path, deadline)
                    try:
                        _need(_mount_id(chain[-1]) == mid == _mount_id(current[-1]) and
                              identities[-1] == files._directory_identity(os.fstat(current[-1])),
                              "evidence location no longer on the measured mount")
                    finally:
                        held.provision._close_all(list(reversed(current)))
        guard()
        yield roots[1][1][-1], guard, tuple(ids[-1] for _, _, ids in roots)
        guard()


def _mount_id(fd):
    from .pi_core_stopped_mask_view import _stat
    return _stat(fd)["mnt_id"]


def _receipt_name(capture_digest):
    return "mask-" + _pin(capture_digest)[7:] + ".json"


def _receipt(fd, name, expected_pin):
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_gid == held.provision._ROOT_GID
          and stat.S_IMODE(before.st_mode) == 0o444, "not an exclusive protected receipt")
    raw = files._read_owned_bytes_at(fd, name, max_bytes=4096, expected_uid=held.provision._ROOT_UID,
                                    exact_mode=0o444, label="mask custody receipt")
    _need(files._file_identity(before) == files._file_identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
          and _digest(raw) == _pin(expected_pin), "receipt changed or differs from independent pin")
    return raw


def _replay(reader, fd, name, capture_digest, receipt_digest, guard):
    guard()
    raw = _receipt(fd, name, receipt_digest)
    doc = load_phase3_exit_gate_manifest_bytes(raw + b"\n")
    limits = _SPINE_LIMITS if doc.get("schema") == _SPINE_SCHEMA else _LIMITS
    _need(set(doc) == {"schema", "capture_digest", "members"} and doc["schema"] in (_SCHEMA, _SPINE_SCHEMA)
          and doc["capture_digest"] == capture_digest and type(doc["members"]) is dict
          and doc["members"].keys() == limits.keys(), "incomplete or mixed capture")
    output = {}
    for key, row in doc["members"].items():
        guard()
        _need(type(row) is dict and set(row) == {"sha256", "size"} and type(row["size"]) is int
              and 0 < row["size"] <= limits[key], "invalid member metadata")
        data = reader.read(_pin(row["sha256"]), max_bytes=row["size"])
        _need(len(data) == row["size"], "member length mismatch")
        _validate(key, data)
        output[key] = data
    _need(_digest(output["bindings"]) == capture_digest and _receipt(fd, name, receipt_digest) == raw,
          "capture identity or external receipt changed")
    _match_spine(output)
    guard()
    return output


def replay_mask_observation(*, store, receipt_directory, capture_digest, receipt_digest):
    """Read the exclusive receipt and its exact versioned member set; never write."""
    name = _receipt_name(capture_digest)
    _pin(receipt_digest)
    with _roots(store, receipt_directory, time.monotonic() + 30.0) as (fd, guard, _):
        return _replay(CAS(store, read_only=True), fd, name, capture_digest, receipt_digest, guard)


def check_mask_destinations(*, store, receipt_directory, deadline):
    """Read-only preflight: the caller must preserve both identities across the capture."""
    with _roots(store, receipt_directory, deadline) as (_, guard, roots):
        CAS(store, read_only=True)
        guard()
        return roots


def _match_spine(original):
    binding = load_phase3_exit_gate_manifest_bytes(original["bindings"] + b"\n")
    vantage = load_phase3_exit_gate_manifest_bytes(original["vantage"] + b"\n")
    expected = ("aragorn/pi-core-stopped-mask-binding/v3", "aragorn/pi-core-stopped-mask-view/v3")
    has = "worker_spine" in original
    for doc, schema in zip((binding, vantage), expected):
        _need((doc.get("schema") == schema) == ("worker_spine_digest" in doc) == has,
              "missing or mixed worker spine custody")
        if has:
            _need(doc["worker_spine_digest"] == _digest(original["worker_spine"]), "worker spine pin differs")


def retain_mask_observation(*, store, receipt_directory, capture_digest, worker_raw, manager_raw,
                            vantage_raw, bindings_raw, proof_raw, expected_roots, deadline,
                            worker_spine_raw=None, topology_guard=None, expected_mounts=None):
    """One no-replace receipt per capture. On error preserve evidence; do not retry."""
    name = _receipt_name(capture_digest)
    original = dict(worker=worker_raw, manager=manager_raw, vantage=vantage_raw,
                    bindings=bindings_raw, proof=proof_raw)
    spine = worker_spine_raw is not None
    _need(callable(topology_guard) and expected_mounts is not None if spine else
          topology_guard is None and expected_mounts is None, "wrong custody guard for version")
    if spine:
        original["worker_spine"] = worker_spine_raw
    for key, raw in original.items():
        _validate(key, raw)
    _need(_digest(bindings_raw) == capture_digest, "capture pin does not bind the exact supplied identities")
    _match_spine(original)
    with _roots(store, receipt_directory, deadline, **({"mount_ids": expected_mounts} if spine else {})) as (fd, path_guard, roots):
        def guard():
            path_guard()
            if spine:
                topology_guard()
        guard()
        _need(type(expected_roots) is tuple and len(expected_roots) == 2
              and all(type(row) is tuple and len(row) == 5 and all(type(v) is int for v in row) for row in expected_roots)
              and expected_roots == roots, "nominated private roots changed after preflight")
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("mask custody receipt already exists")
        reader = CAS(store, read_only=True)  # never implicitly provision a missing private store
        writer = CAS(store)
        rows = {}
        for key, raw in original.items():
            guard()
            pin = writer.put_expected(BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw))
            _need(reader.read(pin, max_bytes=len(raw)) == raw, "private member readback mismatch")
            rows[key] = {"sha256": pin, "size": len(raw)}
        guard()
        receipt_raw = canonical_json(dict(schema=_SPINE_SCHEMA if spine else _SCHEMA,
                                          capture_digest=capture_digest, members=rows))
        receipt_pin = writer.put_expected(BytesIO(receipt_raw), expected_digest=_digest(receipt_raw),
                                          max_bytes=len(receipt_raw))
        guard()
        # CAS.materialize fsyncs the private temp and atomically links it with
        # no replacement. Sync the directory again after removing the temp link.
        reader.materialize(receipt_pin, receipt_directory / name, root=receipt_directory)
        os.fsync(fd)
        _need(_replay(reader, fd, name, capture_digest, receipt_pin, guard) == original, "final readback differs")
    return receipt_pin
