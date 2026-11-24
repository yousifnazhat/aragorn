"""Private local custody for the B109 pilot reader. No allocation, task or export."""
from contextlib import contextmanager
from io import BytesIO
import os
import re
import time

from . import pi_core_mask_custody as custody
from . import pi_core_pilot_output_observer as observer
from .cas import CAS
from .oci_worker_protocol import canonical_json
from .phase3_exit_gate_manifest import load_phase3_exit_gate_manifest_bytes


# The B109 candidate is ancestry, not an assertion that a changed caller is installed.
B109_PAYLOAD_DIGEST = "sha256:f84e61381e72d7630964e07d5b4a6ee97006e7642a1666eaba4fbce7e1563232"
B109_HOST_PROFILE_DIGEST = "sha256:0295b487798b7c3cb329f885448dd6bb21a15f3132fcfd62ba113261d6dc4b8e"
_CLAIM = "aragorn/pi-core-pilot-output-private-claim/v1"
_START = "aragorn/pi-core-pilot-output-private-publication/v1"
_DONE = "aragorn/pi-core-pilot-output-private-receipt/v1"


def _need(value, reason):
    if not value:
        raise ValueError("PILOT_OUTPUT_CUSTODY_" + reason)


def _id(value):
    _need(type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value), "IDENTITY")
    return value


def _context(attempt, path, deployment, plan, release):
    _need(custody._pin(release) != custody._pin(plan), "SEPARATE_RELEASE")
    return dict(attempt_id=_id(attempt), expected_path_digest=custody._pin(path),
                deployment_digest=custody._pin(deployment), plan_digest=plan, release_digest=release,
                base_payload_digest=B109_PAYLOAD_DIGEST, base_host_profile_digest=B109_HOST_PROFILE_DIGEST)


def _names(attempt):
    return tuple("pilot-output-" + _id(attempt) + "-" + s + ".json" for s in ("claim", "publishing", "receipt"))


def _absent(fd, names):
    for name in names:
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise FileExistsError("pilot output attempt slot already exists")


def _root_ids(roots):
    _need(type(roots) is tuple and len(roots) == 2 and all(
        type(row) is tuple and len(row) == 5 and all(type(v) is int and v >= 0 for v in row)
        for row in roots), "ROOT_NOMINATION")
    return [list(row) for row in roots]


def _mount(value):
    _need(value is None or type(value) is int and 0 < value < 2**64, "MOUNT")
    return value


@contextmanager
def _location(store, receipts, deadline, mount_id, topology_guard):
    _mount(mount_id)
    _need(topology_guard is None if mount_id is None else callable(topology_guard), "TOPOLOGY_GUARD")
    if topology_guard is not None:
        topology_guard()
    with custody._roots(store, receipts, deadline, mount_ids=None if mount_id is None else
                        (mount_id, mount_id)) as (fd, path_guard, roots):
        def guard():
            path_guard()
            if topology_guard is not None:
                topology_guard()
        guard()
        yield fd, guard, roots
        guard()


def _document(raw):
    try:
        return load_phase3_exit_gate_manifest_bytes(raw + b"\n")
    except (ValueError, RecursionError) as exc:
        raise ValueError("PILOT_OUTPUT_CUSTODY_DOCUMENT") from exc


def _validate_raw(raw, activation, path):
    _need(type(raw) is bytes and 0 < len(raw) <= 2048, "OBSERVATION_BOUND")
    doc = _document(raw)
    _need(set(doc) == {"schema", "activation_id", "path_descriptor", "before", "after", "file_device",
                       "file_inode", "payload_bytes", "payload_digest", "payload_hex"} and
          doc["schema"] == "aragorn/pi-core-pilot-output-observation/v1" and
          doc["activation_id"] == _id(activation) and (doc["before"], doc["after"]) == ("ABSENT", "PRESENT"),
          "OBSERVATION")
    d = observer.validate_descriptor(doc["path_descriptor"])
    _need(custody._digest(canonical_json(d)) == path and type(doc["file_device"]) is int and
          doc["file_device"] == d["root_device"] and type(doc["file_inode"]) is int and
          0 < doc["file_inode"] < 2**63 and doc["file_inode"] != d["root_inode"], "PATH_IDENTITY")
    _need(type(doc["payload_bytes"]) is int and doc["payload_bytes"] == observer._BYTES and
          doc["payload_digest"] == observer._ORACLE and type(doc["payload_hex"]) is str and
          re.fullmatch(r"[0-9a-f]{22}", doc["payload_hex"]) and
          custody._digest(bytes.fromhex(doc["payload_hex"])) == observer._ORACLE, "OUTPUT_BYTES")
    return d


def _store(writer, reader, raw, guard):
    guard()
    pin = writer.put_expected(BytesIO(raw), expected_digest=custody._digest(raw), max_bytes=len(raw))
    _need(reader.read(pin, max_bytes=len(raw)) == raw, "OBJECT_READBACK")
    guard()
    return pin


def _mark(writer, reader, fd, directory, name, raw, guard):
    pin = _store(writer, reader, raw, guard)
    reader.materialize(pin, directory / name, root=directory)
    os.fsync(fd)
    _need(custody._receipt(fd, name, pin) == raw, "MARKER_READBACK")
    guard()
    return pin


def preflight(*, store, receipt_directory, expected_roots, attempt_id, deadline, expected_path_digest,
              deployment_digest, plan_digest, release_digest, mount_id=None, topology_guard=None):
    """Spend an independently nominated attempt before launch. Never adopt or erase a claim."""
    ctx = _context(attempt_id, expected_path_digest, deployment_digest, plan_digest, release_digest)
    names = _names(attempt_id)
    raw = canonical_json(dict(schema=_CLAIM, context=ctx, roots=_root_ids(expected_roots), mount_id=_mount(mount_id)))
    with _location(store, receipt_directory, deadline, mount_id, topology_guard) as (fd, guard, roots):
        _need(roots == expected_roots, "ROOTS_CHANGED")
        _absent(fd, names)
        reader = CAS(store, read_only=True)  # Never initialize or select an evidence destination.
        return _mark(CAS(store), reader, fd, receipt_directory, names[0], raw, guard)


def _markers(ctx, claim_pin, activation, observation_pin, size):
    publishing = canonical_json(dict(schema=_START, claim_digest=claim_pin, activation_id=_id(activation),
                                     observation_digest=custody._pin(observation_pin), observation_bytes=size))
    complete = canonical_json(dict(schema=_DONE, context=ctx, claim_digest=claim_pin,
                                   publication_digest=custody._digest(publishing), activation_id=activation,
                                   observation_digest=observation_pin, observation_bytes=size))
    return publishing, complete


def retain(*, store, receipt_directory, expected_roots, attempt_id, expected_activation_id,
           expected_path_digest, deployment_digest, plan_digest, release_digest, observation_raw, deadline,
           mount_id=None, topology_guard=None):
    """Publish only the original canonical observation, once, under the already spent claim."""
    ctx = _context(attempt_id, expected_path_digest, deployment_digest, plan_digest, release_digest)
    d = _validate_raw(observation_raw, expected_activation_id, expected_path_digest)
    names = _names(attempt_id)
    claim = canonical_json(dict(schema=_CLAIM, context=ctx, roots=_root_ids(expected_roots), mount_id=_mount(mount_id)))
    claim_pin, obs_pin = map(custody._digest, (claim, observation_raw))
    publish, done = _markers(ctx, claim_pin, expected_activation_id, obs_pin, len(observation_raw))
    with _location(store, receipt_directory, deadline, mount_id, topology_guard) as (fd, guard, roots):
        _need(roots == expected_roots and all(row[:2] != (d["root_device"], d["root_inode"]) for row in roots),
              "ROOTS_CHANGED_OR_ALIAS")
        _need(custody._receipt(fd, names[0], claim_pin) == claim, "CLAIM")
        _absent(fd, names[1:])
        reader, writer = CAS(store, read_only=True), CAS(store)
        _mark(writer, reader, fd, receipt_directory, names[1], publish, guard)
        _need(_store(writer, reader, observation_raw, guard) == obs_pin, "OBSERVATION_READBACK")
        receipt_pin = _mark(writer, reader, fd, receipt_directory, names[2], done, guard)
    return dict(observation_digest=obs_pin, receipt_digest=receipt_pin)


def read_retained(*, store, receipt_directory, attempt_id, expected_activation_id, expected_path_digest,
                  deployment_digest, plan_digest, release_digest, observation_digest, receipt_digest):
    """Verify the external claim, publication and receipt, and return the exact private CAS bytes."""
    ctx = _context(attempt_id, expected_path_digest, deployment_digest, plan_digest, release_digest)
    names = _names(attempt_id)
    with custody._roots(store, receipt_directory, time.monotonic() + 30) as (fd, guard, _):
        receipt = custody._receipt(fd, names[2], custody._pin(receipt_digest))
        claim_pin = custody._pin(_document(receipt).get("claim_digest"))
        claim = _document(custody._receipt(fd, names[0], claim_pin))
        _need(set(claim) == {"schema", "context", "roots", "mount_id"} and claim["schema"] == _CLAIM and
              claim["context"] == ctx and type(claim["roots"]) is list and all(type(row) is list
              for row in claim["roots"]), "CLAIM")
        _root_ids(tuple(tuple(row) for row in claim["roots"]))
        _mount(claim["mount_id"])  # original evidence mount, not necessarily the replay archive's mount
        reader = CAS(store, read_only=True)
        raw = reader.read(custody._pin(observation_digest), max_bytes=2048)
        _validate_raw(raw, expected_activation_id, expected_path_digest)
        publish, done = _markers(ctx, claim_pin, expected_activation_id, observation_digest, len(raw))
        _need(custody._receipt(fd, names[1], custody._digest(publish)) == publish and
              receipt == done == custody._receipt(fd, names[2], receipt_digest), "RECEIPT")
        guard()
        return raw
