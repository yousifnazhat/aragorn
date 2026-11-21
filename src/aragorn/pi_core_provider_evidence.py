"""Protected raw provider/action records with fixed sibling attempt indexes.

This is storage custody, not provider permission, capture completion or an
independent verifier. Raw content stays in the root-owned existing CAS.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
from io import BytesIO
import json
import os
import stat
import time

from . import pi_core_identity_handoff as channel
from . import pi_core_service_provision as provision
from . import pi_core_worker_identity as identity
from . import runtime_action_broker as broker
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-provider-evidence-observation/v1"
ACTION_SCHEMA = "aragorn/pi-core-action-evidence-observation/v1"
AUTHORITY = "RAW_STORAGE_ONLY_NOT_EXECUTION_OR_PHASE3"
_KINDS = frozenset({"SOURCE_HEALTH", "REQUEST", "ACTIVATION", "MEASUREMENT", "LINEAGE", "APPROVAL",
    "POLICY", "REVOCATIONS", "GLOBAL_HEALTH", "OBSERVATION", "DECISION", "SERVICE_REQUEST",
    "SERVICE_CHECK", "SERVICE_PERMIT", "SERVICE_RESULT", "PROVIDER_RESULT", "SOURCE_BOUNDARY", "FAILURE"})
_ACTION_KINDS = frozenset({"REQUEST_FRAME", "REQUEST_CONTEXT", "CHECK", "CURRENT_ATTEMPT",
    "CURRENT_SEND_SUMMARY", "ACTION_DONE", "SENSOR_DONE", "ACTION_RESULT", "CONTROL_READBACK", "FAILURE"})
_MAX_RECORD = 4 * 1024 * 1024
_MAX_RECORDS = 64
_MAX_INDEX = 64 * 1024
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_SEAL = object()
_PROVIDER_STORAGE, _ACTION_STORAGE = object(), object()


class PiProviderEvidenceError(RuntimeError):
    """Storage refused or has an uncertain retained prefix; do not retry."""


def _require(value, reason):
    if not value:
        raise PiProviderEvidenceError(reason)


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class _HeldCAS(CAS):
    """Only adapt the existing writer's directory acquisition, not its format."""

    def __init__(self, owner):
        self.owner = owner
        self.temporary = None
        self.helper_descriptors = []
        super().__init__(owner._path, read_only=False)

    def _prepare_root(self):
        self.owner._guard()
        return os.fstat(self.owner._root)

    def _prepare_internal_directories(self, *, create):
        # CAS initialization normally creates these. Here they must all have
        # been opened and pinned before constructing the writer.
        self.owner._guard()

    def _open_sha_root(self):
        self.owner._guard()
        descriptor = os.dup(self.owner._sha)
        self.helper_descriptors.append(descriptor)
        return descriptor

    def _open_digest_prefix(self, sha_fd, prefix, *, create):
        self.owner._guard()
        descriptor = super()._open_digest_prefix(sha_fd, prefix, create=create)
        self.helper_descriptors.append(descriptor)
        return descriptor

    def _create_temporary_file(self, parent_fd, prefix):
        self.owner._guard()
        descriptor, name = super()._create_temporary_file(parent_fd, prefix)
        self.temporary = name
        self.helper_descriptors.append(descriptor)
        return descriptor, name


class PiProviderEvidence:
    """Single-attempt owner, created only by the fixed holder below."""

    def __init__(self, *, _seal=None):
        _require(_seal is _SEAL, "PROVIDER_EVIDENCE_FACTORY_REQUIRED")
        self._seal, self._active, self._closed, self._failed = _seal, False, False, False
        self._fds, self._ancestry, self._parents = [], [], []
        self._index = self._root = self._sha = None
        self._prefix = b""
        self._references = []
        self._pending_reference = None
        self._uncertainty = []
        self._index_status = "NOT_CREATED"
        self._index_digest = None
        self._index_bytes = 0
        self._activation_digest = None
        self._owned_closed = False
        self._cleanup_hold = False
        self._storage, self._opened_storage = _PROVIDER_STORAGE, None

    def _own(self, descriptor):
        self._fds.append(descriptor)
        return descriptor

    def _close_one(self, descriptor):
        # Revoke ownership before attempting close. A failed close must not be
        # retried against a descriptor number which may have been reused.
        self._fds.remove(descriptor)
        try:
            os.close(descriptor)
        except BaseException:
            self._mark("CLOSE", "DESCRIPTOR_CLOSE_UNCONFIRMED", hold=True)
            raise

    def _mark(self, stage, reason, *, hold=False):
        self._failed = True
        self._cleanup_hold = self._cleanup_hold or hold
        row = {"stage": stage, "reason": reason}
        if row not in self._uncertainty:
            self._uncertainty.append(row)

    def _role(self):
        _require(type(self) is PiProviderEvidence and self._seal is _SEAL and self._active and
            not self._closed and os.getpid() == self._pid and os.geteuid() == os.getegid() == 0 and
            self._storage is self._opened_storage and
            (self._storage is _PROVIDER_STORAGE or self._storage is _ACTION_STORAGE),
            "PROVIDER_EVIDENCE_CUSTODY_REQUIRED")
        channel.validate_deadline(self._deadline)
        _require(time.monotonic_ns() < self._activation_expiry, "PROVIDER_EVIDENCE_ACTIVATION_EXPIRED")

    def _guard(self):
        self._role()
        for index, descriptor in enumerate(self._ancestry):
            provision._ancestor(descriptor)
            observed = os.lstat("/") if index == 0 else os.stat(self._control_path.parent.parts[index],
                dir_fd=self._ancestry[index - 1], follow_symlinks=False)
            _require(broker._directory_identity(os.fstat(descriptor)) == self._ancestor_ids[index] ==
                     broker._directory_identity(observed), "PROVIDER_EVIDENCE_ANCESTRY_CHANGED")
        for parent, name, descriptor, expected in self._parents:
            held, named = os.fstat(descriptor), os.stat(name, dir_fd=parent, follow_symlinks=False)
            _require(broker._directory_identity(held) == expected == broker._directory_identity(named) and
                stat.S_ISDIR(held.st_mode) and held.st_uid == held.st_gid == 0 and held.st_nlink > 0 and
                (descriptor == self._control or stat.S_IMODE(held.st_mode) == 0o700) and
                not held.st_mode & 0o7022 and not os.get_inheritable(descriptor),
                "PROVIDER_EVIDENCE_DIRECTORY_CHANGED")

    def _index_metadata(self, expected_size):
        held = os.fstat(self._index)
        named = os.stat(self._name, dir_fd=self._root, follow_symlinks=False)
        _require(broker._file_identity(held) == broker._file_identity(named) and
            (held.st_dev, held.st_ino) == self._index_identity and stat.S_ISREG(held.st_mode) and
            held.st_uid == held.st_gid == 0 and held.st_nlink == 1 and
            stat.S_IMODE(held.st_mode) == 0o400 and held.st_size == expected_size and
            not os.get_inheritable(self._index), "PROVIDER_EVIDENCE_INDEX_CHANGED")
        return broker._file_identity(held)

    def _prefix_readback(self, expected):
        self._guard()
        before = self._index_metadata(len(expected))
        _require(os.pread(self._index, len(expected) + 1, 0) == expected,
                 "PROVIDER_EVIDENCE_INDEX_PREFIX_CHANGED")
        _require(self._index_metadata(len(expected)) == before, "PROVIDER_EVIDENCE_INDEX_CHANGED")
        self._guard()

    def _append(self, line, *, header=False):
        self._prefix_readback(self._prefix)
        raw = canonical_json(line) + b"\n"
        candidate = self._prefix + raw
        _require(len(candidate) <= _MAX_INDEX, "PROVIDER_EVIDENCE_INDEX_BOUND")
        self._index_status = "UNCONFIRMED"
        try:
            provision.provision._write_all(self._index, raw, self._deadline)
            self._guard()
            os.fsync(self._index)
            if header:
                os.fsync(self._root)
            self._prefix_readback(candidate)
        except BaseException:
            self._mark("INDEX", "APPEND_OR_DURABILITY_UNCONFIRMED", hold=True)
            raise
        self._prefix = candidate
        self._index_digest, self._index_bytes = _digest(candidate), len(candidate)
        self._index_status = "DURABLE_PREFIX"

    def _open(self, config, control_fd, activation, deadline):
        channel.validate_deadline(deadline)
        _require(type(config) is broker.RuntimeActionBrokerConfig and config.expected_broker_uid == 0 and
            os.geteuid() == os.getegid() == 0, "PROVIDER_EVIDENCE_ROOT_CONFIG_REQUIRED")
        broker._validate_config(config)
        _require(type(control_fd) is int and control_fd >= 0 and not os.get_inheritable(control_fd),
                 "PROVIDER_EVIDENCE_BORROWED_CONTROL_REQUIRED")
        activation = identity.validate_activation(activation)
        _require(deadline <= activation["expires_at_monotonic_ns"] / 1_000_000_000,
                 "PROVIDER_EVIDENCE_ACTIVATION_DEADLINE")
        self._deadline, self._pid, self._control = deadline, os.getpid(), control_fd
        self._activation_expiry = activation["expires_at_monotonic_ns"]
        self._control_path = config.control_root
        self._path = config.control_root / "provider-evidence"
        self._opened_storage = self._storage
        self._name = ("action-attempt-" if self._storage is _ACTION_STORAGE else "attempt-") + activation["activation_id"] + ".jsonl"
        self._activation_digest = canonical_digest(activation)
        self._active = True
        try:
            self._ancestry = provision._open_chain(config.control_root.parent, deadline)
        except BaseException:
            self._mark("ACQUISITION", "ANCESTRY_HELPER_CLEANUP_UNCONFIRMED", hold=True)
            raise
        self._fds.extend(self._ancestry)
        self._ancestor_ids = [broker._directory_identity(os.fstat(fd)) for fd in self._ancestry]
        self._parents.append((self._ancestry[-1], config.control_root.name, control_fd,
                              broker._directory_identity(os.fstat(control_fd))))
        self._guard()
        current = control_fd
        for name in ("provider-evidence", "blobs", "sha256"):
            descriptor = self._own(os.open(name, _DIRECTORY, dir_fd=current))
            self._parents.append((current, name, descriptor, broker._directory_identity(os.fstat(descriptor))))
            if name == "provider-evidence":
                self._root = descriptor
            current = descriptor
            self._guard()
        self._sha = current
        self._cas = _HeldCAS(self)
        self._index_status = "UNCONFIRMED"
        try:
            self._index = self._own(os.open(self._name, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL |
                os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=self._root))
        except FileExistsError:
            self._index_status = "NOT_CREATED"
            raise
        os.fchmod(self._index, 0o400)
        state = os.fstat(self._index)
        self._index_identity = (state.st_dev, state.st_ino)
        self._append({"schema": ("aragorn/pi-core-action-evidence-index/v1" if self._storage is _ACTION_STORAGE
                                 else "aragorn/pi-core-provider-evidence-index/v1"),
            "authority": "DURABLE_REFERENCE_PREFIX_ONLY_NOT_COMPLETED_CAPTURE", "sequence": 0, "kind": "HEADER",
            "activation_id": activation["activation_id"], "activation_digest": self._activation_digest}, header=True)

    def _temporary_absent(self):
        _require(self._cas.temporary is not None, "PROVIDER_EVIDENCE_TEMPORARY_UNACCOUNTED")
        try:
            os.stat(self._cas.temporary, dir_fd=self._sha, follow_symlinks=False)
        except FileNotFoundError:
            return
        self._mark("CAS", "TEMPORARY_CLEANUP_UNCONFIRMED", hold=True)
        raise PiProviderEvidenceError("PROVIDER_EVIDENCE_TEMPORARY_RETAINED")

    def _durable_blob(self, digest, raw):
        prefix = leaf = None
        try:
            self._guard()
            prefix = self._own(CAS._open_digest_prefix(self._sha, digest[7:9], create=False))
            prefix_identity = broker._directory_identity(os.fstat(prefix))
            leaf = self._own(os.open(digest[9:], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=prefix))
            before = os.fstat(leaf)
            _require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                stat.S_IMODE(before.st_mode) == 0o444 and before.st_nlink == 1 and before.st_size == len(raw),
                "PROVIDER_EVIDENCE_BLOB_METADATA")
            try:
                reread = self._cas.read(digest, max_bytes=len(raw))
            except BaseException:
                self._mark("CAS_READBACK", "HELPER_HANDLES_UNCONFIRMED", hold=True)
                raise
            _require(reread == raw, "PROVIDER_EVIDENCE_RAW_READBACK")
            self._guard()
            _require(prefix_identity == broker._directory_identity(os.fstat(prefix)) ==
                broker._directory_identity(os.stat(digest[7:9], dir_fd=self._sha, follow_symlinks=False)),
                "PROVIDER_EVIDENCE_SHARD_CHANGED")
            _require(broker._file_identity(before) == broker._file_identity(os.fstat(leaf)) ==
                broker._file_identity(os.stat(digest[9:], dir_fd=prefix, follow_symlinks=False)),
                "PROVIDER_EVIDENCE_BLOB_CHANGED")
            os.fsync(leaf)
            os.fsync(prefix)
            os.fsync(self._sha)  # Includes the writer's temporary-name removal.
            self._guard()
        finally:
            failure = None
            for descriptor in (leaf, prefix):
                if descriptor is not None:
                    try:
                        self._close_one(descriptor)
                    except BaseException as exc:
                        failure = failure or exc
            if failure is not None:
                raise PiProviderEvidenceError("PROVIDER_EVIDENCE_BLOB_HANDLES_UNCONFIRMED") from failure

    def retain(self, kind, value):
        """Retain one actual JSON record, then commit its ordered reference."""
        try:
            self._guard()
            kinds = _ACTION_KINDS if self._storage is _ACTION_STORAGE else _KINDS
            _require(not self._failed and type(kind) is str and kind in kinds and type(value) is dict and
                     len(self._references) < _MAX_RECORDS, "PROVIDER_EVIDENCE_RECORD_REFUSED")
            raw = canonical_json(value)
            _require(0 < len(raw) <= _MAX_RECORD, "PROVIDER_EVIDENCE_RECORD_BOUND")
            digest = _digest(raw)
            ref = {"kind": kind, "digest": digest, "bytes": len(raw)}
            self._pending_reference = ref
            self._cas.temporary = None
            self._cas.helper_descriptors.clear()
            try:
                stored = self._cas.put_expected(BytesIO(raw), expected_digest=digest, max_bytes=len(raw))
            except BaseException:
                self._mark("CAS_WRITE", "HELPER_HANDLES_UNCONFIRMED", hold=True)
                raise
            _require(stored == digest, "PROVIDER_EVIDENCE_DIGEST_CHANGED")
            self._guard()
            self._temporary_absent()
            self._durable_blob(digest, raw)
            self._append({"schema": ("aragorn/pi-core-action-evidence-reference/v1" if self._storage is _ACTION_STORAGE
                                     else "aragorn/pi-core-provider-evidence-reference/v1"),
                "sequence": len(self._references) + 1, "previous_prefix_digest": self._index_digest, **ref})
            self._references.append(ref)
            self._pending_reference = None
            return dict(ref)
        except BaseException:
            self._mark("RETAIN", "RECORD_OR_STORAGE_UNCONFIRMED", hold=True)
            raise

    @property
    def observation(self):
        status = "CLEANUP_HOLD" if self._cleanup_hold else "REFUSED" if self._failed else "CLOSED" if self._closed else "OPEN"
        action = (self._opened_storage is _ACTION_STORAGE or
                  self._opened_storage is None and self._storage is _ACTION_STORAGE)
        return json.loads(canonical_json({"schema": ACTION_SCHEMA if action else SCHEMA, "authority": AUTHORITY,
            "status": status, "activation_digest": self._activation_digest, "references": self._references,
            "pending_reference": self._pending_reference,
            "index_digest": self._index_digest, "index_bytes": self._index_bytes,
            "index_status": self._index_status, "owned_handles_closed": self._owned_closed,
            "uncertainty": self._uncertainty, "phase3_eligible": False}))

    def _close(self):
        _require(not self._closed, "PROVIDER_EVIDENCE_CLOSE_ALREADY_ATTEMPTED")
        failure = None
        if self._active and self._index is not None and not self._failed:
            try:
                self._prefix_readback(self._prefix)
            except BaseException as exc:
                self._mark("CLOSE", "FINAL_PREFIX_UNCONFIRMED", hold=True)
                failure = exc
        self._closed, self._active = True, False
        for descriptor in list(reversed(self._fds)):
            try:
                self._close_one(descriptor)
            except BaseException as exc:
                failure = failure or exc
        self._owned_closed = failure is None and not any(row["reason"] in {
            "DESCRIPTOR_CLOSE_UNCONFIRMED", "ANCESTRY_HELPER_CLEANUP_UNCONFIRMED",
            "HELPER_HANDLES_UNCONFIRMED"} for row in self._uncertainty)
        if failure is not None or self._failed:
            raise PiProviderEvidenceError("PROVIDER_EVIDENCE_REFUSED_OR_CLEANUP_HOLD") from failure


@contextmanager
def hold_provider_evidence(config, control_fd, *, activation, deadline):
    """Borrow existing controls and retain an absent-only attempt; no retries."""
    owner = PiProviderEvidence(_seal=_SEAL)
    failure = None
    entered = False
    try:
        owner._open(config, control_fd, activation, deadline)
        entered = True
        yield owner
    except BaseException as exc:
        failure = exc
        if not entered:
            owner._mark("ACQUISITION", "PRECONDITION_OR_INDEX_REFUSED",
                        hold=owner._index_status == "UNCONFIRMED")
    try:
        owner._close()
    except BaseException as exc:
        failure = failure or exc
    if failure is not None:
        try:
            failure.pi_provider_evidence_observation = owner.observation
        except BaseException:
            pass
        raise failure


@contextmanager
def hold_action_evidence(config, control_fd, *, activation, deadline):
    """Retain only fixed action records in a fresh sibling index, without retries."""
    owner = PiProviderEvidence(_seal=_SEAL)
    owner._storage = _ACTION_STORAGE  # Fixed caller selection, never a wire/namespace argument.
    failure = None
    entered = False
    try:
        owner._open(config, control_fd, activation, deadline)
        entered = True
        yield owner
    except BaseException as exc:
        failure = exc
        if not entered:
            owner._mark("ACQUISITION", "PRECONDITION_OR_INDEX_REFUSED",
                        hold=owner._index_status == "UNCONFIRMED")
    try:
        owner._close()
    except BaseException as exc:
        failure = failure or exc
    if failure is not None:
        try:
            failure.pi_action_evidence_observation = owner.observation
        except BaseException:
            pass
        raise failure
