"""Retain native action records and independently read existing broker receipts.

This root caller owns only its new read handles and raw-evidence store scope.
It never initializes/reconciles a grant, retries an effect, supplies health, or
turns a broker receipt into independent sink or timing qualification.
"""

from contextlib import contextmanager
import base64
import fcntl
import json
import os
import stat
import time

from . import pi_core_identity_handoff as channel
from . import pi_core_provider_evidence as storage
from . import pi_core_provider_observation as observation
from . import pi_core_request_handoff as handoff
from . import pi_core_request_recovery as recovery
from . import pi_core_sensor_channel as sensor
from . import pi_core_service_entry as entry
from . import pi_core_service_lifecycle as lifecycle
from . import pi_core_worker_identity as identity
from . import runtime_action_broker as broker
from . import runtime_action_broker_v4 as grants
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-native-action-evidence/v1"
AUTHORITY = "RETAINED_ACTION_RECORDS_ONLY_NOT_EFFECT_TIMING_HEALTH_OR_PHASE3"
_SEAL = object()
_KINDS = frozenset({"REQUEST_FRAME", "REQUEST_CONTEXT", "CHECK",
    "ACTION_DONE", "SENSOR_DONE", "ACTION_RESULT", "CONTROL_READBACK", "FAILURE"})


class PiNativeActionEvidenceError(RuntimeError):
    """Action evidence refused or its owned handle cleanup remains uncertain."""


def _require(value, reason):
    if not value:
        raise PiNativeActionEvidenceError(reason)


def _copy(value):
    return json.loads(canonical_json(value))


def _boottime_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _time_namespace_inode():
    return os.stat("/proc/thread-self/ns/time").st_ino


class PiNativeActionEvidence:
    """Fixed factory-owned custody; ordinary records are never authority."""

    def __init__(self, seal, custody):
        _require(seal is _SEAL, "ACTION_EVIDENCE_FACTORY_REQUIRED")
        self._seal, self._custody = seal, custody
        self._active = self._closed = self._failed = self._cleanup_hold = False
        self._control_fd = -1
        self._store = None
        self._done_digest = None
        self._context = None
        self._complete_attempted = False
        self._current_rows, self._current_nonces = [], set()
        self._check_digest = self._current_packet = self._source_capture = self._boundary = None
        self._send_phase, self._summary_attempted = "READY", False
        self._store_write_failed = False
        self._record = {"schema": SCHEMA, "authority": AUTHORITY, "status": "PREPARING",
            "activation_digest": None, "grant_digest": None, "configuration_digest": None,
            "retained_evidence": None, "readback": None, "receipt_join_verified": False,
            "owned_handles_closed": False, "cleanup_uncertainty": [],
            "capture_complete": False, "effect_verified": False, "timing_verified": False,
            "health_verified": False, "phase3_exit_eligible": False}

    @property
    def custody(self):
        return self._custody

    @property
    def observation(self):
        return _copy(self._record)

    def _mark(self, stage, reason, *, hold=False):
        self._failed = True
        self._cleanup_hold = self._cleanup_hold or hold
        row = {"stage": stage, "reason": reason}
        if row not in self._record["cleanup_uncertainty"]:
            self._record["cleanup_uncertainty"].append(row)

    def _open(self):
        # Import at the fixed factory boundary to avoid a native-caller cycle.
        from .pi_core_native_request import PiNativeRequestCustody, _provider_dispatch
        from .pi_core_native_provider import PiNativeProviderDispatch
        from .pi_core_service_channels import PiServiceChannels
        custody = self._custody
        _require(type(custody) is PiNativeRequestCustody and os.geteuid() == os.getegid() == 0,
                 "ACTION_EVIDENCE_NATIVE_ROOT_CUSTODY_REQUIRED")
        custody.guard()
        self._deadline = custody.deadline
        services = custody._channels.service_custody
        _require(type(services) is PiServiceChannels and services.request_channels is custody._channels and
                 type(services._lifecycle) is lifecycle.PiServiceLifecycle,
                 "ACTION_EVIDENCE_SERVICE_LIFETIME_REQUIRED")
        self._services, self._lifecycle = services, services._lifecycle
        _require(self._lifecycle._active and not self._lifecycle._closed and
                 self._lifecycle._channels is services, "ACTION_EVIDENCE_SERVICE_OWNER_CHANGED")
        provider = _provider_dispatch(custody._owned)
        _require(type(provider) is PiNativeProviderDispatch and provider.channels.services is services,
                 "ACTION_EVIDENCE_COMPLETED_PROVIDER_REQUIRED")
        provider.require_completed(deadline=self._deadline)
        _require(services.provider_retired and not services.requests_retired,
                 "ACTION_EVIDENCE_TERMINAL_ROLES_DIFFER")
        self._provider, self._config = provider, provider.channels.config
        _require(type(self._config) is broker.RuntimeActionBrokerConfig and self._config.expected_broker_uid == 0,
                 "ACTION_EVIDENCE_ROOT_STORE_REQUIRED")
        self._activation = identity.validate_activation(_copy(custody._activation))
        self._grant = _copy(custody._dispatch.grant)
        self._configs = _copy(self._lifecycle.configuration.configurations)
        selected = self._configs["action"]
        self._uid, self._gid = (selected["identities"]["action"][name] for name in ("uid", "gid"))
        _require(custody._channels.broker_peer[1:] == (self._uid, self._gid) and
                 selected["capability_grant"] == self._grant == provider.grant,
                 "ACTION_EVIDENCE_ACTION_GRANT_OR_OWNER_DIFFERS")
        self._record.update(activation_digest=canonical_digest(self._activation),
            grant_digest=canonical_digest(self._grant), configuration_digest=canonical_digest(self._configs))
        try:
            self._control_fd = broker._open_protected_directory(self._config.control_root, 0,
                                                               "native action evidence control")
        except BaseException:
            self._mark("STORE_ACQUISITION", "ACQUISITION_CLEANUP_UNCONFIRMED", hold=True)
            raise
        self._active = True
        self._record["status"] = "HELD"
        self._guard()

    def _guard(self):
        _require(type(self) is PiNativeActionEvidence and self._seal is _SEAL and
                 self._active and not self._closed, "ACTION_EVIDENCE_SCOPE_INACTIVE")
        channel.validate_deadline(self._deadline)
        self._custody.guard()
        _require(self._custody.deadline == self._deadline and
                 self._custody._channels.service_custody is self._services and
                 self._services._lifecycle is self._lifecycle and
                 self._provider.channels.services is self._services and
                 self._provider.channels.config is self._config and
                 self._lifecycle.configuration.configurations == self._configs and
                 self._custody._activation == self._activation and
                 self._custody._dispatch.grant == self._grant == self._provider.grant,
                 "ACTION_EVIDENCE_HELD_INPUTS_CHANGED")
        self._provider.require_completed(deadline=self._deadline)

    def retain(self, kind, value):
        self._guard()
        _require(type(kind) is str and kind in _KINDS and type(value) is dict and self._store is not None,
                 "ACTION_EVIDENCE_RECORD_REQUIRED")
        if kind == "ACTION_DONE":
            _require(self._done_digest is None, "ACTION_EVIDENCE_DONE_ALREADY_RETAINED")
        if kind == "REQUEST_CONTEXT":
            _require(self._context is None, "ACTION_EVIDENCE_CONTEXT_ALREADY_RETAINED")
        if kind == "CHECK":
            _require(not self._failed and not self._summary_attempted and self._check_digest is None
                     and self._done_digest is None and self._send_phase in ("READY", "RETURNED")
                     and len(self._current_rows) < 16,
                     "ACTION_EVIDENCE_CHECK_ALREADY_BOUND")
        if kind == "FAILURE" and self._current_rows and not self._summary_attempted:
            # Prefix evidence only: null send times are unknown; failure never reissues an attempt.
            self._summary_attempted = True
            value = {**value, "current_send_summary": self._current_summary()}
        result = self._retain_raw(kind, value)
        if kind == "CHECK":
            self._check_digest = result["digest"]
        if kind == "ACTION_DONE":
            self._done_digest = canonical_digest(value)
        if kind == "REQUEST_CONTEXT":
            self._context = _copy(value)
        if kind == "FAILURE":
            self._failed = True
        return result

    def _retain_raw(self, kind, value):
        # The store validates its own held FDs. Do not add a worker challenge in this boundary.
        _require(not self._store_write_failed, "ACTION_EVIDENCE_PRIOR_RETENTION_UNCONFIRMED")
        try:
            return self._store.retain(kind, value)
        except BaseException:
            self._store_write_failed = True
            self._mark("RETAIN", "STORAGE_RETENTION_UNCONFIRMED", hold=True)
            raise

    def prepare_current(self, check, current, guard):
        try:
            self._guard()
            context = self._context
            _require(not self._failed and not self._summary_attempted and self._store is not None and
                     self._send_phase in ("READY", "RETURNED") and type(context) is dict and
                     self._check_digest is not None, "ACTION_EVIDENCE_CURRENT_NOT_EXPECTED")
            self._send_phase = "PREPARING"
            offer, challenge = context["offer_intent"], context["challenge"]
            packet = _copy(current)
            for value in (offer, challenge, check, packet):
                handoff._validate_packet(value, terminal_ack=True)
            expected = {key: offer[key] for key in ("nonce", "activation_digest", "request_digest", "deadline_ns")}
            seq = len(self._current_rows) + 1
            _require(offer["kind"] == "OFFER" and challenge["kind"] == "CHALLENGE" and
                     challenge["nonce"] == offer["nonce"] and offer["activation"] == context["activation"] == self._activation
                     and offer["activation_digest"] == self._record["activation_digest"] and
                     offer["worker_request"] == context["request"] and offer["request_digest"] == canonical_digest(context["request"])
                     and offer["deadline_ns"] <= int(self._deadline * 1_000_000_000) and
                     seq <= 16 and canonical_digest(check) == self._check_digest and
                     check == handoff._packet("CHECK", **expected, sequence=seq, terminal_ack=True) and
                     packet == {**check, "kind": "CURRENT"}, "ACTION_EVIDENCE_CHECK_OR_CURRENT_DIFFERS")
            # This is the native caller's final, authenticated guard. Use its original returned
            # prefix instead of asking for another challenge or looking up a latest snapshot.
            capture = _copy(guard())
            boundary = observation.validate_provider_source_capture(capture, self._activation,
                                                                     boundary_boottime_ns=_boottime_ns())
            nonce = boundary["challenge"]["nonce"]
            _require(nonce not in self._current_nonces and boundary["clock"]["time_namespace_inode"] == _time_namespace_inode(),
                     "ACTION_EVIDENCE_CURRENT_CHALLENGE_OR_CLOCK_DIFFERS")
            prior = self._source_capture
            if prior is not None:
                _require(capture["events"][:len(prior["events"])] == prior["events"] and
                         len(capture["events"]) > len(prior["events"]) and
                         all(capture[k] == prior[k] for k in prior if k not in ("events", "accounting")) and
                         self._current_rows[-1]["send_returned_boottime_ns"] <= boundary["challenge"]["issued_ns"],
                         "ACTION_EVIDENCE_CURRENT_PREFIX_REPLACED")
            attempt = dict(schema="aragorn/pi-core-action-current-attempt/v2",
                           activation_digest=self._record["activation_digest"], check_digest=self._check_digest,
                           sequence=seq, current=packet, source_capture=capture, boundary=boundary)
            ref = self._retain_raw("CURRENT_ATTEMPT", attempt)
            _require(ref["kind"] == "CURRENT_ATTEMPT" and ref["digest"] == canonical_digest(attempt),
                     "ACTION_EVIDENCE_CURRENT_RETENTION_DIFFERS")
            self._current_rows.append(dict(sequence=seq, attempt_digest=ref["digest"],
                                           before_send_boottime_ns=None, send_returned_boottime_ns=None))
            self._current_nonces.add(nonce)
            self._source_capture, self._boundary, self._current_packet = capture, boundary, packet
            self._check_digest, self._send_phase = None, "PREPARED"
        except BaseException:
            self._failed = True
            raise

    def _send_guard(self, packet, phase):
        _require(type(self) is PiNativeActionEvidence and self._seal is _SEAL and self._active and
                 not self._closed and not self._failed and self._send_phase == phase and
                 type(packet) is dict and canonical_digest(packet) == canonical_digest(self._current_packet) and
                 self._boundary["clock"]["time_namespace_inode"] == _time_namespace_inode(),
                 "ACTION_EVIDENCE_CURRENT_STATE_OR_CLOCK_DIFFERS")

    def before_current_send(self, current):
        try:
            self._send_guard(current, "PREPARED")
            self._send_phase = "CHECKING"
            edge = observation.validate_provider_source_capture(self._source_capture, self._activation,
                                                                boundary_boottime_ns=_boottime_ns())
            _require(edge["challenge"] == self._boundary["challenge"] and edge["clock"] == self._boundary["clock"]
                     and edge["boundary_boottime_ns"] >= self._boundary["boundary_boottime_ns"],
                     "ACTION_EVIDENCE_RETAINED_BOUNDARY_CHANGED")
            channel.validate_deadline(self._deadline)
            _require(time.monotonic_ns() < min(current["deadline_ns"], self._activation["expires_at_monotonic_ns"]),
                     "ACTION_EVIDENCE_CURRENT_OPERATION_EXPIRED")
            # Parsing and durable writes consume the same freshness budget; never refresh on failure.
            tick = _boottime_ns()
            _require(edge["boundary_boottime_ns"] <= tick and
                     tick - self._source_capture["events"][-1]["boottime_ns"] <= 200_000_000,
                     "ACTION_EVIDENCE_CURRENT_STALE_BEFORE_SEND")
            self._current_rows[-1]["before_send_boottime_ns"] = tick
            self._send_phase = "SENDING"
        except BaseException:
            self._failed = True
            raise

    def current_send_returned(self, current):
        try:
            tick = _boottime_ns()
            self._send_guard(current, "SENDING")
            _require(tick >= self._current_rows[-1]["before_send_boottime_ns"], "ACTION_EVIDENCE_CURRENT_CLOCK_REGRESSED")
            self._current_rows[-1]["send_returned_boottime_ns"] = tick
            self._send_phase = "RETURNED"
        except BaseException:
            self._failed = True
            raise

    def _current_summary(self):
        return dict(schema="aragorn/pi-core-action-current-sends/v1", activation_digest=self._record["activation_digest"],
                    rows=_copy(self._current_rows))

    def _finish_current_sends(self):
        _require(not self._failed and not self._summary_attempted and self._check_digest is None and
                 self._send_phase == "RETURNED" and 1 <= len(self._current_rows) <= 16 and
                 all(row["send_returned_boottime_ns"] is not None for row in self._current_rows),
                 "ACTION_EVIDENCE_CURRENT_OUTCOMES_INCOMPLETE")
        self._summary_attempted = True
        self._retain_raw("CURRENT_SEND_SUMMARY", self._current_summary())

    def complete(self, *, done, sensor_done, result):
        self._guard()
        _require(not self._complete_attempted, "ACTION_EVIDENCE_COMPLETION_ALREADY_ATTEMPTED")
        self._complete_attempted = True
        if self._done_digest is None:
            self.retain("ACTION_DONE", done)
        else:
            _require(self._done_digest == canonical_digest(done), "ACTION_EVIDENCE_DONE_CHANGED")
        self.retain("SENSOR_DONE", sensor_done)
        self.retain("ACTION_RESULT", result)
        try:
            handoff._validate_packet(done, terminal_ack=True)
            sensor._validate_packet(sensor_done, terminal_ack=True)
            context = self._context
            _require(type(context) is dict and context.get("schema") == "aragorn/pi-core-action-context/v1" and
                     context.get("activation") == self._activation and context.get("grant") == self._grant,
                     "ACTION_EVIDENCE_REQUEST_CONTEXT_MISSING_OR_CHANGED")
            offer = handoff._validate_packet(context["offer_intent"], terminal_ack=True)
            _require(offer["kind"] == "OFFER" and offer["worker_request"] == context["request"] and
                     offer["activation"] == self._activation and
                     all(done[field] == offer[field] for field in (
                         "nonce", "activation_digest", "request_digest", "deadline_ns")),
                     "ACTION_EVIDENCE_TERMINAL_OFFER_DIFFERS")
            _require(handoff._result(done["envelope"], result, context["request"], self._activation,
                                    self._custody._channels.binding) == result,
                     "ACTION_EVIDENCE_REQUEST_PROJECTION_DIFFERS")
            _require(done["kind"] == sensor_done["kind"] == "DONE" and result == done["result"] and
                     result.get("status") == "COMPLETED" and
                     done["activation_digest"] == self._record["activation_digest"] and
                     sensor_done["deadline_ns"] == done["deadline_ns"] <= int(self._deadline * 1_000_000_000) and
                     sensor_done["broker_result_digest"] == canonical_digest(result["broker_result"]) and
                     done["request_digest"] == sensor_done["request_digest"] == result["request_digest"],
                     "ACTION_EVIDENCE_TERMINAL_BINDINGS_DIFFER")
            self._finish_current_sends()
            self._readback(done, result)
            self._guard()
            self._record["receipt_join_verified"] = True
            self._record["status"] = "RECEIPT_JOIN_RETAINED"
        except BaseException:
            self._failed = True
            raise

    def _readback(self, done, result):
        """Read exact original files while both terminal services await ACK."""
        control = lock = -1
        locked = False
        failure = None
        record = {"schema": "aragorn/pi-core-action-control-readback/v1", "status": "INCOMPLETE",
            "read_only": True, "grant_digest": self._record["grant_digest"], "root_identity": None,
            "lock_identity": None, "files": {}, "absence": {}, "receipt_join_verified": False,
            "owned_handles_closed": False, "cleanup_uncertainty": []}
        self._record["readback"] = record

        def uncertain(stage):
            if stage not in record["cleanup_uncertainty"]:
                record["cleanup_uncertainty"].append(stage)
            self._mark("CONTROL_READBACK", stage, hold=True)

        def reached(phase, **fields):
            self.retain("CONTROL_READBACK", {"schema": record["schema"], "phase": phase,
                "grant_digest": record["grant_digest"], **fields})

        def read(name, maximum):
            before = os.stat(name, dir_fd=control, follow_symlinks=False)
            file_identity = list(broker._file_identity(before))
            record["files"][name] = {"identity": file_identity, "digest": None}
            reached("FILE_IDENTITY", name=name, identity=file_identity)
            _require(before.st_uid == self._uid and before.st_gid == self._gid,
                     "ACTION_EVIDENCE_CONTROL_FILE_OWNER")
            try:
                raw = lifecycle._read_at(control, name, self._uid, self._deadline, maximum=maximum)
            except BaseException:
                uncertain("READER_CLEANUP_UNCONFIRMED")
                raise
            reached("FILE_BYTES", name=name, encoding="base64", bytes_base64=base64.b64encode(raw).decode("ascii"))
            _require(broker._file_identity(os.stat(name, dir_fd=control, follow_symlinks=False)) ==
                     tuple(file_identity), "ACTION_EVIDENCE_CONTROL_FILE_CHANGED")
            document = broker._parse_canonical_document(raw, "retained action " + name)
            record["files"][name]["digest"] = canonical_digest(document)
            return document

        try:
            self._guard()
            try:
                control = broker._open_protected_directory(entry.EFFECT_ROOT / "control", self._uid,
                                                           "action receipt control")
            except BaseException:
                uncertain("ACQUISITION_CLEANUP_UNCONFIRMED")
                raise
            root = os.fstat(control)
            record["root_identity"] = list(broker._directory_identity(root))
            reached("ROOT", identity=record["root_identity"])
            _require(root.st_gid == self._gid and stat.S_IMODE(root.st_mode) == 0o710,
                     "ACTION_EVIDENCE_CONTROL_ROOT_OWNER")
            lock = os.open("broker.lock", os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=control)
            metadata = os.fstat(lock)
            record["lock_identity"] = list(broker._file_identity(metadata))
            reached("LOCK_IDENTITY", identity=record["lock_identity"])
            _require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == self._uid and
                     metadata.st_gid == self._gid and stat.S_IMODE(metadata.st_mode) == 0o600 and
                     metadata.st_nlink == 1 and metadata.st_size == 0, "ACTION_EVIDENCE_CONTROL_LOCK_UNSAFE")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
            channel.validate_deadline(self._deadline)
            base = read("state.json", broker._MAX_CONTROL_BYTES)
            state = read("capability-grant-state.json", grants._MAX_STATE_BYTES)
            receipt = read("profile-receipt.json", grants._MAX_STATE_BYTES)
            _require(broker._state(base) == base and base["effect_journal"] is None,
                     "ACTION_EVIDENCE_BASE_STATE_UNRESOLVED")
            state = grants._state(state, self._record["grant_digest"])
            _require(state["status"] == "CONSUMED", "ACTION_EVIDENCE_GRANT_NOT_CONSUMED")
            for name in ("profile-pending.json", grants._archive_name("state", record["grant_digest"]),
                         grants._archive_name("profile-receipt", record["grant_digest"])):
                try:
                    observed = os.stat(name, dir_fd=control, follow_symlinks=False)
                except FileNotFoundError:
                    record["absence"][name] = True
                    reached("ABSENCE", name=name, absent=True)
                else:
                    record["absence"][name] = False
                    reached("ABSENCE", name=name, absent=False, identity=list(broker._file_identity(observed)))
                    _require(False, "ACTION_EVIDENCE_PENDING_OR_ARCHIVED_STATE")
            _require(state["result"] == recovery._result_record(state["claim"], receipt) and
                     receipt["broker_result"] == result["broker_result"] and
                     state["claim"]["profile_claim"]["request_digest"] == canonical_digest(done["envelope"]["request"]),
                     "ACTION_EVIDENCE_RECEIPT_JOIN_DIFFERS")
            self._guard()
            _require(broker._directory_identity(os.fstat(control)) == tuple(record["root_identity"]) ==
                     broker._directory_identity(os.lstat(entry.EFFECT_ROOT / "control")) and
                     broker._file_identity(os.fstat(lock)) == tuple(record["lock_identity"]) ==
                     broker._file_identity(os.stat("broker.lock", dir_fd=control, follow_symlinks=False)),
                     "ACTION_EVIDENCE_READBACK_CUSTODY_CHANGED")
            record["receipt_join_verified"] = True
            record["status"] = "JOINED"
            reached("JOINED", receipt_digest=canonical_digest(receipt), state_digest=canonical_digest(state))
        except BaseException as exc:
            failure = exc
        finally:
            if locked:
                try:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                except BaseException as exc:
                    uncertain("LOCK_RELEASE_UNCONFIRMED")
                    failure = failure or exc
            descriptors = [fd for fd in (lock, control) if fd >= 0]
            try:
                channel._close_installed(descriptors)
            except BaseException as exc:
                uncertain("DESCRIPTOR_CLOSE_UNCONFIRMED")
                failure = failure or exc
            record["owned_handles_closed"] = not record["cleanup_uncertainty"]
            if not record["owned_handles_closed"]:
                record["status"] = "CLEANUP_HOLD"
            elif failure is not None:
                record["status"] = "REFUSED"
        if failure is not None:
            raise failure

    def _snapshot_store(self, failure=None):
        try:
            value = self._store.observation if self._store is not None else getattr(
                failure, "pi_action_evidence_observation", None)
            if value is not None:
                _require(type(value) is dict and value.get("schema") == storage.ACTION_SCHEMA and
                         value.get("authority") == storage.AUTHORITY and
                         value.get("phase3_eligible") is False, "ACTION_EVIDENCE_STORE_OBSERVATION_INVALID")
                self._record["retained_evidence"] = _copy(value)
                if value.get("status") == "CLEANUP_HOLD" or value.get("owned_handles_closed") is False:
                    self._mark("STORE_CLOSE", "STORE_CLEANUP_UNCONFIRMED", hold=True)
        except BaseException:
            self._mark("STORE_OBSERVATION", "STORE_EVIDENCE_UNAVAILABLE", hold=True)


@contextmanager
def hold_native_action_evidence(custody):
    """Own new handles, keep original failure and never repair retained state."""
    owner = PiNativeActionEvidence(_SEAL, custody)
    failure = None
    try:
        owner._open()
        with storage.hold_action_evidence(owner._config, owner._control_fd,
                activation=owner._activation, deadline=owner._deadline) as store:
            owner._store = store
            try:
                yield owner
            except BaseException as exc:
                failure = exc
                owner._failed = True
                raise
    except BaseException as exc:
        failure = failure or exc
        owner._failed = True
    owner._snapshot_store(failure)
    owner._active, owner._closed = False, True
    descriptor, owner._control_fd = owner._control_fd, -1
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except BaseException as exc:
            owner._mark("STORE_CONTROL_CLOSE", "DESCRIPTOR_CLOSE_UNCONFIRMED", hold=True)
            failure = failure or exc
    owner._record["owned_handles_closed"] = not owner._cleanup_hold
    owner._record["status"] = ("CLEANUP_HOLD" if owner._cleanup_hold else
        "REFUSED" if owner._failed or not owner._record["receipt_join_verified"] else "CLOSED")
    if owner._cleanup_hold and failure is None:
        failure = PiNativeActionEvidenceError("ACTION_EVIDENCE_CLEANUP_UNCONFIRMED")
    if failure is not None:
        try:
            failure.pi_native_action_evidence_observation = owner.observation
        except BaseException:
            pass
        raise failure
