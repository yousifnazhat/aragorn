"""One-shot protected OpenAI service with two fresh, short egress permits.

The caller supplies one connected root channel and retains ownership of it. No
listener, unit or credential provisioning is performed here. A terminal receipt
proves only that this invocation's owned transport and peer handles closed, not
unit exit, credential-memory erasure, deployment or Phase 3 qualification. The
root gate retains the durable one-use request claim; failures never retry it.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time

from . import pi_core_identity_handoff as channel
from . import pi_core_openai_responses as codec
from . import pi_core_provider_mediation as mediation
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-provider-service/v2"
AUTHORITY = "PROTECTED_PROVIDER_REQUEST_WITH_FRESH_EGRESS_CHECKS"
MAX_PACKET_BYTES = 64 * 1024
MAX_PERMIT_NS = 100_000_000
_BASE = {"schema", "authority", "nonce", "deadline_ns", "request_digest", "wire_digest"}
_FIELDS = {
    "REQUEST": _BASE | {"kind", "request", "route", "profile", "wire"},
    "CHECK": _BASE | {"kind", "phase", "sequence"},
    "CURRENT": _BASE | {"kind", "phase", "sequence", "permit_expires_monotonic_ns"},
    "RESULT": _BASE | {"kind", "result", "cleanup", "connect_attempted", "send_attempted"},
}
_SEAL = object()


class PiProviderServiceError(RuntimeError):
    """A finite, redacted service failure; never a retry authorization."""


def _require(value, code):
    if not value:
        raise PiProviderServiceError(code)


def _copy(value):
    return json.loads(canonical_json(value))


def validate_packet(value):
    """Validate/detach a v2 document; this alone confers no authority."""
    try:
        _require(type(value) is dict and type(value.get("kind")) is str and
                 value["kind"] in _FIELDS and set(value) == _FIELDS[value["kind"]] and
                 value["schema"] == SCHEMA and value["authority"] == AUTHORITY,
                 "PROVIDER_SERVICE_PACKET_REFUSED")
        _require(type(value["nonce"]) is str and channel._NONCE.fullmatch(value["nonce"]) is not None,
                 "PROVIDER_SERVICE_NONCE_REFUSED")
        for name in ("request_digest", "wire_digest"):
            _require(type(value[name]) is str and channel._DIGEST.fullmatch(value[name]) is not None,
                     "PROVIDER_SERVICE_DIGEST_REFUSED")
        _require(type(value["deadline_ns"]) is int and 0 < value["deadline_ns"] < 2**63,
                 "PROVIDER_SERVICE_DEADLINE_REFUSED")
        kind = value["kind"]
        if kind == "REQUEST":
            request = mediation.validate_provider_request(value["request"])
            _require(canonical_digest(request) == value["request_digest"], "PROVIDER_SERVICE_REQUEST_REFUSED")
            expected = codec.wire_descriptor(request, value["route"], value["profile"])
            _require(value["wire"] == expected and canonical_digest(expected) == value["wire_digest"],
                     "PROVIDER_SERVICE_WIRE_REFUSED")
        elif kind in ("CHECK", "CURRENT"):
            _require(type(value["sequence"]) is int and value["sequence"] in (1, 2) and
                     value["phase"] == ("CONNECT" if value["sequence"] == 1 else "SEND"),
                     "PROVIDER_SERVICE_PHASE_REFUSED")
            if kind == "CURRENT":
                _require(type(value["permit_expires_monotonic_ns"]) is int and
                         0 < value["permit_expires_monotonic_ns"] <= value["deadline_ns"],
                         "PROVIDER_SERVICE_PERMIT_REFUSED")
        else:
            result = mediation.validate_provider_result(value["result"], value["request_digest"])
            _require(value["cleanup"] == "OWNED_TRANSPORT_CLOSED" and
                     type(value["connect_attempted"]) is bool and type(value["send_attempted"]) is bool and
                     (not value["send_attempted"] or value["connect_attempted"]) and
                     (result["status"] != "COMPLETED" or
                      (value["connect_attempted"] and value["send_attempted"])) and
                     (result["status"] != "NOT_SUBMITTED" or
                      (not value["connect_attempted"] and not value["send_attempted"])),
                     "PROVIDER_SERVICE_OUTCOME_REFUSED")
        _require(len(canonical_json(value)) <= MAX_PACKET_BYTES, "PROVIDER_SERVICE_PACKET_LIMIT")
        return _copy(value)
    except (TypeError, ValueError, KeyError, RecursionError, RuntimeError):
        raise PiProviderServiceError("PROVIDER_SERVICE_PACKET_REFUSED") from None


def send_packet(connection, value, deadline):
    document = validate_packet(value)
    channel.send_authenticated_packet(connection, document, deadline, max_bytes=MAX_PACKET_BYTES)


def receive_packet(connection, expected_peer, deadline):
    document, rights = channel.receive_authenticated_packet(connection, expected_peer, deadline,
        expected_rights=0, max_bytes=MAX_PACKET_BYTES)
    try:
        _require(not rights, "PROVIDER_SERVICE_RIGHTS_REFUSED")
        return validate_packet(document), rights
    except BaseException:
        channel._close_installed(rights)
        raise


class PiProviderPermit:
    """Local one-use permit minted only after one authenticated CURRENT packet."""

    __slots__ = ("_seal", "_authority", "_phase", "_sequence", "_wire_digest", "_expires_ns", "_used")

    def __init__(self, seal, authority, phase, sequence, wire_digest, expires_ns):
        _require(seal is _SEAL, "PROVIDER_PERMIT_FACTORY_REFUSED")
        self._seal = seal
        self._authority = authority
        self._phase = phase
        self._sequence = sequence
        self._wire_digest = wire_digest
        self._expires_ns = expires_ns
        self._used = False


class PiProviderServiceAuthority:
    """Scoped root-channel authority, not constructible from a caller's JSON.

    Python service code is trusted. The private seal is an API provenance guard,
    not a sandbox against a compromised provider-service process.
    """

    __slots__ = ("_seal", "_packet", "_connection", "_peer", "_pidfd", "_deadline", "_active",
                 "_begun", "_sequence", "_used_phases", "_permit", "_lock")

    def __init__(self, seal, packet, connection, peer, pidfd, deadline):
        _require(seal is _SEAL, "PROVIDER_AUTHORITY_FACTORY_REFUSED")
        self._seal = seal
        self._packet = _copy(packet)
        self._connection, self._peer, self._pidfd = connection, peer, pidfd
        self._deadline = deadline
        self._active, self._begun, self._sequence = True, False, 0
        self._used_phases = set()
        self._permit = None
        self._lock = threading.Lock()

    @property
    def request(self):
        return _copy(self._packet["request"])

    @property
    def route(self):
        return _copy(self._packet["route"])

    @property
    def profile(self):
        return _copy(self._packet["profile"])

    @property
    def wire(self):
        return _copy(self._packet["wire"])

    @property
    def deadline(self):
        return self._deadline

    def _live(self):
        _require(type(self) is PiProviderServiceAuthority and self._seal is _SEAL and self._active,
                 "PROVIDER_AUTHORITY_INACTIVE")
        channel.require_peer_live(self._connection, self._peer, self._pidfd, self._deadline)

    def begin(self):
        with self._lock:
            _require(not self._begun, "PROVIDER_AUTHORITY_ALREADY_SPENT")
            self._begun = True  # Even a failed peer check cannot begin again.
            self._live()

    def check(self, phase, wire):
        with self._lock:
            _require(self._active and self._begun and
                     ((phase == "CONNECT" and self._sequence == 0) or
                      (phase == "SEND" and self._sequence == 1 and "CONNECT" in self._used_phases)),
                     "PROVIDER_AUTHORITY_PHASE_REFUSED")
            self._sequence += 1  # A failed roundtrip never renews or retries a phase.
            try:
                _require(wire == self.wire and canonical_digest(wire) == self._packet["wire_digest"],
                         "PROVIDER_AUTHORITY_WIRE_REFUSED")
                self._live()
                fields = {key: self._packet[key] for key in _BASE}
                check = {**fields, "kind": "CHECK", "phase": phase, "sequence": self._sequence}
                send_packet(self._connection, check, self._deadline)
                current, rights = receive_packet(self._connection, self._peer, self._deadline)
                _require(not rights and current == {**check, "kind": "CURRENT",
                    "permit_expires_monotonic_ns": current.get("permit_expires_monotonic_ns")},
                    "PROVIDER_AUTHORITY_CURRENT_REFUSED")
                self._live()
                now = time.monotonic_ns()
                expires = current["permit_expires_monotonic_ns"]
                _require(now < expires <= min(self._packet["deadline_ns"], now + MAX_PERMIT_NS),
                         "PROVIDER_AUTHORITY_PERMIT_EXPIRED")
                permit = PiProviderPermit(_SEAL, self, phase, self._sequence,
                    self._packet["wire_digest"], expires)
                self._permit = permit
                return permit
            except BaseException:
                self._active = False
                raise

    def _accept_outcome(self, outcome):
        with self._lock:
            _require(type(outcome) is dict and set(outcome) == {
                "result", "cleanup", "connect_attempted", "send_attempted"}, "PROVIDER_TRANSPORT_OUTCOME_REFUSED")
            fields = {key: self._packet[key] for key in _BASE}
            terminal = validate_packet({**fields, "kind": "RESULT", **outcome})
            _require((not terminal["connect_attempted"] or "CONNECT" in self._used_phases) and
                     (not terminal["send_attempted"] or "SEND" in self._used_phases),
                     "PROVIDER_TRANSPORT_PHASE_REFUSED")
            if terminal["result"]["status"] == "COMPLETED":
                self._live()
                _require(self._begun and self._sequence == 2 and self._used_phases == {"CONNECT", "SEND"},
                         "PROVIDER_TRANSPORT_COMPLETION_REFUSED")
            self._active = False
            return terminal

    def _withdraw(self):
        with self._lock:
            self._active = False


def validate_permit(permit, phase, wire):
    """Consume once immediately before connect/send, with NO blocking I/O.

    Peer/PIDFD checking was completed in check(). This finite same-host lease
    bounds the check/use gap; it does not claim instantaneous revocation.
    """
    _require(type(permit) is PiProviderPermit and getattr(permit, "_seal", None) is _SEAL,
             "PROVIDER_PERMIT_REFUSED")
    authority = permit._authority
    _require(type(authority) is PiProviderServiceAuthority and authority._seal is _SEAL,
             "PROVIDER_PERMIT_AUTHORITY_REFUSED")
    # Never wait behind a concurrent roundtrip at the last check/use boundary.
    _require(authority._lock.acquire(blocking=False), "PROVIDER_PERMIT_BUSY")
    try:
        _require(authority._active and authority._begun and authority._permit is permit and
                 not permit._used and phase == permit._phase and authority._sequence == permit._sequence and
                 wire == authority.wire and canonical_digest(wire) == permit._wire_digest and
                 time.monotonic_ns() < min(permit._expires_ns, authority._packet["deadline_ns"]),
                 "PROVIDER_PERMIT_EXPIRED_OR_SPENT")
        permit._used = True
        authority._used_phases.add(phase)
    finally:
        authority._lock.release()


def handle_pi_provider_service(connection, *, expected_supervisor_pid, deadline):
    """Consume one protected request and close owned handles before its receipt.

    Caller owns the connected channel and must close it after this invocation,
    including on failure. No retry, listener, service start or generic transport
    callback is provided. Unknown/cleanup failures emit no terminal success.
    """
    from . import pi_core_openai_transport as transport

    peer_fd = -1
    authority = None
    terminal = None
    failure = False
    try:
        channel.validate_deadline(deadline)
        _require(type(expected_supervisor_pid) is int and 0 < expected_supervisor_pid < 2**31,
                 "PROVIDER_SUPERVISOR_REFUSED")
        profile = transport.read_profile()
        transport._identity(profile)
        peer = (expected_supervisor_pid, 0, 0)
        peer_fd = channel.guard_channel(connection, peer, deadline)
        packet, rights = receive_packet(connection, peer, deadline)
        _require(not rights and packet["kind"] == "REQUEST" and packet["profile"] == profile and
                 packet["deadline_ns"] <= int(deadline * 1_000_000_000),
                 "PROVIDER_SERVICE_REQUEST_BINDING_REFUSED")
        # Preserve the exact integer budget: float conversion must not extend it.
        bounded = min(deadline, math.nextafter(packet["deadline_ns"] / 1_000_000_000, 0.0))
        channel.validate_deadline(bounded)
        _require(time.monotonic_ns() < packet["deadline_ns"], "PROVIDER_SERVICE_REQUEST_EXPIRED")
        channel.require_peer_live(connection, peer, peer_fd, bounded)
        authority = PiProviderServiceAuthority(_SEAL, packet, connection, peer, peer_fd, bounded)
        try:
            outcome = transport.execute_openai_request(authority, profile=profile)
        except transport.PiOpenAITransportError as exc:
            _require(exc.cleanup == "OWNED_TRANSPORT_CLOSED" and
                     exc.status in ("NOT_SUBMITTED", "INDETERMINATE"), "PROVIDER_SERVICE_CLEANUP_HOLD")
            outcome = {"result": {"schema": mediation.RESULT_SCHEMA, "authority": mediation.RESULT_AUTHORITY,
                "request_digest": packet["request_digest"], "status": exc.status, "completion": None},
                "cleanup": exc.cleanup, "connect_attempted": exc.connect_attempted,
                "send_attempted": exc.send_attempted}
        terminal = authority._accept_outcome(outcome)
        _require(time.monotonic_ns() < packet["deadline_ns"], "PROVIDER_SERVICE_RESULT_EXPIRED")
    except Exception:
        failure = True
    finally:
        if authority is not None:
            authority._withdraw()
        if peer_fd >= 0:
            descriptor, peer_fd = peer_fd, -1
            try:
                os.close(descriptor)
            except BaseException:
                failure = True
    if failure or terminal is None:
        raise PiProviderServiceError("PROVIDER_SERVICE_REFUSED_OR_CLEANUP_HOLD") from None
    try:
        # No further liveness requirement after terminal cleanup: the root still
        # checks kernel per-message credentials and every original binding.
        _require(time.monotonic_ns() < terminal["deadline_ns"], "PROVIDER_SERVICE_RESULT_EXPIRED")
        send_packet(connection, terminal, bounded)
    except Exception:
        raise PiProviderServiceError("PROVIDER_SERVICE_RESULT_UNCERTAIN") from None
    return {"schema": "aragorn/pi-core-provider-service-observation/v1",
        "authority": "OWNED_SERVICE_EXCHANGE_NOT_DEPLOYMENT_OR_PHASE3_QUALIFICATION",
        "status": terminal["result"]["status"], "request_digest": terminal["request_digest"],
        "wire_digest": terminal["wire_digest"], "receipt_digest": canonical_digest(terminal),
        "cleanup": terminal["cleanup"], "root_peer_pidfd_closed": True,
        "connect_attempted": terminal["connect_attempted"], "send_attempted": terminal["send_attempted"],
        "phase3_eligible": False}
