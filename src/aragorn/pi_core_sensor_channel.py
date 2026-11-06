"""One-shot root-read candidate custody; never a sensor attribution claim.

The sensor owns only the received duplicate of the accepted Pi stream. It must
not read, write or shutdown that duplicate: stream state is shared with root.
Both service channels remain caller-owned. No socket/listener is created here.
"""

from __future__ import annotations

import json
import math
import os
import secrets
import socket
import time
from contextlib import contextmanager
from dataclasses import dataclass

from . import pi_core_identity_handoff as transport
from . import runtime_action_broker as broker
from . import runtime_action_worker as worker
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-sensor-custody/v1"
AUTHORITY = "ROOT_READ_CANDIDATE_NOT_SENSOR_ATTRIBUTION_OR_EFFECT_AUTHORITY"
MAX_PACKET_BYTES = 64 * 1024
_BASE = {"schema", "authority", "kind", "nonce"}
_BOUND = _BASE | {"request_digest", "deadline_ns"}
_FIELDS = {"CHALLENGE": _BASE, "OFFER": _BOUND | {"request"},
           "READY": _BOUND, "DONE": _BOUND | {"broker_result_digest"}}
_SEAL = object()


class PiSensorChannelError(RuntimeError):
    """Custody is refused or uncertain; never retry an attempted transfer."""


@dataclass(frozen=True, slots=True)
class PiSensorChannel:
    connection: socket.socket
    expected_peer: tuple[int, int, int]


def _require(value, message):
    if not value:
        raise PiSensorChannelError(message)


def _copy(value):
    return json.loads(canonical_json(value))


def _packet(kind, **values):
    return {"schema": SCHEMA, "authority": AUTHORITY, "kind": kind, **values}


def _validate_packet(document):
    _require(type(document) is dict and type(document.get("kind")) is str and
             document["kind"] in _FIELDS and set(document) == _FIELDS[document["kind"]] and
             document["schema"] == SCHEMA and document["authority"] == AUTHORITY,
             "sensor custody packet fields differ")
    _require(type(document["nonce"]) is str and transport._NONCE.fullmatch(document["nonce"]) is not None,
             "sensor custody nonce differs")
    if document["kind"] != "CHALLENGE":
        worker._worker_digest(document["request_digest"], "sensor candidate request")
        _require(type(document["deadline_ns"]) is int and 0 < document["deadline_ns"] < 2**63,
                 "sensor candidate original deadline differs")
    if document["kind"] == "OFFER":
        candidate, _ = worker._worker_request(document["request"])
        _require(canonical_digest(candidate) == document["request_digest"], "sensor candidate digest differs")
    if document["kind"] == "DONE":
        worker._worker_digest(document["broker_result_digest"], "sensor broker result")
    _require(len(canonical_json(document)) <= MAX_PACKET_BYTES, "sensor custody packet exceeds bound")
    return document


def _send(connection, document, deadline, *, rights=()):
    _validate_packet(document)
    _require(len(rights) == (1 if document["kind"] == "OFFER" else 0), "sensor custody source rights differ")
    transport.send_authenticated_packet(connection, document, deadline, rights=rights, max_bytes=MAX_PACKET_BYTES)


def _receive(connection, peer, deadline, *, rights=0):
    document, descriptors = transport.receive_authenticated_packet(connection, peer, deadline,
        expected_rights=rights, max_bytes=MAX_PACKET_BYTES)
    try:
        _validate_packet(document)
        _require(rights == (1 if document["kind"] == "OFFER" else 0), "sensor custody received rights differ")
        return document, descriptors
    except BaseException:
        transport._close_installed(descriptors)
        raise


def _bound(document):
    return {name: document[name] for name in ("nonce", "request_digest", "deadline_ns")}


class SensorCandidate:
    """Scoped received FD and candidate bytes, not measured worker identity."""

    def __init__(self, seal, connection, peer, peer_fd, worker_connection, offer, deadline):
        _require(seal is _SEAL, "sensor candidate requires authenticated custody")
        self._connection, self._peer, self._peer_fd = connection, peer, peer_fd
        self._worker = worker_connection
        self._worker_peer = worker._valid_peer(broker._peer_credentials(worker_connection), "transferred Pi")
        self._offer, self._deadline = _copy(offer), deadline
        self._active, self._ready, self._finished = True, False, False

    @property
    def worker_connection(self):
        _require(self._active and self._worker is not None, "sensor worker custody ended")
        return self._worker

    @property
    def request(self):
        return _copy(self._offer["request"])

    @property
    def request_digest(self):
        return self._offer["request_digest"]

    @property
    def deadline(self):
        return self._deadline

    def guard(self):
        _require(self._active and not self._finished, "sensor candidate is no longer active")
        transport.require_peer_live(self._connection, self._peer, self._peer_fd, self.deadline)
        _require(time.monotonic_ns() < self._offer["deadline_ns"] and
                 tuple(broker._peer_credentials(self.worker_connection)) == self._worker_peer,
                 "sensor candidate peer or deadline changed")

    def ready(self):
        _require(not self._ready, "sensor READY already attempted")
        self._ready = True
        try:
            self.guard()
            _send(self._connection, _packet("READY", **_bound(self._offer)), self.deadline)
        except BaseException:
            self._active = False
            raise

    def finish(self, broker_result):
        _require(self._ready and not self._finished, "sensor completion is not available")
        self._finished = True  # Even an uncertain close/send cannot be retried.
        packet = _packet("DONE", **_bound(self._offer), broker_result_digest=canonical_digest(broker_result))
        # The finished marker disallows another attempt; explicitly check live
        # custody before closing without treating the marker as expiration.
        _require(self._active, "sensor custody was invalidated")
        transport.require_peer_live(self._connection, self._peer, self._peer_fd, self.deadline)
        _require(time.monotonic_ns() < self._offer["deadline_ns"], "sensor completion expired")
        self._close_owned()
        _send(self._connection, packet, self.deadline)

    def _close_owned(self):
        self._active = False
        connection, self._worker = self._worker, None
        descriptor, self._peer_fd = self._peer_fd, -1
        errors = []
        if connection is not None:
            try:
                connection.close()
            except OSError as exc:
                errors.append(exc)
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                errors.append(exc)
        if errors:
            raise PiSensorChannelError("sensor owned descriptor cleanup is uncertain") from errors[0]


@contextmanager
def hold_sensor_candidate(connection, *, expected_supervisor_pid, deadline):
    peer = transport._peer((expected_supervisor_pid, 0, 0))
    transport.validate_deadline(deadline)
    peer_fd = received_fd = -1
    transferred = candidate = None
    try:
        peer_fd = transport.guard_channel(connection, peer, deadline)
        nonce = secrets.token_hex(16)
        _send(connection, _packet("CHALLENGE", nonce=nonce), deadline)
        offer, descriptors = _receive(connection, peer, deadline, rights=1)
        (received_fd,) = descriptors
        _require(received_fd != peer_fd, "sensor received descriptor aliases peer handle")
        _require(offer["kind"] == "OFFER" and offer["nonce"] == nonce and
                 time.monotonic_ns() < offer["deadline_ns"] <= math.floor(deadline * 1_000_000_000),
                 "sensor candidate challenge or original deadline differs")
        transferred = socket.socket(fileno=received_fd)
        received_fd = -1  # socket object now exclusively owns this duplicate.
        _require(transferred.getsockopt(socket.SOL_SOCKET, transport._DOMAIN) == socket.AF_UNIX and
                 transferred.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM,
                 "sensor requires the actual accepted local Pi stream")
        candidate = SensorCandidate(_SEAL, connection, peer, peer_fd, transferred, offer,
                                    min(deadline, offer["deadline_ns"] / 1_000_000_000))
        peer_fd, transferred = -1, None
        candidate.guard()
        yield candidate
    finally:
        if candidate is not None:
            candidate._close_owned()
        else:
            errors = []
            if transferred is not None:
                try:
                    transferred.close()
                except OSError as exc:
                    errors.append(exc)
            try:
                transport._close_installed([fd for fd in (received_fd, peer_fd) if fd >= 0])
            except Exception as exc:
                errors.append(exc)
            if errors:
                raise PiSensorChannelError("sensor rejected custody cleanup failed") from errors[0]


class SensorTicket:
    def __init__(self, connection, peer, peer_fd, offer, deadline):
        self._connection, self._peer, self._peer_fd = connection, peer, peer_fd
        self._offer, self._deadline, self._attempted = offer, deadline, False

    def finish(self, broker_result):
        _require(not self._attempted and self._peer_fd >= 0, "sensor receipt already attempted or closed")
        self._attempted = True
        # DONE is terminal evidence, not continuing sensor authority. A dedicated
        # sensor may exit after sending it. Retain the originally authenticated
        # connection/PIDFD and exact packet credentials, but do not race that
        # expected exit by requiring a live process after its cleanup receipt.
        self._terminal_peer()
        done, _ = _receive(self._connection, self._peer, self._deadline)
        _require(done == _packet("DONE", **_bound(self._offer), broker_result_digest=canonical_digest(broker_result)),
                 "sensor cleanup/result acknowledgment differs")
        self._terminal_peer()
        self._close_owned()

    def _terminal_peer(self):
        transport.validate_deadline(self._deadline)
        _require(tuple(broker._peer_credentials(self._connection)) == self._peer,
                 "terminal sensor channel peer changed")

    def _close_owned(self):
        descriptor, self._peer_fd = self._peer_fd, -1
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def hold_pi_sensor_channel(connection, worker_connection, request, *, expected_sensor_peer, deadline):
    _require(os.geteuid() == os.getegid() == 0, "sensor publisher requires protected root")
    peer = transport._peer(expected_sensor_peer)
    _require(peer[1] > 0 and peer[2] > 0, "sensor must retain its nonroot service identity")
    transport.validate_deadline(deadline)
    _require(connection is not worker_connection and connection.fileno() != worker_connection.fileno(),
             "sensor custody and Pi request channels overlap")
    candidate, _ = worker._worker_request(request)
    peer_fd = -1
    ticket = None
    try:
        peer_fd = transport.guard_channel(connection, peer, deadline)
        challenge, _ = _receive(connection, peer, deadline)
        _require(challenge["kind"] == "CHALLENGE", "expected fresh sensor custody challenge")
        offer = _packet("OFFER", nonce=challenge["nonce"], request=_copy(candidate),
            request_digest=canonical_digest(candidate), deadline_ns=math.floor(deadline * 1_000_000_000))
        _send(connection, offer, deadline, rights=(worker_connection.fileno(),))
        ready, _ = _receive(connection, peer, deadline)
        _require(ready == _packet("READY", **_bound(offer)), "sensor candidate readiness differs")
        transport.require_peer_live(connection, peer, peer_fd, deadline)
        ticket = SensorTicket(connection, peer, peer_fd, offer, deadline)
        peer_fd = -1
        yield ticket
    finally:
        if ticket is not None:
            ticket._close_owned()
        elif peer_fd >= 0:
            os.close(peer_fd)
