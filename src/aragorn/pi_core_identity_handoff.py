"""One-shot protected Pi identity registration over an authenticated local channel.

No packet authorizes a request, provider call, capability, or effect. Callers
own the preconnected channel and source worker PIDFD; neither is closed here.
Each channel is single-use and its caller must close it after this invocation,
especially after uncertainty. There are no reconnects, resends or fallback paths.
"""

from __future__ import annotations

import array
import math
import os
import re
import socket
import struct
import time
from contextlib import contextmanager
from pathlib import Path

from . import pi_core_worker_identity as identity
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import _parse_canonical_document, _peer_credentials

SCHEMA = "aragorn/pi-core-identity-handoff/v1"
AUTHORITY = "PROTECTED_IDENTITY_REGISTRATION_ONLY_NOT_REQUEST_OR_EFFECT_AUTHORITY"
MAX_PACKET_BYTES = 12 * 1024  # Existing activation is bounded to 8 KiB.
_CLOEXEC = getattr(socket, "MSG_CMSG_CLOEXEC", 0x40000000)
_NOSIGNAL = getattr(socket, "MSG_NOSIGNAL", 0x4000)
_DOMAIN = getattr(socket, "SO_DOMAIN", 39)
_PASSCRED = getattr(socket, "SO_PASSCRED", 16)
_CREDENTIALS = getattr(socket, "SCM_CREDENTIALS", 2)
_PIDFD = getattr(socket, "SCM_PIDFD", 4)
_CRED = struct.Struct("=iII")
_NONCE = re.compile(r"[a-f0-9]{32}\Z")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
_BASE = {"schema", "authority", "kind"}
_FIELDS = {
    "CHALLENGE": _BASE | {"nonce"},
    "HANDOFF": _BASE | {"nonce", "activation", "activation_digest", "deadline_ns"},
    **{kind: _BASE | {"nonce", "activation_digest", "deadline_ns"}
       for kind in ("REGISTERED", "REVOKE", "REVOKED")},
}


class PiIdentityHandoffError(RuntimeError):
    """Identity registration failed; any uncertainty is not effect authority."""


def _require(condition, reason):
    if not condition:
        raise PiIdentityHandoffError(reason)


def validate_deadline(deadline):
    now = time.monotonic()
    _require(type(deadline) in (int, float) and math.isfinite(deadline) and
             now < deadline <= now + 30, "identity handoff original deadline is invalid or expired")


def _timeout(connection, deadline):
    validate_deadline(deadline)
    connection.settimeout(deadline - time.monotonic())


def _peer(value):
    _require(type(value) is tuple and len(value) == 3 and
             all(type(item) is int for item in value) and
             0 < value[0] <= 0x7fffffff and all(0 <= item <= 0xffffffff for item in value[1:]),
             "invalid exact identity-channel peer")
    return value


def require_peer_live(connection, expected_peer, peer_pidfd, deadline):
    validate_deadline(deadline)
    _require(tuple(_peer_credentials(connection)) == _peer(expected_peer), "identity-channel peer changed")
    process.require_live_pidfd(peer_pidfd)


def guard_channel(connection, expected_peer, deadline):
    """Authenticate an already-connected Unix packet socket; return NEW peer PIDFD.

    Caller owns that returned PIDFD. SO_PASSCRED and socket timeouts are updated;
    the caller-owned connection is never closed or replaced.
    """
    validate_deadline(deadline)
    _peer(expected_peer)
    _require(connection.getsockopt(socket.SOL_SOCKET, _DOMAIN) == socket.AF_UNIX and
             connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET,
             "identity handoff requires connected AF_UNIX/SOCK_SEQPACKET")
    _require(tuple(_peer_credentials(connection)) == expected_peer, "identity-channel peer is not authorized")
    connection.setsockopt(socket.SOL_SOCKET, _PASSCRED, 1)
    _require(connection.getsockopt(socket.SOL_SOCKET, _PASSCRED) == 1, "per-message credential checking unavailable")
    descriptor = process.open_peer_pidfd(connection, expected_peer[0])
    try:
        require_peer_live(connection, expected_peer, descriptor, deadline)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_worker_pidfd(descriptor, expected_pid):
    """Check only this process's received/source FD; never cross-UID /proc."""
    _require(type(descriptor) is int and descriptor >= 0 and type(expected_pid) is int and expected_pid > 0,
             "worker PIDFD association is invalid")
    _require(not os.get_inheritable(descriptor), "worker PIDFD must be close-on-exec")
    _require(os.readlink(f"/proc/self/fd/{descriptor}") == "anon_inode:[pidfd]", "worker handle is not a PIDFD")
    raw = process._read_virtual_file(Path(f"/proc/self/fdinfo/{descriptor}"), 16384)
    try:
        pids = [line.partition(":")[2].strip() for line in raw.decode("ascii").splitlines() if line.startswith("Pid:")]
    except UnicodeError as exc:
        raise PiIdentityHandoffError("worker PIDFD fdinfo is malformed") from exc
    _require(pids == [str(expected_pid)], "worker PIDFD does not identify the protected worker")
    process.require_live_pidfd(descriptor)


def _packet(document):
    _require(type(document) is dict and document.get("kind") in _FIELDS and
             set(document) == _FIELDS[document["kind"]] and document["schema"] == SCHEMA and
             document["authority"] == AUTHORITY, "identity packet fields or authority differ")
    _require(type(document["nonce"]) is str and _NONCE.fullmatch(document["nonce"]) is not None,
             "identity packet nonce is invalid")
    if document["kind"] != "CHALLENGE":
        _require(type(document["activation_digest"]) is str and
                 _DIGEST.fullmatch(document["activation_digest"]) is not None,
                 "identity packet activation digest is invalid")
        _require(type(document["deadline_ns"]) is int and 0 < document["deadline_ns"] < 2**63,
                 "identity packet original deadline is invalid")
    if document["kind"] == "HANDOFF":
        activation = identity.validate_activation(document["activation"])
        _require(canonical_digest(activation) == document["activation_digest"] and
                 document["deadline_ns"] <= activation["expires_at_monotonic_ns"],
                 "identity packet activation binding or expiry differs")
    raw = canonical_json(document)
    _require(len(raw) <= MAX_PACKET_BYTES, "identity packet exceeds byte bound")
    return raw


def send_packet(connection, document, deadline, *, rights=()):
    """One atomic send attempt. Caller retains ownership of all source rights."""
    _packet(document)
    _require(type(rights) is tuple and all(type(fd) is int and fd >= 0 for fd in rights) and
             len(rights) == (1 if document["kind"] == "HANDOFF" else 0),
             "identity packet has an invalid source-rights count")
    send_authenticated_packet(connection, document, deadline, rights=rights, max_bytes=MAX_PACKET_BYTES)


def send_authenticated_packet(connection, document, deadline, *, rights=(), max_bytes):
    """Bounded raw transport, not an identity/request authority validator."""
    _require(type(max_bytes) is int and 0 < max_bytes <= 64 * 1024, "invalid packet byte bound")
    raw = canonical_json(document)
    _require(type(document) is dict and 0 < len(raw) <= max_bytes and type(rights) is tuple and
             len(rights) <= 1 and all(type(fd) is int and fd >= 0 for fd in rights),
             "invalid authenticated packet or source rights")
    controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", rights).tobytes())] if rights else []
    _timeout(connection, deadline)
    sent = connection.sendmsg([raw], controls, _NOSIGNAL)
    _require(type(sent) is int and sent == len(raw), "identity packet send was short or uncertain; no retry")


def _close_installed(descriptors):
    failures = []
    for descriptor in dict.fromkeys(descriptors):
        try:
            os.close(descriptor)
        except OSError as exc:
            failures.append(exc)
    if failures:
        raise PiIdentityHandoffError("rejected identity packet descriptor cleanup failed") from failures[0]


def receive_packet(connection, expected_peer, deadline, *, expected_rights=0):
    document, installed = receive_authenticated_packet(connection, expected_peer, deadline,
        expected_rights=expected_rights, max_bytes=MAX_PACKET_BYTES)
    try:
        _packet(document)
        _require(expected_rights == (1 if document["kind"] == "HANDOFF" else 0), "identity packet kind/rights differ")
        return document, installed
    except BaseException:
        _close_installed(installed)
        raise


def receive_authenticated_packet(connection, expected_peer, deadline, *, expected_rights=0, max_bytes):
    """Adopt every installed FD before parsing; return owned rights only on success."""
    _peer(expected_peer)
    _require(type(max_bytes) is int and 0 < max_bytes <= 64 * 1024, "invalid packet byte bound")
    _require(type(expected_rights) is int and expected_rights in (0, 1), "invalid expected rights count")
    _timeout(connection, deadline)
    raw, controls, flags, _address = connection.recvmsg(max_bytes + 1,
        socket.CMSG_SPACE(_CRED.size) + socket.CMSG_SPACE(16 * struct.calcsize("=i")), _CLOEXEC)
    installed = []
    credential_items = []
    rights_items = 0
    invalid = False
    # recvmsg has already installed these handles. Own complete descriptor
    # integers even when their cmsg is malformed or unexpectedly SCM_PIDFD.
    for item in controls:
        if not isinstance(item, tuple) or len(item) != 3 or type(item[2]) is not bytes:
            invalid = True
            continue
        level, kind, data = item
        if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, _PIDFD):
            rights_items += 1
            for offset in range(0, len(data) - len(data) % 4, 4):
                descriptor = struct.unpack("=i", data[offset:offset + 4])[0]
                if descriptor >= 0:
                    installed.append(descriptor)
                else:
                    invalid = True
            invalid |= kind != socket.SCM_RIGHTS or len(data) % 4 != 0
        elif level == socket.SOL_SOCKET and kind == _CREDENTIALS:
            credential_items.append(data)
        else:
            invalid = True
    try:
        allowed_flags = getattr(socket, "MSG_EOR", 128) | _CLOEXEC
        _require(not invalid and not flags & ~allowed_flags and type(raw) is bytes and
                 0 < len(raw) <= max_bytes, "identity packet controls, flags, or size differ")
        _require(credential_items == [_CRED.pack(*expected_peer)], "identity packet sender credentials differ")
        _require(len(installed) == expected_rights and len(set(installed)) == len(installed) and
                 rights_items == (1 if expected_rights else 0), "identity packet installed-rights count differs")
        _require(all(not os.get_inheritable(fd) for fd in installed), "received identity handles lack CLOEXEC")
        document = _parse_canonical_document(raw, "Pi identity handoff")
        return document, tuple(installed)
    except BaseException:
        _close_installed(installed)
        raise


@contextmanager
def hold_pi_identity_handoff(connection, activation, worker_pidfd, *, expected_relay_peer, deadline, guard):
    """Register identity once, then revoke before the worker is released.

    Failure before yield may leave a received registration unconfirmed. Do not
    retry; caller must close its channel after the single invocation. Consumer
    expiry/worker death is mandatory and never promoted to an observed ACK here.
    """
    _require(os.geteuid() == os.getegid() == 0, "identity publisher must be protected root")
    validate_deadline(deadline)
    _peer(expected_relay_peer)
    _require(expected_relay_peer[1] > 0 and expected_relay_peer[2] > 0 and callable(guard),
             "identity publisher requires exact nonroot relay and protected guard")
    activation = identity.validate_activation(activation)
    _require(expected_relay_peer[0] != activation["pid"] and
             expected_relay_peer[1] != activation["uid"] and
             expected_relay_peer[2] != activation["gid"], "identity relay and Pi worker roles overlap")
    deadline = min(deadline, activation["expires_at_monotonic_ns"] / 1_000_000_000)
    validate_deadline(deadline)
    deadline_ns = min(int(deadline * 1_000_000_000), activation["expires_at_monotonic_ns"])
    state = {"schema": "aragorn/pi-core-identity-publication/v1", "authority": AUTHORITY,
             "status": "NOT_REGISTERED", "activation_digest": canonical_digest(activation),
             "deadline_ns": deadline_ns, "nonce": None}
    peer_pidfd = -1
    offer_attempted = False

    def checked():
        identity._remaining(deadline, activation)  # Root verifies real current boot identity.
        guard()
        validate_worker_pidfd(worker_pidfd, activation["pid"])
        if peer_pidfd >= 0:
            require_peer_live(connection, expected_relay_peer, peer_pidfd, deadline)

    def control(kind):
        return {"schema": SCHEMA, "authority": AUTHORITY, "kind": kind,
                "nonce": state["nonce"], "activation_digest": state["activation_digest"],
                "deadline_ns": deadline_ns}

    try:
        checked()
        peer_pidfd = guard_channel(connection, expected_relay_peer, deadline)
        checked()
        challenge, _ = receive_packet(connection, expected_relay_peer, deadline)
        _require(challenge["kind"] == "CHALLENGE", "expected fresh relay challenge")
        state["nonce"] = challenge["nonce"]
        checked()
        offer_attempted = True
        send_packet(connection, {**control("HANDOFF"), "activation": activation}, deadline, rights=(worker_pidfd,))
        checked()
        reply, _ = receive_packet(connection, expected_relay_peer, deadline)
        _require(reply == control("REGISTERED"), "relay registration acknowledgment differs")
        checked()
        state["status"] = "REGISTERED"
        try:
            yield state
        finally:
            # Enter this section once only; an uncertain REVOKE is never retried.
            state["status"] = "REVOKE_ATTEMPTED"
            checked()
            send_packet(connection, control("REVOKE"), deadline)
            reply, _ = receive_packet(connection, expected_relay_peer, deadline)
            _require(reply == control("REVOKED"), "relay revocation acknowledgment differs")
            checked()
            state["status"] = "REVOKED"
    except BaseException as exc:
        if state["status"] != "REVOKED":
            state["status"] = "HOLD_UNCONFIRMED" if offer_attempted else "REFUSED"
        error = PiIdentityHandoffError("protected Pi identity registration/revocation failed")
        error.publication = dict(state)
        raise error from exc
    finally:
        if peer_pidfd >= 0:
            try:
                os.close(peer_pidfd)
            except OSError as exc:
                state["status"] = "HOLD_UNCONFIRMED"
                error = PiIdentityHandoffError("identity peer PIDFD cleanup failed")
                error.publication = dict(state)
                raise error from exc
