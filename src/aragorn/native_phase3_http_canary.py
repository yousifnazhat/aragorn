"""One fixed dummy HTTP send inside the caller's held isolated fixture.

This transport helper makes an actual send when invoked. It has no broker,
attribution, measurement or prevention authority. Unknown effects never retry.
"""

from __future__ import annotations

import socket
import sys
import time
from copy import deepcopy

from . import native_phase3_http_canary_contract as contract
from .native_phase3_http_fixture import owned_http_fixture

SCHEMA = "aragorn/native-http-canary-send/v1"
AUTHORITY = "FIXED_LAB_HTTP_TRANSPORT_OBSERVATION_ONLY"


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _send(expected_fixture, request, kind, attempt_id=None, nonce=None):
    contract.validate_fixture(expected_fixture)
    contract.require(
        type(request) is bytes and 0 < len(request) <= contract.MAX_BYTES,
        "HTTP_REQUEST_SIZE_REFUSED",
    )
    sent, received, failure, stream = 0, bytearray(), None, None
    identity, phase = None, "FIXTURE_ENTER"

    def record():
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "kind": kind,
            "attempt_id": attempt_id,
            "nonce": nonce,
            "endpoint": {"host": contract.HOST, "port": contract.PORT},
            "request_digest": contract.digest(request),
            "request_bytes": len(request),
            "sent_bytes": sent,
            "response_digest": contract.digest(bytes(received)),
            "response_bytes": len(received),
            "status": "RESPONSE_RECEIVED" if failure is None else "FAILED",
            "error_code": failure,
            "identity": deepcopy(identity),
            **{flag: False for flag in contract.FALSE_FLAGS},
        }

    try:
        with owned_http_fixture(expected_fixture) as fixture:
            identity = deepcopy(fixture.identity)
            deadline = time.monotonic() + contract.TIMEOUT_SECONDS
            try:
                phase = "FIXTURE_GUARD"
                fixture.guard()
                phase = "TRANSPORT"
                stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                stream.settimeout(_remaining(deadline))
                stream.connect((contract.HOST, contract.PORT))
                phase = "FIXTURE_GUARD"
                fixture.guard()
                phase = "TRANSPORT"
                stream.settimeout(_remaining(deadline))
                # If this syscall raises, its byte count is unknown, not zero.
                sent = None
                sent = stream.send(request)
                if sent != len(request):
                    failure = "HTTP_SHORT_WRITE_NO_RETRY"
                else:
                    phase = "FIXTURE_GUARD"
                    fixture.guard()
                    phase = "TRANSPORT"
                    stream.settimeout(_remaining(deadline))
                    stream.shutdown(socket.SHUT_WR)
                    while True:
                        phase = "FIXTURE_GUARD"
                        fixture.guard()
                        phase = "TRANSPORT"
                        stream.settimeout(_remaining(deadline))
                        chunk = stream.recv(contract.MAX_BYTES + 1 - len(received))
                        if not chunk:
                            break
                        received.extend(chunk)
                        if len(received) > contract.MAX_BYTES:
                            failure = "HTTP_RESPONSE_LIMIT_EXCEEDED"
                            break
                    if failure is None and bytes(received) != contract.RESPONSE_BYTES:
                        failure = "HTTP_RESPONSE_REFUSED"
                _remaining(deadline)
            except TimeoutError:
                failure = "HTTP_DEADLINE_EXPIRED_NO_RETRY"
            except OSError:
                failure = "HTTP_TRANSPORT_FAILED_NO_RETRY"
            except BaseException:
                failure = (
                    "HTTP_FIXTURE_GUARD_FAILED"
                    if phase == "FIXTURE_GUARD"
                    else "HTTP_OPERATION_INTERRUPTED"
                )
                raise
            finally:
                primary, cleanup_error = sys.exception(), None
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as exc:  # noqa: BLE001 - preserve primary interrupt during cleanup
                        failure = "HTTP_SOCKET_CLOSE_FAILED"
                        # Do not retry close: the descriptor may already be
                        # released, even when its close call was interrupted.
                        if not isinstance(exc, OSError):
                            cleanup_error = exc
                        if primary is not None:
                            primary.add_note("HTTP_SOCKET_CLOSE_FAILED")
                try:
                    fixture.guard()
                except BaseException as exc:  # noqa: BLE001 - retain evidence and preserve the primary exception
                    failure = "HTTP_FIXTURE_GUARD_FAILED"
                    cleanup_error = cleanup_error or exc
                    if primary is not None:
                        primary.add_note("HTTP_FIXTURE_CLEANUP_GUARD_FAILED")
                if primary is None and cleanup_error is not None:
                    raise cleanup_error
            phase = "FIXTURE_EXIT"
        return record()
    except BaseException as exc:
        if phase == "FIXTURE_EXIT":
            failure = "HTTP_FIXTURE_FINAL_GUARD_FAILED"
        elif failure is None:
            failure = "HTTP_FIXTURE_UNAVAILABLE"
        # A controller may retain only this detached classified record. Native
        # exception text and traceback are never copied into public evidence.
        exc.http_canary_observation = record()
        raise


def send_http_canary(*, expected_fixture, attempt_id):
    """Send one prepared canary; inputs cannot choose a destination or body."""
    request = contract.canary_request(attempt_id)
    return _send(expected_fixture, request, "CANARY", attempt_id=attempt_id)


def send_http_readiness(*, expected_fixture, nonce):
    """Send the distinct non-canary readiness request once."""
    request = contract.readiness_request(nonce)
    return _send(expected_fixture, request, "READINESS", nonce=nonce)
