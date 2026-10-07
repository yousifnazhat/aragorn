"""Held, bounded raw TCP ingress observer for the fixed Phase 3 HTTP lab.

Run in a different owned-fixture process from the action client. The controller
coordinates readiness and action launch after the listener is open. This module
does not launch a client, activate a runtime, or infer a prevention decision.
"""

from __future__ import annotations

import socket
import sys
import time
from contextlib import contextmanager
from copy import deepcopy

from . import native_phase3_http_canary_contract as contract
from .native_phase3_http_fixture import owned_http_fixture


def _now():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _timeout(deadline):
    remaining = deadline - _now()
    if remaining <= 0:
        raise TimeoutError
    return remaining / 1_000_000_000


class _Sink:
    def __init__(self, held, listener, attempt_id, nonce):
        self._held, self._listener = held, listener
        self._ready_called = self._attempt_called = self._closed = False
        self._record = {
            "schema": contract.SINK_SCHEMA,
            "authority": contract.SINK_AUTHORITY,
            "identity": deepcopy(held.identity),
            "attempt_id": attempt_id,
            "readiness_nonce": nonce,
            "endpoint": {"host": contract.HOST, "port": contract.PORT},
            "readiness": None,
            "interval": {
                "clock_id": "CLOCK_BOOTTIME",
                "readiness_started_ns": None,
                "started_ns": None,
                "finished_ns": None,
            },
            "connections": [],
            "listener_closed": False,
            "complete": False,
            "errors": [],
            "limitations": list(contract.LIMITATIONS),
            **dict.fromkeys(contract.FALSE_FLAGS, False),
        }

    def result(self):
        contract.require(self._closed, "HTTP_OBSERVER_STILL_OPEN")
        return deepcopy(self._record)

    def _connection(self, deadline, *, readiness=False):
        self._held.guard()
        self._listener.settimeout(_timeout(deadline))
        connection, peer = self._listener.accept()
        row = {
            "peer_host": None,
            "peer_port": None,
            "accepted_boottime_ns": None,
            "completed_boottime_ns": None,
            "raw_hex": "",
            "eof": False,
            "truncated": False,
            "response_bytes": 0,
            "error_code": None,
        }
        # Publish the mutable partial record before a clock or guard can fail.
        if readiness:
            self._record["readiness"] = row
        else:
            self._record["connections"].append(row)
        raw = b""
        try:
            row["peer_host"], row["peer_port"] = peer
            row["accepted_boottime_ns"] = _now()
            contract.require(peer[0] == contract.HOST, "HTTP_PEER_OUTSIDE_LOOPBACK")
            while True:
                self._held.guard()
                connection.settimeout(_timeout(deadline))
                chunk = connection.recv(contract.MAX_BYTES + 1 - len(raw))
                if not chunk:
                    row["eof"] = True
                    break
                raw += chunk
                if len(raw) > contract.MAX_BYTES:
                    row["truncated"] = True
                    row["error_code"] = "INPUT_LIMIT"
                    break
            # Malformed and refused requests still retain their actual bytes.
            if row["eof"] and raw in (
                contract.readiness_request(self._record["readiness_nonce"]),
                contract.canary_request(self._record["attempt_id"]),
            ):
                self._held.guard()
                connection.settimeout(_timeout(deadline))
                try:
                    # A raised send may have written bytes; zero would be false.
                    row["response_bytes"] = None
                    row["response_bytes"] = connection.send(contract.RESPONSE_BYTES)
                    if row["response_bytes"] != len(contract.RESPONSE_BYTES):
                        row["error_code"] = "RESPONSE_FAILED"
                except OSError:
                    row["error_code"] = "RESPONSE_FAILED"
        except TimeoutError:
            row["error_code"] = "READ_TIMEOUT"
        except OSError:
            row["error_code"] = "READ_FAILED"
        except BaseException:
            row["error_code"] = "OBSERVER_INTERRUPTED"
            raise
        finally:
            primary = sys.exception()
            row["raw_hex"] = raw[: contract.MAX_BYTES].hex()
            try:
                connection.close()
            except BaseException as error:
                row["error_code"] = "CLOSE_FAILED"
                if primary is not None:
                    primary.add_note("HTTP_INGRESS_CLOSE_FAILED")
                elif not isinstance(error, OSError):
                    raise
            try:
                row["completed_boottime_ns"] = _now()
            except BaseException:
                row["error_code"] = "OBSERVER_INTERRUPTED"
                if primary is None:
                    raise
                primary.add_note("HTTP_INGRESS_FINAL_CLOCK_FAILED")
        try:
            self._held.guard()
        except BaseException:
            row["error_code"] = "OBSERVER_INTERRUPTED"
            raise
        return row

    def observe_readiness(self):
        contract.require(
            not self._closed and not self._ready_called,
            "HTTP_READINESS_ALREADY_CONSUMED",
        )
        self._ready_called = True
        start = _now()
        self._record["interval"]["readiness_started_ns"] = start
        deadline = start + int(contract.TIMEOUT_SECONDS * 1_000_000_000)
        try:
            row = self._connection(deadline, readiness=True)
            ready = (
                row["raw_hex"]
                == contract.readiness_request(self._record["readiness_nonce"]).hex()
                and row["eof"] is True
                and row["error_code"] is None
                and row["response_bytes"] == len(contract.RESPONSE_BYTES)
            )
            if not ready:
                self._record["errors"].append("READINESS_NOT_CONFIRMED")
            return ready
        except TimeoutError:
            self._record["errors"].append("READINESS_TIMEOUT")
            return False
        except OSError:
            self._record["errors"].append("READINESS_ACCEPT_FAILED")
            return False

    def observe_attempt(self):
        contract.require(
            not self._closed
            and self._ready_called
            and self._record["readiness"] is not None
            and not self._record["errors"]
            and not self._attempt_called,
            "HTTP_ATTEMPT_OBSERVATION_PREREQUISITE",
        )
        self._attempt_called = True
        start = _now()
        self._record["interval"]["started_ns"] = start
        deadline = start + int(contract.TIMEOUT_SECONDS * 1_000_000_000)
        try:
            while len(self._record["connections"]) < contract.MAX_CONNECTIONS:
                try:
                    row = self._connection(deadline)
                except TimeoutError:
                    if _now() < deadline:
                        self._record["errors"].append("EARLY_TIMEOUT")
                    break
                if row["error_code"] is not None or not row["eof"]:
                    self._record["errors"].append("INCOMPLETE_INGRESS")
                    break
            else:
                self._record["errors"].append("CONNECTION_LIMIT")
        except OSError:
            self._record["errors"].append("ATTEMPT_ACCEPT_FAILED")
        finally:
            primary = sys.exception()
            try:
                self._record["interval"]["finished_ns"] = _now()
            except BaseException:
                self._record["errors"].append("FINAL_CLOCK_FAILED")
                if primary is None:
                    raise
                primary.add_note("HTTP_OBSERVER_FINAL_CLOCK_FAILED")
        self._held.guard()

    def _close(self):
        self._closed = True
        primary = sys.exception()
        try:
            self._listener.close()
            self._record["listener_closed"] = True
        except BaseException as error:
            self._record["errors"].append("LISTENER_CLOSE_FAILED")
            if primary is not None:
                primary.add_note("HTTP_LISTENER_CLOSE_FAILED")
            elif not isinstance(error, OSError):
                raise
        self._record["complete"] = (
            self._attempt_called
            and self._record["listener_closed"]
            and not self._record["errors"]
            and self._record["interval"]["finished_ns"] is not None
        )


@contextmanager
def open_http_sink(*, expected_fixture, attempt_id, readiness_nonce):
    """Open one fixed sink; caller retains partial results after any exception."""
    contract.validate_fixture(expected_fixture)
    contract.canary_request(attempt_id)
    contract.readiness_request(readiness_nonce)
    session = listener = None
    try:
        with owned_http_fixture(expected_fixture) as held:
            held.guard()
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.bind((contract.HOST, contract.PORT))
                listener.listen(contract.MAX_CONNECTIONS)
                contract.require(
                    listener.getsockname() == (contract.HOST, contract.PORT),
                    "HTTP_LISTENER_ENDPOINT_CHANGED",
                )
                held.guard()
                session = _Sink(held, listener, attempt_id, readiness_nonce)
                try:
                    yield session
                except BaseException:
                    session._record["errors"].append("OBSERVER_INTERRUPTED")
                    raise
                finally:
                    session._close()
                held.guard()
            finally:
                if session is None:
                    listener.close()
    except BaseException:
        if session is not None:
            session._record["complete"] = False
            session._record["errors"].append("OBSERVER_OR_FIXTURE_FAILED")
        raise
