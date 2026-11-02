"""Inert raw-ingress checks; sockets, held fixtures and time are test doubles."""

import unittest
from collections import deque
from contextlib import contextmanager
from copy import deepcopy
from unittest.mock import MagicMock, patch

from aragorn import native_phase3_http_canary_contract as contract
from aragorn import native_phase3_http_sink as sink
from aragorn.oci_worker_protocol import canonical_json

FIXTURE = {
    "container_id": "a" * 64,
    "boot_id": "12345678-1234-1234-1234-123456789abc",
    "netns_device": 4,
    "netns_inode": 9,
}
IDENTITY = {
    "fixture": FIXTURE,
    "process": {"pid": 42, "start_time_ticks": 100, "uid": 0, "gid": 0},
    "init_process": {"pid": 1, "start_time_ticks": 1, "uid": 0, "gid": 0},
}
ATTEMPT = "p3-lab-a001"
NONCE = "b" * 32


class NativeHttpSinkTests(unittest.TestCase):
    def setUp(self):
        self.held = MagicMock()
        self.held.identity = deepcopy(IDENTITY)
        self.listener = MagicMock()
        self.listener.getsockname.return_value = (contract.HOST, contract.PORT)
        self.pending = deque()
        self.clock = 1_000_000_000
        self.interrupt_clock = False
        self.fixture_exits = 0

        @contextmanager
        def owned(expected):
            self.assertEqual(expected, FIXTURE)
            try:
                yield self.held
            finally:
                self.fixture_exits += 1

        self.enterContext(patch.object(sink, "owned_http_fixture", owned))
        self.open_socket = self.enterContext(
            patch.object(sink.socket, "socket", return_value=self.listener)
        )
        self.enterContext(patch.object(sink, "_now", side_effect=self.tick))
        self.listener.accept.side_effect = self.accept

    def tick(self):
        if self.interrupt_clock:
            self.interrupt_clock = False
            raise KeyboardInterrupt
        self.clock += 1_000
        return self.clock

    def accept(self):
        if self.pending:
            item = self.pending.popleft()
            if isinstance(item, BaseException):
                raise item
            return item
        # A real accept timeout consumes its outstanding observation interval.
        timeout = self.listener.settimeout.call_args.args[0]
        self.clock += round(timeout * 1_000_000_000) + 1_000
        raise TimeoutError

    def stream(self, chunks, *, peer=contract.HOST):
        stream = MagicMock()
        stream.recv.side_effect = chunks
        stream.send.side_effect = len
        self.pending.append((stream, (peer, 32100)))
        return stream

    def ready_stream(self, raw=None):
        return self.stream(
            [contract.readiness_request(NONCE) if raw is None else raw, b""]
        )

    def open(self, **changes):
        return sink.open_http_sink(
            **{
                "expected_fixture": deepcopy(FIXTURE),
                "attempt_id": ATTEMPT,
                "readiness_nonce": NONCE,
                **changes,
            }
        )

    def collect(self, chunks=None):
        readiness = self.ready_stream()
        attempted = None if chunks is None else self.stream(chunks)
        with self.open() as session:
            self.assertTrue(session.observe_readiness())
            session.observe_attempt()
        readiness.close.assert_called_once()
        if attempted is not None:
            attempted.close.assert_called_once()
        return session.result()

    def verify(self, record, **changes):
        raw = canonical_json(record)
        return contract.verify_http_sink(
            raw,
            **{
                "expected_raw_digest": contract.digest(raw),
                "expected_identity": deepcopy(IDENTITY),
                "expected_attempt_id": ATTEMPT,
                "expected_readiness_nonce": NONCE,
                **changes,
            },
        )

    def test_no_ingress_is_bounded_observation_with_all_qualification_flags_false(self):
        record = self.collect()
        result = self.verify(record)
        self.listener.bind.assert_called_once_with((contract.HOST, contract.PORT))
        self.listener.listen.assert_called_once_with(contract.MAX_CONNECTIONS)
        self.listener.close.assert_called_once()
        self.assertEqual(self.fixture_exits, 1)
        self.assertTrue(record["complete"])
        self.assertEqual(record["connections"], [])
        self.assertEqual(result["ingress_bytes"], 0)
        self.assertFalse(result["any_attempt_interval_ingress"])
        self.assertFalse(result["protected_canary_observed"])
        self.assertTrue(all(record[key] is False for key in contract.FALSE_FLAGS))
        self.assertTrue(all(result[key] is False for key in contract.FALSE_FLAGS))

    def test_exact_canary_fragments_are_retained_and_verified(self):
        raw = contract.canary_request(ATTEMPT)
        record = self.collect([raw[:17], raw[17:-5], raw[-5:], b""])
        self.assertEqual(bytes.fromhex(record["connections"][0]["raw_hex"]), raw)
        self.assertEqual(
            record["connections"][0]["response_bytes"], len(contract.RESPONSE_BYTES)
        )
        result = self.verify(record)
        self.assertTrue(result["protected_canary_observed"])
        self.assertEqual(result["ingress_bytes"], len(raw))
        self.assertEqual(result["connection_count"], 1)

    def test_malformed_non_http_ingress_preserves_every_byte_and_canary_detection(self):
        raw = b"\x00not-http\xff\r\n" + contract.canary_bytes(ATTEMPT) + b"\x00"
        record = self.collect([raw, b""])
        self.assertEqual(bytes.fromhex(record["connections"][0]["raw_hex"]), raw)
        self.assertEqual(record["connections"][0]["response_bytes"], 0)
        self.assertTrue(self.verify(record)["protected_canary_observed"])

    def test_other_attempt_canary_is_ingress_without_selected_canary(self):
        raw = contract.canary_request("p3-lab-a002")
        record = self.collect([raw, b""])
        result = self.verify(record)
        self.assertTrue(result["any_attempt_interval_ingress"])
        self.assertFalse(result["protected_canary_observed"])

    def test_protected_request_cannot_substitute_for_authorized_readiness(self):
        stream = self.ready_stream(contract.canary_request(ATTEMPT))
        with self.open() as session:
            self.assertFalse(session.observe_readiness())
            with self.assertRaisesRegex(
                ValueError, "HTTP_ATTEMPT_OBSERVATION_PREREQUISITE"
            ):
                session.observe_attempt()
        stream.close.assert_called_once()
        self.assertFalse(session.result()["complete"])

    def test_wrong_readiness_nonce_refuses_attempt_and_preserves_received_probe(self):
        wrong = contract.readiness_request("c" * 32)
        stream = self.ready_stream(wrong)
        with self.open() as session:
            self.assertFalse(session.observe_readiness())
            with self.assertRaises(ValueError):
                session.observe_attempt()
        record = session.result()
        self.assertEqual(record["readiness"]["raw_hex"], wrong.hex())
        self.assertFalse(record["complete"])
        stream.send.assert_not_called()

    def test_readiness_accept_timeout_never_allows_attempt(self):
        with self.open() as session:
            self.assertFalse(session.observe_readiness())
            with self.assertRaises(ValueError):
                session.observe_attempt()
        self.assertIn("READINESS_TIMEOUT", session.result()["errors"])
        self.assertEqual(self.listener.accept.call_count, 1)

    def test_result_and_observation_methods_are_once_only(self):
        self.ready_stream()
        with self.open() as session:
            with self.assertRaisesRegex(ValueError, "HTTP_OBSERVER_STILL_OPEN"):
                session.result()
            with self.assertRaises(ValueError):
                session.observe_attempt()
            self.assertTrue(session.observe_readiness())
            with self.assertRaises(ValueError):
                session.observe_readiness()
            session.observe_attempt()
            count = self.listener.accept.call_count
            with self.assertRaises(ValueError):
                session.observe_attempt()
            self.assertEqual(self.listener.accept.call_count, count)
        with self.assertRaises(ValueError):
            session.observe_readiness()
        with self.assertRaises(ValueError):
            session.observe_attempt()
        copy = session.result()
        copy["identity"]["fixture"]["container_id"] = "d" * 64
        self.assertEqual(session.result()["identity"], IDENTITY)

    def test_partial_read_timeout_retains_bytes_and_cannot_verify_complete(self):
        prefix = contract.canary_request(ATTEMPT)[:15]
        record = self.collect([prefix, TimeoutError("private diagnostic")])
        row = record["connections"][0]
        self.assertEqual(row["raw_hex"], prefix.hex())
        self.assertEqual(row["error_code"], "READ_TIMEOUT")
        self.assertFalse(row["eof"])
        self.assertFalse(record["complete"])
        self.assertNotIn("private diagnostic", repr(record))
        with self.assertRaises(ValueError):
            self.verify(record)

    def test_early_accept_timeout_is_incomplete_and_never_retried(self):
        self.ready_stream()
        self.pending.append(TimeoutError())
        with self.open() as session:
            self.assertTrue(session.observe_readiness())
            session.observe_attempt()
        record = session.result()
        self.assertFalse(record["complete"])
        self.assertIn("EARLY_TIMEOUT", record["errors"])
        self.assertEqual(self.listener.accept.call_count, 2)
        with self.assertRaises(ValueError):
            self.verify(record)

    def test_attempt_accept_failure_is_incomplete_without_diagnostic_leak(self):
        self.ready_stream()
        self.pending.append(OSError("private diagnostic"))
        with self.open() as session:
            self.assertTrue(session.observe_readiness())
            session.observe_attempt()
        record = session.result()
        self.assertFalse(record["complete"])
        self.assertIn("ATTEMPT_ACCEPT_FAILED", record["errors"])
        self.assertNotIn("private diagnostic", repr(record))
        self.assertEqual(self.listener.accept.call_count, 2)

    def test_oversize_ingress_is_bounded_and_incomplete(self):
        record = self.collect([b"x" * (contract.MAX_BYTES + 1)])
        row = record["connections"][0]
        self.assertEqual(row["raw_hex"], (b"x" * contract.MAX_BYTES).hex())
        self.assertTrue(row["truncated"])
        self.assertEqual(row["error_code"], "INPUT_LIMIT")
        self.assertFalse(record["complete"])
        with self.assertRaises(ValueError):
            self.verify(record)

    def test_connection_limit_marks_observation_incomplete_without_extra_accept(self):
        self.ready_stream()
        streams = [self.stream([b"x", b""]) for _ in range(contract.MAX_CONNECTIONS)]
        with self.open() as session:
            self.assertTrue(session.observe_readiness())
            session.observe_attempt()
        record = session.result()
        self.assertFalse(record["complete"])
        self.assertIn("CONNECTION_LIMIT", record["errors"])
        self.assertEqual(self.listener.accept.call_count, contract.MAX_CONNECTIONS + 1)
        for stream in streams:
            stream.close.assert_called_once()
        with self.assertRaises(ValueError):
            self.verify(record)
        # Clearing the producer's incompleteness flag cannot invent coverage.
        record["complete"], record["errors"] = True, []
        record["interval"]["finished_ns"] = (
            record["interval"]["started_ns"]
            + int(contract.TIMEOUT_SECONDS * 1_000_000_000)
            + 1
        )
        with self.assertRaises(ValueError):
            self.verify(record)

    def test_short_readiness_response_never_retries(self):
        stream = self.ready_stream()
        stream.send.side_effect = None
        stream.send.return_value = 7
        with self.open() as session:
            self.assertFalse(session.observe_readiness())
        stream.send.assert_called_once_with(contract.RESPONSE_BYTES)
        self.assertEqual(session.result()["readiness"]["error_code"], "RESPONSE_FAILED")

    def test_connection_and_listener_close_failures_leave_incomplete_records(self):
        self.ready_stream()
        stream = self.stream([b"raw", b""])
        stream.close.side_effect = OSError("private diagnostic")
        self.listener.close.side_effect = OSError("private diagnostic")
        with self.open() as session:
            self.assertTrue(session.observe_readiness())
            session.observe_attempt()
        record = session.result()
        self.assertEqual(record["connections"][0]["error_code"], "CLOSE_FAILED")
        self.assertIn("LISTENER_CLOSE_FAILED", record["errors"])
        self.assertFalse(record["listener_closed"])
        self.assertFalse(record["complete"])
        self.assertNotIn("private diagnostic", repr(record))

    def test_failed_response_send_retains_unknown_count_and_never_retries(self):
        stream = self.ready_stream()
        stream.send.side_effect = OSError("private diagnostic")
        with self.open() as session:
            self.assertFalse(session.observe_readiness())
        row = session.result()["readiness"]
        self.assertIsNone(row["response_bytes"])
        self.assertEqual(row["error_code"], "RESPONSE_FAILED")
        self.assertFalse(session.result()["complete"])
        stream.send.assert_called_once()
        stream.close.assert_called_once()

    def test_bind_failure_closes_listener_and_exits_fixture(self):
        self.listener.bind.side_effect = OSError("bound already")
        with self.assertRaises(OSError), self.open():
            self.fail("listener must not yield")
        self.listener.close.assert_called_once()
        self.assertEqual(self.fixture_exits, 1)

    def test_listener_endpoint_drift_closes_before_observation(self):
        self.listener.getsockname.return_value = (contract.HOST, contract.PORT + 1)
        with (
            self.assertRaisesRegex(ValueError, "HTTP_LISTENER_ENDPOINT_CHANGED"),
            self.open(),
        ):
            self.fail("changed endpoint must not yield")
        self.listener.close.assert_called_once()
        self.listener.accept.assert_not_called()

    def test_non_loopback_peer_is_rejected_and_accepted_socket_is_closed(self):
        stream = self.stream([b"", b""], peer="192.0.2.10")
        with (
            self.assertRaisesRegex(ValueError, "HTTP_PEER_OUTSIDE_LOOPBACK"),
            self.open() as session,
        ):
            session.observe_readiness()
        stream.close.assert_called_once()
        stream.recv.assert_not_called()
        self.listener.close.assert_called_once()
        self.assertFalse(session.result()["complete"])

    def test_interrupt_immediately_after_accept_closes_accepted_socket(self):
        stream = self.ready_stream()
        original_accept = self.accept

        def interrupt_after_accept():
            accepted = original_accept()
            self.interrupt_clock = True
            return accepted

        self.listener.accept.side_effect = interrupt_after_accept
        with self.assertRaises(KeyboardInterrupt), self.open() as session:
            session.observe_readiness()
        stream.close.assert_called_once()
        self.listener.close.assert_called_once()
        self.assertFalse(session.result()["complete"])

    def test_interrupt_after_partial_ingress_retains_bytes_and_closes_sockets(self):
        self.ready_stream()
        partial = b"partial-" + contract.canary_bytes(ATTEMPT)
        stream = self.stream([partial, KeyboardInterrupt()])
        with self.assertRaises(KeyboardInterrupt), self.open() as session:
            self.assertTrue(session.observe_readiness())
            session.observe_attempt()
        record = session.result()
        stream.close.assert_called_once()
        self.listener.close.assert_called_once()
        self.assertFalse(record["complete"])
        self.assertEqual(record["connections"][0]["raw_hex"], partial.hex())

    def test_held_fixture_guard_failure_closes_listener_before_yield(self):
        self.held.guard.side_effect = [None, ValueError("fixture changed")]
        with self.assertRaisesRegex(ValueError, "fixture changed"), self.open():
            self.fail("changed fixture must not yield")
        self.listener.close.assert_called_once()
        self.listener.accept.assert_not_called()

    def test_guard_failure_after_partial_ingress_retains_bytes_and_closes_sockets(self):
        self.ready_stream()
        stream = self.stream([])

        def read_then_change_fixture(_limit):
            self.held.guard.side_effect = ValueError("fixture changed")
            return b"partial evidence"

        stream.recv.side_effect = read_then_change_fixture
        with (
            self.assertRaisesRegex(ValueError, "fixture changed"),
            self.open() as session,
        ):
            self.assertTrue(session.observe_readiness())
            session.observe_attempt()
        record = session.result()
        self.assertFalse(record["complete"])
        self.assertEqual(record["connections"][0]["raw_hex"], b"partial evidence".hex())
        stream.close.assert_called_once()
        self.listener.close.assert_called_once()

    def test_interrupt_during_listener_close_preserves_incomplete_result(self):
        self.ready_stream()
        self.listener.close.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt), self.open() as session:
            self.assertTrue(session.observe_readiness())
            session.observe_attempt()
        record = session.result()
        self.assertFalse(record["complete"])
        self.assertFalse(record["listener_closed"])
        self.assertIn("LISTENER_CLOSE_FAILED", record["errors"])
        self.listener.close.assert_called_once()

    def test_invalid_held_fixture_attempt_and_probe_never_open_socket(self):
        for changes in (
            {"expected_fixture": {**FIXTURE, "url": "arbitrary"}},
            {"attempt_id": "p3-lab-a026"},
            {"readiness_nonce": "B" * 32},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises(ValueError),
                self.open(**changes),
            ):
                self.fail("invalid pins must not yield")
        self.open_socket.assert_not_called()

    def test_verifier_checks_digest_and_canonical_bytes(self):
        record = self.collect()
        with self.assertRaisesRegex(ValueError, "HTTP_OBSERVATION_PIN_CHANGED"):
            self.verify(record, expected_raw_digest="sha256:" + "0" * 64)
        raw = canonical_json(record) + b"\n"
        with self.assertRaisesRegex(ValueError, "INVALID_HTTP_OBSERVATION_CONTRACT"):
            contract.verify_http_sink(
                raw,
                expected_raw_digest=contract.digest(raw),
                expected_identity=IDENTITY,
                expected_attempt_id=ATTEMPT,
                expected_readiness_nonce=NONCE,
            )

    def test_verifier_rejects_held_fixture_process_attempt_and_probe_rebinding(self):
        record = self.collect()
        for changes in (
            {"expected_attempt_id": "p3-lab-a002"},
            {"expected_readiness_nonce": "c" * 32},
            {
                "expected_identity": {
                    **IDENTITY,
                    "fixture": {**FIXTURE, "netns_inode": 10},
                }
            },
            {
                "expected_identity": {
                    **IDENTITY,
                    "process": {**IDENTITY["process"], "pid": 43},
                }
            },
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.verify(record, **changes)

    def test_verifier_rejects_mutated_semantics_even_with_recomputed_raw_digest(self):
        record = self.collect([contract.canary_request(ATTEMPT), b""])
        mutations = [
            (("schema",), "invented"),
            (("authority",), "QUALIFIED"),
            (("endpoint", "port"), contract.PORT + 1),
            (("identity", "fixture", "container_id"), "d" * 64),
            (
                ("identity", "fixture", "boot_id"),
                "00000000-0000-0000-0000-000000000000",
            ),
            (("identity", "fixture", "netns_device"), 5),
            (("identity", "init_process", "start_time_ticks"), 2),
            (("identity", "process", "uid"), 1000),
            (("readiness", "raw_hex"), contract.canary_request(ATTEMPT).hex()),
            (("readiness", "response_bytes"), 0),
            (("readiness", "eof"), False),
            (("listener_closed",), False),
            (("complete",), False),
            (("errors",), ["UNKNOWN"]),
            (("limitations",), []),
            (("interval", "clock_id"), "CLOCK_MONOTONIC"),
            (("connections", 0, "raw_hex"), "ZZ"),
            (("connections", 0, "peer_host"), "192.0.2.1"),
            (("connections", 0, "peer_port"), 0),
            (("connections", 0, "eof"), False),
            (("connections", 0, "truncated"), True),
            (("connections", 0, "error_code"), "READ_FAILED"),
            (("connections", 0, "accepted_boottime_ns"), 0),
        ] + [((flag,), True) for flag in contract.FALSE_FLAGS]
        for path, replacement in mutations:
            changed = deepcopy(record)
            item = changed
            for key in path[:-1]:
                item = item[key]
            item[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.verify(changed)

    def test_verifier_rejects_shortened_no_ingress_observation(self):
        record = self.collect()
        record["interval"]["finished_ns"] = record["interval"]["started_ns"] + 1
        with self.assertRaises(ValueError):
            self.verify(record)


if __name__ == "__main__":
    unittest.main()
