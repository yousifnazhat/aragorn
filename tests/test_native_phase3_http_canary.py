"""Inert client/fixture checks: no sockets, namespaces or effects are opened."""

import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from aragorn import native_phase3_http_canary as client
from aragorn import native_phase3_http_canary_contract as contract
from aragorn import native_phase3_http_fixture as fixture

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


class NativeHttpCanaryTests(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.session.identity = IDENTITY
        self.stream = MagicMock()
        self.stream.send.side_effect = lambda raw: len(raw)
        self.stream.recv.side_effect = [contract.RESPONSE_BYTES, b""]
        self.clock = 10.0

        @contextmanager
        def owned(expected):
            self.assertEqual(expected, FIXTURE)
            yield self.session

        self.context = self.enterContext(
            patch.object(client, "owned_http_fixture", owned)
        )
        self.open = self.enterContext(
            patch.object(client.socket, "socket", return_value=self.stream)
        )
        self.enterContext(
            patch.object(client.time, "monotonic", side_effect=lambda: self.clock)
        )

    def send(self):
        return client.send_http_canary(
            expected_fixture=FIXTURE, attempt_id="p3-lab-a001"
        )

    def test_success_records_actual_fixed_request_and_does_not_qualify(self):
        result = self.send()
        raw = contract.canary_request("p3-lab-a001")
        self.stream.connect.assert_called_once_with(("127.0.0.1", 47631))
        self.stream.send.assert_called_once_with(raw)
        self.stream.close.assert_called_once()
        self.assertEqual(result["sent_bytes"], len(raw))
        self.assertEqual(result["request_digest"], contract.digest(raw))
        self.assertEqual(
            result["response_digest"], contract.digest(contract.RESPONSE_BYTES)
        )
        self.assertEqual(result["status"], "RESPONSE_RECEIVED")
        self.assertIsNone(result["error_code"])
        self.assertEqual(result["identity"], IDENTITY)
        self.assertTrue(all(result[flag] is False for flag in contract.FALSE_FLAGS))

    def test_invalid_attempt_never_opens_socket(self):
        for attempt in ("p3-lab-a026", "https://example.com", None, True):
            with self.subTest(attempt=attempt), self.assertRaises(ValueError):
                client.send_http_canary(expected_fixture=FIXTURE, attempt_id=attempt)
        self.open.assert_not_called()

    def test_invalid_fixture_never_opens_socket(self):
        with self.assertRaises(ValueError):
            client.send_http_canary(
                expected_fixture={**FIXTURE, "url": "x"}, attempt_id="p3-lab-a001"
            )
        self.open.assert_not_called()

    def test_readiness_is_distinct_and_nonce_is_validated(self):
        result = client.send_http_readiness(expected_fixture=FIXTURE, nonce="b" * 32)
        self.assertEqual(result["kind"], "READINESS")
        self.assertIsNone(result["attempt_id"])
        self.stream.send.assert_called_once_with(contract.readiness_request("b" * 32))
        self.assertNotEqual(
            self.stream.send.call_args.args[0], contract.canary_request("p3-lab-a001")
        )
        with self.assertRaises(ValueError):
            client.send_http_readiness(expected_fixture=FIXTURE, nonce="B" * 32)
        self.open.assert_called_once()

    def test_short_write_never_retries_or_reads_response(self):
        self.stream.send.side_effect = None
        self.stream.send.return_value = 7
        result = self.send()
        self.assertEqual(result["error_code"], "HTTP_SHORT_WRITE_NO_RETRY")
        self.assertEqual(result["sent_bytes"], 7)
        self.stream.send.assert_called_once()
        self.stream.recv.assert_not_called()
        self.stream.close.assert_called_once()

    def test_failed_connect_is_failure_without_exposing_exception(self):
        self.stream.connect.side_effect = OSError("private diagnostic")
        result = self.send()
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["error_code"], "HTTP_TRANSPORT_FAILED_NO_RETRY")
        self.assertNotIn("private diagnostic", repr(result))
        self.assertEqual(result["sent_bytes"], 0)
        self.stream.connect.assert_called_once()
        self.stream.send.assert_not_called()
        self.stream.close.assert_called_once()

    def test_overall_deadline_stops_after_connect_before_send(self):
        def late_connect(endpoint):
            self.clock += contract.TIMEOUT_SECONDS + 1

        self.stream.connect.side_effect = late_connect
        result = self.send()
        self.assertEqual(result["error_code"], "HTTP_DEADLINE_EXPIRED_NO_RETRY")
        self.stream.send.assert_not_called()
        self.stream.close.assert_called_once()

    def test_response_is_bounded_and_socket_closes(self):
        self.stream.recv.side_effect = [b"x" * (contract.MAX_BYTES + 1)]
        result = self.send()
        self.assertEqual(result["error_code"], "HTTP_RESPONSE_LIMIT_EXCEEDED")
        self.assertEqual(result["response_bytes"], contract.MAX_BYTES + 1)
        self.stream.recv.assert_called_once()
        self.stream.close.assert_called_once()

    def test_wrong_response_and_timeout_are_distinct_failures(self):
        self.stream.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n", b""]
        self.assertEqual(self.send()["error_code"], "HTTP_RESPONSE_REFUSED")
        self.stream.reset_mock()
        self.stream.recv.side_effect = TimeoutError
        self.assertEqual(self.send()["error_code"], "HTTP_DEADLINE_EXPIRED_NO_RETRY")
        self.stream.send.assert_called_once()
        self.stream.close.assert_called_once()

    def test_fixture_guard_failure_after_connect_closes_without_sending(self):
        self.session.guard.side_effect = [None, ValueError("fixture changed"), None]
        with self.assertRaises(ValueError):
            self.send()
        self.stream.send.assert_not_called()
        self.stream.close.assert_called_once()

    def test_socket_close_failure_is_not_success(self):
        self.stream.close.side_effect = OSError("private diagnostic")
        result = self.send()
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["error_code"], "HTTP_SOCKET_CLOSE_FAILED")
        self.assertNotIn("private diagnostic", repr(result))

    def test_partial_response_survives_interrupt_with_sent_count(self):
        interrupted = KeyboardInterrupt("private diagnostic")
        self.stream.recv.side_effect = [b"HTTP/1.1", interrupted]
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.send()
        self.assertIs(raised.exception, interrupted)
        record = raised.exception.http_canary_observation
        self.assertEqual(record["status"], "FAILED")
        self.assertEqual(record["error_code"], "HTTP_OPERATION_INTERRUPTED")
        self.assertEqual(
            record["sent_bytes"], len(contract.canary_request("p3-lab-a001"))
        )
        self.assertEqual(record["response_bytes"], 8)
        self.assertEqual(record["response_digest"], contract.digest(b"HTTP/1.1"))
        self.assertNotIn("private diagnostic", repr(record))
        self.assertTrue(all(record[flag] is False for flag in contract.FALSE_FLAGS))
        self.stream.close.assert_called_once()

    def test_interrupted_send_retains_unknown_count_without_retry(self):
        self.stream.send.side_effect = KeyboardInterrupt("private diagnostic")
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.send()
        record = raised.exception.http_canary_observation
        self.assertIsNone(record["sent_bytes"])
        self.assertEqual(record["response_bytes"], 0)
        self.assertEqual(record["status"], "FAILED")
        self.stream.send.assert_called_once()
        self.stream.close.assert_called_once()

    def test_partial_write_record_survives_final_context_guard_failure(self):
        self.stream.send.side_effect = None
        self.stream.send.return_value = 7

        @contextmanager
        def failed_final_guard(expected):
            yield self.session
            raise ValueError("private final guard diagnostic")

        with (
            patch.object(client, "owned_http_fixture", failed_final_guard),
            self.assertRaises(ValueError) as raised,
        ):
            self.send()
        record = raised.exception.http_canary_observation
        self.assertEqual(record["sent_bytes"], 7)
        self.assertEqual(record["error_code"], "HTTP_FIXTURE_FINAL_GUARD_FAILED")
        self.assertEqual(record["status"], "FAILED")
        self.assertNotIn("private final guard diagnostic", repr(record))
        self.assertTrue(all(record[flag] is False for flag in contract.FALSE_FLAGS))
        self.stream.send.assert_called_once()
        self.stream.close.assert_called_once()

    def test_post_send_guard_failure_retains_known_effect_counts(self):
        self.session.guard.side_effect = [None, None, ValueError("changed"), None]
        with self.assertRaises(ValueError) as raised:
            self.send()
        record = raised.exception.http_canary_observation
        self.assertEqual(
            record["sent_bytes"], len(contract.canary_request("p3-lab-a001"))
        )
        self.assertEqual(record["response_bytes"], 0)
        self.assertEqual(record["error_code"], "HTTP_FIXTURE_GUARD_FAILED")
        self.stream.close.assert_called_once()

    def test_primary_interrupt_survives_close_and_cleanup_guard_failures(self):
        interrupted = KeyboardInterrupt("primary")
        self.stream.recv.side_effect = interrupted
        self.stream.close.side_effect = OSError("private close failure")
        self.session.guard.side_effect = [None, None, None, None, ValueError("cleanup")]
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.send()
        self.assertIs(raised.exception, interrupted)
        record = raised.exception.http_canary_observation
        self.assertEqual(record["status"], "FAILED")
        self.assertEqual(record["error_code"], "HTTP_FIXTURE_GUARD_FAILED")
        self.assertNotIn("private close failure", repr(record))
        self.stream.close.assert_called_once()

    def test_retained_failure_identity_is_detached(self):
        self.stream.recv.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.send()
        record = raised.exception.http_canary_observation
        record["identity"]["process"]["pid"] = 999
        self.assertEqual(self.session.identity["process"]["pid"], 42)


class NativeHttpFixtureTests(unittest.TestCase):
    def environment(self, cgroup=None, interfaces=None, boot=None, own_cgroup=None):
        root = "/docker/" + FIXTURE["container_id"]
        records = {
            "/proc/1/cgroup": (cgroup or "0::" + root + "/init.scope\n").encode(),
            "/proc/self/cgroup": (
                own_cgroup or "0::" + root + "/exec.scope\n"
            ).encode(),
            "/proc/sys/kernel/random/boot_id": (
                boot or FIXTURE["boot_id"] + "\n"
            ).encode(),
        }
        self.enterContext(patch.object(fixture.sys, "platform", "linux"))
        self.enterContext(patch.object(fixture.os, "geteuid", return_value=0))
        self.enterContext(patch.object(fixture.os, "getegid", return_value=0))
        self.enterContext(patch.object(fixture.os, "getpid", return_value=42))
        self.enterContext(
            patch.object(fixture.threading, "get_native_id", return_value=42)
        )
        self.enterContext(
            patch.object(
                fixture, "_read", side_effect=lambda path, limit: records[path]
            )
        )
        self.enterContext(
            patch.object(
                fixture.socket, "if_nameindex", return_value=interfaces or [(1, "lo")]
            )
        )

    def test_host_cgroup_is_rejected(self):
        self.environment(cgroup="0::/init.scope\n")
        with self.assertRaisesRegex(ValueError, "HTTP_OWNED_FIXTURE_REQUIRED"):
            fixture._environment(FIXTURE)

    def test_owned_container_root_cgroup_is_accepted(self):
        self.environment(own_cgroup="0::/docker/" + FIXTURE["container_id"] + "\n")
        fixture._environment(FIXTURE)

    def test_external_interface_is_rejected(self):
        self.environment(interfaces=[(1, "lo"), (2, "eth0")])
        with self.assertRaisesRegex(ValueError, "HTTP_LOOPBACK_ONLY_REQUIRED"):
            fixture._environment(FIXTURE)

    def test_boot_mismatch_is_rejected(self):
        self.environment(boot="00000000-0000-0000-0000-000000000000\n")
        with self.assertRaisesRegex(ValueError, "HTTP_BOOT_CHANGED"):
            fixture._environment(FIXTURE)

    def test_identity_metadata_requires_actual_root_status(self):
        with patch.object(
            fixture, "_read", return_value=b"Uid:\t0 0 0 0\nGid:\t0 0 0 0\n"
        ):
            fixture._root_process_status(1)
        with (
            patch.object(
                fixture, "_read", return_value=b"Uid:\t0 1000 0 0\nGid:\t0 0 0 0\n"
            ),
            self.assertRaisesRegex(ValueError, "HTTP_ROOT_PROCESS_IDENTITY_CHANGED"),
        ):
            fixture._root_process_status(1)

    def test_non_linux_refuses_before_any_descriptor(self):
        with (
            patch.object(fixture.sys, "platform", "darwin"),
            patch.object(fixture.os, "open") as opened,
            self.assertRaises(ValueError),
            fixture.owned_http_fixture(FIXTURE),
        ):
            self.fail("unexpected fixture")
        opened.assert_not_called()

    def test_partial_descriptor_acquisition_closes_owned_descriptor(self):
        with (
            patch.object(fixture, "_environment"),
            patch.object(fixture.os, "open", side_effect=[10, OSError("refused")]),
            patch.object(fixture.os, "close") as closed,
            self.assertRaises(OSError),
            fixture.owned_http_fixture(FIXTURE),
        ):
            self.fail("unexpected fixture")
        closed.assert_called_once_with(10)

    def test_guard_detects_changed_namespace(self):
        with (
            patch.object(fixture.os, "getpid", return_value=42),
            patch.object(fixture.process, "_process_start_time", return_value=100),
        ):
            session = fixture._Session(FIXTURE, 10, 11, 12)
        with (
            patch.object(fixture, "_environment"),
            patch.object(
                fixture.os, "fstat", return_value=SimpleNamespace(st_dev=4, st_ino=9)
            ),
            patch.object(
                fixture.os, "stat", return_value=SimpleNamespace(st_dev=4, st_ino=10)
            ),
            self.assertRaisesRegex(ValueError, "HTTP_NETWORK_NAMESPACE_CHANGED"),
        ):
            session.guard()

    def test_context_guard_failure_still_closes_all_descriptors(self):
        fake = MagicMock()
        fake.guard.side_effect = [None, ValueError("changed")]
        with (
            patch.object(fixture, "_environment"),
            patch.object(fixture.os, "open", side_effect=[10, 11]),
            patch.object(fixture.os, "pidfd_open", return_value=12, create=True),
            patch.object(fixture, "_Session", return_value=fake),
            patch.object(fixture.os, "close") as closed,
            self.assertRaisesRegex(ValueError, "changed"),
            fixture.owned_http_fixture(FIXTURE),
        ):
            pass
        self.assertEqual([call.args[0] for call in closed.call_args_list], [12, 11, 10])
        self.assertIs(fake._active, False)


if __name__ == "__main__":
    unittest.main()
