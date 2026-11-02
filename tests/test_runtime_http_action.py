"""Finite protocol/transport checks with inert socket, credential and proc doubles."""

import copy
import os
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from aragorn import runtime_http_action as http
from aragorn import native_phase3_http_canary_contract as canary
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

FIXTURE = {
    "container_id": "a" * 64,
    "boot_id": "12345678-1234-1234-1234-123456789abc",
    "netns_device": 4,
    "netns_inode": 9,
}
BINDING = {
    "schema": http.BINDING_SCHEMA,
    "fixture": FIXTURE,
    "expected_broker_uid": 1001,
    "expected_broker_gid": 1002,
}
IDENTITY = {
    "fixture": FIXTURE,
    "pid": 42,
    "start_time_ticks": 123,
    "uid": 1001,
    "gid": 1002,
}
ATTEMPT = "p3-lab-a001"


def metadata(
    *, mode=stat.S_IFREG | 0o440, uid=0, gid=1002, size=None, inode=11, links=1
):
    return SimpleNamespace(
        st_mode=mode,
        st_uid=uid,
        st_gid=gid,
        st_size=len(canonical_json(BINDING)) if size is None else size,
        st_nlink=links,
        st_dev=4,
        st_ino=inode,
        st_mtime_ns=12,
        st_ctime_ns=13,
    )


class RuntimeHttpProtocolTests(unittest.TestCase):
    def test_action_digests_bind_fixed_wire_request_and_fixture(self):
        digests = http.action_digests(ATTEMPT, BINDING)
        self.assertEqual(
            digests["operation_digest"], canonical_digest(http.operation_descriptor())
        )
        self.assertEqual(
            digests["payload_digest"], canary.digest(canary.canary_request(ATTEMPT))
        )
        self.assertEqual(
            digests["path_digest"], canonical_digest(http.endpoint_descriptor(BINDING))
        )
        changed = copy.deepcopy(BINDING)
        changed["fixture"]["netns_inode"] += 1
        self.assertNotEqual(
            digests["path_digest"], http.action_digests(ATTEMPT, changed)["path_digest"]
        )
        self.assertNotEqual(
            digests["payload_digest"],
            http.action_digests("p3-lab-a002", BINDING)["payload_digest"],
        )

    def test_effect_forbids_destination_body_and_out_of_range_attempt(self):
        effect = http.effect_for_attempt(ATTEMPT)
        self.assertEqual(set(effect), http.EFFECT_FIELDS)
        for changed in (
            {**effect, "url": "http://127.0.0.1"},
            {**effect, "payload": "x"},
            {**effect, "attempt_id": "p3-lab-a026"},
            {**effect, "operation": "create"},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                http.validate_effect(changed)

    def test_binding_is_detached_and_refuses_root_or_boolean_identities(self):
        detached = http.validate_fixture_binding(BINDING)
        detached["fixture"]["netns_inode"] += 1
        self.assertEqual(FIXTURE["netns_inode"], 9)
        for field in ("expected_broker_uid", "expected_broker_gid"):
            for value in (True, 0, -1, 2**31):
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(http.RuntimeHttpActionError),
                ):
                    http.validate_fixture_binding({**BINDING, field: value})

    def test_worker_request_has_finite_schema_and_identifiers(self):
        request = http.build_worker_request(
            attempt_id=ATTEMPT,
            session_id="session-1",
            run_id="run-1",
            tool_call_digest="sha256:" + "c" * 64,
        )
        self.assertEqual(request["schema"], http.WORKER_SCHEMA)
        for changed in (
            {**request, "payload_base64": ""},
            {**request, "session_id": "../x"},
            {**request, "authority": "EFFECT_AUTHORITY"},
            {**request, "tool_call_digest": "wrong"},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                http.validate_worker_request(changed)


class RuntimeHttpCredentialTests(unittest.TestCase):
    def setUp(self):
        self.raw = canonical_json(BINDING)
        self.file = metadata()
        self.directory = metadata(mode=stat.S_IFDIR | 0o755, gid=0)
        self.enterContext(
            patch.object(
                Path,
                "lstat",
                autospec=True,
                side_effect=lambda path: (
                    self.file if path == http.BINDING_PATH else self.directory
                ),
            )
        )
        self.open = self.enterContext(patch.object(http.os, "open", return_value=8))
        self.enterContext(
            patch.object(http.os, "fstat", side_effect=lambda fd: self.file)
        )
        self.read = self.enterContext(
            patch.object(http.os, "read", side_effect=lambda fd, count: self.raw)
        )
        self.close = self.enterContext(patch.object(http.os, "close"))

    def test_reads_only_fixed_nofollow_root_credential(self):
        self.assertEqual(http.load_fixture_binding(), BINDING)
        self.open.assert_called_once_with(
            http.BINDING_PATH,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        self.close.assert_called_once_with(8)

    def test_refuses_unsafe_modes_owners_links_groups_and_ancestry(self):
        for replacement in (
            metadata(mode=stat.S_IFREG | 0o444),
            metadata(uid=1001),
            metadata(links=2),
            metadata(gid=1003),
            metadata(mode=stat.S_IFLNK | 0o440),
        ):
            self.file = replacement
            with (
                self.subTest(replacement=replacement),
                self.assertRaises(http.RuntimeHttpActionError),
            ):
                http.load_fixture_binding()
        self.file = metadata()
        self.directory = metadata(mode=stat.S_IFDIR | 0o775, gid=0)
        with self.assertRaises(http.RuntimeHttpActionError):
            http.load_fixture_binding()

    def test_refuses_noncanonical_duplicate_truncated_or_replaced_credential(self):
        for raw in (self.raw + b"\n", self.raw[:-1], b'{"schema":"x","schema":"y"}'):
            self.raw = raw
            with self.subTest(raw=raw), self.assertRaises(http.RuntimeHttpActionError):
                http.load_fixture_binding()
        self.raw = canonical_json(BINDING)
        with (
            patch.object(
                http.os, "fstat", side_effect=[metadata(), metadata(inode=22)]
            ),
            self.assertRaises(http.RuntimeHttpActionError),
        ):
            http.load_fixture_binding()

    def test_read_interrupt_survives_credential_descriptor_close_failure(self):
        for interruption in (KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(interruption=type(interruption).__name__):
                self.close.reset_mock()
                self.read.side_effect = interruption
                self.close.side_effect = OSError("private cleanup diagnostic")
                with self.assertRaises(type(interruption)) as raised:
                    http.load_fixture_binding()
                self.assertIs(raised.exception, interruption)
                self.assertTrue(interruption.http_binding_cleanup_failed)
                self.assertEqual(
                    interruption.__notes__,
                    ["HTTP_BINDING_DESCRIPTOR_CLOSE_FAILED"],
                )
                self.close.assert_called_once_with(8)


class RuntimeHttpGuardTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(http.sys, "platform", "linux"))
        for name, value in (
            ("getpid", 42),
            ("getuid", 1001),
            ("geteuid", 1001),
            ("getgid", 1002),
            ("getegid", 1002),
        ):
            self.enterContext(patch.object(http.os, name, return_value=value))
        self.enterContext(
            patch.object(http.threading, "get_native_id", return_value=42)
        )
        self.enterContext(
            patch.object(http.socket, "if_nameindex", return_value=[(1, "lo")])
        )
        self.data = {
            "/proc/self/status": b"Uid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\n",
            "/proc/self/cgroup": f"0::/docker/{FIXTURE['container_id']}/system.slice/{http.BROKER_UNIT}\n".encode(),
            str(http.BOOT_PATH): (FIXTURE["boot_id"] + "\n").encode(),
        }
        self.enterContext(
            patch.object(
                http, "_read", side_effect=lambda path, count: self.data[str(path)]
            )
        )
        self.enterContext(
            patch.object(
                http, "load_fixture_binding", return_value=copy.deepcopy(BINDING)
            )
        )
        self.start = self.enterContext(
            patch.object(http.process, "_process_start_time", return_value=123)
        )
        self.open = self.enterContext(patch.object(http.os, "open", return_value=9))
        self.enterContext(
            patch.object(http.os, "fstat", return_value=metadata(inode=9))
        )
        self.enterContext(patch.object(http.os, "stat", return_value=metadata(inode=9)))
        self.close = self.enterContext(patch.object(http.os, "close"))

    def test_holds_actual_namespace_and_exact_nonroot_identity(self):
        held = http._ExecutionGuard(BINDING)
        self.assertEqual(held.identity(), IDENTITY)
        held.close()
        self.close.assert_called_once_with(9)
        with self.assertRaises(http.RuntimeHttpActionError):
            held.guard()

    def test_refuses_saved_or_filesystem_identity_mismatch(self):
        for ids in (b"1001\t1001\t0\t1001", b"1001\t1001\t1001\t0"):
            self.data["/proc/self/status"] = (
                b"Uid:\t" + ids + b"\nGid:\t1002\t1002\t1002\t1002\n"
            )
            with self.subTest(ids=ids), self.assertRaises(http.RuntimeHttpActionError):
                http._ExecutionGuard(BINDING)
        self.open.assert_not_called()

    def test_refuses_other_cgroup_boot_or_external_interface(self):
        original = dict(self.data)
        for path in ("/proc/self/cgroup", str(http.BOOT_PATH)):
            self.data[path] = b"other\n"
            with (
                self.subTest(path=path),
                self.assertRaises(http.RuntimeHttpActionError),
            ):
                http._ExecutionGuard(BINDING)
            self.data = dict(original)
        with (
            patch.object(
                http.socket, "if_nameindex", return_value=[(1, "lo"), (2, "eth0")]
            ),
            self.assertRaises(http.RuntimeHttpActionError),
        ):
            http._ExecutionGuard(BINDING)
        self.open.assert_not_called()

    def test_rechecks_namespace_process_and_root_binding(self):
        held = http._ExecutionGuard(BINDING)
        with (
            patch.object(http.os, "stat", return_value=metadata(inode=12)),
            self.assertRaises(http.RuntimeHttpActionError),
        ):
            held.guard()
        self.start.return_value = 124
        with self.assertRaises(http.RuntimeHttpActionError):
            held.guard()
        self.start.return_value = 123
        with (
            patch.object(
                http,
                "load_fixture_binding",
                return_value={**BINDING, "expected_broker_uid": 1003},
            ),
            self.assertRaises(http.RuntimeHttpActionError),
        ):
            held.guard()
        held.close()


class RuntimeHttpEffectTests(unittest.TestCase):
    def setUp(self):
        self.held = MagicMock()
        self.held.identity.return_value = copy.deepcopy(IDENTITY)
        self.guard = self.enterContext(
            patch.object(http, "_ExecutionGuard", return_value=self.held)
        )
        self.stream = MagicMock()
        self.stream.send.side_effect = lambda raw: len(raw)
        self.stream.recv.side_effect = [canary.RESPONSE_BYTES, b""]
        self.open = self.enterContext(
            patch.object(http.socket, "socket", return_value=self.stream)
        )
        self.clock = 10.0
        self.enterContext(
            patch.object(http.time, "monotonic", side_effect=lambda: self.clock)
        )

    def execute(self, deadline=10.5):
        return http.execute_http_effect(
            http.effect_for_attempt(ATTEMPT),
            fixture_binding=BINDING,
            deadline_monotonic=deadline,
        )

    def test_one_send_uses_inherited_deadline_and_fixed_bytes(self):
        result = self.execute()
        self.stream.connect.assert_called_once_with((canary.HOST, canary.PORT))
        self.stream.send.assert_called_once_with(canary.canary_request(ATTEMPT))
        self.assertTrue(
            all(call.args == (0.5,) for call in self.stream.settimeout.call_args_list)
        )
        self.assertEqual(result["status"], "SENT")
        self.assertEqual(result["identity"], IDENTITY)
        self.assertTrue(all(result[key] is False for key in canary.FALSE_FLAGS))
        self.stream.close.assert_called_once()
        self.held.close.assert_called_once()

    def test_authorization_runs_after_guard_timeout_immediately_before_each_effect(
        self,
    ):
        order = []
        self.held.guard.side_effect = lambda: order.append("guard")
        self.stream.settimeout.side_effect = lambda value: order.append("timeout")
        self.stream.connect.side_effect = lambda endpoint: order.append("connect")

        def send(raw):
            order.append("send")
            return len(raw)

        def authorize():
            order.append("authorize")
            return True

        self.stream.send.side_effect = send
        result = http.execute_http_effect(
            http.effect_for_attempt(ATTEMPT),
            fixture_binding=BINDING,
            deadline_monotonic=10.5,
            authorize_effect=authorize,
        )
        self.assertEqual(result["status"], "SENT")
        indexes = [index for index, name in enumerate(order) if name == "authorize"]
        self.assertEqual(len(indexes), 2)
        self.assertEqual(
            [order[index - 2 : index + 3] for index in indexes],
            [
                ["guard", "timeout", "authorize", "timeout", "connect"],
                ["guard", "timeout", "authorize", "timeout", "send"],
            ],
        )

    def test_callback_deadline_expiry_refuses_connect_or_send(self):
        for late_callback in (1, 2):
            with self.subTest(late_callback=late_callback):
                self.clock = 10.0
                self.stream.reset_mock()
                calls = 0

                def authorize():
                    nonlocal calls
                    calls += 1
                    if calls == late_callback:
                        self.clock = 10.6
                    return True

                with self.assertRaises(http.RuntimeHttpActionError) as raised:
                    http.execute_http_effect(
                        http.effect_for_attempt(ATTEMPT),
                        fixture_binding=BINDING,
                        deadline_monotonic=10.5,
                        authorize_effect=authorize,
                    )
                record = raised.exception.observation
                self.assertEqual(record["error_code"], "HTTP_DEADLINE_EXPIRED")
                self.assertEqual(
                    record["status"],
                    "NOT_PERFORMED" if late_callback == 1 else "INDETERMINATE",
                )
                self.assertEqual(self.stream.connect.call_count, late_callback - 1)
                self.stream.send.assert_not_called()

    def test_authorization_denial_or_failure_preserves_connection_boundary(self):
        for answers, exception, status, reason in (
            (
                [False],
                http.RuntimeHttpActionError,
                "NOT_PERFORMED",
                "HTTP_AUTHORIZATION_REFUSED",
            ),
            (
                [True, False],
                http.RuntimeHttpActionIndeterminate,
                "INDETERMINATE",
                "HTTP_AUTHORIZATION_REFUSED",
            ),
            (
                [True, OSError("private diagnostic")],
                http.RuntimeHttpActionIndeterminate,
                "INDETERMINATE",
                "HTTP_TRANSPORT_FAILED",
            ),
        ):
            with self.subTest(status=status, reason=reason):
                self.stream.reset_mock()
                authorize = MagicMock(side_effect=answers)
                with self.assertRaises(exception) as raised:
                    http.execute_http_effect(
                        http.effect_for_attempt(ATTEMPT),
                        fixture_binding=BINDING,
                        deadline_monotonic=10.5,
                        authorize_effect=authorize,
                    )
                record = raised.exception.observation
                self.assertEqual(record["status"], status)
                self.assertEqual(record["error_code"], reason)
                self.assertEqual(record["sent_bytes"], 0)
                self.assertEqual(
                    self.stream.connect.call_count, int(status == "INDETERMINATE")
                )
                self.stream.send.assert_not_called()
                self.assertNotIn("private diagnostic", repr(record))

    def test_refuses_expired_nonfinite_and_extended_deadlines_before_effect(self):
        for value in (10.0, 11.0, True, float("inf"), float("nan"), 10**500):
            with (
                self.subTest(value=value),
                self.assertRaises(http.RuntimeHttpActionError) as raised,
            ):
                self.execute(value)
            self.assertEqual(raised.exception.observation["status"], "NOT_PERFORMED")
        self.open.assert_not_called()
        self.guard.assert_not_called()

    def test_credential_guard_failure_never_opens_socket(self):
        self.guard.side_effect = http.RuntimeHttpActionError("HTTP_BINDING_REFUSED")
        with self.assertRaises(http.RuntimeHttpActionError) as raised:
            self.execute()
        self.assertEqual(raised.exception.observation["status"], "NOT_PERFORMED")
        self.open.assert_not_called()

    def test_connect_failure_is_indeterminate_even_without_sent_bytes(self):
        self.stream.connect.side_effect = OSError("private diagnostic")
        with self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised:
            self.execute()
        record = raised.exception.observation
        self.assertEqual(record["status"], "INDETERMINATE")
        self.assertEqual(record["sent_bytes"], 0)
        self.assertNotIn("private diagnostic", repr(record))
        self.stream.send.assert_not_called()
        self.stream.connect.assert_called_once()

    def test_send_exception_retains_unknown_byte_count(self):
        self.stream.send.side_effect = OSError("private diagnostic")
        with self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised:
            self.execute()
        self.assertIsNone(raised.exception.observation["sent_bytes"])
        self.stream.send.assert_called_once()
        self.stream.recv.assert_not_called()

    def test_partial_send_never_retries(self):
        self.stream.send.side_effect = None
        self.stream.send.return_value = 7
        with self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised:
            self.execute()
        self.assertEqual(raised.exception.observation["sent_bytes"], 7)
        self.assertEqual(raised.exception.observation["error_code"], "HTTP_SHORT_WRITE")
        self.stream.send.assert_called_once()
        self.stream.recv.assert_not_called()

    def test_timeout_after_connect_prevents_send(self):
        self.stream.connect.side_effect = lambda endpoint: setattr(self, "clock", 10.6)
        with self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised:
            self.execute()
        self.assertEqual(
            raised.exception.observation["error_code"], "HTTP_DEADLINE_EXPIRED"
        )
        self.stream.send.assert_not_called()

    def test_response_limit_retains_bounded_received_prefix(self):
        self.stream.recv.side_effect = [b"x" * (canary.MAX_BYTES + 1)]
        with self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised:
            self.execute()
        self.assertEqual(
            raised.exception.observation["response_bytes"], canary.MAX_BYTES + 1
        )
        self.stream.recv.assert_called_once()

    def test_wrong_response_is_indeterminate(self):
        self.stream.recv.side_effect = [b"wrong", b""]
        with self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised:
            self.execute()
        self.assertEqual(
            raised.exception.observation["error_code"], "HTTP_RESPONSE_REFUSED"
        )

    def test_guard_change_after_connect_prevents_send_and_retains_uncertainty(self):
        self.held.guard.side_effect = [
            None,
            http.RuntimeHttpActionError("HTTP_NAMESPACE_CHANGED"),
            None,
        ]
        with self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised:
            self.execute()
        self.assertEqual(
            raised.exception.observation["error_code"], "HTTP_NAMESPACE_CHANGED"
        )
        self.stream.send.assert_not_called()
        self.held.close.assert_called_once()

    def test_socket_and_guard_cleanup_failures_do_not_return_success(self):
        self.stream.close.side_effect = OSError("private diagnostic")
        with self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised:
            self.execute()
        self.assertEqual(
            raised.exception.observation["error_code"], "HTTP_SOCKET_CLOSE_FAILED"
        )
        self.held.close.assert_called_once()

    def test_guard_descriptor_close_failure_preserves_indeterminate_effect(self):
        self.held.close.side_effect = OSError("private diagnostic")
        with self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised:
            self.execute()
        self.assertEqual(
            raised.exception.observation["error_code"], "HTTP_GUARD_CLOSE_FAILED"
        )
        self.assertEqual(
            raised.exception.observation["sent_bytes"],
            len(canary.canary_request(ATTEMPT)),
        )
        self.held.close.assert_called_once()

    def test_invalid_send_count_is_unknown_and_never_retried(self):
        self.stream.send.side_effect = None
        self.stream.send.return_value = True
        with self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised:
            self.execute()
        self.assertIsNone(raised.exception.observation["sent_bytes"])
        self.assertEqual(
            raised.exception.observation["error_code"], "HTTP_TRANSPORT_RESULT_REFUSED"
        )
        self.stream.send.assert_called_once()

    def test_final_result_validation_failure_is_indeterminate(self):
        with (
            patch.object(
                http, "validate_result", side_effect=ValueError("private diagnostic")
            ),
            self.assertRaises(http.RuntimeHttpActionIndeterminate) as raised,
        ):
            self.execute()
        self.assertEqual(raised.exception.observation["status"], "INDETERMINATE")
        self.assertEqual(
            raised.exception.observation["error_code"], "HTTP_TRANSPORT_RESULT_REFUSED"
        )
        self.stream.send.assert_called_once()

    def test_interrupt_retains_counts_and_original_interrupt(self):
        interruption = KeyboardInterrupt("private diagnostic")
        self.stream.recv.side_effect = [b"HTTP/1.1", interruption]
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.execute()
        self.assertIs(raised.exception, interruption)
        result = raised.exception.http_action_observation
        self.assertEqual(result["response_bytes"], 8)
        self.assertEqual(result["sent_bytes"], len(canary.canary_request(ATTEMPT)))
        self.assertEqual(result["status"], "INDETERMINATE")
        self.assertNotIn("private diagnostic", repr(result))
        self.held.close.assert_called_once()

    def test_cleanup_interrupt_is_not_swallowed_by_prior_transport_error(self):
        interruption = KeyboardInterrupt()
        self.stream.connect.side_effect = OSError()
        self.stream.close.side_effect = interruption
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.execute()
        self.assertIs(raised.exception, interruption)
        self.assertEqual(
            raised.exception.http_action_observation["status"], "INDETERMINATE"
        )
        self.held.close.assert_called_once()

    def test_result_validator_refuses_false_success_and_rebound_identity(self):
        result = self.execute()
        for changed in (
            {**result, "sent_bytes": None},
            {**result, "response_digest": "sha256:" + "0" * 64},
            {**result, "fixture_binding_digest": "sha256:" + "0" * 64},
            {**result, "phase3_exit_eligible": True},
            {**result, "identity": None},
        ):
            with (
                self.subTest(changed=changed),
                self.assertRaises(http.RuntimeHttpActionError),
            ):
                http.validate_result(
                    changed,
                    effect=http.effect_for_attempt(ATTEMPT),
                    fixture_binding=BINDING,
                )
        binding = {
            **BINDING,
            "expected_broker_uid": 1,
            "expected_broker_gid": 1,
        }
        identity = {**result["identity"], "uid": 1, "gid": 1}
        for field in ("uid", "gid"):
            changed = {
                **result,
                "fixture_binding_digest": canonical_digest(binding),
                "action_digests": http.action_digests(ATTEMPT, binding),
                "identity": {**identity, field: True},
            }
            with (
                self.subTest(field=field),
                self.assertRaises(http.RuntimeHttpActionError),
            ):
                http.validate_result(
                    changed,
                    effect=http.effect_for_attempt(ATTEMPT),
                    fixture_binding=binding,
                )


if __name__ == "__main__":
    unittest.main()
