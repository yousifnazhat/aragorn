"""Focused readiness/listener joins and cleanup; no socket, child or service runs."""

from contextlib import nullcontext
from copy import deepcopy
import unittest
from unittest.mock import MagicMock, patch

from aragorn import native_phase3_http_broker_ready_capture as subject
from aragorn.oci_worker_protocol import canonical_json


FIXTURE = {
    "container_id": "a" * 64,
    "boot_id": "11111111-2222-3333-4444-555555555555",
    "netns_device": 4,
    "netns_inode": 9,
}
IDENTITY = {
    "fixture": FIXTURE,
    "pid": 42,
    "start_time_ticks": 123,
    "uid": 996,
    "gid": 997,
}


def witness():
    unit = subject.UNIT
    argv = [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        "/usr/libexec/aragorn/aragorn-runtime-action-service-v5.py",
        *(
            f"/run/credentials/{unit}/{name}"
            for name in (
                "runtime-binding",
                "capability-grant",
                "decision-measurement-binding",
            )
        ),
    ]
    status = "Uid:\t996 996 996 996\nGid:\t997 997 997 997\n" + "".join(
        key + ":\t" + value + "\n" for key, value in subject.readiness._SECURITY.items()
    )
    cgroup = f"/docker/{FIXTURE['container_id']}/system.slice/{unit}"
    raws = {
        "unit": f"Id={unit}\nMainPID=42\nControlGroup={cgroup}\nActiveState=active\nSubState=running\n".encode(),
        "stat": (
            "42 (broker) " + " ".join(["S", *(["0"] * 18), "123"]) + "\n"
        ).encode(),
        "status": status.encode(),
        "cgroup": f"0::{cgroup}\n".encode(),
        "cmdline": b"\0".join(arg.encode() for arg in argv) + b"\0",
        "unix": f"Num RefCount Protocol Flags Type St Inode Path\n0000: 00000002 00000000 00010000 0001 01 999 {subject.SOCKET}\n".encode(),
    }
    return {
        "schema": "aragorn/native-http-broker-listener-witness/v1",
        "broker_identity": deepcopy(IDENTITY),
        **{name + "_raw_hex": raw.hex() for name, raw in raws.items()},
        "network_namespace": {"device": 4, "inode": 9},
        "fd_links": {"7": "socket:[999]"},
        "socket_metadata": {
            "device": 1,
            "inode": 2,
            "uid": 996,
            "gid": 997,
            "mode": 0o660,
        },
        "pidfd_pid": 42,
        "observed_boottime_ns": 200,
    }


class BrokerReadyCaptureTests(unittest.TestCase):
    def verify(self, document):
        raw = canonical_json(document)
        return subject.verify_listener_witness(
            witness_raw=raw,
            expected_raw_digest=subject.canary.digest(raw),
            expected_broker_identity=IDENTITY,
        )

    def test_listener_requires_same_process_epoch_and_owned_listen_inode(self):
        self.assertTrue(self.verify(witness())["same_broker_process_listener_verified"])
        mutations = [
            (
                "stat_raw_hex",
                bytes.fromhex(witness()["stat_raw_hex"]).replace(b"123", b"124").hex(),
            ),
            (
                "unit_raw_hex",
                bytes.fromhex(witness()["unit_raw_hex"])
                .replace(b"MainPID=42", b"MainPID=43")
                .hex(),
            ),
            ("fd_links", {"7": "socket:[998]"}),
            (
                "unix_raw_hex",
                bytes.fromhex(witness()["unix_raw_hex"])
                .replace(b"00010000", b"00000000")
                .hex(),
            ),
            ("network_namespace", {"device": 4, "inode": 10}),
            ("pidfd_pid", True),
        ]
        for name, changed in mutations:
            with self.subTest(field=name):
                value = witness()
                value[name] = changed
                with self.assertRaises(subject.BrokerReadinessCaptureError):
                    self.verify(value)

    def test_unit_active_alone_and_weakened_sandbox_are_not_listener_proof(self):
        for name, old, new in (
            ("status", b"Seccomp:\t2", b"Seccomp:\t0"),
            ("status", b"CapEff:\t0000000000000000", b"CapEff:\t0000000000000001"),
            ("cgroup", b"/system.slice/", b"/other.slice/"),
            ("cmdline", b"decision-measurement-binding", b"other-binding"),
        ):
            with self.subTest(field=name, change=new):
                value = witness()
                value[name + "_raw_hex"] = (
                    bytes.fromhex(value[name + "_raw_hex"]).replace(old, new).hex()
                )
                with self.assertRaises(subject.BrokerReadinessCaptureError):
                    self.verify(value)
        value = witness()
        value["fd_links"] = {}
        with self.assertRaises(subject.BrokerReadinessCaptureError):
            self.verify(value)

    def test_duplicate_named_socket_and_changed_raw_digest_are_refused(self):
        value = witness()
        raw = bytes.fromhex(value["unix_raw_hex"])
        value["unix_raw_hex"] = (raw + raw.splitlines(keepends=True)[1]).hex()
        with self.assertRaises(subject.BrokerReadinessCaptureError):
            self.verify(value)
        raw = canonical_json(witness())
        with self.assertRaises(subject.BrokerReadinessCaptureError):
            subject.verify_listener_witness(
                witness_raw=raw,
                expected_raw_digest="sha256:" + "0" * 64,
                expected_broker_identity=IDENTITY,
            )

    def test_listener_parent_handle_closes_without_masking_kernel_read_failure(self):
        failure = ValueError("inert kernel refusal")
        with (
            patch.object(
                subject.readiness.core, "_open_protected_directory", return_value=15
            ),
            patch.object(subject.os, "fstat"),
            patch.object(
                subject.readiness.core, "_directory_identity", return_value=(1, 2)
            ),
            patch.object(subject, "_read_listener", side_effect=failure),
            patch.object(
                subject.os, "close", side_effect=OSError("inert close failure")
            ) as close,
        ):
            with self.assertRaises(ValueError) as caught:
                subject._witness(IDENTITY, 11)
        self.assertIs(caught.exception, failure)
        close.assert_called_once_with(15)
        self.assertIn("HTTP_READY_SOCKET_PARENT_CLOSE_FAILED", failure.__notes__)

    def context(self, source=b"source"):
        self.enterContext(patch.object(subject, "_read_fixed", return_value=source))
        self.enterContext(
            patch.object(
                subject, "owned_http_fixture", return_value=nullcontext(MagicMock())
            )
        )
        self.enterContext(patch.object(subject.os.path, "lexists", return_value=False))
        self.enterContext(patch.object(subject.os, "pipe2", return_value=(10, 12), create=True))
        self.enterContext(patch.object(subject.os, "fork", return_value=77))
        self.enterContext(patch.object(subject.os, "close"))
        self.enterContext(patch.object(subject, "_pidfd", return_value=11))
        identity = {"fixture": FIXTURE, "process": {"pid": 77}}
        self.enterContext(
            patch.object(subject._Capture, "_child_identity", return_value=identity)
        )
        self.enterContext(
            patch.object(
                subject._Capture,
                "_receive",
                return_value={"kind": "LISTENING", "identity": identity},
            )
        )
        close = self.enterContext(patch.object(subject._Capture, "close"))
        return subject.capture_broker_readiness(
            expected_fixture=FIXTURE,
            attempt_id="p3-lab-a001",
            readiness_nonce="b" * 32,
            expected_source_digest=subject.canary.digest(source),
        ), close

    def test_success_is_not_published_until_context_and_handles_close(self):
        context, close = self.context()
        with context as capture:
            capture.consumed = True
            capture.report["status"] = "OBSERVED"
            self.assertFalse(capture.report["cleanup_complete"])
        self.assertTrue(capture.report["cleanup_complete"])
        self.assertGreaterEqual(close.call_count, 1)

    def test_body_failure_and_partial_observation_survive_cleanup_failure(self):
        context, close = self.context()
        failure = ValueError("activation refused")
        close.side_effect = OSError("inert close failure")
        with self.assertRaises(ValueError) as caught:
            with context as capture:
                capture.report["sink"] = {"partial": True}
                raise failure
        self.assertIs(caught.exception, failure)
        self.assertEqual(
            failure.http_broker_readiness_observation["sink"], {"partial": True}
        )
        self.assertFalse(failure.http_broker_readiness_observation["cleanup_complete"])

    def test_existing_claim_refuses_before_any_child_or_socket(self):
        context, _ = self.context()
        with (
            patch.object(subject.os.path, "lexists", return_value=True),
            patch.object(subject.os, "fork") as fork,
        ):
            with self.assertRaisesRegex(
                subject.BrokerReadinessCaptureError, "ALREADY_CONSUMED"
            ):
                with context:
                    self.fail("unexpected listener")
            fork.assert_not_called()

    def test_cleanup_cancels_only_owned_child_retains_sink_and_closes_all_handles(self):
        capture = subject._Capture(FIXTURE, b"source")
        capture.pid, capture.reader, capture.pidfd, capture.broker_pidfd = (
            77,
            10,
            11,
            12,
        )
        with (
            patch.object(subject.os, "kill") as kill,
            patch.object(subject.os, "close") as close,
            patch.object(
                capture,
                "_receive",
                return_value={"kind": "RESULT", "sink": {"partial": True}},
            ),
            patch.object(capture, "_reap"),
        ):
            capture.close()
        kill.assert_called_once_with(77, subject.signal.SIGTERM)
        self.assertEqual(capture.report["sink"]["document"], {"partial": True})
        self.assertEqual([call.args[0] for call in close.call_args_list], [10, 11, 12])
        self.assertIsNone(capture.reader)
        self.assertFalse(capture.report["cleanup_complete"])


if __name__ == "__main__":
    unittest.main()
