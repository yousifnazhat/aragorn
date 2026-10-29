"""New broker readiness branches only; all OS, socket and service effects inert."""

from contextlib import nullcontext
from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from aragorn import runtime_http_readiness as subject
from aragorn import native_phase3_http_readiness_verify as verifier
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_runtime_http_readiness as renderer
from scripts import stage_runtime_phase3_http_profile as http_stage

FIXTURE = {
    "container_id": "a" * 64,
    "boot_id": "11111111-2222-3333-4444-555555555555",
    "netns_device": 4,
    "netns_inode": 9,
}
BINDING = {
    "schema": "aragorn/runtime-http-fixture-binding/v1",
    "fixture": FIXTURE,
    "expected_broker_uid": 996,
    "expected_broker_gid": 997,
}
IDENTITY = {
    "fixture": FIXTURE,
    "pid": 42,
    "start_time_ticks": 123,
    "uid": 996,
    "gid": 997,
}
NONCE = "b" * 32


def request():
    return subject.build_readiness_input(fixture_binding=BINDING, readiness_nonce=NONCE)


def claim():
    return {
        "schema": subject.CLAIM_SCHEMA,
        "authority": subject.AUTHORITY,
        "request_digest": canonical_digest(request()),
        "fixture_binding_digest": canonical_digest(BINDING),
        "identity": deepcopy(IDENTITY),
        "claimed_boottime_ns": 500,
    }


class ReadinessTests(unittest.TestCase):
    def probe(self):
        held = SimpleNamespace(
            identity=MagicMock(return_value=deepcopy(IDENTITY)),
            guard=MagicMock(),
            close=MagicMock(),
        )
        stream = MagicMock()
        stream.getsockname.return_value = ("127.0.0.1", 34567)
        stream.send.return_value = len(subject.canary.readiness_request(NONCE))
        stream.recv.side_effect = [subject.canary.RESPONSE_BYTES, b""]
        guard = self.enterContext(
            patch.object(subject.http, "_ExecutionGuard", return_value=held)
        )
        socket = self.enterContext(
            patch.object(subject.socket, "socket", return_value=stream)
        )
        security = self.enterContext(
            patch.object(subject, "_security", return_value=dict(subject._SECURITY))
        )
        self.enterContext(patch.object(subject.time, "monotonic", return_value=1.0))
        self.enterContext(patch.object(subject, "_now", side_effect=[1000, 2000]))
        return held, stream, guard, socket, security

    def test_actual_broker_guard_precedes_one_body_free_get(self):
        held, stream, guard, socket, _ = self.probe()
        result = subject._probe(request(), BINDING, claim())
        guard.assert_called_once_with(BINDING)
        socket.assert_called_once_with(
            subject.socket.AF_INET, subject.socket.SOCK_STREAM
        )
        stream.connect.assert_called_once_with(("127.0.0.1", 47631))
        stream.send.assert_called_once_with(subject.canary.readiness_request(NONCE))
        self.assertNotIn(b"POST", stream.send.call_args.args[0])
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["identity"], IDENTITY)
        self.assertEqual(result["local_port"], 34567)
        held.close.assert_called_once()
        stream.close.assert_called_once()
        self.assertTrue(all(result[key] is False for key in subject.FALSE_FLAGS))

    def test_guard_refusal_never_opens_socket(self):
        _, _, guard, socket, _ = self.probe()
        guard.side_effect = subject.http.RuntimeHttpActionError(
            "HTTP_ENVIRONMENT_REFUSED"
        )
        with self.assertRaises(subject.HttpReadinessError) as caught:
            subject._probe(request(), BINDING, claim())
        self.assertEqual(
            caught.exception.http_readiness_observation["status"], "NOT_PERFORMED"
        )
        socket.assert_not_called()

    def test_changed_capability_or_seccomp_state_blocks_before_connect(self):
        _, stream, _, _, security = self.probe()
        security.side_effect = subject.HttpReadinessError("inert restrictions")
        with self.assertRaises(subject.HttpReadinessError):
            subject._probe(request(), BINDING, claim())
        stream.connect.assert_not_called()

    def test_short_send_never_retries_or_reports_ready(self):
        _, stream, _, _, _ = self.probe()
        stream.send.return_value = 2
        with self.assertRaises(subject.HttpReadinessError) as caught:
            subject._probe(request(), BINDING, claim())
        self.assertEqual(
            caught.exception.http_readiness_observation["status"], "INDETERMINATE"
        )
        self.assertEqual(caught.exception.http_readiness_observation["sent_bytes"], 2)
        self.assertEqual(stream.send.call_count, 1)
        stream.recv.assert_not_called()

    def test_interrupted_send_retains_unknown_count_and_interrupt(self):
        _, stream, _, _, _ = self.probe()
        interrupt = KeyboardInterrupt()
        stream.send.side_effect = interrupt
        stream.close.side_effect = OSError("inert close")
        with self.assertRaises(KeyboardInterrupt) as caught:
            subject._probe(request(), BINDING, claim())
        self.assertIs(caught.exception, interrupt)
        self.assertIsNone(interrupt.http_readiness_observation["sent_bytes"])
        self.assertEqual(
            interrupt.http_readiness_observation["status"], "INDETERMINATE"
        )

    def test_response_mismatch_or_oversize_refuses(self):
        _, stream, _, _, _ = self.probe()
        stream.recv.side_effect = [b"x" * 4097]
        with self.assertRaises(subject.HttpReadinessError) as caught:
            subject._probe(request(), BINDING, claim())
        self.assertEqual(
            caught.exception.http_readiness_observation["response_bytes"], 4097
        )
        self.assertEqual(
            caught.exception.http_readiness_observation["status"], "INDETERMINATE"
        )

    def test_postconnect_timeout_is_indeterminate_without_retry(self):
        _, stream, _, _, _ = self.probe()
        stream.connect.side_effect = TimeoutError()
        with self.assertRaises(subject.HttpReadinessError) as caught:
            subject._probe(request(), BINDING, claim())
        self.assertTrue(
            caught.exception.http_readiness_observation["connect_attempted"]
        )
        self.assertEqual(stream.connect.call_count, 1)
        stream.send.assert_not_called()

    def test_guard_close_failure_cannot_return_ready(self):
        held, _, _, _, _ = self.probe()
        held.close.side_effect = OSError("inert guard close")
        with self.assertRaises(subject.HttpReadinessError) as caught:
            subject._probe(request(), BINDING, claim())
        self.assertEqual(
            caught.exception.http_readiness_observation["status"], "INDETERMINATE"
        )

    def test_fixed_request_forbids_url_and_timeout_overrides(self):
        for changed in (
            request() | {"url": "http://elsewhere"},
            request() | {"timeout_ms": 501},
        ):
            with self.assertRaises(subject.HttpReadinessError):
                subject._input(canonical_json(changed), BINDING)

    def test_security_reads_only_bounded_self_status_and_requires_all_zero_caps(self):
        raw = b"".join(
            (name + ":\t" + value + "\n").encode()
            for name, value in subject._SECURITY.items()
        )
        with patch.object(subject.http, "_read", return_value=raw) as read:
            self.assertEqual(subject._security(), subject._SECURITY)
        read.assert_called_once_with("/proc/self/status", 16384)
        for changed in (
            raw + b"Seccomp:\t2\n",
            raw.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0"),
            raw.replace(b"CapEff:\t0000000000000000", b"CapEff:\t0000000000000001"),
        ):
            with (
                patch.object(subject.http, "_read", return_value=changed),
                self.assertRaises(subject.HttpReadinessError),
            ):
                subject._security()

    def startup(self):
        events = []
        raw, metadata = canonical_json(request()), {"identity": [1, 2]}
        held = SimpleNamespace(
            identity=MagicMock(return_value=deepcopy(IDENTITY)),
            guard=MagicMock(),
            close=MagicMock(side_effect=lambda: events.append("closed")),
        )
        self.enterContext(
            patch.object(subject.http, "load_fixture_binding", return_value=BINDING)
        )
        self.enterContext(
            patch.object(subject.http, "_ExecutionGuard", return_value=held)
        )
        reader = self.enterContext(
            patch.object(subject, "_read_owned", return_value=(raw, metadata))
        )
        self.enterContext(
            patch.object(subject, "_security", return_value=subject._SECURITY)
        )
        self.enterContext(patch.object(subject, "_now", return_value=500))
        self.enterContext(patch.object(subject.os.path, "lexists", return_value=False))
        writes = []

        def publish(path, raw, _binding):
            events.append(path.name)
            writes.append((path, json.loads(raw)))

        writer = self.enterContext(
            patch.object(subject, "_publish_absent", side_effect=publish)
        )
        record = {"status": "READY", "connect_attempted": True, "error_code": None}
        probe = self.enterContext(
            patch.object(
                subject,
                "_probe",
                side_effect=lambda *_: events.append("probe") or record,
            )
        )
        return held, reader, writer, probe, events, writes, record

    def test_durable_claim_before_probe_final_cleanup_before_result(self):
        _, reader, _, probe, events, writes, _ = self.startup()
        self.assertEqual(subject.run_startup_readiness()["status"], "READY")
        self.assertEqual(
            events, [subject.CLAIM.name, "probe", "closed", subject.RESULT.name]
        )
        self.assertEqual(reader.call_count, 3)
        self.assertEqual(writes[0][1]["schema"], subject.CLAIM_SCHEMA)
        probe.assert_called_once()

    def test_existing_claim_blocks_restart_without_probe(self):
        _, _, writer, probe, _, _, _ = self.startup()
        writer.side_effect = FileExistsError("inert existing claim")
        with self.assertRaises(FileExistsError):
            subject.run_startup_readiness()
        writer.assert_called_once()
        probe.assert_not_called()

    def test_outer_guard_close_failure_publishes_only_indeterminate(self):
        held, _, _, _, _, writes, _ = self.startup()
        held.close.side_effect = OSError("inert close")
        with self.assertRaises(OSError):
            subject.run_startup_readiness()
        self.assertEqual(writes[-1][1]["status"], "INDETERMINATE")

    def test_post_probe_credential_mutation_prevents_ready_result(self):
        _, reader, _, _, _, writes, _ = self.startup()
        good = reader.return_value
        reader.side_effect = [good, good, (good[0], {"identity": [9, 9]})]
        with self.assertRaises(subject.HttpReadinessError):
            subject.run_startup_readiness()
        self.assertEqual(writes[-1][1]["status"], "INDETERMINATE")

    def test_interruption_survives_result_publication_failure(self):
        _, _, writer, probe, _, _, record = self.startup()
        interrupt = KeyboardInterrupt()
        interrupt.http_readiness_observation = record
        probe.side_effect = interrupt
        writer.side_effect = [None, OSError("inert publication")]
        with self.assertRaises(KeyboardInterrupt) as caught:
            subject.run_startup_readiness()
        self.assertIs(caught.exception, interrupt)
        self.assertEqual(
            interrupt.http_readiness_observation["status"], "INDETERMINATE"
        )

    def test_root_provision_checks_stopped_fixture_before_single_write(self):
        held = SimpleNamespace(guard=MagicMock())
        with (
            patch.object(subject, "owned_http_fixture", return_value=nullcontext(held)),
            patch.object(subject.http, "load_fixture_binding", return_value=BINDING),
            patch.object(subject.provision, "_new_binding", return_value=BINDING),
            patch.object(subject.provision, "_stopped") as stopped,
            patch.object(subject.os.path, "lexists", return_value=False),
            patch.object(
                subject, "_publish_absent", return_value={"completed": True}
            ) as write,
        ):
            result = subject.provision_readiness_input(
                expected_fixture=FIXTURE, readiness_nonce=NONCE
            )
        write.assert_called_once_with(
            subject.CREDENTIAL, canonical_json(request()), BINDING, root_writer=True
        )
        self.assertEqual(stopped.call_count, 2)
        self.assertFalse(result["activation_performed"])

    def test_active_service_refuses_root_publication(self):
        with (
            patch.object(
                subject,
                "owned_http_fixture",
                return_value=nullcontext(SimpleNamespace(guard=MagicMock())),
            ),
            patch.object(subject.http, "load_fixture_binding", return_value=BINDING),
            patch.object(subject.provision, "_new_binding", return_value=BINDING),
            patch.object(
                subject.provision, "_stopped", side_effect=ValueError("active")
            ),
            patch.object(subject, "_publish_absent") as write,
        ):
            with self.assertRaises(ValueError):
                subject.provision_readiness_input(
                    expected_fixture=FIXTURE, readiness_nonce=NONCE
                )
        write.assert_not_called()


class ReadinessRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original, replacements, _ = http_stage._verified_payloads()
        merged = original | replacements
        cls.inputs = {key: merged[key][2] for key in renderer.INPUTS}

    def test_exact_http93_service_and_unit_only(self):
        outputs = renderer.render(self.inputs)
        self.assertEqual(set(outputs), {renderer.SERVICE, renderer.UNIT})
        service, unit = outputs[renderer.SERVICE], outputs[renderer.UNIT]
        self.assertIn(b'if state["status"] == "EXPIRED":\n        return\n', service)
        self.assertLess(
            service.index(b"    run_startup_readiness()"),
            service.index(b"    serve_runtime_action_broker_v5(config)"),
        )
        self.assertIn(b"ReadOnlyPaths=/etc/aragorn/runtime-http-readiness.json\n", unit)
        for line in (
            b"User=aragorn-broker",
            b"NoNewPrivileges=yes",
            b"CapabilityBoundingSet=",
            b"IPAddressDeny=any",
            b"IPAddressAllow=127.0.0.1/32",
            b"TasksMax=2",
            b"Restart=no",
        ):
            self.assertIn(line + b"\n", unit)

    def test_changed_or_repository_predecessor_refused(self):
        for changes in (
            {},
            self.inputs | {renderer.SERVICE: self.inputs[renderer.SERVICE] + b"\n"},
        ):
            with self.assertRaises(renderer.HttpReadinessRenderError):
                renderer.render(changes)


class ReadinessPublicationTests(unittest.TestCase):
    def setUp(self):
        self.raw = canonical_json(request())
        self.parent = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=996,
            st_gid=997,
            st_nlink=1,
            st_size=0,
            st_mtime_ns=3,
            st_ctime_ns=4,
        )
        self.file = SimpleNamespace(
            st_dev=1,
            st_ino=5,
            st_mode=stat.S_IFREG | 0o400,
            st_uid=996,
            st_gid=997,
            st_nlink=1,
            st_size=0,
            st_mtime_ns=6,
            st_ctime_ns=7,
        )
        self.enterContext(
            patch.object(subject.core, "_open_protected_directory", return_value=10)
        )
        self.enterContext(patch.object(Path, "lstat", return_value=self.parent))
        names = (
            "O_RDONLY",
            "O_DIRECTORY",
            "O_NONBLOCK",
            "O_WRONLY",
            "O_CREAT",
            "O_EXCL",
            "O_NOFOLLOW",
            "O_CLOEXEC",
        )
        self.os = SimpleNamespace(
            **{name: getattr(subject.os, name) for name in names},
            geteuid=MagicMock(return_value=996),
            open=MagicMock(return_value=11),
            fstat=MagicMock(
                side_effect=lambda fd: self.parent if fd == 10 else self.file
            ),
            fchown=MagicMock(),
            fchmod=MagicMock(),
            write=MagicMock(side_effect=lambda _fd, raw: len(raw)),
            fsync=MagicMock(),
            close=MagicMock(),
            read=MagicMock(side_effect=[self.raw, b""]),
            stat=MagicMock(return_value=self.file),
        )
        self.enterContext(patch.object(subject, "os", self.os))

    def test_one_absent_only_write_has_exact_owner_mode_and_readback(self):
        with patch.object(subject, "_read_owned", return_value=(self.raw, {})):
            result = subject._publish_absent(subject.CLAIM, self.raw, BINDING)
        self.assertTrue(result["completed"])
        self.os.write.assert_called_once_with(11, self.raw)
        self.assertTrue(self.os.open.call_args.args[1] & self.os.O_EXCL)
        self.os.fchmod.assert_called_once_with(11, 0o400)
        self.os.fchown.assert_not_called()
        self.assertEqual(
            [call.args[0] for call in self.os.close.call_args_list], [11, 10]
        )

    def test_existing_claim_never_repaired(self):
        self.os.open.side_effect = FileExistsError()
        with self.assertRaises(FileExistsError) as caught:
            subject._publish_absent(subject.CLAIM, self.raw, BINDING)
        self.assertIsNone(caught.exception.http_readiness_publication["created"])
        self.os.write.assert_not_called()

    def test_interrupted_write_preserves_unknown_count_and_closes_both(self):
        self.os.write.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            subject._publish_absent(subject.CLAIM, self.raw, BINDING)
        self.assertIsNone(caught.exception.http_readiness_publication["bytes_written"])
        self.assertEqual(self.os.close.call_count, 2)

    def test_short_write_is_not_retried(self):
        self.os.write.side_effect = None
        self.os.write.return_value = 1
        with self.assertRaises(subject.HttpReadinessError) as caught:
            subject._publish_absent(subject.CLAIM, self.raw, BINDING)
        self.assertEqual(
            caught.exception.http_readiness_publication["bytes_written"], 1
        )
        self.assertEqual(self.os.write.call_count, 1)

    def test_final_close_failure_clears_publication_completion(self):
        self.os.close.side_effect = [OSError("close"), None]
        with (
            patch.object(subject, "_read_owned", return_value=(self.raw, {})),
            self.assertRaises(OSError) as caught,
        ):
            subject._publish_absent(subject.CLAIM, self.raw, BINDING)
        self.assertFalse(caught.exception.http_readiness_publication["completed"])
        self.assertTrue(caught.exception.http_readiness_publication["cleanup_failed"])

    def test_protected_read_is_bounded_and_identity_checked(self):
        self.file.st_size = len(self.raw)
        raw, _ = subject._read_owned(subject.CLAIM, uid=996, gid=997, mode=0o400)
        self.assertEqual(raw, self.raw)
        self.assertTrue(self.os.open.call_args.args[1] & self.os.O_NONBLOCK)
        self.assertTrue(self.os.open.call_args.args[1] & self.os.O_NOFOLLOW)

    def test_credential_group_or_symlink_refused_before_read(self):
        self.file.st_gid = 999
        with self.assertRaises(subject.HttpReadinessError):
            subject._read_owned(subject.CLAIM, uid=996, gid=997, mode=0o400)
        self.os.read.assert_not_called()


class ReadinessVerifierTests(unittest.TestCase):
    def fixture(self):
        cls = ReadinessTests(
            methodName="test_actual_broker_guard_precedes_one_body_free_get"
        )
        self.addCleanup(cls.doCleanups)
        cls.probe()
        result = subject._probe(request(), BINDING, claim())
        sink_identity = {
            "fixture": FIXTURE,
            "process": {"pid": 77, "start_time_ticks": 321, "uid": 0, "gid": 0},
            "init_process": {"pid": 1, "start_time_ticks": 1, "uid": 0, "gid": 0},
        }
        sink = {
            "schema": subject.canary.SINK_SCHEMA,
            "authority": subject.canary.SINK_AUTHORITY,
            "identity": sink_identity,
            "attempt_id": "p3-lab-a001",
            "readiness_nonce": NONCE,
            "endpoint": {"host": "127.0.0.1", "port": 47631},
            "readiness": {
                "peer_host": "127.0.0.1",
                "peer_port": 34567,
                "accepted_boottime_ns": 1100,
                "completed_boottime_ns": 1900,
                "raw_hex": subject.canary.readiness_request(NONCE).hex(),
                "eof": True,
                "truncated": False,
                "response_bytes": len(subject.canary.RESPONSE_BYTES),
                "error_code": None,
            },
            "interval": {
                "clock_id": "CLOCK_BOOTTIME",
                "readiness_started_ns": 900,
                "started_ns": None,
                "finished_ns": None,
            },
            "connections": [],
            "listener_closed": True,
            "complete": False,
            "errors": [],
            "limitations": list(subject.canary.LIMITATIONS),
            **dict.fromkeys(subject.canary.FALSE_FLAGS, False),
        }
        return {
            "request": request(),
            "claim": claim(),
            "result": result,
            "sink": sink,
        }, sink_identity

    def verify(self, records, sink_identity):
        raws = {key: canonical_json(value) for key, value in records.items()}
        return verifier.verify_broker_readiness(
            **{key + "_raw": value for key, value in raws.items()},
            expected_digests={
                key: subject.canary.digest(value) for key, value in raws.items()
            },
            expected_fixture_binding=BINDING,
            expected_broker_identity=IDENTITY,
            expected_sink_identity=sink_identity,
        )

    def test_independent_sink_process_nonce_port_and_clock_join(self):
        records, sink_identity = self.fixture()
        verified = self.verify(records, sink_identity)
        self.assertTrue(verified["broker_process_round_trip_verified"])
        self.assertFalse(verified["broker_restricted_readiness_verified"])
        self.assertFalse(verified["phase3_exit_eligible"])

    def test_root_client_does_not_count_as_broker_readiness(self):
        records, sink_identity = self.fixture()
        records["result"]["identity"]["uid"] = 0
        with self.assertRaises(ValueError):
            self.verify(records, sink_identity)

    def test_changed_sink_nonce_port_or_boottime_refused(self):
        original, sink_identity = self.fixture()
        for field, changed in (
            ("peer_port", 34568),
            ("accepted_boottime_ns", 899),
            ("raw_hex", subject.canary.readiness_request("c" * 32).hex()),
        ):
            records = deepcopy(original)
            records["sink"]["readiness"][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(records, sink_identity)

    def test_qualified_or_incomplete_client_result_refused(self):
        original, sink_identity = self.fixture()
        for field, changed in (
            ("phase3_exit_eligible", True),
            ("status", "INDETERMINATE"),
            ("security", {}),
        ):
            records = deepcopy(original)
            records["result"][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(records, sink_identity)


class PrivateFileReadinessTests(unittest.TestCase):
    """Real private temporary files; never root paths or a broker process.

    Caller UID/GID stand in for the broker. Only unrelated parent-ancestry
    observations are stubbed; the actual owned directory, no-follow opens,
    O_EXCL, file metadata, bounded reads, writes and close paths are exercised.
    """

    def setUp(self):
        self.directory = self.enterContext(
            tempfile.TemporaryDirectory(prefix="aragorn-readiness-unit-")
        )
        self.root = Path(self.directory).resolve()
        self.claim = self.root / "used.json"
        self.binding = {
            **BINDING,
            "expected_broker_uid": os.geteuid(),
            "expected_broker_gid": self.root.stat().st_gid,
        }
        self.raw = canonical_json(request())
        self.enterContext(patch.object(subject, "CLAIM", self.claim))
        self.enterContext(patch.object(subject, "RESULT", self.root / "result.json"))
        self.enterContext(patch.object(subject.core, "_require_protected_ancestry"))

    def read(self):
        return subject._read_owned(
            self.claim,
            uid=self.binding["expected_broker_uid"],
            gid=self.binding["expected_broker_gid"],
            mode=0o400,
        )

    def test_private_absent_only_publication_and_protected_readback(self):
        result = subject._publish_absent(self.claim, self.raw, self.binding)
        raw, _ = self.read()
        self.assertTrue(result["completed"])
        self.assertEqual(raw, self.raw)
        info = self.claim.stat(follow_symlinks=False)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o400)
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(info.st_uid, os.geteuid())

    def test_private_existing_claim_is_preserved(self):
        subject._publish_absent(self.claim, self.raw, self.binding)
        with self.assertRaises(FileExistsError):
            subject._publish_absent(self.claim, b"different", self.binding)
        self.assertEqual(self.claim.read_bytes(), self.raw)

    def test_private_symlink_is_not_followed(self):
        target = self.root / "inert-target"
        target.write_bytes(self.raw)
        target.chmod(0o400)
        self.claim.symlink_to(target)
        with self.assertRaises(OSError):
            self.read()
        with self.assertRaises(FileExistsError):
            subject._publish_absent(self.claim, self.raw, self.binding)
        self.assertEqual(target.read_bytes(), self.raw)

    def test_private_wrong_mode_is_refused(self):
        self.claim.write_bytes(self.raw)
        self.claim.chmod(0o600)
        with self.assertRaises(subject.HttpReadinessError):
            self.read()
        self.assertEqual(self.claim.read_bytes(), self.raw)

    def test_private_short_write_retains_exact_partial_file(self):
        real_write = os.write
        with patch.object(
            subject.os, "write", side_effect=lambda fd, raw: real_write(fd, raw[:3])
        ) as write:
            with self.assertRaises(subject.HttpReadinessError) as caught:
                subject._publish_absent(self.claim, self.raw, self.binding)
        self.assertEqual(write.call_count, 1)
        self.assertTrue(caught.exception.http_readiness_publication["created"])
        self.assertEqual(
            caught.exception.http_readiness_publication["bytes_written"], 3
        )
        self.assertEqual(self.claim.read_bytes(), self.raw[:3])


if __name__ == "__main__":
    unittest.main()
