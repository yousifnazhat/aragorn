"""Inert fixed-workload orchestration and descriptor/subprocess doubles only.

No service, guest, driver, revocation publisher or historical test is executed.
The positive orchestration path is test-double evidence, not live qualification.
"""

import ast
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import runtime_native_blocked_create_workload as subject


CONTAINER = "c" * 64
PIN = "sha256:" + "a" * 64
GENESIS = "sha256:" + "b" * 64
NODE_PIN = "sha256:3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37"
TOKEN = "d" * 64
WORKER = "/etc/aragorn/runtime-action-worker.json"
GENESIS_PATH = "/etc/aragorn/runtime-native-tool-genesis.json"
BROKER_SOURCE = "/usr/lib/aragorn/aragorn/runtime_action_broker.py"
DESCRIPTOR = {
    "schema": "aragorn/runtime-protected-path/v1",
    "root_device": 7,
    "root_inode": 44,
    "target_name": "runtime-worker-qualified.txt",
}
ACCOUNTS = {"broker_uid": 993, "broker_gid": 993, "runtime_gid": 997}
PROCESSES = {
    "worker": {"pid": 100, "start_time_ticks": 1000, "uid": 992, "gid": 997},
    "broker": {"pid": 101, "start_time_ticks": 1001, "uid": 993, "gid": 997},
    "gateway": {"pid": 102, "start_time_ticks": 1002, "uid": 994, "gid": 994},
}


class NativeBlockedCreateWorkloadTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.arguments = {
            "expected_container_id": CONTAINER,
            "expected_genesis_digest": GENESIS,
            "expected_path_descriptor": deepcopy(DESCRIPTOR),
            "expected_sink_source_digest": PIN,
            "expected_sink_accounts": deepcopy(ACCOUNTS),
            "expected_workload_source_digest": PIN,
            "expected_revocation_source_digest": PIN,
            "expected_file_digests": {
                subject._NODE: NODE_PIN,
                WORKER: PIN,
                GENESIS_PATH: GENESIS,
                BROKER_SOURCE: PIN,
            },
            "expected_processes": deepcopy(PROCESSES),
            "nonce": "e" * 32,
        }
        self.before = {
            "files": {GENESIS_PATH: {"digest": GENESIS}},
            "processes": {
                role: {
                    "pid": record["pid"],
                    "start_time_ticks": record["start_time_ticks"],
                    "uids": [record["uid"]] * 4,
                    "gids": [record["gid"]] * 4,
                    "cgroup": "/fixed/" + role,
                }
                for role, record in PROCESSES.items()
            },
            "measured_joins": {
                "declared_input_digests_not_cas_readback": {
                    "path_digest": subject._digest(subject._canonical(DESCRIPTOR)),
                    "payload_digest": subject._digest(
                        b"Aragorn P3.7b distinct worker create\n"
                    ),
                }
            },
        }
        self.binding = {
            "policy_digest": PIN,
            "runtime_digest": PIN,
            "active_skill_digest": PIN,
        }
        published = {"generation": 2, "revoked_skill_digests": [PIN]}
        self.publication = {
            "status": "PUBLISHED",
            "child_attempted": True,
            "publication": {"published": subject._record(published)},
        }
        self.driver = {
            "schema": "aragorn/native-blocked-create-tool-driver/v1",
            "status": "OBSERVED",
            "container_id": CONTAINER,
            "source_result": {
                "document": {
                    "status": "COMPLETED",
                    "broker_result": {
                        "verdict": "BLOCK",
                        "effect_status": "NOT_PERFORMED",
                        "decision": {
                            "reason_codes": ["ACTIVE_SKILL_REVOKED"],
                            "revocation_snapshot_digest": self.publication[
                                "publication"
                            ]["published"]["digest"],
                            "revocation_generation": 2,
                        },
                    },
                }
            },
        }
        self.observation = {
            "directories": {
                role: {
                    "empty": True,
                    "scan_complete": True,
                    "entry_count_lower_bound": 0,
                }
                for role in ("protected", "staging")
            },
            "target": {"status": "ABSENT"},
        }
        self.after_error = None

    def harness(self, stack):
        def replace(owner, name, **kwargs):
            return stack.enter_context(patch.object(owner, name, **kwargs))

        self.environment = replace(
            subject,
            "_environment",
            side_effect=lambda *_: self.events.append("environment"),
        )
        self.sources = replace(
            subject,
            "_sources",
            side_effect=lambda *_: self.events.append("sources") or {"fixed": PIN},
        )
        self.read_identity = Mock(
            side_effect=lambda **_: (
                self.events.append("identity") or deepcopy(self.before)
            )
        )
        self.compare = Mock(return_value={"status": "CALLER_COMMON_MEASUREMENTS_EQUAL"})
        common = SimpleNamespace(
            read_native_common_identity=self.read_identity,
            compare_native_common_identity=self.compare,
            prior=SimpleNamespace(_GENESIS=GENESIS_PATH, _WORKER=WORKER),
        )

        def snapshot(expected, count):
            self.assertEqual(expected, GENESIS)
            self.events.append("receipt:" + str(count))
            if count == 2 and self.after_error is not None:
                raise self.after_error
            return {
                "genesis": {"digest": GENESIS},
                "state": {"count": count},
                "receipts": ["inert"] * count,
                "state_digest": PIN,
            }

        self.snapshot = Mock(side_effect=snapshot)
        native = SimpleNamespace(_snapshot=self.snapshot)
        self.sink_after = Mock(
            side_effect=lambda: (
                self.events.append("sink:after") or deepcopy(self.observation)
            )
        )
        self.session = SimpleNamespace(
            before=deepcopy(self.observation), after=self.sink_after, failures=[]
        )

        @contextmanager
        def sink_session(**_):
            self.events.append("sink:enter")
            try:
                yield self.session
            finally:
                self.events.append("sink:close")

        sink = SimpleNamespace(
            hold_native_denied_create_sink=Mock(side_effect=sink_session)
        )
        self.publish = Mock(
            side_effect=lambda **_: (
                self.events.append("publish") or deepcopy(self.publication)
            )
        )
        revocation = SimpleNamespace(
            publish_native_blocked_create_revocation=self.publish
        )
        self.helpers = replace(
            subject,
            "_helpers",
            side_effect=lambda: (
                self.events.append("imports") or (native, common, sink, revocation)
            ),
        )
        self.live_guard = Mock(side_effect=lambda: self.events.append("live:guard"))

        @contextmanager
        def live(*_):
            self.events.append("live:enter")
            try:
                yield self.live_guard
            finally:
                self.events.append("live:close")

        replace(subject, "_live_processes", side_effect=live)
        self.attempt_guard = Mock(
            side_effect=lambda: self.events.append("attempt:guard")
        )

        @contextmanager
        def attempt(raw, claim):
            self.assertEqual(raw, subject._input(self.arguments["nonce"]))
            self.events.append("claim")
            claim["attempt_claimed"] = True
            try:
                yield 20, self.attempt_guard
            finally:
                self.events.append("attempt:close")

        self.attempt = replace(subject, "_attempt_files", side_effect=attempt)
        replace(subject, "_worker_binding", return_value=deepcopy(self.binding))
        self.token = replace(
            subject,
            "_token",
            side_effect=lambda: self.events.append("token") or (TOKEN, {"digest": PIN}),
        )
        self.invoke = replace(
            subject,
            "_invoke",
            side_effect=lambda *_: self.events.append("driver") or {"exit_code": 0},
        )
        self.output = replace(
            subject,
            "_read_at",
            side_effect=lambda *_: (
                self.events.append("output")
                or (subject._canonical(self.driver), {"digest": PIN})
            ),
        )
        replace(subject, "_read_fixed", return_value=(b"private", {"digest": PIN}))

    def run_workload(self):
        return subject.run_native_blocked_create_workload(**self.arguments)

    def test_actual_fixed_order_public_raws_and_false_claims(self):
        with ExitStack() as stack:
            self.harness(stack)
            report = self.run_workload()
        self.assertEqual(report["status"], "OBSERVED")
        self.assertEqual(report["invocation_count"], 1)
        self.assertEqual(report["revocation_call_count"], 1)
        self.assertEqual(self.snapshot.call_args_list[0].args, (GENESIS, 0))
        self.assertEqual(self.snapshot.call_args_list[1].args, (GENESIS, 2))
        self.assertEqual(self.sink_after.call_count, 1)
        self.assertEqual(self.invoke.call_args.args, (CONTAINER, TOKEN))
        order = [
            "sources",
            "imports",
            "identity",
            "receipt:0",
            "sink:enter",
            "claim",
            "token",
            "publish",
            "driver",
            "output",
            "receipt:2",
            "sink:after",
            "sink:close",
        ]
        cursor = -1
        for name in order:
            cursor = self.events.index(name, cursor + 1)
        for name, record in report["records"].items():
            raw = record["text"].encode("ascii")
            self.assertEqual(record["bytes"], len(raw))
            self.assertEqual(record["digest"], subject._digest(raw))
            if name == "driver_input":
                self.assertEqual(raw, subject._input(self.arguments["nonce"]))
            else:
                self.assertEqual(raw, subject._canonical(json.loads(raw)))
        self.assertTrue(all(report[name] is False for name in subject.FALSE_FLAGS))
        self.assertNotIn(TOKEN, subject._canonical(report).decode())

    def test_environment_and_source_refusal_precede_import_or_claim(self):
        for name in ("environment", "sources"):
            with self.subTest(name=name), ExitStack() as stack:
                self.harness(stack)
                getattr(self, name).side_effect = ValueError("SECRET_DIAGNOSTIC")
                report = self.run_workload()
                self.assertEqual(report["status"], "REFUSED")
                self.helpers.assert_not_called()
                self.attempt.assert_not_called()
                self.publish.assert_not_called()
                self.invoke.assert_not_called()
                self.assertNotIn("SECRET_DIAGNOSTIC", str(report))

    def test_common_epoch_action_and_genesis_mismatch_precede_claim(self):
        variants = (
            lambda: self.arguments["expected_processes"]["worker"].update(pid=999),
            lambda: self.before["measured_joins"][
                "declared_input_digests_not_cas_readback"
            ].update(path_digest=PIN),
            lambda: self.before["files"][GENESIS_PATH].update(digest=PIN),
        )
        for change in variants:
            self.setUp()
            with ExitStack() as stack:
                self.harness(stack)
                change()
                report = self.run_workload()
                self.assertEqual(report["status"], "REFUSED")
                self.attempt.assert_not_called()
                self.invoke.assert_not_called()

    def test_publication_refusal_skips_driver_and_retains_all_postreads(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.publication["status"] = "REFUSED"
            report = self.run_workload()
            self.invoke.assert_not_called()
            self.publish.assert_called_once()
            self.assertEqual(self.snapshot.call_count, 2)
            self.sink_after.assert_called_once()
        self.assertEqual(report["revocation"]["status"], "REFUSED")
        self.assertEqual(report["refusal"]["phase"], "REVOCATION_PUBLICATION")
        self.assertIn("receipt_after", report["records"])
        self.assertIn("sink_after", report["records"])

    def test_driver_failure_still_reads_published_output_without_retry(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.invoke.side_effect = ValueError("PRIVATE_TOKEN=" + TOKEN)
            report = self.run_workload()
            self.invoke.assert_called_once()
            self.output.assert_called_once()
        self.assertEqual(report["refusal"]["phase"], "DRIVER")
        self.assertIn("driver", report["records"])
        self.assertIn("receipt_after", report["records"])
        self.assertIn("sink_after", report["records"])
        self.assertNotIn(TOKEN, str(report))

    def test_incomplete_receipts_refused_once_but_sink_and_identity_retained(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.after_error = ValueError("incomplete one-record state")
            report = self.run_workload()
            self.assertEqual(
                [call.args[1] for call in self.snapshot.call_args_list], [0, 2]
            )
        self.assertEqual(report["status"], "REFUSED")
        self.assertEqual(report["postcondition_failures"], ["RECEIPT_AFTER_REFUSED"])
        self.assertNotIn("receipt_after", report["records"])
        self.assertIn("sink_after", report["records"])
        self.assertIn("identity_after", report["records"])

    def test_actual_revocation_digest_generation_reason_and_verdict_required(self):
        changes = (
            {"verdict": "ALLOW"},
            {"effect_status": "CREATED"},
            {"decision": None},
            {
                "decision": {
                    "reason_codes": ["ANOTHER_REASON"],
                    "revocation_snapshot_digest": PIN,
                    "revocation_generation": 2,
                }
            },
        )
        for fields in changes:
            with self.subTest(fields=fields):
                candidate = deepcopy(self.driver)
                candidate["source_result"]["document"]["broker_result"].update(fields)
                with self.assertRaises((ValueError, TypeError)):
                    subject._blocked_result(candidate, self.publication, CONTAINER)
        for field, value in (
            ("revocation_generation", 3),
            ("revocation_snapshot_digest", PIN),
        ):
            candidate = deepcopy(self.driver)
            candidate["source_result"]["document"]["broker_result"]["decision"][
                field
            ] = value
            with self.assertRaises(ValueError):
                subject._blocked_result(candidate, self.publication, CONTAINER)
        candidate = deepcopy(self.driver)
        candidate["source_result"]["document"]["broker_result"]["decision"][
            "reason_codes"
        ].append("LEASE_EXPIRED")
        subject._blocked_result(candidate, self.publication, CONTAINER)

    def test_nonempty_after_is_retained_but_refused(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.observation["directories"]["protected"]["empty"] = False
            report = self.run_workload()
        self.assertEqual(report["status"], "REFUSED")
        self.assertIn("SINK_AFTER_REFUSED", report["postcondition_failures"])
        self.assertIn("sink_after", report["records"])

    def test_interrupt_keeps_primary_and_attaches_postread_report(self):
        interruption = KeyboardInterrupt()
        with ExitStack() as stack:
            self.harness(stack)
            self.invoke.side_effect = interruption
            self.after_error = ValueError("secondary")
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.run_workload()
        self.assertIs(raised.exception, interruption)
        report = interruption._native_blocked_create_workload
        self.assertEqual(report["refusal"]["phase"], "DRIVER")
        self.assertIn("RECEIPT_AFTER_REFUSED", report["postcondition_failures"])
        self.assertIn("sink_after", report["records"])

    def test_output_read_interrupt_survives_later_missing_driver_refusal(self):
        interruption = KeyboardInterrupt()
        with ExitStack() as stack:
            self.harness(stack)
            self.output.side_effect = interruption
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.run_workload()
            self.invoke.assert_called_once()
            self.output.assert_called_once()
            self.sink_after.assert_called_once()
            self.assertEqual(self.snapshot.call_count, 2)
            self.assertEqual(self.read_identity.call_count, 2)
        self.assertIs(raised.exception, interruption)
        report = interruption._native_blocked_create_workload
        self.assertEqual(report["refusal"]["phase"], "DRIVER")
        self.assertIn(
            "DRIVER_OUTPUT_READBACK_REFUSED", report["postcondition_failures"]
        )
        self.assertIn("SECONDARY_WORKLOAD_REFUSED", report["postcondition_failures"])
        self.assertIn("receipt_after", report["records"])
        self.assertIn("sink_after", report["records"])

    def test_source_or_identity_drift_after_attempt_cannot_pass(self):
        for variant in ("source", "identity"):
            with self.subTest(variant=variant), ExitStack() as stack:
                self.harness(stack)
                if variant == "source":
                    self.sources.side_effect = [
                        {"fixed": PIN},
                        {"fixed": PIN},
                        {"fixed": GENESIS},
                    ]
                else:
                    self.compare.side_effect = ValueError("identity drift")
                report = self.run_workload()
                self.assertEqual(report["status"], "REFUSED")
                self.assertIn("driver", report["records"])
                self.assertTrue(report["postcondition_failures"])

    def test_fixed_input_and_invalid_nonce_cannot_select_action_or_path(self):
        raw = subject._input("e" * 32)
        value = json.loads(raw)
        self.assertEqual(raw, subject._canonical(value) + b"\n")
        self.assertEqual(
            value["scenario"]["target_name"], "runtime-worker-qualified.txt"
        )
        self.assertEqual(
            value["scenario"]["content"], "Aragorn P3.7b distinct worker create\n"
        )
        for nonce in ("../escape", "f" * 64, "G" * 32, None, True):
            with self.subTest(nonce=nonce), self.assertRaises(ValueError):
                subject._input(nonce)

    def test_import_surface_is_stdlib_only_until_guarded_loader(self):
        source = Path(subject.__file__).read_text()
        tree = ast.parse(source)
        imports = [
            node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        roots = {
            node.module.split(".")[0]
            if isinstance(node, ast.ImportFrom)
            else alias.name.split(".")[0]
            for node in imports
            for alias in (node.names if isinstance(node, ast.Import) else [None])
        }
        self.assertNotIn("aragorn", roots)
        self.assertNotIn("scripts", roots)
        self.assertNotIn("unittest", roots)
        self.assertNotIn("subprocess.run", source)
        self.assertNotIn("_activate(", source)
        self.assertNotIn("journalctl", source)

    def test_absence_refuses_any_existing_entry_and_never_deletes(self):
        with patch.object(subject.os, "stat", side_effect=FileNotFoundError):
            subject._absent(5, "input.json")
        for mode in (stat.S_IFREG, stat.S_IFLNK, stat.S_IFDIR):
            with patch.object(
                subject.os, "stat", return_value=SimpleNamespace(st_mode=mode)
            ) as read:
                with self.assertRaises(ValueError):
                    subject._absent(5, "input.json")
                read.assert_called_once_with(
                    "input.json", dir_fd=5, follow_symlinks=False
                )

    def test_close_all_attempts_each_and_preserves_active_failure(self):
        primary = ValueError("primary")
        with patch.object(
            subject.os, "close", side_effect=[OSError(), None, OSError()]
        ) as close:
            try:
                raise primary
            except ValueError:
                subject._close_all([1, 2, 3])
            self.assertEqual([call.args[0] for call in close.call_args_list], [3, 2, 1])
        self.assertEqual(
            primary._workload_cleanup_failures, ("DESCRIPTOR_CLOSE_REFUSED",)
        )

    def test_attempt_claim_fsynced_before_yield_and_never_repaired_or_removed(self):
        raw = subject._input("e" * 32)
        events, claim = [], {"attempt_claimed": False}
        directory = SimpleNamespace(
            st_dev=7, st_ino=111, st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0
        )
        file = SimpleNamespace(
            st_dev=7,
            st_ino=112,
            st_mode=stat.S_IFREG | 0o400,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=len(raw),
            st_mtime_ns=1,
            st_ctime_ns=1,
        )

        @contextmanager
        def ancestry(path):
            self.assertEqual(path, "/run")
            yield 10, lambda: events.append("parent:guard")

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(subject, "_ancestry", side_effect=ancestry)
            )
            stack.enter_context(
                patch.object(
                    subject, "_absent", side_effect=lambda *_: events.append("absent")
                )
            )
            mkdir = stack.enter_context(
                patch.object(
                    subject.os,
                    "mkdir",
                    side_effect=lambda *_a, **_k: events.append("mkdir"),
                )
            )
            stack.enter_context(patch.object(subject.os, "open", side_effect=[11, 12]))
            stack.enter_context(
                patch.object(subject.os, "stat", return_value=directory)
            )
            stack.enter_context(patch.object(subject.os, "fstat", return_value=file))
            stack.enter_context(
                patch.object(
                    subject,
                    "_directory",
                    return_value=[7, 111, directory.st_mode, 0, 0],
                )
            )
            stack.enter_context(
                patch.object(
                    subject,
                    "_read_at",
                    return_value=(raw, {"identity": subject._identity(file)}),
                )
            )
            stack.enter_context(
                patch.object(
                    subject.os,
                    "write",
                    side_effect=lambda _fd, value: events.append("write") or len(value),
                )
            )
            stack.enter_context(
                patch.object(
                    subject.os,
                    "fsync",
                    side_effect=lambda fd: events.append("fsync:" + str(fd)),
                )
            )
            close = stack.enter_context(patch.object(subject.os, "close"))
            with subject._attempt_files(raw, claim) as (fd, guard):
                self.assertEqual(fd, 11)
                self.assertTrue(claim["attempt_claimed"])
                self.assertLess(events.index("mkdir"), events.index("fsync:10"))
                self.assertLess(events.index("write"), events.index("fsync:12"))
                self.assertLess(events.index("fsync:12"), events.index("fsync:11"))
                guard()
            self.assertEqual([call.args[0] for call in close.call_args_list], [12, 11])
            mkdir.assert_called_once_with(
                Path(subject.ATTEMPT_ROOT).name, 0o700, dir_fd=10
            )
            mkdir.side_effect = FileExistsError()
            with self.assertRaises(FileExistsError):
                with subject._attempt_files(raw, {"attempt_claimed": False}):
                    self.fail("existing marker was accepted")

    def test_fixed_subprocess_argv_environment_bound_and_failure_cleanup(self):
        class Selector:
            def __init__(self):
                self.entries = {}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def register(self, stream, _event):
                self.entries[id(stream)] = stream

            def unregister(self, stream):
                del self.entries[id(stream)]

            def get_map(self):
                return self.entries

            def select(self, _remaining):
                return [
                    (SimpleNamespace(fileobj=stream), 1)
                    for stream in self.entries.values()
                ]

        for refusal in (False, True):
            with self.subTest(refusal=refusal), ExitStack() as stack:
                child = SimpleNamespace(
                    pid=1234,
                    stdout=Mock(),
                    stderr=Mock(),
                    wait=Mock(return_value=0),
                    poll=Mock(return_value=0),
                )
                child.stdout.fileno.return_value = 50
                child.stderr.fileno.return_value = 51
                popen = stack.enter_context(
                    patch.object(subject.subprocess, "Popen", return_value=child)
                )
                stack.enter_context(
                    patch.object(subject.selectors, "DefaultSelector", new=Selector)
                )
                stack.enter_context(patch.object(subject.os, "set_blocking"))
                stack.enter_context(
                    patch.object(
                        subject.os, "read", return_value=b"x" if refusal else b""
                    )
                )
                kill = stack.enter_context(patch.object(subject.os, "killpg"))
                stack.enter_context(
                    patch.object(subject.time, "monotonic", return_value=100.0)
                )
                if refusal:
                    with self.assertRaises(
                        subject.NativeBlockedCreateWorkloadError
                    ) as error:
                        subject._invoke(CONTAINER, TOKEN)
                    self.assertEqual(
                        str(error.exception), "FIXED_DRIVER_UNEXPECTED_OUTPUT"
                    )
                    kill.assert_called_once_with(1234, subject.signal.SIGKILL)
                else:
                    self.assertEqual(subject._invoke(CONTAINER, TOKEN)["exit_code"], 0)
                    kill.assert_not_called()
                popen.assert_called_once()
                self.assertEqual(
                    popen.call_args.args[0],
                    [
                        subject._NODE,
                        subject.DRIVER_PATH,
                        "blocked-create",
                        CONTAINER,
                        subject._INPUT,
                        subject._OUTPUT,
                    ],
                )
                environment = popen.call_args.kwargs["env"]
                self.assertEqual(
                    environment["HOME"], "/var/lib/aragorn-agent-gateway/home"
                )
                self.assertEqual(
                    environment["OPENCLAW_STATE_DIR"],
                    "/var/lib/aragorn-agent-gateway/state",
                )
                self.assertEqual(
                    environment["OPENCLAW_CONFIG_PATH"],
                    "/etc/aragorn/agent-gateway/openclaw.json",
                )
                self.assertEqual(environment["OPENCLAW_GATEWAY_TOKEN"], TOKEN)
                self.assertEqual(environment["ARAGORN_MOCK_PROVIDER_TOKEN"], TOKEN)
                self.assertTrue(popen.call_args.kwargs["start_new_session"])
                child.stdout.close.assert_called_once()
                child.stderr.close.assert_called_once()

    def test_sink_context_cleanup_failures_are_retained_with_original_refusal(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.invoke.side_effect = ValueError("original")

            @contextmanager
            def failed_sink(**_):
                try:
                    yield self.session
                finally:
                    self.session.failures.append("SINK_CLOSE_REFUSED")

            native, common, _sink, revocation = self.helpers()
            self.helpers.side_effect = lambda: (
                native,
                common,
                SimpleNamespace(hold_native_denied_create_sink=failed_sink),
                revocation,
            )
            report = self.run_workload()
        self.assertEqual(report["refusal"]["phase"], "DRIVER")
        self.assertIn("SINK_CLOSE_REFUSED", report["sink_failures"])
        self.assertIn("sink_after", report["records"])


if __name__ == "__main__":
    unittest.main()
