"""Inert custody/publication checks; never a service, driver or live capture."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import runtime_action_broker as broker
from aragorn import runtime_action_decision as decision
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import runtime_native_blocked_create_revocation as subject
from tests.test_runtime_action_broker import _Fixture, _write_control, _RUNTIME, _SKILL


PIN = "sha256:" + "e" * 64
CONTAINER = "a" * 64


class NativeBlockedCreateRevocationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        os.chown(self.root, os.geteuid(), os.getegid())
        # Only the data constructor is reused, never historical test methods.
        self.fixture = _Fixture(self.root)
        self.args = (
            CONTAINER,
            canonical_digest(self.fixture.policy),
            _RUNTIME,
            _SKILL,
            PIN,
            PIN,
        )
        self.kwargs = dict(
            zip(
                (
                    "expected_container_id",
                    "expected_policy_digest",
                    "expected_runtime_digest",
                    "expected_skill_digest",
                    "expected_source_digest",
                    "expected_broker_source_digest",
                ),
                self.args,
            )
        )

    def ancestry(self, path, uid):
        """Check every fixture ancestor; system temporary parents are outside it."""
        current = path
        self.assertTrue(current.is_relative_to(self.root))
        while True:
            item = current.lstat()
            self.assertTrue(stat.S_ISDIR(item.st_mode))
            self.assertEqual(item.st_uid, uid)
            self.assertFalse(stat.S_IMODE(item.st_mode) & 0o022)
            if current == self.root:
                break
            current = current.parent

    @contextmanager
    def inert(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(subject, "_environment"))
            stack.enter_context(patch.object(subject, "_alive"))
            stack.enter_context(
                patch.object(
                    subject, "_source", return_value={"bytes": 5, "digest": PIN}
                )
            )
            stack.enter_context(
                patch.object(
                    subject.os,
                    "pidfd_open",
                    create=True,
                    side_effect=lambda *_: os.open("/dev/null", os.O_RDONLY),
                )
            )
            stack.enter_context(
                patch.object(subject, "CONTROL", str(self.fixture.control))
            )
            stack.enter_context(
                patch.object(subject, "_config", return_value=self.fixture.config)
            )
            identities = (
                os.geteuid(),
                os.geteuid() + 2,
                os.getegid(),
                os.geteuid() + 1,
                os.getegid() + 1,
            )
            service = SimpleNamespace(_service_identities=lambda: identities)
            stack.enter_context(
                patch.object(
                    subject, "_dependencies", return_value=(broker, service, decision)
                )
            )
            stack.enter_context(
                patch.object(
                    broker, "_require_protected_ancestry", side_effect=self.ancestry
                )
            )
            stack.enter_context(patch.object(subject.time, "time", return_value=1000))
            yield

    def test_real_locked_publication_preserves_action_and_only_advances_revocations(
        self,
    ):
        untouched = {
            name: self.fixture.paths[name].read_bytes()
            for name in ("policy", "health", "observation")
        }
        with (
            self.inert(),
            patch.object(
                broker, "_publish_control_locked", wraps=broker._publish_control_locked
            ) as publish,
        ):
            report = subject._run_child(*self.args)
        self.assertEqual(report["status"], "PUBLISHED")
        publish.assert_called_once()
        self.assertEqual(
            publish.call_args.args[1], self.fixture.config.revocations_path
        )
        raw = self.fixture.paths["revocations"].read_bytes()
        document = subject._parse(raw)
        self.assertEqual(document["skill_digests"], [_SKILL])
        self.assertEqual(
            (
                document["generation"],
                document["observed_at_unix"],
                document["expires_at_unix"],
            ),
            (4, 1000, 1015),
        )
        self.assertEqual(report["published"], subject._record(raw))
        self.assertEqual(report["after"]["revocations"], report["published"])
        self.assertEqual(self.fixture.load_state()["minimum_revocation_generation"], 4)
        self.assertEqual(
            stat.S_IMODE(self.fixture.paths["revocations"].stat().st_mode), 0o400
        )
        self.assertEqual(
            {name: self.fixture.paths[name].read_bytes() for name in untouched},
            untouched,
        )
        self.assertTrue(all(report[flag] is False for flag in subject.FALSE_FLAGS))
        self.assertEqual(list(self.fixture.protected.iterdir()), [])
        self.assertEqual(list(self.fixture.staging.iterdir()), [])

    def test_published_revocation_produces_real_same_action_policy_block(self):
        with self.inert():
            report = subject._run_child(*self.args)
        self.assertEqual(report["status"], "PUBLISHED")
        revoked = subject._document(report["published"])
        request = {
            **self.fixture.request,
            "issued_at_unix": 1000,
            "expires_at_unix": 1005,
        }
        health = {
            **self.fixture.health,
            "observed_at_unix": 1000,
            "expires_at_unix": 1015,
        }
        result = decision.evaluate_runtime_action(
            request,
            self.fixture.policy,
            revocations=revoked,
            mediator_health=health,
            active=self.fixture.observation["active"],
            measured_action=self.fixture.observation["measured_action"],
            now_unix=1000,
            minimum_revocation_generation=4,
            minimum_mediator_health_epoch=1,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("ACTIVE_SKILL_REVOKED", result["reason_codes"])
        self.assertEqual(
            result["revocation_snapshot_digest"], report["published"]["digest"]
        )
        self.assertEqual(result["revocation_generation"], 4)

    def test_source_or_policy_or_used_state_refuses_before_publication(self):
        cases = ("source", "policy", "consumed", "already-revoked", "bool-generation")
        for case in cases:
            with self.subTest(case=case), self.inert(), ExitStack() as stack:
                _write_control(self.fixture.paths["state"], self.fixture.state)
                _write_control(
                    self.fixture.paths["revocations"], self.fixture.revocations
                )
                args = list(self.args)
                if case == "source":
                    stack.enter_context(
                        patch.object(
                            subject, "_source", side_effect=ValueError("secret")
                        )
                    )
                elif case == "policy":
                    args[1] = PIN
                elif case == "consumed":
                    _write_control(
                        self.fixture.paths["state"],
                        {**self.fixture.state, "consumed": [{}]},
                    )
                elif case == "already-revoked":
                    _write_control(
                        self.fixture.paths["revocations"],
                        {**self.fixture.revocations, "skill_digests": [_SKILL]},
                    )
                else:
                    _write_control(
                        self.fixture.paths["revocations"],
                        {**self.fixture.revocations, "generation": True},
                    )
                publish = stack.enter_context(
                    patch.object(broker, "_publish_control_locked")
                )
                report = subject._run_child(*args)
                self.assertEqual(report["status"], "REFUSED")
                self.assertFalse(report["publication_attempted"])
                publish.assert_not_called()
                self.assertNotIn("secret", subject._canonical(report).decode())

    def test_fifo_lock_is_rejected_without_waiting_or_publication(self):
        self.fixture.lock_path.unlink()
        os.mkfifo(self.fixture.lock_path, 0o600)
        with (
            self.inert(),
            patch.object(broker, "_acquire_lock") as lock,
            patch.object(broker, "_publish_control_locked") as publish,
        ):
            report = subject._run_child(*self.args)
        self.assertEqual(report["status"], "REFUSED")
        lock.assert_not_called()
        publish.assert_not_called()
        self.assertTrue(stat.S_ISFIFO(self.fixture.lock_path.lstat().st_mode))

    def test_partial_publication_failure_retains_actual_after_state_without_retry(self):
        original = broker._publish_control_locked

        def publish_then_fail(*args):
            original(*args)
            raise OSError("private failure text")

        with (
            self.inert(),
            patch.object(
                broker, "_publish_control_locked", side_effect=publish_then_fail
            ) as publish,
        ):
            report = subject._run_child(*self.args)
        self.assertEqual(report["status"], "REFUSED")
        self.assertEqual(report["refusal"]["phase"], "PUBLICATION")
        self.assertEqual(set(report["after"]), {"policy", "revocations", "state"})
        self.assertEqual(report["after"]["revocations"], report["published"])
        self.assertEqual(self.fixture.load_state()["minimum_revocation_generation"], 4)
        publish.assert_called_once()
        self.assertNotIn("private failure text", subject._canonical(report).decode())
        with self.inert(), patch.object(broker, "_publish_control_locked") as retry:
            again = subject._run_child(*self.args)
        retry.assert_not_called()
        self.assertEqual(again["status"], "REFUSED")

    def test_after_reads_are_independent_and_preserve_publication_error(self):
        original_read = subject._read_at
        failed_publication = False
        seen = []

        def publish(*_args):
            nonlocal failed_publication
            failed_publication = True
            raise OSError("do not disclose")

        def read(fd, name, **kwargs):
            if failed_publication:
                seen.append(name)
                if name == "policy.json":
                    raise OSError("do not disclose either")
            return original_read(fd, name, **kwargs)

        with (
            self.inert(),
            patch.object(broker, "_publish_control_locked", side_effect=publish),
            patch.object(subject, "_read_at", side_effect=read),
        ):
            report = subject._run_child(*self.args)
        self.assertEqual(seen, ["policy.json", "revocations.json", "state.json"])
        self.assertEqual(report["refusal"]["phase"], "PUBLICATION")
        self.assertEqual(report["postcondition_failures"], ["AFTER_POLICY_REFUSED"])
        self.assertEqual(set(report["after"]), {"revocations", "state"})

    def test_expired_final_readback_does_not_restore_or_republish(self):
        with (
            self.inert(),
            patch.object(subject.time, "time", side_effect=[1000, 1000, 1015]),
            patch.object(
                broker, "_publish_control_locked", wraps=broker._publish_control_locked
            ) as publish,
        ):
            report = subject._run_child(*self.args)
        self.assertEqual(report["status"], "REFUSED")
        self.assertEqual(report["refusal"]["phase"], "FINAL_READBACK")
        self.assertEqual(report["after"]["revocations"], report["published"])
        publish.assert_called_once()

    @contextmanager
    def launcher(self, completed):
        with self.inert(), ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    subject.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=993)
                )
            )
            stack.enter_context(
                patch.object(
                    subject.grp,
                    "getgrnam",
                    side_effect=lambda name: SimpleNamespace(
                        gr_gid=992 if name.endswith("runtime") else 991
                    ),
                )
            )
            returned = (
                None if completed is None else (completed.stdout, completed.returncode)
            )
            run = stack.enter_context(
                patch.object(subject, "_invoke", return_value=returned)
            )
            yield run

    def test_root_launcher_uses_one_fixed_privilege_drop_and_retains_child_raw(self):
        with self.inert():
            child = subject._run_child(*self.args)
        raw = subject._canonical(child)
        completed = SimpleNamespace(returncode=0, stdout=raw + b"\n")
        with self.launcher(completed) as run:
            report = subject.publish_native_blocked_create_revocation(**self.kwargs)
        self.assertEqual(report["status"], "PUBLISHED")
        self.assertEqual(report["publication_raw"], subject._record(raw))
        run.assert_called_once()
        argv = run.call_args.args[0]
        self.assertEqual(
            argv[:7],
            ["/usr/bin/setpriv", "--reuid", "993", "--regid", "992", "--groups", "991"],
        )
        self.assertIn("--no-new-privs", argv)
        self.assertEqual(
            argv[11:16], ["/usr/bin/python3.12", "-I", "-S", "-B", subject.SOURCE_PATH]
        )
        self.assertEqual(argv[16:], list(self.args))

    def test_root_child_refusal_and_timeout_are_not_retried(self):
        with (
            self.inert(),
            patch.object(broker, "_publish_control_locked", side_effect=OSError),
        ):
            child = subject._run_child(*self.args)
        raw = subject._canonical(child)
        with self.launcher(SimpleNamespace(returncode=126, stdout=raw + b"\n")) as run:
            report = subject.publish_native_blocked_create_revocation(**self.kwargs)
        self.assertEqual(report["status"], "REFUSED")
        self.assertEqual(report["publication_raw"], subject._record(raw))
        self.assertTrue(report["publication"]["publication_attempted"])
        run.assert_called_once()
        with self.launcher(None) as run:
            run.side_effect = subprocess.TimeoutExpired("fixed", 5, output=b"secret")
            timeout = subject.publish_native_blocked_create_revocation(**self.kwargs)
        run.assert_called_once()
        self.assertTrue(timeout["child_attempted"])
        self.assertIsNone(timeout["publication"])
        self.assertNotIn("secret", subject._canonical(timeout).decode())

    def test_launcher_rejects_claim_escalation_and_wrong_bound_policy(self):
        with self.inert():
            good = subject._run_child(*self.args)
        for key, value in (("phase3_eligible", True), ("expected_policy_digest", PIN)):
            child = deepcopy(good)
            child[key] = value
            with (
                self.subTest(key=key),
                self.launcher(
                    SimpleNamespace(
                        returncode=0, stdout=subject._canonical(child) + b"\n"
                    )
                ),
            ):
                report = subject.publish_native_blocked_create_revocation(**self.kwargs)
            self.assertEqual(report["status"], "REFUSED")
            self.assertIsNotNone(report["publication_raw"])

    def test_interruption_retains_complete_child_report_then_propagates(self):
        with self.inert():
            child = subject._run_child(*self.args)
        error = KeyboardInterrupt()
        error._native_revocation_stdout = subject._canonical(child) + b"\n"
        error._native_revocation_cleanup = ("INERT_CLOSE_REFUSED",)
        with self.launcher(None) as run:
            run.side_effect = error
            with self.assertRaises(KeyboardInterrupt) as caught:
                subject.publish_native_blocked_create_revocation(**self.kwargs)
        self.assertIs(caught.exception, error)
        retained = error._native_blocked_create_revocation
        self.assertEqual(retained["status"], "REFUSED")
        self.assertEqual(retained["publication"], child)
        self.assertEqual(retained["cleanup_failures"], ["INERT_CLOSE_REFUSED"])
        run.assert_called_once()

    def test_bounded_child_drain_and_independent_cleanup_with_syscall_doubles(self):
        class Stream:
            def __init__(self, fd):
                self.fd, self.closed = fd, 0

            def fileno(self):
                return self.fd

            def close(self):
                self.closed += 1

        class Selector:
            def __init__(self):
                self.streams = []

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def register(self, stream, _):
                self.streams.append(stream)

            def unregister(self, stream):
                self.streams.remove(stream)

            def get_map(self):
                return self.streams

            def select(self, _):
                return [
                    (SimpleNamespace(fileobj=item), 1) for item in list(self.streams)
                ]

        for mode in ("success", "oversize", "stderr", "timeout", "interrupt"):
            with self.subTest(mode=mode), ExitStack() as stack:
                stdout, stderr = Stream(80), Stream(81)
                child = SimpleNamespace(
                    stdout=stdout,
                    stderr=stderr,
                    pid=987654,
                    wait=Mock(return_value=0),
                    poll=Mock(return_value=0),
                )
                popen = stack.enter_context(
                    patch.object(subject.subprocess, "Popen", return_value=child)
                )
                stack.enter_context(
                    patch.object(
                        subject.selectors, "DefaultSelector", return_value=Selector()
                    )
                )
                stack.enter_context(patch.object(subject.os, "set_blocking"))
                kill = stack.enter_context(patch.object(subject.os, "killpg"))
                chunks = {80: [b"OK\n", b""], 81: [b""]}
                if mode == "oversize":
                    chunks[80] = [b"x" * 9]
                if mode == "stderr":
                    chunks[81] = [b"x"]

                def read(fd, size):
                    if mode == "interrupt":
                        raise KeyboardInterrupt()
                    value = chunks[fd].pop(0)
                    self.assertLessEqual(len(value), size)
                    return value

                stack.enter_context(patch.object(subject.os, "read", side_effect=read))
                stack.enter_context(patch.object(subject, "MAX_RESULT", 8))
                stack.enter_context(
                    patch.object(
                        subject.time,
                        "monotonic",
                        side_effect=[0, 6] if mode == "timeout" else None,
                        return_value=0,
                    )
                )
                if mode == "success":
                    self.assertEqual(subject._invoke(["inert-only"]), (b"OK\n", 0))
                    kill.assert_not_called()
                else:
                    with self.assertRaises(
                        KeyboardInterrupt
                        if mode == "interrupt"
                        else subject.NativeBlockedCreateRevocationError
                    ) as caught:
                        subject._invoke(["inert-only"])
                    self.assertLessEqual(
                        len(caught.exception._native_revocation_stdout), 8
                    )
                    kill.assert_called_once_with(child.pid, subject.signal.SIGKILL)
                self.assertEqual((stdout.closed, stderr.closed), (1, 1))
                self.assertGreaterEqual(child.wait.call_count, 1)
                popen.assert_called_once()
                self.assertTrue(popen.call_args.kwargs["start_new_session"])
                self.assertIs(popen.call_args.kwargs["stderr"], subprocess.PIPE)


if __name__ == "__main__":
    unittest.main()
