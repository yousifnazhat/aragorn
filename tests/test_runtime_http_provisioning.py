"""Only new absent-only provisioning branches, with inert OS/service doubles."""

from contextlib import contextmanager
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import runtime_http_provisioning as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


class HttpProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.fixture = {
            "container_id": "a" * 64,
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "netns_device": 4,
            "netns_inode": 9,
        }
        self.binding = {
            "schema": subject.http.BINDING_SCHEMA,
            "fixture": self.fixture,
            "expected_broker_uid": 996,
            "expected_broker_gid": 997,
        }
        self.held = SimpleNamespace(guard=Mock())

        @contextmanager
        def owned(expected):
            self.assertEqual(expected, self.fixture)
            yield self.held

        self.enterContext(patch.object(subject, "owned_http_fixture", owned))
        accounts = {
            "aragorn-broker": SimpleNamespace(pw_uid=996, pw_gid=996),
            "aragorn-runtime": SimpleNamespace(pw_uid=997, pw_gid=997),
        }
        self.accounts = accounts
        self.enterContext(
            patch.object(subject.pwd, "getpwnam", side_effect=accounts.__getitem__)
        )
        self.enterContext(
            patch.object(
                subject.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=997)
            )
        )
        self.service = self.enterContext(
            patch.object(
                subject.subprocess,
                "run",
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout=b"ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\n",
                    stderr=b"",
                ),
            )
        )
        self.loader = self.enterContext(
            patch.object(
                subject.http, "load_fixture_binding", return_value=self.binding
            )
        )
        self.metadata = SimpleNamespace(
            st_uid=0, st_mode=stat.S_IFDIR | 0o755, st_dev=1, st_ino=2
        )
        self.stat = self.enterContext(
            patch.object(Path, "lstat", return_value=self.metadata)
        )
        self.os = SimpleNamespace(
            **{
                name: getattr(subject.os, name)
                for name in (
                    "O_RDONLY",
                    "O_DIRECTORY",
                    "O_NOFOLLOW",
                    "O_CLOEXEC",
                    "O_WRONLY",
                    "O_CREAT",
                    "O_EXCL",
                )
            },
            open=Mock(side_effect=[10, 11]),
            fstat=Mock(return_value=self.metadata),
            fchown=Mock(),
            fchmod=Mock(),
            write=Mock(side_effect=lambda _fd, raw: len(raw)),
            fsync=Mock(),
            close=Mock(),
        )
        self.enterContext(patch.object(subject, "os", self.os))

    def test_one_absent_only_write_without_activation(self):
        result = subject.provision_fixture_binding(self.fixture)
        self.assertTrue(result["completed"])
        self.assertTrue(result["created"])
        self.assertEqual(result["binding_digest"], canonical_digest(self.binding))
        self.assertFalse(result["activation_performed"])
        self.assertFalse(result["phase3_exit_eligible"])
        self.os.write.assert_called_once_with(11, canonical_json(self.binding))
        self.os.fchown.assert_called_once_with(11, 0, 997)
        self.os.fchmod.assert_called_once_with(11, 0o440)
        self.assertEqual(self.os.open.call_args_list[1].kwargs, {"dir_fd": 10})
        self.assertEqual(
            self.os.open.call_args_list[1].args[1],
            self.os.O_WRONLY
            | self.os.O_CREAT
            | self.os.O_EXCL
            | self.os.O_NOFOLLOW
            | self.os.O_CLOEXEC,
        )
        self.assertEqual(
            [call.args[0] for call in self.os.close.call_args_list], [11, 10]
        )
        self.assertEqual(self.service.call_count, 8)
        for call in self.service.call_args_list:
            self.assertIn("show", call.args[0])
            self.assertEqual(call.kwargs["timeout"], 2)

    def test_existing_binding_is_never_repaired_or_retried(self):
        self.os.open.side_effect = [10, FileExistsError("existing")]
        with self.assertRaises(FileExistsError) as caught:
            subject.provision_fixture_binding(self.fixture)
        self.assertFalse(caught.exception.http_provisioning_observation["completed"])
        self.os.write.assert_not_called()
        self.os.close.assert_called_once_with(10)

    def test_short_write_retains_exact_partial_outcome(self):
        self.os.write.side_effect = None
        self.os.write.return_value = 3
        with self.assertRaises(subject.http.RuntimeHttpActionError) as caught:
            subject.provision_fixture_binding(self.fixture)
        self.assertTrue(caught.exception.http_provisioning_observation["created"])
        self.assertEqual(
            caught.exception.http_provisioning_observation["bytes_written"], 3
        )
        self.assertEqual(self.os.write.call_count, 1)

    def test_interrupted_write_retains_unknown_count(self):
        self.os.write.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            subject.provision_fixture_binding(self.fixture)
        self.assertIsNone(
            caught.exception.http_provisioning_observation["bytes_written"]
        )
        self.assertEqual(self.os.close.call_count, 2)

    def test_close_failure_prevents_success(self):
        self.os.close.side_effect = [OSError("close"), None]
        with self.assertRaises(OSError) as caught:
            subject.provision_fixture_binding(self.fixture)
        result = caught.exception.http_provisioning_observation
        self.assertTrue(result["cleanup_failed"])
        self.assertFalse(result["completed"])
        self.assertEqual(self.os.close.call_count, 2)

    def test_interrupt_survives_secondary_cleanup_failure(self):
        interrupt = KeyboardInterrupt()
        self.os.write.side_effect = interrupt
        self.os.close.side_effect = [OSError("close"), None]
        with self.assertRaises(KeyboardInterrupt) as caught:
            subject.provision_fixture_binding(self.fixture)
        self.assertIs(caught.exception, interrupt)
        self.assertTrue(interrupt.http_provisioning_observation["cleanup_failed"])

    def test_active_service_refuses_before_open(self):
        self.service.return_value.stdout = (
            b"ActiveState=active\nSubState=running\nMainPID=10\nControlPID=0\n"
        )
        with self.assertRaises(subject.http.RuntimeHttpActionError):
            subject.provision_fixture_binding(self.fixture)
        self.os.open.assert_not_called()

    def test_duplicate_service_fields_refuse(self):
        self.service.return_value.stdout = (
            b"ActiveState=inactive\nSubState=dead\nMainPID=0\nMainPID=0\n"
        )
        with self.assertRaises(subject.http.RuntimeHttpActionError):
            subject.provision_fixture_binding(self.fixture)
        self.os.open.assert_not_called()

    def test_service_timeout_refuses_without_retry(self):
        self.service.side_effect = subject.subprocess.TimeoutExpired("inert", 2)
        with self.assertRaises(subject.subprocess.TimeoutExpired):
            subject.provision_fixture_binding(self.fixture)
        self.service.assert_called_once()
        self.os.open.assert_not_called()

    def test_group_or_root_account_mismatch_refuses(self):
        self.accounts["aragorn-runtime"].pw_uid = 0
        with self.assertRaises(subject.http.RuntimeHttpActionError):
            subject.provision_fixture_binding(self.fixture)
        self.os.open.assert_not_called()

    def test_symlink_or_writable_parent_refuses(self):
        self.metadata.st_mode = stat.S_IFLNK | 0o777
        with self.assertRaises(subject.http.RuntimeHttpActionError):
            subject.provision_fixture_binding(self.fixture)
        self.os.open.assert_not_called()

    def test_readback_mismatch_retains_created_file(self):
        self.loader.return_value = {**self.binding, "expected_broker_uid": 995}
        with self.assertRaises(subject.http.RuntimeHttpActionError) as caught:
            subject.provision_fixture_binding(self.fixture)
        self.assertTrue(caught.exception.http_provisioning_observation["created"])
        self.assertEqual(self.os.write.call_count, 1)

    def test_guard_refusal_prevents_write(self):
        self.held.guard.side_effect = ValueError("changed namespace")
        with self.assertRaises(ValueError):
            subject.provision_fixture_binding(self.fixture)
        self.os.write.assert_not_called()

    def test_activation_rechecks_stopped_fixture_without_writes(self):
        self.assertEqual(
            subject.validate_activation_fixture(), canonical_digest(self.binding)
        )
        self.assertEqual(self.service.call_count, 4)
        self.assertEqual(self.loader.call_count, 2)
        self.held.guard.assert_called_once()
        self.os.open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
