from __future__ import annotations

import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

from aragorn import runtime_action_service as service
from aragorn.oci_worker_protocol import canonical_json

_DIGEST = "sha256:" + "1" * 64


def _binding(**changes: object) -> bytes:
    document = {
        "schema": "aragorn/runtime-action-runtime-binding/v1",
        "runtime_digest": _DIGEST,
        **changes,
    }
    return canonical_json(document)


def _write_binding(root: Path, raw: bytes | None = None) -> Path:
    root = root.resolve()
    path = root / "runtime-binding"
    path.write_bytes(_binding() if raw is None else raw)
    path.chmod(0o400)
    return path


class RuntimeActionServiceTests(unittest.TestCase):
    def test_main_resolves_identities_and_serves_fixed_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_binding(Path(temporary))
            broker_uid = os.geteuid()
            runtime_uid = broker_uid + 1
            runtime_gid = os.getegid() + 1
            with (
                patch.object(service.sys, "platform", "linux"),
                patch.object(
                    service.pwd,
                    "getpwnam",
                    side_effect=(
                        SimpleNamespace(pw_uid=broker_uid),
                        SimpleNamespace(pw_uid=runtime_uid, pw_gid=runtime_gid),
                    ),
                ) as users,
                patch.object(
                    service.grp,
                    "getgrnam",
                    return_value=SimpleNamespace(gr_gid=runtime_gid),
                ) as groups,
                patch.dict(
                    os.environ,
                    {"CREDENTIALS_DIRECTORY": str(path.parent)},
                ),
                patch.object(service, "serve_runtime_action_broker") as serve,
            ):
                self.assertEqual(service.main([str(path)]), 0)

            self.assertEqual(
                users.call_args_list,
                [call("aragorn-broker"), call("aragorn-runtime")],
            )
            groups.assert_called_once_with("aragorn-runtime")
            serve.assert_called_once()
            config = serve.call_args.args[0]
            root = Path("/var/lib/aragorn-runtime-action")
            self.assertEqual(config.control_root, root / "control")
            self.assertEqual(config.protected_root, root / "protected")
            self.assertEqual(config.staging_root, root / "staging")
            self.assertEqual(config.socket_path, root / "control" / "broker.sock")
            self.assertEqual(
                config.instance_lock_path,
                root / "control" / "broker.instance.lock",
            )
            self.assertEqual(config.lock_path, root / "control" / "broker.lock")
            self.assertEqual(config.policy_path, root / "control" / "policy.json")
            self.assertEqual(
                config.revocations_path,
                root / "control" / "revocations.json",
            )
            self.assertEqual(config.health_path, root / "control" / "health.json")
            self.assertEqual(
                config.observation_path,
                root / "control" / "observation.json",
            )
            self.assertEqual(config.state_path, root / "control" / "state.json")
            self.assertEqual(config.expected_broker_uid, broker_uid)
            self.assertEqual(config.expected_peer_uid, runtime_uid)
            self.assertEqual(config.expected_peer_gid, runtime_gid)
            self.assertEqual(config.expected_runtime_digest, _DIGEST)

    def test_main_rejects_usage_platform_and_identity_errors(self) -> None:
        cases = (
            ([], "usage:"),
            (["one", "two"], "usage:"),
        )
        for arguments, message in cases:
            with self.subTest(arguments=arguments):
                stderr = StringIO()
                with redirect_stderr(stderr):
                    self.assertNotEqual(service.main(arguments), 0)
                self.assertIn(message, stderr.getvalue())

        stderr = StringIO()
        with (
            patch.object(service.sys, "platform", "darwin"),
            patch.object(service, "serve_runtime_action_broker") as serve,
            redirect_stderr(stderr),
        ):
            self.assertNotEqual(service.main(["binding.json"]), 0)
        self.assertIn("Linux execution is required", stderr.getvalue())
        serve.assert_not_called()

        broker_uid = os.geteuid() + 1
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_binding(Path(temporary))
            stderr = StringIO()
            with (
                patch.object(service.sys, "platform", "linux"),
                patch.object(
                    service.pwd,
                    "getpwnam",
                    side_effect=(
                        SimpleNamespace(pw_uid=broker_uid),
                        SimpleNamespace(pw_uid=broker_uid + 1, pw_gid=1234),
                    ),
                ),
                patch.object(
                    service.grp,
                    "getgrnam",
                    return_value=SimpleNamespace(gr_gid=1234),
                ),
                patch.object(service, "serve_runtime_action_broker") as serve,
                redirect_stderr(stderr),
            ):
                self.assertNotEqual(service.main([str(path)]), 0)
            self.assertIn("broker process identity is invalid", stderr.getvalue())
            serve.assert_not_called()

    def test_main_treats_service_manager_interrupt_as_clean_stop(self) -> None:
        with (
            patch.object(service, "_run", side_effect=KeyboardInterrupt),
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(service.main(["runtime-binding"]), 0)

    def test_runtime_group_must_be_the_users_primary_group(self) -> None:
        with (
            patch.object(
                service.pwd,
                "getpwnam",
                side_effect=(
                    SimpleNamespace(pw_uid=os.geteuid()),
                    SimpleNamespace(pw_uid=os.geteuid() + 1, pw_gid=1001),
                ),
            ),
            patch.object(
                service.grp,
                "getgrnam",
                return_value=SimpleNamespace(gr_gid=1002),
            ),
            self.assertRaisesRegex(
                service.RuntimeActionServiceError,
                "runtime user and group identities disagree",
            ),
        ):
            service._service_identities()

    def test_runtime_and_broker_users_must_be_distinct(self) -> None:
        uid = os.geteuid()
        with (
            patch.object(
                service.pwd,
                "getpwnam",
                side_effect=(
                    SimpleNamespace(pw_uid=uid),
                    SimpleNamespace(pw_uid=uid, pw_gid=1001),
                ),
            ),
            patch.object(
                service.grp,
                "getgrnam",
                return_value=SimpleNamespace(gr_gid=1001),
            ),
            self.assertRaisesRegex(
                service.RuntimeActionServiceError,
                "runtime and broker identities overlap",
            ),
        ):
            service._service_identities()

    def test_binding_requires_exact_canonical_schema_and_digest(self) -> None:
        invalid = (
            _binding(extra=True),
            canonical_json(
                {
                    "schema": "aragorn/runtime-action-runtime-binding/v2",
                    "runtime_digest": _DIGEST,
                }
            ),
            canonical_json(
                {
                    "schema": "aragorn/runtime-action-runtime-binding/v1",
                    "runtime_digest": "SHA256:" + "1" * 64,
                }
            ),
            _binding() + b"\n",
            (
                b'{"runtime_digest":"'
                + _DIGEST.encode()
                + b'", "schema":"aragorn/runtime-action-runtime-binding/v1"}'
            ),
        )
        for raw in invalid:
            with self.subTest(raw=raw[:80]), tempfile.TemporaryDirectory() as temporary:
                path = _write_binding(Path(temporary), raw)
                with self.assertRaisesRegex(
                    service.RuntimeActionServiceError,
                    "runtime binding credential is invalid",
                ):
                    service._read_runtime_binding(path, os.geteuid())

    def test_binding_requires_protected_regular_single_link_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = _write_binding(root)
            path.chmod(0o600)
            with self.assertRaisesRegex(
                service.RuntimeActionServiceError,
                "runtime binding credential is unsafe",
            ):
                service._read_runtime_binding(path, os.geteuid())

            path.chmod(0o400)
            linked = root / "linked.json"
            os.link(path, linked)
            with self.assertRaisesRegex(
                service.RuntimeActionServiceError,
                "runtime binding credential is unsafe",
            ):
                service._read_runtime_binding(path, os.geteuid())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = _write_binding(root)
            link = root / "binding-link.json"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                service._read_runtime_binding(link, os.geteuid())

    def test_binding_accepts_systemd_root_acl_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_binding(Path(temporary))
            actual = os.stat(path)
            root_acl = SimpleNamespace(
                st_dev=actual.st_dev,
                st_ino=actual.st_ino,
                st_mode=stat.S_IFREG | 0o440,
                st_uid=0,
                st_gid=0,
                st_nlink=1,
                st_size=actual.st_size,
                st_mtime_ns=actual.st_mtime_ns,
                st_ctime_ns=actual.st_ctime_ns,
            )
            with patch.object(service.os, "fstat", return_value=root_acl):
                self.assertEqual(
                    service._read_runtime_binding(path, os.geteuid()),
                    _DIGEST,
                )

    def test_run_requires_the_exact_systemd_credential_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = _write_binding(root)
            with patch.dict(
                os.environ,
                {"CREDENTIALS_DIRECTORY": str(root)},
            ):
                with self.assertRaisesRegex(
                    service.RuntimeActionServiceError,
                    "systemd credential path is invalid",
                ):
                    service._credential_path(root / "other", os.geteuid())
                self.assertEqual(
                    service._credential_path(path, os.geteuid()),
                    path,
                )

    def test_binding_rejects_owner_and_descriptor_identity_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_binding(Path(temporary))
            with self.assertRaisesRegex(
                service.RuntimeActionServiceError,
                "runtime binding credential is unsafe",
            ):
                service._read_runtime_binding(path, os.geteuid() + 1)

            real_fstat = os.fstat
            calls = 0

            def changed(descriptor: int) -> object:
                nonlocal calls
                metadata = real_fstat(descriptor)
                calls += 1
                if calls == 1:
                    return metadata
                values = {
                    name: getattr(metadata, name)
                    for name in (
                        "st_dev",
                        "st_ino",
                        "st_mode",
                        "st_uid",
                        "st_gid",
                        "st_nlink",
                        "st_size",
                        "st_mtime_ns",
                        "st_ctime_ns",
                    )
                }
                values["st_ctime_ns"] += 1
                return SimpleNamespace(**values)

            with (
                patch.object(service.os, "fstat", side_effect=changed),
                self.assertRaisesRegex(
                    service.RuntimeActionServiceError,
                    "runtime binding credential changed while read",
                ),
            ):
                service._read_runtime_binding(path, os.geteuid())


if __name__ == "__main__":
    unittest.main()
