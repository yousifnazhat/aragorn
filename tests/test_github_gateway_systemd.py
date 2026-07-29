from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest import mock

from aragorn import github_gateway
from aragorn.github_gateway import GitHubGatewayError
from aragorn.oci_runtime import _ProcessResult


class GitHubGatewaySystemdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.environment = {
            "HOME": os.fspath(self.root),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
            "TZ": "UTC",
        }

    def test_linux_launch_uses_fixed_systemd_policy_and_cleans_up(self) -> None:
        completed = _ProcessResult(b"ok\n", b"", 0)
        identity = ("sha256:" + "1" * 64, (1, 2, 3, 4))

        with (
            mock.patch.object(github_gateway, "_require_systemd_host"),
            mock.patch.object(github_gateway, "_require_bounded_transfer_mount"),
            mock.patch.object(
                github_gateway,
                "_denied_network_listener",
                return_value=nullcontext(18443),
            ),
            mock.patch.object(
                github_gateway,
                "_trusted_root_executable",
                side_effect=(
                    (Path("/usr/bin/systemd-run"), identity),
                    (Path("/usr/bin/systemctl"), identity),
                ),
            ),
            mock.patch.object(
                github_gateway.secrets,
                "token_hex",
                return_value="a" * 24,
            ),
            mock.patch.object(
                github_gateway,
                "_run_bounded",
                return_value=completed,
            ) as launch,
            mock.patch.object(github_gateway, "_stop_systemd_unit") as stop,
            mock.patch.object(
                github_gateway,
                "_reverify_root_executable",
            ) as reverify,
        ):
            observed = github_gateway._run_systemd_gateway_process(
                ("/usr/bin/python3", "-I", "-c", "pass"),
                timeout=12.5,
                environment=self.environment,
                worker_uid=999,
                worker_gid=987,
                allowed_addresses=("1.1.1.1",),
                writable_root=self.root,
                stdin_bytes=b"{}\n",
            )

        self.assertEqual(observed, completed)
        argv = launch.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/systemd-run")
        self.assertIn("--unit=aragorn-gateway-" + "a" * 24 + ".service", argv)
        self.assertIn("--uid=999", argv)
        self.assertIn("--gid=987", argv)
        for required in (
            "--property=IPAddressDeny=any",
            "--property=IPAddressAllow=1.1.1.1",
            "--property=TasksMax=1",
            "--property=KillMode=control-group",
            "--property=NoNewPrivileges=yes",
            "--property=CapabilityBoundingSet=",
            "--property=ProtectSystem=strict",
            "--property=SocketBindDeny=any",
            "--property=InaccessiblePaths=/tmp /var/tmp",
            "--property=RestrictAddressFamilies=AF_INET AF_INET6",
            "--property=UnsetEnvironment=LOGNAME USER SHELL MEMORY_PRESSURE_WATCH MEMORY_PRESSURE_WRITE",
            f"--property=ReadWritePaths={self.root}",
        ):
            self.assertIn(required, argv)
        self.assertIn("--setenv=ARAGORN_DENIED_PROBE=18443", argv)
        self.assertNotIn(
            "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", argv
        )
        separator = argv.index("--")
        self.assertEqual(
            argv[separator + 1 :], ("/usr/bin/python3", "-I", "-c", "pass")
        )
        self.assertNotIn("user", launch.call_args.kwargs)
        self.assertNotIn("group", launch.call_args.kwargs)
        self.assertEqual(launch.call_args.kwargs["stdin_bytes"], b"{}\n")
        stop.assert_called_once_with(
            Path("/usr/bin/systemctl"),
            "aragorn-gateway-" + "a" * 24 + ".service",
        )
        self.assertEqual(reverify.call_count, 2)

    def test_systemd_cleanup_runs_before_uid_postflight_after_launch_error(
        self,
    ) -> None:
        events: list[str] = []

        def fail_launch(*args: object, **kwargs: object) -> _ProcessResult:
            events.append("launch")
            raise OSError("systemd client failed")

        def stop(*args: object, **kwargs: object) -> None:
            events.append("stop")

        def census(*args: object, **kwargs: object) -> None:
            events.append("census")

        identity = ("sha256:" + "1" * 64, (1, 2, 3, 4))
        with (
            mock.patch.object(github_gateway.sys, "platform", "linux"),
            mock.patch.object(github_gateway, "_require_systemd_host"),
            mock.patch.object(github_gateway, "_require_bounded_transfer_mount"),
            mock.patch.object(
                github_gateway,
                "_denied_network_listener",
                return_value=nullcontext(18443),
            ),
            mock.patch.object(
                github_gateway,
                "_trusted_root_executable",
                side_effect=(
                    (Path("/usr/bin/systemd-run"), identity),
                    (Path("/usr/bin/systemctl"), identity),
                ),
            ),
            mock.patch.object(github_gateway, "_run_bounded", side_effect=fail_launch),
            mock.patch.object(github_gateway, "_stop_systemd_unit", side_effect=stop),
            mock.patch.object(github_gateway, "_reverify_root_executable"),
            mock.patch.object(github_gateway, "_require_idle_uid", side_effect=census),
            self.assertRaisesRegex(OSError, "systemd client failed"),
        ):
            github_gateway._run_gateway_process(
                ("/usr/bin/false",),
                timeout=1.0,
                environment=self.environment,
                worker_uid=999,
                worker_gid=987,
                allowed_addresses=("1.1.1.1",),
                writable_root=self.root,
                postflight_stage="after worker shutdown",
            )

        self.assertEqual(events, ["launch", "stop", "census"])

    def test_systemd_cleanup_failure_still_runs_uid_postflight(self) -> None:
        events: list[str] = []
        identity = ("sha256:" + "1" * 64, (1, 2, 3, 4))

        def stop(*args: object, **kwargs: object) -> None:
            events.append("stop")
            raise GitHubGatewayError("cleanup failed")

        def census(*args: object, **kwargs: object) -> None:
            events.append("census")

        with (
            mock.patch.object(github_gateway.sys, "platform", "linux"),
            mock.patch.object(github_gateway, "_require_systemd_host"),
            mock.patch.object(github_gateway, "_require_bounded_transfer_mount"),
            mock.patch.object(
                github_gateway,
                "_denied_network_listener",
                return_value=nullcontext(18443),
            ),
            mock.patch.object(
                github_gateway,
                "_trusted_root_executable",
                side_effect=(
                    (Path("/usr/bin/systemd-run"), identity),
                    (Path("/usr/bin/systemctl"), identity),
                ),
            ),
            mock.patch.object(
                github_gateway,
                "_run_bounded",
                return_value=_ProcessResult(b"", b"", 0),
            ),
            mock.patch.object(github_gateway, "_stop_systemd_unit", side_effect=stop),
            mock.patch.object(github_gateway, "_require_idle_uid", side_effect=census),
            self.assertRaisesRegex(GitHubGatewayError, "cleanup failed"),
        ):
            github_gateway._run_gateway_process(
                ("/usr/bin/true",),
                timeout=1.0,
                environment=self.environment,
                worker_uid=999,
                worker_gid=987,
                allowed_addresses=("1.1.1.1",),
                writable_root=self.root,
                postflight_stage="after worker shutdown",
            )

        self.assertEqual(events, ["stop", "census"])

    def test_transfer_root_requires_bounded_hardened_tmpfs(self) -> None:
        mount = (
            f"36 25 0:32 / {self.root} "
            "rw,nosuid,nodev,noexec,relatime - "
            "tmpfs tmpfs rw,size=524288k,nr_inodes=20000\n"
        ).encode("ascii")
        filesystem = os.statvfs_result(
            (4096, 4096, 131072, 65536, 65536, 20000, 10000, 10000, 0, 255)
        )
        with (
            mock.patch.object(
                github_gateway,
                "_read_virtual_file",
                return_value=mount,
            ),
            mock.patch.object(github_gateway.os, "statvfs", return_value=filesystem),
        ):
            github_gateway._require_bounded_transfer_mount(self.root)

        weak = mount.replace(b",noexec", b"")
        with (
            mock.patch.object(
                github_gateway,
                "_read_virtual_file",
                return_value=weak,
            ),
            self.assertRaisesRegex(GitHubGatewayError, "tmpfs mount"),
        ):
            github_gateway._require_bounded_transfer_mount(self.root)

    def test_reachable_denied_network_probe_is_fatal(self) -> None:
        with (
            self.assertRaisesRegex(GitHubGatewayError, "probe was reachable"),
            github_gateway._denied_network_listener() as port,
        ):
            connection = github_gateway.socket.create_connection(
                ("127.0.0.1", port),
                timeout=1.0,
            )
            connection.close()

    def test_stopped_unit_state_must_be_inactive_and_jobless(self) -> None:
        stop = _ProcessResult(b"", b"", 0)
        active = _ProcessResult(
            b"LoadState=loaded\nActiveState=active\nSubState=running\nJob=7 stop\n",
            b"",
            0,
        )
        with (
            mock.patch.object(
                github_gateway,
                "_run_bounded",
                side_effect=(stop, active),
            ),
            self.assertRaisesRegex(GitHubGatewayError, "did not stop completely"),
        ):
            github_gateway._stop_systemd_unit(
                Path("/usr/bin/systemctl"),
                "aragorn-gateway-test.service",
            )

    def test_stopped_collected_unit_without_cgroup_is_accepted(self) -> None:
        stop = _ProcessResult(b"", b"", 5)
        missing = _ProcessResult(
            b"LoadState=not-found\nActiveState=inactive\nSubState=dead\nJob=\n",
            b"",
            0,
        )
        with (
            mock.patch.object(
                github_gateway,
                "_run_bounded",
                side_effect=(stop, missing),
            ),
            mock.patch.object(
                github_gateway.os,
                "lstat",
                side_effect=FileNotFoundError,
            ),
        ):
            github_gateway._stop_systemd_unit(
                Path("/usr/bin/systemctl"),
                "aragorn-gateway-test.service",
            )

    def test_stopped_unit_rejects_populated_cgroup(self) -> None:
        unit = "aragorn-gateway-test.service"
        cgroup = self.root / unit
        cgroup.mkdir()
        (cgroup / "cgroup.procs").write_bytes(b"321\n")
        (cgroup / "cgroup.events").write_bytes(b"populated 1\n")
        stopped = _ProcessResult(b"", b"", 0)
        inactive = _ProcessResult(
            b"LoadState=loaded\nActiveState=inactive\nSubState=dead\nJob=\n",
            b"",
            0,
        )
        with (
            mock.patch.object(
                github_gateway,
                "_SYSTEMD_CGROUP_ROOT",
                self.root,
            ),
            mock.patch.object(
                github_gateway,
                "_run_bounded",
                side_effect=(stopped, inactive),
            ),
            self.assertRaisesRegex(GitHubGatewayError, "remains populated"),
        ):
            github_gateway._stop_systemd_unit(
                Path("/usr/bin/systemctl"),
                unit,
            )


if __name__ == "__main__":
    unittest.main()
