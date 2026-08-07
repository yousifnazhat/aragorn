from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_action_service_v3 as service
from tests.test_runtime_action_service_v2 import _binding

_ROOT = Path(__file__).resolve().parents[1]
_INSTALLER = _ROOT / "packaging/install-runtime-capability-host.sh"
_ACTIVATOR = _ROOT / "packaging/activate-runtime-capability-host.sh"
_BROKER_UNIT = (
    _ROOT / "packaging/systemd/aragorn-runtime-capability-action-broker.service"
)
_SENSOR_UNIT = (
    _ROOT / "packaging/systemd/aragorn-runtime-capability-observation-publisher.service"
)
_OBSOLETE_SHIMS = (
    "aragorn-runtime-action-service.py",
    "aragorn-runtime-action-service-v2.py",
    "aragorn-runtime-action-service-v3.py",
    "aragorn-runtime-observation-service.py",
    "aragorn-runtime-observation-service-v2.py",
)


def _credentials(root: Path) -> tuple[Path, Path]:
    runtime = root.resolve() / "runtime-binding"
    lease = root.resolve() / "capability-lease"
    runtime.write_bytes(_binding())
    lease.write_bytes(b"canonical lease bytes")
    runtime.chmod(0o400)
    lease.chmod(0o400)
    return runtime, lease


class RuntimeActionServiceV3Tests(unittest.TestCase):
    def test_main_initializes_then_serves_fixed_v3_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, lease = _credentials(Path(temporary))
            identities = (
                os.geteuid(),
                os.geteuid() + 1,
                os.getegid() + 1,
                os.geteuid() + 2,
                os.getegid() + 2,
            )
            order: list[str] = []
            with (
                patch.object(service.sys, "platform", "linux"),
                patch.object(service, "_service_identities", return_value=identities),
                patch.dict(
                    os.environ,
                    {"CREDENTIALS_DIRECTORY": str(runtime.parent)},
                ),
                patch.object(
                    service,
                    "initialize_runtime_capability_lease",
                    side_effect=lambda _config: order.append("initialize"),
                ) as initialize,
                patch.object(
                    service,
                    "serve_runtime_action_broker_v3",
                    side_effect=lambda _config: order.append("serve"),
                ) as serve,
            ):
                self.assertEqual(service.main([str(runtime), str(lease)]), 0)

        self.assertEqual(order, ["initialize", "serve"])
        config = serve.call_args.args[0]
        self.assertIs(config, initialize.call_args.args[0])
        root = Path("/var/lib/aragorn-runtime-action")
        self.assertEqual(config.capability_lease, b"canonical lease bytes")
        self.assertEqual(
            config.lease_state_path,
            root / "control/capability-lease-state.json",
        )
        self.assertEqual(config.broker.expected_runtime_profile_digest[-64:], "2" * 64)
        self.assertEqual(config.broker.broker.expected_broker_uid, identities[0])
        self.assertEqual(config.broker.broker.expected_runtime_uid, identities[1])
        self.assertEqual(config.broker.broker.expected_peer_uid, identities[3])

    def test_usage_platform_and_interrupt_are_bounded(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(service.main([]), 64)
        self.assertIn("usage: aragorn-runtime-action-service-v3", stderr.getvalue())

        with (
            patch.object(service.sys, "platform", "darwin"),
            patch.object(service, "serve_runtime_action_broker_v3") as serve,
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(service.main(["runtime-binding", "capability-lease"]), 126)
        serve.assert_not_called()

        with (
            patch.object(service, "_run", side_effect=KeyboardInterrupt),
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(service.main(["runtime-binding", "capability-lease"]), 0)

    def test_units_expose_only_the_grant_redeemer_to_the_v3_sensor(self) -> None:
        broker = _BROKER_UNIT.read_text(encoding="utf-8")
        sensor = _SENSOR_UNIT.read_text(encoding="utf-8")
        self.assertIn(
            "Conflicts=aragorn-runtime-action-broker.service "
            "aragorn-runtime-profile-action-broker.service",
            broker,
        )
        self.assertIn("LoadCredential=runtime-binding:", broker)
        self.assertIn("LoadCredential=capability-grant:", broker)
        self.assertIn("aragorn-runtime-action-service-v4.py", broker)
        self.assertIn("%d/runtime-binding %d/capability-grant", broker)
        self.assertIn("NoNewPrivileges=yes", broker)
        self.assertIn("CapabilityBoundingSet=", broker)
        self.assertIn(
            "Requires=aragorn-runtime-capability-action-broker.service",
            sensor,
        )
        self.assertIn("LoadCredential=capability-grant:", sensor)
        self.assertIn("aragorn-runtime-observation-service-v3.py", sensor)
        self.assertIn("%d/observation-binding %d/capability-grant", sensor)
        self.assertNotIn("capability-lease", broker + sensor)
        self.assertNotIn("aragorn-runtime-action-service-v2.py", broker)

    def test_installer_stages_v2_dependencies_without_legacy_broker_units(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            obsolete_root = Path(temporary) / "usr/libexec/aragorn"
            obsolete_root.mkdir(parents=True)
            for name in _OBSOLETE_SHIMS:
                (obsolete_root / name).write_text("obsolete\n", encoding="utf-8")
            subprocess.run(
                ["sh", str(_INSTALLER)],
                check=True,
                cwd=_ROOT,
                env={**os.environ, "DESTDIR": temporary},
                capture_output=True,
            )
            staged = Path(temporary)
            modules = staged / "usr/lib/aragorn/aragorn"
            for name in (
                "runtime_action_broker_v2.py",
                "runtime_action_service_v2.py",
                "runtime_action_broker_v3.py",
                "runtime_capability_grant.py",
                "runtime_action_observation_publisher_v3.py",
                "runtime_action_broker_v4.py",
                "runtime_action_service_v4.py",
                "runtime_observation_service_v3.py",
            ):
                self.assertTrue((modules / name).is_file())
            launcher = (
                staged / "usr/libexec/aragorn/aragorn-runtime-action-service-v4.py"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(launcher)],
                check=False,
                cwd="/",
                env={"PATH": "/usr/bin:/bin"},
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 64, result.stderr)
            self.assertIn("usage: aragorn-runtime-action-service-v4", result.stderr)
            self.assertTrue(
                (staged / "usr/libexec/aragorn" / _ACTIVATOR.name).is_file()
            )
            for name in _OBSOLETE_SHIMS:
                self.assertFalse((staged / "usr/libexec/aragorn" / name).exists())
            for unit in (_BROKER_UNIT, _SENSOR_UNIT):
                self.assertTrue(
                    (staged / "usr/lib/systemd/system" / unit.name).is_file()
                )
            for legacy in (
                "aragorn-runtime-action-broker.service",
                "aragorn-runtime-profile-action-broker.service",
                "aragorn-runtime-observation-publisher.service",
                "aragorn-runtime-profile-observation-publisher.service",
            ):
                self.assertFalse((staged / "usr/lib/systemd/system" / legacy).exists())

    def test_activation_masks_every_legacy_route_before_v3_start(self) -> None:
        script = _ACTIVATOR.read_text(encoding="utf-8")
        for legacy in (
            "aragorn-runtime-action-broker.service",
            "aragorn-runtime-profile-action-broker.service",
            "aragorn-runtime-observation-publisher.service",
            "aragorn-runtime-profile-observation-publisher.service",
        ):
            self.assertIn(legacy, script)
        self.assertIn('disable --now "$unit"', script)
        self.assertIn('disable --now "$new_sensor" "$new_broker"', script)
        self.assertIn('mask "$unit"', script)
        self.assertIn('is-active --quiet "$new_broker"', script)
        self.assertIn('is-active --quiet "$new_sensor"', script)

    def test_activation_pins_grant_authority_and_effective_units(self) -> None:
        script = _ACTIVATOR.read_text(encoding="utf-8")
        self.assertIn("require_safe_root_directory /\n", script)
        self.assertIn("require_safe_root_directory /etc", script)
        self.assertIn("require_safe_root_directory /etc/aragorn", script)
        self.assertIn('[ -L "$grant_path" ]', script)
        self.assertIn("stat -c '%u:%g:%a:%h' -- \"$grant_path\"", script)
        self.assertIn('"$grant_metadata" != "0:0:400:1"', script)
        for property_name in (
            "FragmentPath",
            "DropInPaths",
            "User",
            "Group",
            "SupplementaryGroups",
            "ExecStart",
            "LoadCredential",
        ):
            self.assertIn(property_name, script)
        self.assertIn("aragorn-runtime-action-service-v4.py", script)
        self.assertIn("aragorn-runtime-observation-service-v3.py", script)
        self.assertIn("verified_argv=${verified_after_argv%% ; *}", script)
        self.assertIn("/usr/bin/busctl get-property", script)
        self.assertIn('verified_expected_credentials="a(ss) 2', script)
        self.assertNotIn(
            'unit_property "$verified_unit" LoadCredential',
            script,
        )
        self.assertIn(
            "runtime-binding:/etc/aragorn/runtime-action-runtime.json",
            script,
        )
        self.assertIn(
            "observation-binding:/etc/aragorn/runtime-action-observation.json",
            script,
        )
        self.assertIn(
            "capability-grant:/etc/aragorn/runtime-capability-grant.json",
            script,
        )
        verification = script.index('verify_effective_unit \\\n    "$new_broker"')
        stop = script.index('disable --now "$new_sensor" "$new_broker"')
        start = script.index('/usr/bin/systemctl enable --now "$new_broker"')
        self.assertLess(stop, verification)
        self.assertLess(verification, start)


if __name__ == "__main__":
    unittest.main()
