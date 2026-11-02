from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_observation_service_v4 as service
from tests.test_runtime_capability_services import _credentials

_ROOT = Path(__file__).resolve().parents[1]
_LAUNCHER = _ROOT / "packaging/libexec/aragorn-runtime-observation-service-v4.py"
_UNIT = (
    _ROOT
    / "packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service"
)


class RuntimeObservationServiceV4Tests(unittest.TestCase):
    def test_service_builds_the_lineage_publisher_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _runtime, observation, grant, grant_bytes = _credentials(Path(temporary))
            identities = (
                os.geteuid(),
                os.getegid(),
                os.geteuid() + 1,
                os.getegid() + 1,
                os.geteuid() + 2,
            )
            with (
                patch.object(service.sys, "platform", "linux"),
                patch.object(service, "_service_identities", return_value=identities),
                patch.dict(
                    os.environ,
                    {"CREDENTIALS_DIRECTORY": str(observation.parent)},
                ),
                patch.object(
                    service,
                    "serve_runtime_action_observation_publisher_v4",
                ) as serve,
            ):
                self.assertEqual(service.main([str(observation), str(grant)]), 0)

        config = serve.call_args.args[0]
        self.assertEqual(config.capability_grant, grant_bytes)
        self.assertEqual(
            config.protected_install_root,
            Path("/var/lib/aragorn-protected/skills"),
        )

    def test_launcher_and_unit_select_only_the_additive_v4_route(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(service.main([]), 64)
        self.assertIn(
            "usage: aragorn-runtime-observation-service-v4", stderr.getvalue()
        )

        launcher = _LAUNCHER.read_text(encoding="utf-8")
        unit = _UNIT.read_text(encoding="utf-8")
        self.assertIn("aragorn.runtime_observation_service_v4", launcher)
        self.assertIn(
            "BindsTo=aragorn-runtime-lineage-capability-action-broker.service",
            unit,
        )
        self.assertNotIn(
            "Requires=aragorn-runtime-lineage-capability-action-broker.service",
            unit,
        )
        self.assertIn(
            "After=local-fs.target nss-user-lookup.target "
            "aragorn-runtime-lineage-capability-action-broker.service",
            unit,
        )
        self.assertEqual(unit.count("Restart=no"), 1)
        self.assertNotIn("Restart=on-failure", unit)
        self.assertNotIn("RestartSec=", unit)
        self.assertIn("aragorn-runtime-observation-service-v4.py", unit)
        self.assertIn(
            "ConditionPathExists=/var/lib/aragorn-protected/skills/"
            ".aragorn-active-runtime.json",
            unit,
        )
        self.assertIn("ReadOnlyPaths=/var/lib/aragorn-runtime-action/control ", unit)
        self.assertIn("/var/lib/aragorn-protected/skills", unit)
        self.assertIn(
            "aragorn-runtime-capability-observation-publisher.service",
            unit,
        )


if __name__ == "__main__":
    unittest.main()
