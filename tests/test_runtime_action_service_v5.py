from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_action_service_v5 as service
from tests.test_runtime_capability_services import _credentials

_ROOT = Path(__file__).resolve().parents[1]
_UNIT = (
    _ROOT / "packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service"
)


class RuntimeActionServiceV5Tests(unittest.TestCase):
    def test_service_initializes_v4_state_then_serves_lineage_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, _observation, grant, grant_raw = _credentials(Path(temporary))
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
                patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(runtime.parent)}),
                patch.object(
                    service,
                    "initialize_runtime_capability_grant",
                    side_effect=lambda _config: order.append("initialize"),
                ) as initialize,
                patch.object(
                    service,
                    "serve_runtime_action_broker_v5",
                    side_effect=lambda _config: order.append("serve"),
                ) as serve,
            ):
                self.assertEqual(service.main([str(runtime), str(grant)]), 0)

        self.assertEqual(order, ["initialize", "serve"])
        config = serve.call_args.args[0]
        self.assertIs(config.broker, initialize.call_args.args[0])
        self.assertEqual(config.broker.capability_grant, grant_raw)
        self.assertEqual(
            config.protected_install_root,
            Path("/var/lib/aragorn-protected/skills"),
        )

    def test_usage_launcher_and_unit_are_lineage_bounded(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(service.main([]), 64)
        self.assertIn("usage: aragorn-runtime-action-service-v5", stderr.getvalue())

        launcher = (
            _ROOT / "packaging/libexec/aragorn-runtime-action-service-v5.py"
        ).read_text(encoding="utf-8")
        self.assertIn("aragorn.runtime_action_service_v5", launcher)

        unit = _UNIT.read_text(encoding="utf-8")
        self.assertIn("aragorn-runtime-action-service-v5.py", unit)
        self.assertIn(
            "RequiresMountsFor=/var/lib/aragorn-runtime-action/control ",
            unit,
        )
        self.assertIn("/var/lib/aragorn-protected/skills", unit)
        self.assertIn(
            "ReadOnlyPaths=/var/lib/aragorn-protected/skills",
            unit,
        )
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("CapabilityBoundingSet=\n", unit)


if __name__ == "__main__":
    unittest.main()
