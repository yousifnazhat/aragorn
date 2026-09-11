from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_action_broker as broker
from aragorn import runtime_health_service as service
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests.test_runtime_action_broker import _Fixture
from tests.test_runtime_action_service_v2 import _binding
from tests.test_runtime_revocation_service import _IDENTITIES, _RUNTIME


def _replace(path: Path, raw: bytes) -> None:
    path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o400)


@contextmanager
def _environment():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        fixture = _Fixture(root)
        credentials = root / "credentials"
        credentials.mkdir(mode=0o700)
        runtime, health = credentials / "runtime-binding", credentials / "health"
        runtime.write_bytes(_binding())
        health.write_bytes(
            canonical_json({**fixture.health, "epoch": 5, "status": "unhealthy"})
        )
        runtime.chmod(0o400)
        health.chmod(0o400)
        with (
            patch.object(service.sys, "platform", "linux"),
            patch.object(service, "_service_identities", return_value=_IDENTITIES),
            patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(credentials)}),
            patch.object(service, "_CONTROL_ROOT", fixture.control),
            patch.object(service, "_PROTECTED_ROOT", fixture.protected),
            patch.object(service, "_STAGING_ROOT", fixture.staging),
            patch.object(broker.time, "time", return_value=100),
        ):
            yield fixture, runtime, health


class RuntimeHealthServiceTests(unittest.TestCase):
    def test_publisher_uses_only_fixed_health_configuration(self):
        with _environment() as (fixture, runtime, health):
            document = json.loads(health.read_bytes())
            with patch.object(service, "publish_runtime_control_document") as publish:
                result = service._run(runtime, health)
            expected = service.RuntimeActionBrokerConfig(
                socket_path=fixture.control / "broker.sock",
                instance_lock_path=fixture.control / "broker.instance.lock",
                lock_path=fixture.control / "broker.lock",
                control_root=fixture.control,
                protected_root=fixture.protected,
                staging_root=fixture.staging,
                policy_path=fixture.paths["policy"],
                revocations_path=fixture.paths["revocations"],
                health_path=fixture.paths["health"],
                observation_path=fixture.paths["observation"],
                state_path=fixture.paths["state"],
                expected_broker_uid=_IDENTITIES[0],
                expected_peer_uid=_IDENTITIES[3],
                expected_peer_gid=_IDENTITIES[4],
                expected_runtime_digest=_RUNTIME,
                expected_runtime_uid=_IDENTITIES[1],
                expected_runtime_gid=_IDENTITIES[2],
            )
            publish.assert_called_once_with(expected.health_path, document, expected)
            self.assertEqual(
                result,
                {
                    "schema": "aragorn/runtime-health-publication-result/v1",
                    "authority": "LOCAL_PROCESS_RESULT_ONLY_NOT_DURABLE_PROVENANCE_OR_RESPONSE_AUTHORITY",
                    "health_digest": canonical_digest(document),
                    "epoch": 5,
                    "health_status": "unhealthy",
                },
            )

    def test_real_publication_advances_floor_without_other_control_changes(self):
        with _environment() as (fixture, runtime, health):
            before = {name: path.read_bytes() for name, path in fixture.paths.items()}
            for epoch, status in ((5, "unhealthy"), (5, "unhealthy"), (6, "healthy")):
                document = {**fixture.health, "epoch": epoch, "status": status}
                _replace(health, canonical_json(document))
                with redirect_stdout(output := StringIO()):
                    self.assertEqual(service.main([str(runtime), str(health)]), 0)
                self.assertEqual(
                    json.loads(output.getvalue())["health_digest"],
                    canonical_digest(document),
                )
                self.assertEqual(
                    fixture.paths["health"].read_bytes(), health.read_bytes()
                )
                self.assertEqual(
                    fixture.load_state()["minimum_mediator_health_epoch"], epoch
                )
                for name in ("policy", "revocations", "observation"):
                    self.assertEqual(fixture.paths[name].read_bytes(), before[name])
                self.assertEqual(list(fixture.protected.iterdir()), [])

    def test_invalid_credentials_and_unaccepted_health_never_report_success(self):
        for mutation in (
            "malformed",
            "newline",
            "duplicate",
            "array",
            "mode",
            "name",
            "binding",
            {"epoch": 4},
            {"status": "healthy"},
            {"epoch": True},
            {"status": "unknown"},
            {"epoch": 6, "runtime_digest": "sha256:" + "0" * 64},
            {"epoch": 6, "sensor_digest": "sha256:" + "0" * 64},
            {"epoch": 6, "observed_at_unix": 80, "expires_at_unix": 90},
            {"epoch": 6, "observed_at_unix": 101, "expires_at_unix": 110},
            {"epoch": 6, "extra": True},
        ):
            with (
                self.subTest(mutation=mutation),
                _environment() as (fixture, runtime, health),
            ):
                accepted = service._run(runtime, health)
                self.assertEqual(accepted["epoch"], 5)
                before = {
                    name: path.read_bytes() for name, path in fixture.paths.items()
                }
                document = json.loads(health.read_bytes())
                if isinstance(mutation, dict):
                    _replace(health, canonical_json({**document, **mutation}))
                elif mutation == "mode":
                    health.chmod(0o600)
                elif mutation == "name":
                    health = health.parent / "arbitrary"
                elif mutation == "binding":
                    value = json.loads(runtime.read_bytes())
                    value["runtime_digest"] = "sha256:" + "0" * 64
                    _replace(runtime, canonical_json(value))
                else:
                    _replace(
                        health,
                        {
                            "malformed": b"{",
                            "newline": health.read_bytes() + b"\n",
                            "duplicate": b'{"epoch":5,"epoch":5}',
                            "array": b"[]",
                        }[mutation],
                    )
                with redirect_stdout(output := StringIO()), redirect_stderr(StringIO()):
                    self.assertEqual(service.main([str(runtime), str(health)]), 126)
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(
                    {name: path.read_bytes() for name, path in fixture.paths.items()},
                    before,
                )

    def test_cleanup_failure_after_publication_is_not_reported_as_success(self):
        release = broker._release_lock_and_close

        def fail_after_close(*args):
            self.assertIsNone(release(*args))
            return OSError("cleanup failed after publication")

        with _environment() as (fixture, runtime, health):
            with (
                patch.object(
                    broker, "_release_lock_and_close", side_effect=fail_after_close
                ),
                redirect_stdout(output := StringIO()),
                redirect_stderr(error := StringIO()),
            ):
                self.assertEqual(service.main([str(runtime), str(health)]), 126)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("publication cleanup failed", error.getvalue())
            # Publication already happened; nonzero is not a rollback claim.
            self.assertEqual(fixture.paths["health"].read_bytes(), health.read_bytes())
            self.assertEqual(fixture.load_state()["minimum_mediator_health_epoch"], 5)

    def test_cli_and_publication_failures_do_not_emit_success(self):
        for args in ([], ["binding"], ["a", "b", "c"]):
            with redirect_stderr(StringIO()):
                self.assertEqual(service.main(args), 64)
        for failure, code in (
            (KeyboardInterrupt(), 130),
            (service.RuntimeActionBrokerError("cleanup"), 126),
        ):
            with (
                patch.object(service, "_run", side_effect=failure),
                redirect_stdout(output := StringIO()),
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(service.main(["binding", "health"]), code)
                self.assertEqual(output.getvalue(), "")
        with _environment() as (_fixture, runtime, health):
            for target, value in (("platform", "darwin"), ("identity", None)):
                context = (
                    patch.object(service.sys, "platform", value)
                    if target == "platform"
                    else patch.object(
                        service,
                        "_service_identities",
                        side_effect=service.RuntimeActionServiceError("identity"),
                    )
                )
                with (
                    context,
                    patch.object(
                        service, "publish_runtime_control_document"
                    ) as publish,
                    redirect_stderr(StringIO()),
                ):
                    self.assertEqual(service.main([str(runtime), str(health)]), 126)
                publish.assert_not_called()
        for failure in (KeyboardInterrupt(), OSError("publication interrupted")):
            with _environment() as (fixture, runtime, health):
                before = {
                    name: path.read_bytes() for name, path in fixture.paths.items()
                }
                with (
                    patch.object(broker, "_atomic_publish_at", side_effect=failure),
                    redirect_stdout(output := StringIO()),
                    redirect_stderr(StringIO()),
                ):
                    self.assertNotEqual(service.main([str(runtime), str(health)]), 0)
                    self.assertEqual(output.getvalue(), "")
                self.assertEqual(
                    {name: path.read_bytes() for name, path in fixture.paths.items()},
                    before,
                )


if __name__ == "__main__":
    unittest.main()
