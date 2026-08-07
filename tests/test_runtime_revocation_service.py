from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_revocation_service as service
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import RuntimeActionBrokerError
from tests.test_runtime_action_broker import _SKILL, _Fixture
from tests.test_runtime_action_service_v2 import _binding

_SOURCE = "sha256:" + "7" * 64
_RUNTIME = "sha256:" + "1" * 64
_IDENTITIES = (
    os.geteuid(),
    os.geteuid() + 1,
    os.getegid() + 1,
    os.geteuid() + 2,
    os.getegid() + 2,
)


def _revocations(**changes: object) -> dict[str, object]:
    return {
        "schema": "aragorn/runtime-action-revocations/v1",
        "source_digest": _SOURCE,
        "generation": 4,
        "observed_at_unix": 95,
        "expires_at_unix": 105,
        "skill_digests": [],
        **changes,
    }


def _credentials(
    root: Path,
    revocations: bytes | None = None,
) -> tuple[Path, Path]:
    runtime = root.resolve() / "runtime-binding"
    revocation = root.resolve() / "revocations"
    runtime.write_bytes(_binding())
    revocation.write_bytes(
        canonical_json(_revocations()) if revocations is None else revocations
    )
    runtime.chmod(0o400)
    revocation.chmod(0o400)
    return runtime, revocation


class RuntimeRevocationServiceTests(unittest.TestCase):
    def test_main_publishes_exact_fixed_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, revocations = _credentials(Path(temporary))
            with (
                patch.object(service.sys, "platform", "linux"),
                patch.object(
                    service,
                    "_service_identities",
                    return_value=_IDENTITIES,
                ),
                patch.dict(
                    os.environ,
                    {"CREDENTIALS_DIRECTORY": str(runtime.parent)},
                ),
                patch.object(service, "publish_runtime_control_document") as publish,
                redirect_stdout(stdout := StringIO()),
            ):
                self.assertEqual(
                    service.main([str(runtime), str(revocations)]),
                    0,
                )

        path, document, config = publish.call_args.args
        root = Path("/var/lib/aragorn-runtime-action")
        expected = service.RuntimeActionBrokerConfig(
            socket_path=root / "control/broker.sock",
            instance_lock_path=root / "control/broker.instance.lock",
            lock_path=root / "control/broker.lock",
            control_root=root / "control",
            protected_root=root / "protected",
            staging_root=root / "staging",
            policy_path=root / "control/policy.json",
            revocations_path=root / "control/revocations.json",
            health_path=root / "control/health.json",
            observation_path=root / "control/observation.json",
            state_path=root / "control/state.json",
            expected_broker_uid=_IDENTITIES[0],
            expected_peer_uid=_IDENTITIES[3],
            expected_peer_gid=_IDENTITIES[4],
            expected_runtime_digest=_RUNTIME,
            expected_runtime_uid=_IDENTITIES[1],
            expected_runtime_gid=_IDENTITIES[2],
        )
        self.assertEqual(
            (path, document, config),
            (expected.revocations_path, _revocations(), expected),
        )
        self.assertEqual(publish.call_args.kwargs, {})
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "schema": "aragorn/runtime-revocation-publication-result/v1",
                "authority": (
                    "LOCAL_PROCESS_RESULT_ONLY_NOT_DURABLE_PROVENANCE_AUTHORITY"
                ),
                "revocations_digest": canonical_digest(_revocations()),
                "generation": 4,
            },
        )

    def test_usage_platform_and_identity_are_bounded(self) -> None:
        for arguments in ([], ["binding"], ["a", "b", "c"]):
            with self.subTest(arguments=arguments), redirect_stderr(StringIO()):
                self.assertEqual(service.main(arguments), 64)

        stderr = StringIO()
        with (
            patch.object(service.sys, "platform", "darwin"),
            patch.object(service, "publish_runtime_control_document") as publish,
            redirect_stderr(stderr),
        ):
            self.assertEqual(service.main(["binding", "revocations"]), 126)
        self.assertIn("Linux execution is required", stderr.getvalue())
        publish.assert_not_called()

        with (
            patch.object(service.sys, "platform", "linux"),
            patch.object(
                service,
                "_service_identities",
                side_effect=service.RuntimeActionServiceError(
                    "broker process identity is invalid"
                ),
            ),
            redirect_stderr(stderr := StringIO()),
        ):
            self.assertEqual(service.main(["binding", "revocations"]), 126)
        self.assertIn("broker process identity is invalid", stderr.getvalue())

    def test_unsafe_revocation_credential_is_not_published(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, revocations = _credentials(Path(temporary))
            revocations.chmod(0o600)
            with (
                patch.object(service.sys, "platform", "linux"),
                patch.object(
                    service,
                    "_service_identities",
                    return_value=_IDENTITIES,
                ),
                patch.dict(
                    os.environ,
                    {"CREDENTIALS_DIRECTORY": str(runtime.parent)},
                ),
                patch.object(service, "publish_runtime_control_document") as publish,
                redirect_stderr(stderr := StringIO()),
            ):
                self.assertEqual(
                    service.main([str(runtime), str(revocations)]),
                    126,
                )
        self.assertIn("runtime revocations credential is unsafe", stderr.getvalue())
        publish.assert_not_called()

    def test_noncanonical_revocations_are_rejected_before_publication(self) -> None:
        invalid = (
            b"{",
            canonical_json(_revocations()) + b"\n",
            b"[]",
            b'{"value":1,"value":1}',
        )
        for raw in invalid:
            with self.subTest(raw=raw[:80]), tempfile.TemporaryDirectory() as temporary:
                runtime, revocations = _credentials(Path(temporary), raw)
                with (
                    patch.object(service.sys, "platform", "linux"),
                    patch.object(
                        service,
                        "_service_identities",
                        return_value=_IDENTITIES,
                    ),
                    patch.dict(
                        os.environ,
                        {"CREDENTIALS_DIRECTORY": str(runtime.parent)},
                    ),
                    patch.object(
                        service,
                        "publish_runtime_control_document",
                    ) as publish,
                    redirect_stderr(stderr := StringIO()),
                ):
                    self.assertEqual(
                        service.main([str(runtime), str(revocations)]),
                        126,
                    )
                self.assertIn(
                    "runtime revocations credential is invalid",
                    stderr.getvalue(),
                )
                publish.assert_not_called()

    def test_publisher_interrupt_and_invalid_updates_preserve_control_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            accepted = {
                **fixture.revocations,
                "generation": 5,
                "skill_digests": [_SKILL],
            }
            service.publish_runtime_control_document(
                fixture.paths["revocations"],
                accepted,
                fixture.config,
                clock=lambda: 100,
            )
            retained = fixture.paths["revocations"].read_bytes()
            retained_state = fixture.paths["state"].read_bytes()

            interrupted = {**accepted, "generation": 6}
            with (
                patch.object(
                    service,
                    "_run",
                    side_effect=lambda *_: service.publish_runtime_control_document(
                        fixture.paths["revocations"],
                        interrupted,
                        fixture.config,
                        clock=lambda: 100,
                    ),
                ),
                patch(
                    "aragorn.runtime_action_broker._atomic_publish_at",
                    side_effect=KeyboardInterrupt,
                ),
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(service.main(["binding", "revocations"]), 130)
            self.assertEqual(fixture.paths["revocations"].read_bytes(), retained)
            self.assertEqual(fixture.paths["state"].read_bytes(), retained_state)

            candidates = (
                {**accepted, "generation": 4},
                {**accepted, "skill_digests": []},
                {
                    **accepted,
                    "generation": 6,
                    "observed_at_unix": 80,
                    "expires_at_unix": 90,
                },
            )
            for candidate in candidates:
                with (
                    self.subTest(candidate=candidate),
                    self.assertRaises(RuntimeActionBrokerError),
                ):
                    service.publish_runtime_control_document(
                        fixture.paths["revocations"],
                        candidate,
                        fixture.config,
                        clock=lambda: 100,
                    )
                self.assertEqual(
                    fixture.paths["revocations"].read_bytes(),
                    retained,
                )
                self.assertEqual(fixture.paths["state"].read_bytes(), retained_state)


if __name__ == "__main__":
    unittest.main()
