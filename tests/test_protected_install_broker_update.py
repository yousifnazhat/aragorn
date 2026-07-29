from __future__ import annotations

import argparse
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from aragorn.cas import CAS
from aragorn.manifest_diff import diff_verified_manifests_between
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests.test_admission_artifact_graph import _retain_github_quarantine
from tests.test_protected_install_broker import (
    _ROOT,
    _github_args,
    _load_producer,
    _service_args,
)


def _resolved_service_args(
    direct,
    *,
    base: Path,
    operation: str,
    expected_active: dict[str, object] | None,
    expected_manifest_diff_digest: str | None,
    previous_root: Path | None,
):
    direct.service_request = "/run/credentials/test/install-request"
    direct.cas_base_root = str(base)
    direct.operation = operation
    direct.expected_active = expected_active
    direct.expected_manifest_diff_digest = expected_manifest_diff_digest
    direct.expected_active_cas_root = (
        None if previous_root is None else str(previous_root)
    )
    return direct


def _request_v2(
    direct,
    *,
    expected_active: dict[str, object],
    expected_manifest_diff_digest: str,
) -> dict[str, object]:
    return {
        "schema": "aragorn/protected-install-broker-request/v2",
        "expires_at_unix": direct.expires_at_unix,
        "operation": "update",
        "expected_active": expected_active,
        "expected_manifest_diff_digest": expected_manifest_diff_digest,
        "target_runtime_digest": direct.target_runtime_digest,
        "runtime_conformance_digest": direct.runtime_conformance_digest,
        "manifest_digest": direct.manifest_digest,
        "quarantine_receipt_digest": direct.quarantine_receipt_digest,
        "gateway_profile_digest": direct.gateway_profile_digest,
        "context_id": direct.context_id,
        "source_request": {
            "schema": "aragorn/github-gateway-request/v1",
            "owner": direct.expected_owner,
            "repository": direct.expected_repository,
            "commit": direct.expected_commit,
            "skill_path": direct.expected_skill_path,
        },
        "expected_producer_implementation_digest": (
            direct.expected_producer_implementation_digest
        ),
        "expected_analyzer_implementation_digest": (
            direct.expected_analyzer_implementation_digest
        ),
        "expected_analyzer_executable_digest": (
            direct.expected_analyzer_executable_digest
        ),
        "expected_analyzer_configuration_digest": (
            direct.expected_analyzer_configuration_digest
        ),
        "expected_policy_digest": direct.expected_policy_digest,
        "expected_analyzer_verifier_digest": (
            direct.expected_analyzer_verifier_digest
        ),
        "expected_artifact_graph_verifier_digest": (
            direct.expected_artifact_graph_verifier_digest
        ),
    }


@unittest.skipUnless(os.name == "posix", "protected install requires POSIX")
class ProtectedInstallBrokerUpdateTests(unittest.TestCase):
    def test_service_v2_installs_updates_and_rejects_stale_predecessor(
        self,
    ) -> None:
        producer = _load_producer()
        with (
            TemporaryDirectory(dir=_ROOT) as temporary,
            mock.patch(
                "aragorn.github_quarantine_receipt.sys.platform",
                "linux",
            ),
            mock.patch(
                "aragorn.admission_artifact_graph._REQUIRED_BROKER_UID",
                os.geteuid(),
            ),
        ):
            root = Path(temporary).resolve()
            base = root / "quarantine"
            base.mkdir(mode=0o700)
            protected = root / "protected"
            protected.mkdir(mode=0o700)

            def retain(label: str, content: bytes):
                staging = base / f".{label}"
                staging_cas = CAS(staging)
                (
                    manifest_digest,
                    _proof_digest,
                    receipt_digest,
                    gateway_profile_digest,
                ) = _retain_github_quarantine(staging_cas, content)
                request = json.loads(staging_cas.read(receipt_digest))[
                    "request"
                ]
                namespace = base / canonical_digest(request)[7:]
                staging.rename(namespace)
                return (
                    CAS(namespace),
                    namespace,
                    manifest_digest,
                    receipt_digest,
                    gateway_profile_digest,
                    request,
                )

            old = retain("old", b"# inert GitHub skill v1\n")
            new = retain("new", b"# inert GitHub skill v2\n")
            third = retain("third", b"# inert GitHub skill v3\n")

            def github_args(source, context_character: str):
                (
                    _cas,
                    namespace,
                    manifest_digest,
                    receipt_digest,
                    gateway_profile_digest,
                    request,
                ) = source
                direct = _github_args(
                    producer=producer,
                    cas_root=namespace,
                    protected_root=protected,
                    manifest_digest=manifest_digest,
                    receipt_digest=receipt_digest,
                    gateway_profile_digest=gateway_profile_digest,
                    request=request,
                )
                direct.context_id = "sha256:" + context_character * 64
                return direct

            install_args = _resolved_service_args(
                github_args(old, "3"),
                base=base,
                operation="install",
                expected_active=None,
                expected_manifest_diff_digest=None,
                previous_root=None,
            )
            with mock.patch.object(producer.time, "time", return_value=101):
                installed = producer._run(install_args)
            self.assertEqual(installed["transaction"]["operation"], "install")
            self.assertEqual(
                (protected / producer._TARGET / "SKILL.md").read_bytes(),
                b"# inert GitHub skill v1\n",
            )

            expected_active = {
                "context_id": install_args.context_id,
                "manifest_digest": old[2],
                "source_request": old[5],
                "quarantine_receipt_digest": old[3],
                "gateway_profile_digest": old[4],
            }
            update_diff = diff_verified_manifests_between(
                old[0],
                old[2],
                new[0],
                new[2],
            )
            update_args = _resolved_service_args(
                github_args(new, "4"),
                base=base,
                operation="update",
                expected_active=expected_active,
                expected_manifest_diff_digest=canonical_digest(update_diff),
                previous_root=old[1],
            )
            wrong_diff = argparse.Namespace(**vars(update_args))
            wrong_diff.expected_manifest_diff_digest = "sha256:" + "0" * 64
            before_wrong_diff = producer._bounded_tree_snapshot_digest(
                protected
            )
            with (
                mock.patch.object(producer, "run_analyzer") as analyzer,
                mock.patch.object(producer, "_publish") as publication,
                self.assertRaisesRegex(
                    producer.BrokerConformanceError,
                    "diff does not match",
                ),
            ):
                producer._run(wrong_diff)
            analyzer.assert_not_called()
            publication.assert_not_called()
            self.assertEqual(
                before_wrong_diff,
                producer._bounded_tree_snapshot_digest(protected),
            )

            update_diff_digest = canonical_digest(update_diff)
            update_diff_path = (
                new[1]
                / "blobs"
                / "sha256"
                / update_diff_digest[7:9]
                / update_diff_digest[9:]
            )
            run_analyzer = producer.run_analyzer

            def analyze_then_remove_diff(*args, **kwargs):
                result = run_analyzer(*args, **kwargs)
                update_diff_path.unlink()
                return result

            with (
                mock.patch.object(producer.time, "time", return_value=101),
                mock.patch.object(
                    producer,
                    "run_analyzer",
                    side_effect=analyze_then_remove_diff,
                ),
            ):
                updated = producer._run(update_args)

            self.assertEqual(updated["transaction"]["operation"], "update")
            self.assertEqual(
                updated["transaction"]["expected_active"],
                {
                    "context_id": install_args.context_id,
                    "manifest_digest": old[2],
                },
            )
            self.assertEqual(
                updated["transition"]["manifest_diff"],
                {
                    "digest": canonical_digest(update_diff),
                    "document": update_diff,
                },
            )
            self.assertIn(
                "manifest-update-diff-v1",
                updated["verified_sequence"],
            )
            self.assertEqual(
                new[0].read(update_diff_digest),
                canonical_json(update_diff),
            )
            self.assertEqual(
                (protected / producer._TARGET / "SKILL.md").read_bytes(),
                b"# inert GitHub skill v2\n",
            )

            stale_diff = diff_verified_manifests_between(
                old[0],
                old[2],
                third[0],
                third[2],
            )
            stale_args = _resolved_service_args(
                github_args(third, "5"),
                base=base,
                operation="update",
                expected_active=expected_active,
                expected_manifest_diff_digest=canonical_digest(stale_diff),
                previous_root=old[1],
            )
            before = producer._bounded_tree_snapshot_digest(protected)
            with (
                mock.patch.object(producer.time, "time", return_value=101),
                self.assertRaisesRegex(
                    producer.ProtectedInstallTransactionError,
                    "active link does not match",
                ),
            ):
                producer._run(stale_args)
            self.assertEqual(
                before,
                producer._bounded_tree_snapshot_digest(protected),
            )
            self.assertEqual(
                (protected / producer._TARGET / "SKILL.md").read_bytes(),
                b"# inert GitHub skill v2\n",
            )

            credential_root = root / "credentials"
            credential_root.mkdir(mode=0o700)
            request = _request_v2(
                update_args,
                expected_active=expected_active,
                expected_manifest_diff_digest=canonical_digest(update_diff),
            )
            request_path = credential_root / "install-request"
            request_path.write_bytes(canonical_json(request))
            request_path.chmod(0o400)
            loaded, authority = producer._load_service_request(
                str(request_path),
                os.geteuid(),
            )
            self.assertEqual(loaded, request)
            self.assertEqual(
                authority["request_schema"],
                "aragorn/protected-install-broker-request/v2",
            )

            mapping_direct = github_args(new, "4")
            mapping_direct.cas_root = str(base)
            service = _service_args(
                producer,
                mapping_direct,
                request_path,
            )
            service.expected_broker_uid = 0
            authority["credential"]["uid"] = 0
            with (
                mock.patch.object(producer.os, "geteuid", return_value=0),
                mock.patch.object(
                    producer,
                    "_load_service_request",
                    return_value=(loaded, authority),
                ),
                mock.patch.object(producer.time, "time", return_value=150),
            ):
                resolved, _authority = producer._resolve_service_request(
                    service
                )
            self.assertEqual(resolved.operation, "update")
            self.assertEqual(resolved.expected_active, expected_active)
            self.assertEqual(resolved.cas_base_root, str(base))
            self.assertEqual(resolved.cas_root, str(new[1]))
            self.assertEqual(
                resolved.expected_active_cas_root,
                str(old[1]),
            )

            invalid = request | {
                "operation": "install",
            }
            invalid_path = credential_root / "invalid-install"
            invalid_path.write_bytes(canonical_json(invalid))
            invalid_path.chmod(0o400)
            with self.assertRaisesRegex(
                producer.BrokerConformanceError,
                "must not bind an active predecessor",
            ):
                producer._load_service_request(
                    str(invalid_path),
                    os.geteuid(),
                )

            changed_lineage = request | {
                "expected_active": expected_active
                | {
                    "source_request": expected_active["source_request"]
                    | {"owner": "other"}
                }
            }
            changed_lineage_path = credential_root / "changed-lineage"
            changed_lineage_path.write_bytes(canonical_json(changed_lineage))
            changed_lineage_path.chmod(0o400)
            with self.assertRaisesRegex(
                producer.BrokerConformanceError,
                "source lineage must not change",
            ):
                producer._load_service_request(
                    str(changed_lineage_path),
                    os.geteuid(),
                )


if __name__ == "__main__":
    unittest.main()
