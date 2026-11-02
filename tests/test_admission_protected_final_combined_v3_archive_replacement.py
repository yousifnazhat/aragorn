from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import admission_protected_final_combined_v3_archive_replacement as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_ORIGINAL = json.loads(_EVIDENCE.read_bytes())


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _store(raw: bytes) -> tuple[tempfile.TemporaryDirectory[str], CAS]:
    temporary = tempfile.TemporaryDirectory()
    store = CAS(temporary.name)
    store.put_expected(BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw))
    return temporary, store


class FinalCombinedV3ArchiveReplacementTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v3_archive_replacement(
            evidence_cas=store
        )

    def verify_document(self, changed: dict[str, object]) -> None:
        observation = changed["route_observation"]
        document = observation["document"]
        digests = {**subject._DIGESTS, "action": canonical_digest(document["action"])}
        static_digests = {
            **subject._STATIC_DIGESTS,
            "boundary_before": canonical_digest(document["protected_boundary"]),
            "boundary_after": canonical_digest(
                document["action"]["observations"]["boundary_after"]
            ),
        }
        with (
            patch.object(subject, "_DIGESTS", digests),
            patch.object(subject, "_STATIC_DIGESTS", static_digests),
        ):
            subject._verify_document(
                document,
                harness=changed["harness"]["document"],
                execution=observation["execution"],
                composition_recorded_at=changed["composition"]["recorded_at"],
                outer_recorded_at=changed["recorded_at"],
            )

    def verify_execution(self, changed: dict[str, object]) -> None:
        observation = changed["route_observation"]
        digests = {
            **subject._DIGESTS,
            "stack": canonical_digest(observation["stack_before"]),
        }
        with patch.object(subject, "_DIGESTS", digests):
            subject._verify_execution(
                observation,
                changed["composition"]["action"]["boundaries"],
                changed["harness"]["document"],
            )

    def test_exact_one_route_pass_with_all_broad_eligibility_false(self) -> None:
        result = self.verify()
        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})
        statuses = {route["id"]: route["status"] for route in result["profile"]["routes"]}
        self.assertEqual(statuses[subject._ROUTE], "PASS")
        self.assertEqual(list(statuses.values()).count("PASS"), 1)
        self.assertTrue(
            all(result["decision"][key] is False for key in subject.contract._ELIGIBILITY_KEYS)
        )
        self.assertEqual(_ORIGINAL["decision"]["route_pass_count"], 0)
        self.assertIs(
            _ORIGINAL["route_observation"]["raw"]["raw_is_canonical_json_lf"],
            False,
        )

    def test_outer_cas_retention_duplicate_and_nan_drift_fail(self) -> None:
        original = _EVIDENCE.read_bytes()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(AdmissionEvidenceError):
            subject.verify_openclaw_final_combined_v3_archive_replacement(
                evidence_cas=CAS(temporary.name)
            )

        pretty = (json.dumps(_ORIGINAL, indent=2) + "\n").encode()
        identity = {**subject._EVIDENCE, "bytes": len(pretty), "digest": _digest(pretty)}
        temporary, store = _store(pretty)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", identity),
            patch.object(subject, "_verify_dependencies", return_value=None),
            patch.object(subject, "_verify_retained_evidence", return_value=pretty),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v3_archive_replacement(
                evidence_cas=store
            )

        for raw in (
            original.replace(b'"authority":', b'"authority":"duplicate","authority":', 1),
            original.replace(b'"route_fail_count":0', b'"route_fail_count":NaN', 1),
        ):
            identity = {**subject._EVIDENCE, "bytes": len(raw), "digest": _digest(raw)}
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", identity),
                patch.object(subject, "_verify_dependencies", return_value=None),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v3_archive_replacement(
                    evidence_cas=store
                )

        temporary, store = _store(original)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_RETENTION_BLOB", "0" * 40),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v3_archive_replacement(
                evidence_cas=store
            )

    def test_nested_canonical_reencoding_is_not_retained_raw(self) -> None:
        document = _ORIGINAL["route_observation"]["document"]
        canonical = canonical_json(document)
        raw = canonical + b"\n"
        envelope = {
            "base64": base64.b64encode(raw).decode(),
            "bytes": len(raw),
            "canonical_digest": _digest(canonical),
            "digest": _digest(raw),
            "raw_is_canonical_json_lf": True,
        }
        with self.assertRaisesRegex(AdmissionEvidenceError, "raw identity"):
            subject._decode_route_raw(envelope)

    def test_semantic_mutations_fail_even_with_action_digest_repinned(self) -> None:
        def writable_source(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["protected_boundary"]["inputs"]["source"]["read_only"] = False

        def upload_accepted(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["action"]["observations"]["upload_begin"]["response"]["value"]["ok"] = True

        def no_workspace_delta(value: dict[str, object]) -> None:
            document = value["route_observation"]["document"]
            before = document["protected_boundary"]["roots"]["workspace_skills"]["observation"]
            document["action"]["observations"]["boundary_after"]["roots"]["workspace_skills"]["observation"] = deepcopy(before)

        def catalog_allowed(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["action"]["observations"]["discovery_after"]["command"]["exit_code"] = 0

        def protected_target_changed(value: dict[str, object]) -> None:
            document = value["route_observation"]["document"]
            target = document["action"]["prerequisites"]["target_before"]
            target["entries"][0]["digest"] = "sha256:" + "0" * 64
            document["action"]["observations"]["target_after"] = deepcopy(target)

        def configuration_changed(value: dict[str, object]) -> None:
            document = value["route_observation"]["document"]
            for boundary in (
                document["protected_boundary"],
                document["action"]["observations"]["boundary_after"],
            ):
                boundary["configuration"]["canonical_digest"] = "sha256:" + "0" * 64
                boundary["configuration"]["file"]["digest"] = "sha256:" + "0" * 64

        def runtime_tree_changed(value: dict[str, object]) -> None:
            document = value["route_observation"]["document"]
            runtime = document["action"]["prerequisites"]["runtime_tree"]
            runtime["tree_digest"] = "sha256:" + "0" * 64
            document["action"]["observations"]["runtime_tree_after"] = deepcopy(runtime)

        def extra_source_entry(value: dict[str, object]) -> None:
            document = value["route_observation"]["document"]
            source = document["action"]["prerequisites"]["source"]
            extra = deepcopy(source["entries"][0])
            extra["path"] = "EXTRA.md"
            source["entries"].append(extra)
            document["action"]["observations"]["source_after"] = deepcopy(source)

        def version_changed(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["action"]["prerequisites"]["version"]["stdout_excerpt"] = "OpenClaw 2026.7.2 (bogus)\n"

        def discovery_changed(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["action"]["prerequisites"]["discovery"]["response"]["value"]["eligible"] = False

        def source_changed(value: dict[str, object]) -> None:
            document = value["route_observation"]["document"]
            source = document["action"]["prerequisites"]["source"]
            source["tree_digest"] = "sha256:" + "0" * 64
            document["action"]["observations"]["source_after"] = deepcopy(source)

        def command_order_changed(value: dict[str, object]) -> None:
            commands = value["route_observation"]["document"]["action"]["commands"]
            commands[0], commands[1] = commands[1], commands[0]

        def conventional_root_changed(value: dict[str, object]) -> None:
            document = value["route_observation"]["document"]
            document["protected_boundary"]["roots"]["extensions"]["writable"] = False
            document["action"]["observations"]["boundary_after"]["roots"]["extensions"]["writable"] = False

        for mutation in (
            writable_source,
            upload_accepted,
            no_workspace_delta,
            catalog_allowed,
            protected_target_changed,
            configuration_changed,
            runtime_tree_changed,
            extra_source_entry,
            version_changed,
            discovery_changed,
            source_changed,
            command_order_changed,
            conventional_root_changed,
        ):
            with self.subTest(mutation=mutation.__name__):
                changed = deepcopy(_ORIGINAL)
                mutation(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify_document(changed)

    def test_gateway_root_capabilities_fail_with_stack_and_boundaries_coordinated(self) -> None:
        changed = deepcopy(_ORIGINAL)
        gateway = "aragorn-agent-gateway.service"
        stack = changed["route_observation"]["stack_before"]
        process = stack["processes"][gateway]
        process["uids"] = [0, 0, 0, 0]
        process["gids"] = [0, 0, 0, 0]
        process["groups"] = [0]
        process["capabilities_effective"] = "000001ffffffffff"
        changed["composition"]["action"]["boundaries"]["processes"] = deepcopy(
            stack["processes"]
        )
        with self.assertRaises(AdmissionEvidenceError):
            self.verify_execution(changed)

        changed = deepcopy(_ORIGINAL)
        stack = changed["route_observation"]["stack_before"]
        unit = stack["units"][gateway]
        unit["User"] = "root"
        unit["Group"] = "root"
        unit["AmbientCapabilities"] = "cap_sys_admin"
        unit["CapabilityBoundingSet"] = "cap_sys_admin"
        changed["composition"]["action"]["boundaries"]["units"][gateway] = (
            deepcopy(unit)
        )
        with self.assertRaises(AdmissionEvidenceError):
            self.verify_execution(changed)

    def test_source_provenance_and_runtime_materialization_drift_fail(self) -> None:
        changed = deepcopy(_ORIGINAL)
        changed["source_artifacts"]["checked_in_probe"]["digest"] = (
            "sha256:" + "0" * 64
        )
        digests = {
            **subject._DIGESTS,
            "source_artifacts": canonical_digest(changed["source_artifacts"]),
        }
        with (
            patch.object(subject, "_DIGESTS", digests),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject._verify_evidence(changed)

        for name in ("collector dockerfile", "runtime probe"):
            with self.subTest(name=name):
                changed = deepcopy(_ORIGINAL)
                artifact = changed["composition"]["action"]["artifacts"][
                    "final_combined_v3_archive_source_force_replacement"
                ]
                target = (
                    artifact["collector"]["dockerfile"]
                    if name == "collector dockerfile"
                    else artifact["archive_source_force_replacement_probe"][
                        "runtime_probe"
                    ]
                )
                target["digest"] = "sha256:" + "0" * 64
                with self.assertRaises(AdmissionEvidenceError):
                    subject._verify_composition(
                        changed["composition"], changed["source_artifacts"]
                    )


if __name__ == "__main__":
    unittest.main()
