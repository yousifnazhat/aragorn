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

from aragorn import (
    admission_protected_final_combined_v3_chat_session_snapshot_consumer as subject,
)
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


def _sync_nested(changed: dict[str, object]) -> None:
    observation = changed["route_observation"]
    document = observation["document"]
    raw = (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        + b"\n"
    )
    canonical = canonical_json(document)
    observation["raw"] = {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "canonical_digest": _digest(canonical),
        "digest": _digest(raw),
        "raw_is_canonical_json_lf": False,
    }


def _repin(
    changed: dict[str, object], *, sync_nested: bool = True
) -> tuple[object, ...]:
    if sync_nested:
        _sync_nested(changed)
    observation = changed["route_observation"]
    document = observation["document"]
    action = document["action"]
    before = action["prerequisites"]
    nested_raw = base64.b64decode(observation["raw"]["base64"], validate=True)
    canonical_route = canonical_json(document)
    route_raw = {
        "bytes": len(nested_raw),
        "canonical_bytes": len(canonical_route),
        "canonical_digest": _digest(canonical_route),
        "digest": _digest(nested_raw),
    }
    harness = changed["harness"]["document"]
    replay = action["observations"]["compiled_route_replay"]
    digests = {
        "action": canonical_digest(action),
        "composition": canonical_digest(changed["composition"]),
        "composition_action": canonical_digest(changed["composition"]["action"]),
        "execution": canonical_digest(observation["execution"]),
        "gateway_binding": canonical_digest(observation["gateway_pid_binding"]),
        "harness": canonical_digest(harness),
        "host_config": canonical_digest(harness["host_config"]),
        "image_lineage": canonical_digest(harness["image_lineage"]),
        "module_files": canonical_digest(replay["module_files"]),
        "replay": canonical_digest(replay),
        "route_observation": canonical_digest(observation),
        "source_artifacts": canonical_digest(changed["source_artifacts"]),
        "stack": canonical_digest(observation["stack_before"]),
    }
    stable = {
        "boundary": before["boundary_before"],
        "config": before["config_before"],
        "config_lock": before["config_lock_before"],
        "config_tree": before["config_tree_before"],
        "gateway": before["gateway_process_before"],
        "openclaw": before["openclaw_before"],
        "protected_roots": before["protected_root_trees_before"],
        "runtime_tree": before["runtime_tree_before"],
        "target": before["target_before"],
    }
    static = {name: canonical_digest(value) for name, value in stable.items()}
    artifact = changed["composition"]["action"]["artifacts"][
        "final_combined_v3_chat_session_snapshot_consumer"
    ]
    artifact_digests = {
        name: canonical_digest(value) for name, value in artifact.items()
    }
    outer = canonical_json(changed)
    raw = outer + b"\n"
    evidence = {
        **subject._EVIDENCE,
        "bytes": len(raw),
        "canonical_bytes": len(outer),
        "canonical_digest": _digest(outer),
        "digest": _digest(raw),
    }
    return (
        raw,
        evidence,
        route_raw,
        digests,
        static,
        artifact_digests,
        canonical_digest(subject.v3_contract._type_shape(changed)),
        canonical_digest(subject.v3_contract._type_shape(document)),
    )


def _replace_strings(value: object, old: str, new: str) -> object:
    if isinstance(value, dict):
        return {
            _replace_strings(key, old, new): _replace_strings(item, old, new)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_replace_strings(item, old, new) for item in value]
    if isinstance(value, str):
        return value.replace(old, new)
    return value


class FinalCombinedV3ChatSessionSnapshotConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.closure_files = subject._verify_compiled_closure()

    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v3_chat_session_snapshot_consumer(
            evidence_cas=store
        )

    def repinned(
        self, changed: dict[str, object], *, sync_nested: bool = True
    ) -> dict[str, object]:
        (
            raw,
            evidence,
            route_raw,
            digests,
            static,
            artifact_digests,
            outer_shape,
            route_shape,
        ) = _repin(changed, sync_nested=sync_nested)
        temporary, store = _store(raw)
        self.addCleanup(temporary.cleanup)
        closure = {name: bytes(value) for name, value in self.closure_files.items()}
        with (
            patch.object(subject, "_EVIDENCE", evidence),
            patch.object(subject, "_ROUTE_RAW", route_raw),
            patch.object(subject, "_DIGESTS", digests),
            patch.object(subject, "_STATIC_DIGESTS", static),
            patch.object(subject, "_ARTIFACT_DIGESTS", artifact_digests),
            patch.object(subject, "_TYPE_SHAPE_DIGEST", outer_shape),
            patch.object(subject, "_ROUTE_TYPE_SHAPE_DIGEST", route_shape),
            patch.object(subject, "_verify_dependencies", return_value=None),
            patch.object(subject, "_verify_retained_evidence", return_value=raw),
            patch.object(subject, "_verify_compiled_closure", return_value=closure),
        ):
            return subject.verify_openclaw_final_combined_v3_chat_session_snapshot_consumer(
                evidence_cas=store
            )

    def test_exact_chat_route_identity_and_one_bounded_pass(self) -> None:
        result = self.verify()
        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})
        statuses = {
            route["id"]: route["status"] for route in result["profile"]["routes"]
        }
        self.assertEqual(statuses[subject._ROUTE], "PASS")
        self.assertEqual(list(statuses.values()).count("PASS"), 1)
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.contract._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(_ORIGINAL["route_id"], subject._ROUTE)
        document = _ORIGINAL["route_observation"]["document"]
        self.assertEqual(document["action"]["id"], "session-snapshot-consumer-fixed")
        initial = document["action"]["observations"]["initial_turn"]
        self.assertTrue(
            initial["request_params"]["sessionKey"].startswith(
                "agent:main:aragorn-protected-session-snapshot-fixed-"
            )
        )
        self.assertTrue(
            initial["request_params"]["idempotencyKey"].startswith(
                "aragorn-protected-session-snapshot-fixed-initial-"
            )
        )
        self.assertIs(
            _ORIGINAL["route_observation"]["raw"]["raw_is_canonical_json_lf"],
            False,
        )
        binding = result["bindings"]["chat_session_snapshot_consumer_observation"]
        self.assertEqual(binding["route_source"]["commit"], subject._SOURCE["commit"])
        self.assertEqual(binding["retention"]["commit"], subject._RETENTION["commit"])

    def test_outer_cas_retention_dependency_duplicate_and_nan_drift_fail(self) -> None:
        original_raw = _EVIDENCE.read_bytes()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(AdmissionEvidenceError):
            subject.verify_openclaw_final_combined_v3_chat_session_snapshot_consumer(
                evidence_cas=CAS(temporary.name)
            )

        pretty = (json.dumps(_ORIGINAL, indent=2) + "\n").encode()
        identity = {
            **subject._EVIDENCE,
            "bytes": len(pretty),
            "digest": _digest(pretty),
        }
        temporary, store = _store(pretty)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", identity),
            patch.object(subject, "_verify_dependencies", return_value=None),
            patch.object(subject, "_verify_retained_evidence", return_value=pretty),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v3_chat_session_snapshot_consumer(
                evidence_cas=store
            )

        for label, raw in (
            (
                "duplicate",
                original_raw.replace(
                    b'"authority":', b'"authority":"duplicate","authority":', 1
                ),
            ),
            (
                "nan",
                original_raw.replace(
                    b'"route_fail_count":0', b'"route_fail_count":NaN', 1
                ),
            ),
        ):
            with self.subTest(label=label):
                identity = {
                    **subject._EVIDENCE,
                    "bytes": len(raw),
                    "digest": _digest(raw),
                }
                temporary, store = _store(raw)
                self.addCleanup(temporary.cleanup)
                with (
                    patch.object(subject, "_EVIDENCE", identity),
                    patch.object(subject, "_verify_dependencies", return_value=None),
                    patch.object(
                        subject, "_verify_retained_evidence", return_value=raw
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    subject.verify_openclaw_final_combined_v3_chat_session_snapshot_consumer(
                        evidence_cas=store
                    )

        temporary, store = _store(original_raw)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_RETENTION_BLOB", "0" * 40),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v3_chat_session_snapshot_consumer(
                evidence_cas=store
            )

        dependencies = deepcopy(subject._DEPENDENCIES)
        dependencies["v2_chat_semantics"]["digest"] = "sha256:" + "0" * 64
        temporary, store = _store(original_raw)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_DEPENDENCIES", dependencies),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v3_chat_session_snapshot_consumer(
                evidence_cas=store
            )

    def test_nested_canonical_reencoding_is_not_retained_raw(self) -> None:
        changed = deepcopy(_ORIGINAL)
        observation = changed["route_observation"]
        canonical = canonical_json(observation["document"])
        raw = canonical + b"\n"
        observation["raw"] = {
            "base64": base64.b64encode(raw).decode(),
            "bytes": len(raw),
            "canonical_digest": _digest(canonical),
            "digest": _digest(raw),
            "raw_is_canonical_json_lf": True,
        }
        with self.assertRaisesRegex(AdmissionEvidenceError, "raw identity"):
            self.repinned(changed, sync_nested=False)

    def test_fully_repinned_route_replay_refresh_and_persistence_drift_fail(
        self,
    ) -> None:
        def positive_eligibility(value: dict[str, object]) -> None:
            value["decision"]["edr_eligible"] = True

        def wrong_route(value: dict[str, object]) -> None:
            value["route_id"] = "ADM-02/reload/session-snapshot-consumer"
            value["route_observation"]["route"]["id"] = value["route_id"]
            value["route_observation"]["document"]["route"]["id"] = value["route_id"]

        def wrong_action_id(value: dict[str, object]) -> None:
            document = value["route_observation"]["document"]
            document["route"]["action_id"] = "chat-session-snapshot-consumer"
            document["action"]["id"] = "chat-session-snapshot-consumer"

        def renamed_legacy_prefix(value: dict[str, object]) -> None:
            document = value["route_observation"]["document"]
            value["route_observation"]["document"] = _replace_strings(
                document,
                "aragorn-protected-session-snapshot-fixed-",
                "aragorn-protected-chat-session-snapshot-",
            )

        def writable_probe_mount(value: dict[str, object]) -> None:
            action = value["route_observation"]["document"]["action"]
            action["prerequisites"]["boundary_before"]["probe"]["read_only"] = False
            action["observations"]["boundary_after"]["probe"]["read_only"] = False

        def native_replay(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["action"]["observations"][
                "compiled_route_replay"
            ]["native_agent_execution"] = True

        def no_refresh(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["action"]["observations"][
                "compiled_route_replay"
            ]["resolver"]["injected_should_refresh"] = False

        def module_drift(value: dict[str, object]) -> None:
            modules = value["route_observation"]["document"]["action"]["observations"][
                "compiled_route_replay"
            ]["module_files"]
            modules[min(modules)]["digest"] = "sha256:" + "0" * 64

        def final_snapshot_drift(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["action"]["observations"][
                "final_snapshot"
            ]["prompt"]["digest"] = "sha256:" + "0" * 64

        def non_atomic_mutation(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["action"]["observations"][
                "mutation"
            ]["atomic_store_replacement"]["directory_fsync"] = False

        def referenced_attacker_blob(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["action"]["observations"][
                "attacker_blob_unreferenced_after"
            ] = False

        def timing_drift(value: dict[str, object]) -> None:
            value["route_observation"]["document"]["action"]["observations"][
                "native_recovery_timing"
            ]["injected_wait_completed_at"] += 1

        def command_order_drift(value: dict[str, object]) -> None:
            commands = value["route_observation"]["document"]["action"]["commands"]
            commands[0], commands[1] = commands[1], commands[0]

        for mutation in (
            positive_eligibility,
            wrong_route,
            wrong_action_id,
            renamed_legacy_prefix,
            writable_probe_mount,
            native_replay,
            no_refresh,
            module_drift,
            final_snapshot_drift,
            non_atomic_mutation,
            referenced_attacker_blob,
            timing_drift,
            command_order_drift,
        ):
            with self.subTest(mutation=mutation.__name__):
                changed = deepcopy(_ORIGINAL)
                mutation(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    self.repinned(changed)

    def test_fully_repinned_source_artifact_drift_fails_signed_source_check(
        self,
    ) -> None:
        changed = deepcopy(_ORIGINAL)
        changed["source_artifacts"]["collector"]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(AdmissionEvidenceError):
            self.repinned(changed)


if __name__ == "__main__":
    unittest.main()
