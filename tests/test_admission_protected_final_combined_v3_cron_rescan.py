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

from aragorn import admission_protected_final_combined_v3_cron_rescan as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]


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
    canonical = canonical_json(document)
    raw = canonical + b"\n"
    observation["raw"] = {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "canonical_digest": _digest(canonical),
        "digest": _digest(raw),
        "raw_is_canonical_json_lf": True,
    }


def _sync_harness(changed: dict[str, object]) -> None:
    envelope = changed["composition"]["action"]["harness"]
    raw = canonical_json(envelope["document"])
    envelope["digest"] = _digest(raw)
    envelope["file"]["base64"] = base64.b64encode(raw).decode()
    envelope["file"]["bytes"] = len(raw)
    envelope["file"]["digest"] = _digest(raw)
    envelope["file"]["stat"]["size"] = len(raw)
    changed["harness"] = deepcopy(envelope)


def _sync_terminal_run_at(changed: dict[str, object], run_at_ms: int) -> None:
    action = changed["route_observation"]["document"]["action"]
    observed = action["observations"]
    observed["terminal_result"]["runAtMs"] = run_at_ms
    poll = observed["run"]["terminal_poll"]
    poll["response"]["value"]["entries"][0]["runAtMs"] = run_at_ms
    stdout = (json.dumps(poll["response"]["value"], indent=2) + "\n").encode()
    poll["command"]["stdout_excerpt"] = stdout.decode()
    poll["command"]["stdout_bytes"] = len(stdout)
    poll["command"]["stdout_digest"] = _digest(stdout)
    observed["run"]["polls"] = [deepcopy(poll)]
    action["commands"][6] = deepcopy(poll["command"])


def _repin(changed: dict[str, object]) -> tuple[object, ...]:
    _sync_nested(changed)
    observation = changed["route_observation"]
    document = observation["document"]
    action = document["action"]
    before = action["prerequisites"]
    nested_raw = base64.b64decode(observation["raw"]["base64"], validate=True)
    route_raw = {
        "bytes": len(nested_raw),
        "canonical_digest": _digest(canonical_json(document)),
        "digest": _digest(nested_raw),
    }
    harness = changed["harness"]["document"]
    digests = {
        "action": canonical_digest(action),
        "composition": canonical_digest(changed["composition"]),
        "composition_action": canonical_digest(changed["composition"]["action"]),
        "execution": canonical_digest(observation["execution"]),
        "gateway_binding": canonical_digest(observation["gateway_pid_binding"]),
        "harness": canonical_digest(harness),
        "host_config": canonical_digest(harness["host_config"]),
        "image_lineage": canonical_digest(harness["image_lineage"]),
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
        "modules": before["module_files_before"],
        "openclaw": before["openclaw_before"],
        "protected_roots": before["protected_root_trees_before"],
        "runtime_tree": before["runtime_tree_before"],
        "session_store": before["session_store_before"],
        "target": before["target_before"],
    }
    static = {name: canonical_digest(value) for name, value in stable.items()}
    artifact = changed["composition"]["action"]["artifacts"][
        "final_combined_v3_cron_rescan"
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
    outer_shape = canonical_digest(subject.v3_contract._type_shape(changed))
    route_shape = canonical_digest(subject.v3_contract._type_shape(document))
    return (
        raw,
        evidence,
        route_raw,
        digests,
        static,
        artifact_digests,
        outer_shape,
        route_shape,
    )


class FinalCombinedV3CronRescanTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v3_cron_rescan(evidence_cas=store)

    def repinned(self, changed: dict[str, object]) -> dict[str, object]:
        (
            raw,
            evidence,
            route_raw,
            digests,
            static,
            artifact_digests,
            outer_shape,
            route_shape,
        ) = _repin(changed)
        temporary, store = _store(raw)
        self.addCleanup(temporary.cleanup)
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
        ):
            return subject.verify_openclaw_final_combined_v3_cron_rescan(
                evidence_cas=store
            )

    def test_exact_one_route_pass_with_all_broad_eligibility_false(self) -> None:
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
        self.assertEqual(result["route_semantics"]["observed_run_at_delta_ms"], 1)
        self.assertEqual(
            json.loads(_EVIDENCE.read_bytes())["decision"]["route_pass_count"], 0
        )

    def test_run_at_uses_causal_bounds_not_flaky_exact_clock_equality(self) -> None:
        changed = json.loads(_EVIDENCE.read_bytes())
        terminal = changed["route_observation"]["document"]["action"]["observations"][
            "terminal_result"
        ]
        match = subject.semantics.cron._RUN_ID.fullmatch(terminal["runId"])
        self.assertIsNotNone(match)
        run_epoch = int(match.group(2))
        self.assertEqual(terminal["runAtMs"], run_epoch + 1)
        _sync_terminal_run_at(changed, run_epoch)
        result = self.repinned(changed)
        self.assertEqual(result["route_semantics"]["observed_run_at_delta_ms"], 0)

        changed = json.loads(_EVIDENCE.read_bytes())
        _sync_terminal_run_at(changed, run_epoch - 1)
        with self.assertRaisesRegex(AdmissionEvidenceError, "terminal causality"):
            self.repinned(changed)

    def test_coordinated_hostile_repins_fail_closed(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        mutations = []
        changed = deepcopy(original)
        changed["route_observation"]["document"]["action"]["observations"]["run"][
            "request"
        ]["params"]["mode"] = "due"
        mutations.append(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["action"]["observations"][
            "terminal_result"
        ]["errorReason"] = "success"
        mutations.append(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["action"]["observations"]["snapshot"][
            "prompt"
        ]["storage"] = "inline"
        mutations.append(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["action"]["observations"]["cleanup"][
            "response"
        ]["value"]["removed"] = False
        mutations.append(changed)

        changed = deepcopy(original)
        changed["decision"]["phase3_exit_eligible"] = True
        mutations.append(changed)

        for changed in mutations:
            with (
                self.subTest(digest=canonical_digest(changed)),
                self.assertRaises(AdmissionEvidenceError),
            ):
                self.repinned(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["harness"]["document"]["host_config"][
            "network_mode"
        ] = "host"
        _sync_harness(changed)
        with self.assertRaisesRegex(AdmissionEvidenceError, "harness"):
            self.repinned(changed)

    def test_duplicate_and_nonfinite_outer_json_fail_closed(self) -> None:
        original = _EVIDENCE.read_bytes()
        hostile = (
            original.replace(
                b'{"authority":', b'{"authority":"forged","authority":', 1
            ),
            original.replace(b'"route_pass_count":0', b'"route_pass_count":NaN', 1),
        )
        for raw in hostile:
            identity = {**subject._EVIDENCE, "bytes": len(raw), "digest": _digest(raw)}
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", identity),
                patch.object(subject, "_verify_dependencies", return_value=None),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v3_cron_rescan(
                    evidence_cas=store
                )


if __name__ == "__main__":
    unittest.main()
