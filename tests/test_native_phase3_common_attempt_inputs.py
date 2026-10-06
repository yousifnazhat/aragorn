"""Inert public input contracts, not attempts, clocks or acceptance samples."""

import ast
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from aragorn import native_phase3_common_attempt_inputs as subject
from aragorn.oci_worker_protocol import canonical_json
from tests import test_native_phase3_common_preparation as common_data


class AttemptInputsData(unittest.TestCase):
    """Data-only constructor for wrappers; no historical test methods inherited."""

    def setUp(self):
        fixture = common_data.NativeCommonPreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.base_sources = {
            path: ("inert test-only base source: " + path).encode()
            for path in subject.base.SOURCE_PATHS
        }
        arguments = {
            key: value
            for key, value in fixture.arguments.items()
            if key not in {"container_id", "provisioning_inputs"}
        }
        arguments["implementation_source_raws"] = {
            path: self.base_sources[path] for path in subject.base.IMPLEMENTATION_PATHS
        }
        self.base_bundle = subject.base.prepare_common_setup_inputs(
            **arguments,
            source_raws=self.base_sources,
            setup_source_raw=self.base_sources[subject.base.SETUP_SOURCE],
            wrapper_source_raw=self.base_sources[subject.base.WRAPPER_SOURCE],
            host_source_raw=self.base_sources[subject.base.HOST_SOURCE],
        )
        identifiers = [f"inert-attempt-{index:03d}" for index in range(100)]
        self.plan = {
            "expected_attempt_ids": identifiers,
            "expected_attempt_families": {
                name: "EXFILTRATION" if index < 50 else "DESTRUCTIVE"
                for index, name in enumerate(identifiers)
            },
            "expected_unattributed_attempt_id": identifiers[0],
            "expected_overhead_pair_bindings": {
                f"inert-pair-{index:03d}": {
                    "task_digest": "sha256:" + "a" * 64,
                    "input_digest": f"sha256:{index + 1:064x}",
                    "host_profile_digest": "sha256:" + "b" * 64,
                }
                for index in range(100)
            },
            "expected_gate_manifest_digest": "sha256:" + "c" * 64,
            "expected_campaign_contract_digest": "sha256:" + "d" * 64,
            "selected_attempt_id": identifiers[1],
        }
        self.sources = {
            path: ("inert test-only additional source: " + path).encode()
            for path in subject.EXTRA_SOURCE_PATHS
        }
        self.arguments = {
            "setup_bundle_raw": self.base_bundle["bundle_raw"],
            "expected_setup_bundle_digest": self.base_bundle["bundle_digest"],
            "plan_arguments": self.plan,
            "source_raws": self.sources,
        }
        self.bound = subject.prepare_common_attempt_inputs(**self.arguments)


class NativeCommonAttemptInputsTests(AttemptInputsData):
    def test_round_trip_closes_exact_bytes_without_native_effects(self):
        with (
            patch("builtins.open", side_effect=AssertionError("no file open")),
            patch(
                "pathlib.Path.read_bytes", side_effect=AssertionError("no file read")
            ),
            patch("os.scandir", side_effect=AssertionError("no filesystem scan")),
            patch("time.time", side_effect=AssertionError("no time sample")),
            patch("time.clock_gettime_ns", side_effect=AssertionError("no clock")),
            patch("subprocess.run", side_effect=AssertionError("no process")),
        ):
            restored = subject.inspect_common_attempt_inputs(
                self.bound["bundle_raw"],
                expected_bundle_digest=self.bound["bundle_digest"],
            )
        self.assertEqual(restored, self.bound)
        self.assertEqual(restored["source_raws"], self.base_sources | self.sources)
        self.assertEqual(restored["plan_arguments"], self.plan)
        self.assertNotIn("container_id", restored["common_arguments"])
        self.assertNotIn("expected_setup_digest", restored["common_arguments"])
        self.assertEqual(
            restored["expected_setup_digest"],
            subject._digest(self.base_sources[subject.base.SETUP_SOURCE]),
        )
        self.assertEqual(
            set(restored["expected_source_digests"]), set(subject.ATTEMPT_SOURCE_PATHS)
        )
        self.assertEqual(
            restored["source_raw"], self.fixture.arguments["source_record_raw"]
        )
        self.assertEqual(
            restored["stage_raw"], self.fixture.arguments["staged_profile_raw"]
        )
        for pin, raw in restored["input_blobs"].items():
            self.assertEqual(pin, subject._digest(raw))
        self.assertTrue(
            all(value is False for value in restored["bundle"]["decision"].values())
        )

    def test_extra_sources_cannot_override_base_or_expand_inventory(self):
        for change in ("missing", "unknown", "base_override", "empty", "text"):
            with self.subTest(change=change):
                sources = dict(self.sources)
                path = subject.EXTRA_SOURCE_PATHS[0]
                if change == "missing":
                    del sources[path]
                elif change == "unknown":
                    sources["scripts/arbitrary.py"] = b"arbitrary"
                elif change == "base_override":
                    sources[subject.base.SETUP_SOURCE] = b"replacement"
                elif change == "empty":
                    sources[path] = b""
                else:
                    sources[path] = "not raw bytes"
                with self.assertRaises(subject.NativeCommonAttemptInputsError):
                    subject.prepare_common_attempt_inputs(
                        **(self.arguments | {"source_raws": sources})
                    )

    def test_inventory_validators_reject_incomplete_or_invalid_public_plan(self):
        changes = {
            "missing key": lambda plan: plan.pop("expected_gate_manifest_digest"),
            "extra key": lambda plan: plan.update(container_id="b" * 64),
            "incomplete attempts": lambda plan: plan["expected_attempt_ids"].pop(),
            "tuple attempts": lambda plan: plan.update(
                expected_attempt_ids=tuple(plan["expected_attempt_ids"])
            ),
            "reordered attempts": lambda plan: plan["expected_attempt_ids"].reverse(),
            "unknown family": lambda plan: plan["expected_attempt_families"].update(
                {plan["selected_attempt_id"]: "UNKNOWN_FAMILY"}
            ),
            "incomplete pairs": lambda plan: plan[
                "expected_overhead_pair_bindings"
            ].popitem(),
            "non-digest gate": lambda plan: plan.update(
                expected_gate_manifest_digest="not-a-pin"
            ),
            "negative selected": lambda plan: plan.update(
                selected_attempt_id=plan["expected_unattributed_attempt_id"]
            ),
            "unknown selected": lambda plan: plan.update(
                selected_attempt_id="unlisted"
            ),
            "unknown negative": lambda plan: plan.update(
                expected_unattributed_attempt_id="unlisted"
            ),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                plan = deepcopy(self.plan)
                change(plan)
                with self.assertRaises(subject.NativeCommonAttemptInputsError):
                    subject.prepare_common_attempt_inputs(
                        **(self.arguments | {"plan_arguments": plan})
                    )

    def test_nested_base_pin_and_outer_canonical_contract_are_mandatory(self):
        with self.assertRaises(subject.NativeCommonAttemptInputsError):
            subject.prepare_common_attempt_inputs(
                **(
                    self.arguments
                    | {"expected_setup_bundle_digest": "sha256:" + "0" * 64}
                )
            )
        for name in (
            "schema",
            "authority",
            "decision",
            "limitations",
            "extra",
            "nested",
        ):
            with self.subTest(name=name):
                bundle = deepcopy(self.bound["bundle"])
                if name in {"schema", "authority"}:
                    bundle[name] = "other"
                elif name == "decision":
                    bundle[name]["phase3_exit_eligible"] = True
                elif name == "limitations":
                    bundle[name].pop()
                elif name == "extra":
                    bundle["runtime_identity"] = "invented"
                else:
                    bundle["base_setup_bundle"] += "\n"
                raw = canonical_json(bundle)
                with self.assertRaises(subject.NativeCommonAttemptInputsError):
                    subject.inspect_common_attempt_inputs(
                        raw, expected_bundle_digest=subject._digest(raw)
                    )
        raw = self.bound["bundle_raw"] + b"\n"
        with self.assertRaises(subject.NativeCommonAttemptInputsError):
            subject.inspect_common_attempt_inputs(
                raw, expected_bundle_digest=subject._digest(raw)
            )
        with self.assertRaises(subject.NativeCommonAttemptInputsError):
            subject.inspect_common_attempt_inputs(
                self.bound["bundle_raw"], expected_bundle_digest="sha256:" + "0" * 64
            )

    def test_stage_overlap_is_refused_without_changing_any_staged_mode(self):
        original_stage = self.bound["stage_raw"]
        stage_target = self.fixture.stage["files"][0]["path"]
        with patch.dict(
            subject.FIXTURE_HELPERS, {subject.CONSUMER_SOURCE: stage_target}
        ):
            with self.assertRaisesRegex(
                subject.NativeCommonAttemptInputsError, "helper/stage overlap"
            ):
                subject.prepare_common_attempt_inputs(**self.arguments)
        self.assertEqual(self.bound["stage_raw"], original_stage)

    def test_receipt_alias_installs_same_source_at_distinct_explicit_targets(self):
        source = "scripts/runtime_native_receipt_systemd_check.py"
        alias = "/opt/aragorn/runtime_native_receipt_systemd_check.py"
        self.assertEqual(subject.HELPER_ALIASES, {alias: source})
        self.assertEqual(
            subject.FIXTURE_HELPERS[source],
            "/opt/aragorn/runtime-native-receipt-systemd-check.py",
        )
        self.assertNotIn(alias, subject.FIXTURE_HELPERS.values())
        self.assertEqual(self.bound["source_raws"][source], self.base_sources[source])

    def test_controller_inventory_mirror_matches_without_importing_controller(self):
        root = Path(__file__).resolve().parents[1]
        tree = ast.parse((root / subject.ATTEMPT_SOURCE).read_text())
        assignment = next(
            node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "SOURCE_PATHS"
                for target in node.targets
            )
        )
        references = {
            "SOURCE_PATH": "/opt/aragorn/runtime_native_common_attempt.py",
            "setup.SETUP_PATH": "/opt/aragorn/runtime_native_common_case_setup.py",
            "workload.SOURCE_PATH": "/opt/aragorn/runtime_native_blocked_create_workload.py",
            "workload.REVOCATION_SOURCE_PATH": "/opt/aragorn/runtime_native_blocked_create_revocation.py",
            "workload.SINK_SOURCE_PATH": "/usr/lib/aragorn/aragorn/native_phase3_denied_create_sink.py",
        }
        actual = tuple(
            node.value
            if isinstance(node, ast.Constant)
            else references[ast.unparse(node)]
            for node in assignment.elts
        )
        self.assertEqual(subject.ATTEMPT_SOURCE_PATHS, actual)
        contract = ast.parse((root / subject.CONSUMER_SOURCE).read_text())
        for node in ast.walk(contract):
            if isinstance(node, ast.ImportFrom):
                self.assertNotIn(
                    node.module, {"scripts", "runtime_native_common_attempt"}
                )
            elif isinstance(node, ast.Import):
                self.assertFalse(
                    any(item.name.startswith("scripts") for item in node.names)
                )

    def test_mutating_caller_plan_after_preparation_does_not_change_bound_plan(self):
        retained_raw = self.bound["bundle_raw"]
        self.plan["expected_attempt_ids"].clear()
        self.plan["expected_overhead_pair_bindings"].clear()
        self.sources.clear()
        self.assertEqual(len(self.bound["plan_arguments"]["expected_attempt_ids"]), 100)
        self.assertEqual(
            len(self.bound["plan_arguments"]["expected_overhead_pair_bindings"]), 100
        )
        self.assertEqual(self.bound["bundle_raw"], retained_raw)
        self.assertEqual(set(self.bound["source_raws"]), set(subject.SOURCE_PATHS))


if __name__ == "__main__":
    unittest.main()
