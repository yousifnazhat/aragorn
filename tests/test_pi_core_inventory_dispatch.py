"""Only new preparation dispatch/report cases and affected legacy routing cases."""

import copy
import json
import sys
import types
import unittest
from unittest import mock

import test_pi_core_coordinator_wrapper as legacy
import test_pi_core_source_inventory_prepare as inventory_fixture
from aragorn import pi_core_installed_inventory_entry as installed_entry


class InventoryDispatchTests(legacy.CoordinatorWrapperTests):
    def test_real_entry_and_existing_helper_emit_the_fixed_public_contract(self):
        fixture = inventory_fixture.SourceInventoryPreparationTests()
        fixture.setUp()
        base = self.observation()
        source_pin = inventory_fixture.digest(inventory_fixture.base.canonical_json(fixture.plan))
        plan = dict(schema=installed_entry.SCHEMA,
            host_profile_digest=base["host_before"]["host_profile_digest"],
            source_plan={"path": "/var/lib/pi/source-plan.json", "digest": source_pin},
            worker_view={"path": "/var/lib/pi/completed-view",
                         "identity": fixture.arguments["expected_worker_root_identity"]},
            observer_root_identity=fixture.arguments["expected_observer_root_identity"])
        inputs = mock.Mock(cleanup_uncertainty=[], read=mock.Mock(return_value=plan),
                           ref=mock.Mock(return_value=fixture.plan))
        views = mock.Mock(worker=10, observer=11, cleanup_uncertainty=[])
        with fixture.environment(), \
                mock.patch.object(installed_entry.coordinator.time, "monotonic", return_value=100.0), \
                mock.patch.object(installed_entry.coordinator.time, "monotonic_ns", return_value=100_000_000_000), \
                mock.patch.object(installed_entry, "_custody", return_value=(plan["host_profile_digest"],
                    base["source_before"], base["host_before"])), \
                mock.patch.object(installed_entry.coordinator, "_Inputs", return_value=inputs), \
                mock.patch.object(installed_entry, "_Views", return_value=views):
            result = installed_entry.run("/var/lib/pi/plan.json",
                installed_entry.canonical_digest(plan), deadline_ns=125_000_000_000,
                source_loader=object(), host_custody=object())
        report = self.s._public_preparation(result)
        self.assertEqual(report["entry_status"], "INVENTORIES_PREPARED_NOT_QUALIFIED")
        self.assertEqual(report["artifacts"]["preparation"]["expected_manifest_digest"], source_pin)
        self.assertEqual(set(fixture.views.descriptors), {10, 11})
        self.assertFalse(report["phase3_exit_eligible"])

    def prepared_observation(self):
        fixture = inventory_fixture.SourceInventoryPreparationTests()
        fixture.setUp()
        prepared = fixture.run_preparation()
        value = self.observation()
        artifacts = {name: json.loads(getattr(prepared, name + "_raw")) for name in
                     ("source_inventory", "loader_inventory", "profile", "preparation")}
        value.update(schema="aragorn/pi-core-installed-inventory-result/v1",
            status="INVENTORIES_PREPARED_NOT_QUALIFIED", managed_call_attempted=False,
            managed_result=None, deployment_digest=None, preparation_attempted=True,
            owned_views_closed=True, artifacts=artifacts,
            artifact_digests={name: self.s._digest(self.s._canonical(document))
                              for name, document in artifacts.items()})
        return value

    def invoke_preparation(self, value, *, error=False, cleanup_error=False, after_guard=None,
                           prefix="--prepare-inventories"):
        host = types.SimpleNamespace(guard=mock.Mock(side_effect=after_guard), close=mock.Mock())
        loader = types.SimpleNamespace(close=mock.Mock(side_effect=OSError("private cleanup") if cleanup_error else None))
        entry = types.ModuleType("aragorn.pi_core_installed_inventory_entry")
        exception = ValueError("private preparation detail")
        exception.observation = value
        entry.run = mock.Mock(side_effect=exception if error else None, return_value=value)
        forbidden = types.ModuleType("aragorn.pi_core_coordinator_entry")
        forbidden.run = mock.Mock(side_effect=AssertionError("preparation must never launch"))
        package = types.ModuleType("aragorn")
        package.__path__ = []
        with mock.patch.object(self.s, "__file__", str(self.wrapper)), \
                mock.patch.object(self.s, "_hold_host", return_value=host), \
                mock.patch.object(self.s, "_bootstrap", return_value=loader), \
                mock.patch.object(sys, "argv", [str(self.wrapper), prefix, str(self.profile_path),
                    "sha256:" + "d" * 64, str(self.root / "plan.json"), "sha256:" + "e" * 64,
                    str(int(self.deadline * 1_000_000_000))]), \
                mock.patch.dict(sys.modules, {"aragorn": package, entry.__name__: entry,
                                               forbidden.__name__: forbidden}), \
                mock.patch("builtins.print") as printed:
            sys.modules.pop(self.s._PRIVATE, None)
            result = self.s.main()
        forbidden.run.assert_not_called()
        if prefix == "--prepare-inventories":
            entry.run.assert_called_once()
            host.close.assert_called_once()
            loader.close.assert_called_once()
        else:
            entry.run.assert_not_called()
        return result, json.loads(printed.call_args.args[0])

    def test_literal_preparation_route_retains_exact_existing_artifacts_without_launch(self):
        value = self.prepared_observation()
        code, report = self.invoke_preparation(value)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "INVENTORIES_PREPARED_NOT_QUALIFIED")
        self.assertEqual(report["artifacts"], value["artifacts"])
        self.assertEqual(report["artifact_digests"], value["artifact_digests"])
        self.assertFalse(report["managed_call_attempted"])
        self.assertFalse(report["phase3_exit_eligible"])

    def test_unknown_or_arbitrary_selector_refuses_before_dispatch(self):
        for selector in ("--prepare", "--module=private", "--prepare-inventories=1"):
            code, report = self.invoke_preparation(None, prefix=selector)
            self.assertEqual(code, 126)
            self.assertFalse(report["entry_call_attempted"])

    def test_preparation_cannot_return_managed_authority(self):
        value = self.prepared_observation()
        value["managed_result"] = {"private": "NEVER_EMIT"}
        code, report = self.invoke_preparation(value)
        self.assertEqual(code, 126)
        self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")
        self.assertNotIn("NEVER_EMIT", json.dumps(report))
        self.assertTrue(report["preparation_attempted"])

    def test_bad_artifact_digest_and_nested_private_field_are_not_emitted(self):
        original = self.prepared_observation()
        for nested in (False, True):
            value = copy.deepcopy(original)
            if nested:
                value["artifacts"]["source_inventory"]["sources"][0]["private"] = "NEVER_EMIT"
                value["artifact_digests"]["source_inventory"] = self.s._digest(
                    self.s._canonical(value["artifacts"]["source_inventory"]))
            else:
                value["artifact_digests"]["profile"] = "sha256:" + "0" * 64
            code, report = self.invoke_preparation(value)
            self.assertEqual(code, 126)
            self.assertIsNone(report["artifacts"])
            self.assertNotIn("NEVER_EMIT", json.dumps(report))

    def test_preparation_requires_both_owned_cleanup_results(self):
        original = self.prepared_observation()
        for field in ("owned_inputs_closed", "owned_views_closed"):
            value = copy.deepcopy(original)
            value[field] = False
            code, report = self.invoke_preparation(value)
            self.assertEqual(code, 126)
            self.assertIsNone(report["artifacts"])

    def test_wrapper_cleanup_failure_withholds_artifacts_and_retains_custody(self):
        value = self.prepared_observation()
        code, report = self.invoke_preparation(value, cleanup_error=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["wrapper_cleanup"]["source_loader"], "CLEANUP_HOLD")
        self.assertIsNone(report["artifacts"])
        self.assertIsNone(report["artifact_digests"])
        self.assertEqual(report["source_before"], value["source_before"])

    def test_post_call_host_failure_withholds_artifacts_without_retry(self):
        value = self.prepared_observation()
        code, report = self.invoke_preparation(value, after_guard=[None, ValueError("changed host")])
        self.assertEqual(code, 126)
        self.assertEqual(report["wrapper_stage"], "POST_CALL_CUSTODY")
        self.assertTrue(report["preparation_attempted"])
        self.assertIsNone(report["artifacts"])

    def test_preparation_exception_preserves_attempt_and_fixed_failure_phase(self):
        value = self.prepared_observation()
        value.update(status="REFUSED_OR_INDETERMINATE", failure_stage="INVENTORY_PREPARATION",
                     artifacts=None, artifact_digests=None)
        code, report = self.invoke_preparation(value, error=True)
        self.assertEqual(code, 126)
        self.assertTrue(report["preparation_attempted"])
        self.assertEqual(report["entry_failure_stage"], "INVENTORY_PREPARATION")

    def test_absent_exception_observation_is_unknown_not_not_attempted(self):
        code, report = self.invoke_preparation(None, error=True)
        self.assertEqual(code, 126)
        self.assertIsNone(report["preparation_attempted"])
        self.assertFalse(report["managed_call_attempted"])

    def test_helper_cleanup_metadata_is_retained_without_artifacts_or_retry(self):
        value = self.prepared_observation()
        uncertainty = [{"scope": "INVENTORY_HELPER_DESCRIPTORS", "held_fds": [71, 72], "ambiguous_fds": [72]}]
        value.update(status="CLEANUP_HOLD", failure_stage="INVENTORY_PREPARATION", artifacts=None,
                     artifact_digests=None, input_cleanup_uncertainty=uncertainty)
        code, report = self.invoke_preparation(value, error=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["input_cleanup_uncertainty"], uncertainty)
        self.assertIsNone(report["artifacts"])

    def test_cleanup_metadata_cannot_smuggle_private_text(self):
        value = self.prepared_observation()
        value["input_cleanup_uncertainty"] = [{"scope": "DESCRIPTOR_CLOSE", "descriptors": ["NEVER_EMIT"]}]
        code, report = self.invoke_preparation(value)
        self.assertEqual(code, 126)
        self.assertNotIn("NEVER_EMIT", json.dumps(report))

    def test_artifact_join_or_required_source_changes_are_refused(self):
        original = self.prepared_observation()
        for field in ("required_sources", "pins"):
            value = copy.deepcopy(original)
            profile = value["artifacts"]["profile"]
            if field == "pins":
                profile["pins"]["source_inventory_digest"] = "sha256:" + "0" * 64
            else:
                profile["required_sources"] = ["/not/in/approved/sources"]
            value["artifact_digests"]["profile"] = self.s._digest(self.s._canonical(profile))
            with self.assertRaises(ValueError):
                self.s._public_preparation(value)


def load_tests(loader, tests, pattern):
    # Only routing/reporting methods touched by the new branch; no host suite.
    affected = [name for name in legacy.CoordinatorWrapperTests.__dict__
                if name.startswith(("test_main_", "test_public_report_", "test_partial_host_"))]
    new = [name for name in InventoryDispatchTests.__dict__ if name.startswith("test_")]
    return unittest.TestSuite([*(InventoryDispatchTests(name) for name in new),
                              *(legacy.CoordinatorWrapperTests(name) for name in affected)])
