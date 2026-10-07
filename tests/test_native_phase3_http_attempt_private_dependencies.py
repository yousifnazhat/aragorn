"""Host-only staged import joins; no fixture, receipt sample or live effect."""

import importlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from scripts import capture_native_phase3_http_attempt as launcher
from scripts import materialize_native_phase3_http_attempt_capture as renderer
from scripts import stage_runtime_phase3_http_ready_profile as stage

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "src/aragorn/"


class HttpAttemptPrivateDependencyTests(unittest.TestCase):
    def test_staged_semantics_and_late_imports_leave_frozen_globals_unchanged(self):
        paths = (
            *renderer.PRIVATE_STAGED_SOURCES,
            PREFIX + "runtime_broker_decision_measurement_verify.py",
            PREFIX + "runtime_broker_measurement_plan.py",
            PREFIX + "runtime_broker_effective_receipt_verify.py",
        )
        frozen = {
            path: importlib.import_module("aragorn." + Path(path).stem)
            for path in paths
        }
        package = sys.modules["aragorn"]
        snapshots = {path: dict(vars(module)) for path, module in frozen.items()}
        private_names = {name for name in sys.modules if "._http_attempt_" in name}
        original = {
            name: (ROOT / name).read_bytes() for name in renderer.source_paths()
        }
        staged, loaded, payloads = {}, {}, {}
        real_stage, real_load = launcher._staged_private_sources, launcher._load

        def remember_stage(sources):
            staged.update(real_stage(sources))
            return staged

        def remember_load(raw, source, modules):
            payloads[source] = raw
            loaded[source] = real_load(raw, source, modules)
            return loaded[source]

        with (
            patch.object(launcher, "_staged_private_sources", remember_stage),
            patch.object(launcher, "_load", remember_load),
        ):
            host = launcher.build_controller(original)

        def module(name):
            return loaded[PREFIX + name + ".py"]

        self.assertEqual(tuple(loaded)[:6], renderer.PRIVATE_STAGED_SOURCES)
        for path in renderer.PRIVATE_STAGED_SOURCES:
            self.assertEqual(payloads[path], staged[path])
            self.assertIsNot(loaded[path], frozen[path])
        capability = module("runtime_http_capability")
        v2, grant, v3, v4 = (
            module(name)
            for name in (
                "runtime_action_broker_v2",
                "runtime_capability_grant",
                "runtime_action_broker_v3",
                "runtime_action_broker_v4",
            )
        )
        http = module("native_phase3_http_collection_verify")
        prior = module("runtime_broker_decision_measurement_verify")
        effective = module("runtime_broker_effective_receipt_verify")
        for value in (v2, grant, v3, v4):
            self.assertIs(value._http_capability, capability)
        self.assertIs(v3.RuntimeActionBrokerV2Config, v2.RuntimeActionBrokerV2Config)
        self.assertIs(v4.RuntimeActionBrokerV2Config, v2.RuntimeActionBrokerV2Config)
        self.assertIs(v4._validate_profile_claim, v3._claim)
        self.assertIs(v4._validate_profile_result, v3._lease_result)
        self.assertIs(prior.v4, v4)
        self.assertIs(
            prior._canonical_profiled_submission, grant._canonical_profiled_submission
        )
        self.assertIs(effective.v4, v4)
        self.assertIs(effective.prior, prior)
        for value in (prior, effective, module("runtime_broker_measurement_plan")):
            self.assertIs(value._http_collection, http)
        self.assertIs(host.private_inputs.planning.http, http)
        self.assertIs(host.private_inputs.planning.broker, prior)
        late = http.__dict__["__builtins__"]["__import__"]
        self.assertIs(
            late(
                "", http.__dict__, None, ("runtime_broker_effective_receipt_verify",), 1
            ).runtime_broker_effective_receipt_verify,
            effective,
        )
        late_capability = capability.__dict__["__builtins__"]["__import__"]
        self.assertIs(
            late_capability(
                "", capability.__dict__, None, ("runtime_action_broker_v3",), 1
            ).runtime_action_broker_v3,
            v3,
        )
        # Shape-only contract check, explicitly not a valid action or evidence.
        submission = {
            key: None
            for key in grant._OBSERVED_SUBMISSION_FIELDS | {"runtime_attribution"}
        }
        submission["schema"] = capability.PROFILED_SCHEMA
        self.assertEqual(grant._canonical_profiled_submission(submission), submission)
        with self.assertRaises(
            frozen[PREFIX + "runtime_capability_grant.py"].RuntimeCapabilityGrantError
        ):
            frozen[
                PREFIX + "runtime_capability_grant.py"
            ]._canonical_profiled_submission(submission)
        config = v2.RuntimeActionBrokerV2Config(
            None, "shape-only", Path("pending"), Path("receipt")
        )
        self.assertEqual(config.expected_runtime_profile_digest, "shape-only")
        for path, value in frozen.items():
            self.assertIs(sys.modules["aragorn." + Path(path).stem], value)
            self.assertIs(getattr(package, Path(path).stem), value)
            self.assertEqual(vars(value), snapshots[path])
        self.assertEqual(
            {name for name in sys.modules if "._http_attempt_" in name}, private_names
        )

    def test_private_stage_rejects_evidence_source_substitution_and_wrong_destination(
        self,
    ):
        original = {
            name: (ROOT / name).read_bytes() for name in renderer.PRIVATE_STAGED_SOURCES
        }
        source = PREFIX + "runtime_capability_grant.py"
        inherited, replacements, inputs = stage._verified_payloads()
        rows = inherited | replacements
        with patch.object(
            stage, "_verified_payloads", return_value=(inherited, replacements, inputs)
        ):
            with self.assertRaisesRegex(ValueError, "source differs from pinned stage"):
                launcher._staged_private_sources(
                    original | {source: original[source] + b"\n"}
                )
        destination = "usr/lib/aragorn/aragorn/runtime_capability_grant.py"
        moved = dict(rows)
        moved["tmp/runtime_capability_grant.py"] = moved.pop(destination)
        with patch.object(
            stage, "_verified_payloads", return_value=(moved, {}, inputs)
        ):
            with self.assertRaisesRegex(ValueError, "private stage payload differs"):
                launcher._staged_private_sources(original)

    def test_failed_private_compile_removes_only_its_temporary_registration(self):
        before = dict(sys.modules)
        modules = {}
        with self.assertRaisesRegex(RuntimeError, "inert import failure"):
            launcher._load(
                b"raise RuntimeError('inert import failure')\n",
                PREFIX + "runtime_capability_grant.py",
                modules,
            )
        self.assertEqual(modules, {})
        self.assertEqual(
            {key for key in sys.modules if "._http_attempt_" in key},
            {key for key in before if "._http_attempt_" in key},
        )
        for key, value in before.items():
            self.assertIs(sys.modules.get(key), value)


if __name__ == "__main__":
    unittest.main()
