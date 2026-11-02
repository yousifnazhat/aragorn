"""Development artifact construction only; no live capture or workload run."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from scripts import prepare_native_phase3_http_development_plan as subject
from tests.test_native_phase3_http_ready_helpers import _stage_data

ROOT = Path(__file__).resolve().parents[1]


class NativeHttpDevelopmentPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {
            name: (ROOT / name).read_bytes() for name in subject.source_paths()
        }
        cls.stage_raw = canonical_json(_stage_data()[0])
        # Pure unit custody placeholder, never a signed-source/live assertion.
        cls.source_raw = canonical_json({"commit": "a" * 40})

    def build(self, **updates):
        return subject.build_development_plan(
            **{
                "source_raws": self.sources,
                "source_record_raw": self.source_raw,
                "staged_profile_raw": self.stage_raw,
                **updates,
            }
        )

    def test_real_artifact_bindings_reserve_inventory_but_select_only_one_positive_capture(
        self,
    ):
        with patch.object(
            subject.tasks,
            "execute_reference_task",
            side_effect=AssertionError("builder must not execute tasks"),
        ):
            built = self.build()
        arguments, contract = built["plan_arguments"], built["contract"]
        self.assertEqual(set(arguments), subject.attempt_inputs.PLAN_ARGUMENTS)
        self.assertEqual(len(arguments["expected_attempt_ids"]), 100)
        self.assertEqual(len(arguments["expected_overhead_pair_bindings"]), 100)
        self.assertEqual(arguments["expected_unattributed_attempt_id"], "p3-lab-a100")
        self.assertEqual(arguments["selected_attempt_id"], "p3-lab-a001")
        self.assertEqual(contract["scope"], subject.SCOPE)
        self.assertEqual(contract["permitted_attempt_ids"], ["p3-lab-a001"])
        self.assertEqual(contract["permitted_pair_ids"], [])
        self.assertEqual(contract["attempt_budget"], 1)
        self.assertEqual(contract["automatic_effect_retries"], 0)
        self.assertEqual(
            contract["possible_effect"],
            "ALLOW_SENT_IS_NOT_BLOCKED_EXFILTRATION_ACCEPTANCE",
        )
        self.assertTrue(all(contract[name] is False for name in subject._FALSE))
        blobs = built["input_blobs"]
        self.assertEqual(
            blobs[arguments["expected_campaign_contract_digest"]], built["contract_raw"]
        )
        self.assertEqual(
            blobs[subject._digest(built["plan_arguments_raw"])],
            built["plan_arguments_raw"],
        )
        for name, raw in self.sources.items():
            self.assertEqual(blobs[subject._digest(raw)], raw, name)
        expected_os = subject.preparation.old._artifact(
            "os_profile",
            {
                "fixture_image": subject.preparation.old.reported._IMAGE,
                "staged_schema": subject.ready.STAGED_SCHEMA,
                "staged_files_digest": subject._digest(
                    canonical_json(json.loads(self.stage_raw)["files"])
                ),
            },
        )
        self.assertEqual(blobs[contract["host_profile_digest"]], expected_os)
        lab = json.loads(self.sources[subject.LAB_DATA])
        for name, binding in built["task_bindings"].items():
            descriptor = json.loads(blobs[binding["task_digest"]])
            self.assertEqual(descriptor["template_id"], name)
            self.assertEqual(
                descriptor["module_source_digest"],
                subject._digest(self.sources[subject.TASK_SOURCE]),
            )
            self.assertEqual(
                blobs[binding["input_digest"]],
                lab["static_inputs"][descriptor["input"]["ref"]]["utf8"].encode(
                    "utf-8"
                ),
            )
            self.assertEqual(
                binding["host_profile_digest"], contract["host_profile_digest"]
            )
        self.assertEqual(
            blobs[contract["selected_canary_digest"]], b"p3canary-p3-lab-a001"
        )

    def test_changed_reference_stage_or_closure_refuses_and_publication_is_absent_only(
        self,
    ):
        changed = deepcopy(self.sources)
        changed[subject.REFERENCE] += b"\n"
        with self.assertRaisesRegex(ValueError, "reviewed reference bytes differ"):
            self.build(source_raws=changed)
        changed = dict(self.sources)
        del changed[subject.TASK_SOURCE]
        with self.assertRaisesRegex(ValueError, "source closure differs"):
            self.build(source_raws=changed)
        with self.assertRaisesRegex(ValueError, "ready94 stage report differs"):
            self.build(staged_profile_raw=self.stage_raw + b"\n")
        built = self.build()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            store, output = CAS(root / "cas"), root / "plan.json"
            subject._publish(built, store, output)
            self.assertEqual(output.read_bytes(), built["plan_arguments_raw"])
            for pin, raw in built["input_blobs"].items():
                self.assertEqual(store.read(pin, max_bytes=subject._LIMIT), raw)
            with self.assertRaises(subject.pins.PinPreparationError):
                subject._publish(built, store, output)
            self.assertEqual(output.read_bytes(), built["plan_arguments_raw"])


if __name__ == "__main__":
    unittest.main()
