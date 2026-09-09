from __future__ import annotations

import base64
import json
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_json
from scripts import openclaw_final_v3_core_updater_case as core
from scripts import openclaw_final_v3_workshop_invalidation_case as subject

_ROOT = Path(__file__).resolve().parents[1]


class WorkshopInvalidationCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name).resolve()
        cls.contract = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="a" * 64
        )
        cls.request = campaign.build_openclaw_final_v3_subfixture_request(
            cls.contract, subject._CASE
        )
        cls.prepared = subject.prepare_case(
            cls.contract, cls.request, directory=cls.directory
        )
        cls.source = {**subject.old._SOURCE, "files": cls.prepared["source_files"]}
        cls.raw = (_ROOT / subject.old._EVIDENCE["path"]).read_bytes()
        cls.native = json.loads(cls.raw)
        cls.invocation = {
            "argv": [
                "/bin/sh",
                str(_ROOT / subject._RECIPE),
                str(cls.directory / "native.json"),
            ],
            "exit_code": 0,
            "started_at": "2026-09-01T00:00:00Z",
            "completed_at": "2026-09-02T00:00:00Z",
        }

    def test_exact_two_file_mapping_preserves_undeclared_materializer(self) -> None:
        self.assertIsNone(self.prepared["descriptor"]["materializer"])
        self.assertEqual(
            self.prepared["native_materializer"]["entrypoint"], subject._ENTRYPOINT
        )
        self.assertEqual(self.prepared["bundle_files"], subject.old._probe_bundle())
        self.assertFalse(
            self.prepared["path_mapping"]["literal_dispatch_argv_equality"]
        )
        for item in self.prepared["path_mapping"]["files"]:
            self.assertTrue(
                item["provisional"].startswith(subject._PROVISIONAL_ROOT + "/")
            )
            self.assertTrue(item["native"].startswith(subject._NATIVE_ROOT + "/"))
        self.assertEqual(len(self.prepared["path_mapping"]["files"]), 2)

    def test_request_or_descriptor_substitution_precedes_materialization(self) -> None:
        changed = deepcopy(self.request)
        changed["case"]["ordinal"] = True
        with TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            with self.assertRaises(AdmissionEvidenceError):
                subject.prepare_case(self.contract, changed, directory=directory)
            self.assertEqual(list(directory.iterdir()), [])
        descriptor = deepcopy(
            subject.dispatch_openclaw_final_v3_campaign_case(subject._CASE)
        )
        descriptor["descriptor"]["materializer"] = {"unexpected": True}
        with TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            with (
                patch.object(
                    subject,
                    "dispatch_openclaw_final_v3_campaign_case",
                    return_value=descriptor,
                ),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.prepare_case(self.contract, self.request, directory=directory)
            self.assertEqual(list(directory.iterdir()), [])

    def test_native_observation_is_verified_without_qualification_or_rewriting(
        self,
    ) -> None:
        observed = subject.verify_capture(
            self.raw, self.prepared, source=self.source, invocation=self.invocation
        )
        self.assertEqual(observed["native_capture"], self.native)
        self.assertEqual(observed["harness"], self.native["harness"]["document"])
        self.assertEqual(
            observed["proof"]["actual_native_argv"],
            self.native["route_observation"]["execution"]["argv"],
        )
        self.assertEqual(
            observed["proof"]["native_capture_digest"], subject.old._digest(self.raw)
        )
        self.assertTrue(
            all(
                value is False
                for key, value in observed["decision"].items()
                if key.endswith("_eligible")
            )
        )

    def test_rejects_prepared_source_raw_argv_and_positive_claim_mutations(
        self,
    ) -> None:
        for mutation in (
            "source",
            "duplicate_source",
            "mapping",
            "bundle",
            "argv",
            "raw",
            "boolean_exit",
            "eligibility",
            "chronology",
        ):
            with self.subTest(mutation=mutation):
                prepared, source, native, invocation = map(
                    deepcopy, (self.prepared, self.source, self.native, self.invocation)
                )
                if mutation == "source":
                    source["files"][0]["digest"] = "sha256:" + "0" * 64
                elif mutation == "duplicate_source":
                    source["files"].append(source["files"][0])
                elif mutation == "mapping":
                    prepared["path_mapping"]["native_root"] = "/elsewhere"
                elif mutation == "bundle":
                    native["route_observation"]["bundle"][0]["bytes"] += 1
                elif mutation == "argv":
                    native["route_observation"]["execution"]["argv"][-1] = (
                        "ADM-02/update/workshop-proposal-apply"
                    )
                elif mutation == "raw":
                    native["route_observation"]["raw"]["base64"] = base64.b64encode(
                        b"{}"
                    ).decode()
                elif mutation == "boolean_exit":
                    native["route_observation"]["execution"]["exit_code"] = False
                elif mutation == "eligibility":
                    native["decision"]["phase3_exit_eligible"] = True
                else:
                    invocation["completed_at"] = invocation["started_at"]
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_capture(
                        canonical_json(native) + b"\n",
                        prepared,
                        source=source,
                        invocation=invocation,
                    )

    def test_rejects_native_artifact_custody_drift(self) -> None:
        native = deepcopy(self.native)
        native["composition"]["action"]["artifacts"][
            "final_combined_v3_workshop_invalidation"
        ]["proposal_fixture"]["stat"]["mode"] = "0666"
        with self.assertRaises(AdmissionEvidenceError):
            subject.verify_capture(
                canonical_json(native) + b"\n",
                self.prepared,
                source=self.source,
                invocation=self.invocation,
            )

    def test_shared_extraction_preserves_retained_live_core_observation(self) -> None:
        wrapper = json.loads(
            (
                _ROOT
                / "benchmark/evidence/phase3-openclaw-final-v3-core-updater-development-case-v1-2026-09-09.json"
            ).read_bytes()
        )
        raw = base64.b64decode(wrapper["native_capture"]["base64"], validate=True)
        result = core.verify_capture(
            raw,
            wrapper["request_binding"],
            source=wrapper["source"],
            invocation=wrapper["invocation"],
        )
        self.assertEqual(result["proof"], wrapper["capture_checks"])


if __name__ == "__main__":
    unittest.main()
