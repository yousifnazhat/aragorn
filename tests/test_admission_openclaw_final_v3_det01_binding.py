from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import admission_openclaw_final_v3_det01_binding as subject
from aragorn.oci_worker_protocol import canonical_digest
from scripts import materialize_openclaw_final_v3_det01 as materializer


class Det01RequestBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.bundle = self.root / "bundle"
        materializer.materialize_openclaw_final_v3_det01(self.bundle)
        self.contract = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="a" * 64
        )
        self.request = campaign.build_openclaw_final_v3_subfixture_request(
            self.contract, "DET-01"
        )

    def bind(self, request: dict | None = None, contract: dict | None = None) -> dict:
        return subject.bind_openclaw_final_v3_det01_request(
            self.contract if contract is None else contract,
            self.request if request is None else request,
            bundle_root=self.bundle,
        )

    def test_exact_binding_is_read_only_and_non_authoritative(self) -> None:
        def snapshot() -> dict:
            return {
                str(path.relative_to(self.root)): (
                    path.stat().st_mode,
                    path.read_bytes() if path.is_file() else None,
                )
                for path in self.root.rglob("*")
            }

        before = snapshot()
        inputs = deepcopy((self.contract, self.request))
        with (
            patch("subprocess.run", side_effect=AssertionError("execution forbidden")),
            patch(
                "runpy.run_path",
                side_effect=AssertionError("module execution forbidden"),
            ),
        ):
            result = self.bind()
        self.assertEqual(snapshot(), before)
        self.assertEqual((self.contract, self.request), inputs)
        self.assertEqual(result["request"], self.request)
        self.assertFalse(result["native_execution_enabled"])
        self.assertFalse(result["descriptor"]["native_execution_enabled"])
        self.assertEqual(
            result["decision"]["status"], "REQUEST_AND_LOCAL_BYTES_BOUND_NOT_EXECUTED"
        )
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key.endswith("_eligible")
            )
        )
        bindings = result["bindings"]
        self.assertEqual(bindings["contract_digest"], canonical_digest(self.contract))
        self.assertEqual(bindings["request_digest"], canonical_digest(self.request))
        self.assertEqual(
            bindings["source_files_digest"], canonical_digest(bindings["source_files"])
        )
        self.assertEqual(
            bindings["bundle_files_digest"], canonical_digest(bindings["bundle_files"])
        )
        self.assertEqual(len(bindings["source_files"]), 7)
        self.assertEqual(
            [item["role"] for item in bindings["bundle_files"]],
            ["probe", "vector", *["probe-dependency"] * 5],
        )
        self.assertEqual(bindings["source_files"][0]["bytes"], 7_330)
        self.assertEqual(bindings["bundle_files"][0]["bytes"], 7_211)
        self.assertIn(
            "NO_SIGNED_CAPTURE_SOURCE_FRESHNESS_CLEANUP_REPLAY_OR_QUALIFICATION_VERIFIED",
            result["limitations"],
        )

    def test_shared_builder_equals_all_runner_requests(self) -> None:
        requests = []

        def observe(request: dict) -> dict:
            requests.append(request)
            case = request["case"]
            return {
                "case_id": case["case_id"],
                "fixture_id": case["fixture_id"],
                "destroyed": True,
                "fresh": True,
                "outcome": "NOT_TESTED",
                "evidence_refs": [],
                "parent_identity_digest": request["frozen_parent"]["digest"],
            }

        result = campaign.run_openclaw_final_v3_campaign(self.contract, observe)
        self.assertEqual(
            requests,
            [
                campaign.build_openclaw_final_v3_subfixture_request(
                    self.contract, case["case_id"]
                )
                for case in self.contract["ordered_cases"]
            ],
        )
        self.assertEqual(result["decision"]["case_not_tested_count"], 31)

    def test_request_field_mutations_are_rejected(self) -> None:
        mutations = [
            (("schema",), "aragorn/unrelated/v1"),
            (("authority",), "PASS"),
            (("campaign_nonce",), "b" * 64),
            (("case", "case_id"), "ADM-01/exact-admitted-bytes"),
            (("case", "fixture_id"), "b" * 64 + "-00"),
            (("case", "ordinal"), False),
            (("case", "isolation", "fresh"), False),
            (("case", "isolation", "destroy_before_next"), False),
            (("case", "isolation", "network"), "host"),
            (("extra",), "unrecognized"),
        ]
        for path, replacement in mutations:
            request = deepcopy(self.request)
            node = request
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = replacement
            with (
                self.subTest(path=path),
                self.assertRaises(campaign.CampaignContractError),
            ):
                self.bind(request)
        request = deepcopy(self.request)
        del request["authority"]
        with self.assertRaises(campaign.CampaignContractError):
            self.bind(request)

    def test_coherent_substituted_campaign_and_wrong_case_are_rejected(self) -> None:
        other = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="b" * 64
        )
        other_request = campaign.build_openclaw_final_v3_subfixture_request(
            other, "DET-01"
        )
        with self.assertRaises(campaign.CampaignContractError):
            self.bind(other_request)
        with self.assertRaises(campaign.CampaignContractError):
            self.bind(
                campaign.build_openclaw_final_v3_subfixture_request(
                    self.contract, "ADM-02/update/core-updater-plugin-replacement"
                )
            )

    def test_builder_rejects_unknown_or_inexact_case_ids(self) -> None:
        class StringSubclass(str):
            pass

        for case_id in (
            None,
            True,
            0,
            b"DET-01",
            StringSubclass("DET-01"),
            "det-01",
            "DET-01 ",
            "unknown",
        ):
            with (
                self.subTest(case_id=case_id),
                self.assertRaises(campaign.CampaignContractError),
            ):
                campaign.build_openclaw_final_v3_subfixture_request(
                    self.contract, case_id
                )

    def test_each_parent_identity_is_frozen_even_with_recomputed_digests(self) -> None:
        for key, value in self.contract["frozen_parent"]["identity"].items():
            with self.subTest(key=key):
                changed = deepcopy(self.contract)
                identity = changed["frozen_parent"]["identity"]
                identity[key] = (
                    "sha256:" + "0" * 64
                    if value.startswith("sha256:")
                    else "0" * 40
                    if len(value) == 40
                    else value + "-changed"
                )
                digest = canonical_digest(identity)
                changed["frozen_parent"]["digest"] = digest
                for case in changed["ordered_cases"]:
                    case["isolation"]["parent_identity_digest"] = digest
                request = deepcopy(self.request)
                request["frozen_parent"] = changed["frozen_parent"]
                request["case"] = changed["ordered_cases"][0]
                with self.assertRaises(campaign.CampaignContractError):
                    self.bind(request)
                with self.assertRaises(campaign.CampaignContractError):
                    self.bind(request, changed)

    def test_materializer_and_source_drift_are_rejected_without_touching_repository(
        self,
    ) -> None:
        checkout = self.root / "source"
        materializer_path = "scripts/materialize_openclaw_final_v3_det01.py"
        paths = [
            materializer_path,
            *[item[0] for item in materializer._SOURCES.values()],
        ]
        for name in paths:
            destination = checkout / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(subject._ROOT / name, destination)
        with patch.object(subject, "_ROOT", checkout):
            self.bind()
            for name in (materializer_path, "src/aragorn/policy.py"):
                path = checkout / name
                original = path.read_bytes()
                for oversized in (False, True):
                    with self.subTest(path=name, oversized=oversized):
                        if oversized:
                            with path.open("wb") as stream:
                                stream.truncate(1_048_577)
                        else:
                            path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                        with self.assertRaises(campaign.CampaignContractError):
                            self.bind()
                        path.write_bytes(original)

    def test_bundle_mutations_are_rejected(self) -> None:
        for mutation in (
            "missing",
            "extra",
            "changed",
            "oversized",
            "writable",
            "symlink",
            "hardlink",
            "writable-directory",
        ):
            with self.subTest(mutation=mutation):
                bundle = self.root / mutation
                materializer.materialize_openclaw_final_v3_det01(bundle)
                path = bundle / "run_admission_authority_replay.py"
                if mutation in {"missing", "extra", "symlink", "hardlink"}:
                    bundle.chmod(0o755)
                    if mutation == "extra":
                        (bundle / "extra").write_bytes(b"extra")
                    else:
                        path.unlink()
                        target = self.bundle / path.name
                        if mutation == "symlink":
                            path.symlink_to(target)
                        elif mutation == "hardlink":
                            os.link(target, path)
                    bundle.chmod(0o555)
                elif mutation == "writable-directory":
                    (bundle / "aragorn").chmod(0o755)
                else:
                    path.chmod(0o644)
                    if mutation == "changed":
                        raw = path.read_bytes()
                        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                    elif mutation == "oversized":
                        with path.open("wb") as stream:
                            stream.truncate(1_048_577)
                    if mutation != "writable":
                        path.chmod(0o444)
                with self.assertRaises(campaign.CampaignContractError):
                    subject.bind_openclaw_final_v3_det01_request(
                        self.contract, self.request, bundle_root=bundle
                    )

    def test_returned_binding_is_detached(self) -> None:
        expected = self.bind()
        changed = self.bind()
        changed["request"]["case"]["isolation"]["fresh"] = False
        changed["descriptor"]["argv"][0] = "/tmp/untrusted"
        changed["bindings"]["source_files"][0]["digest"] = "sha256:" + "0" * 64
        changed["bindings"]["bundle_files"][0]["role"] = "fixture"
        self.assertEqual(self.bind(), expected)

    def test_oversized_file_is_rejected_before_reading_contents(self) -> None:
        path = self.root / "oversized-file"
        path.write_bytes(b"too long")
        with (
            path.open("rb") as stream,
            patch.object(subject.os, "open", return_value=stream.fileno()),
            patch.object(subject.os, "fdopen") as opened,
        ):
            reader = opened.return_value.__enter__.return_value
            reader.fileno.return_value = stream.fileno()
            with self.assertRaises(campaign.CampaignContractError):
                subject._read_file(path, 1, "sha256:" + "0" * 64)
            reader.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
