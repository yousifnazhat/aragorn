from __future__ import annotations

import base64
import hashlib
import json
import os
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import admission_openclaw_final_v3_det01_campaign_qualification as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _raw_record(document: dict) -> dict:
    raw = canonical_json(document) + b"\n"
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "bytes": len(raw),
        "digest": _digest(raw),
    }


class Det01CampaignQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = (subject._ROOT / subject._EVIDENCE["path"]).read_bytes()
        cls.evidence = json.loads(cls.raw)
        cls.native = json.loads(
            base64.b64decode(cls.evidence["native_capture"]["base64"])
        )

    def _cas(self, temporary: str) -> CAS:
        cas = CAS(Path(temporary) / "cas")
        cas.put_expected(
            BytesIO(self.raw),
            expected_digest=subject._EVIDENCE["digest"],
            max_bytes=len(self.raw),
        )
        return cas

    def test_exact_signed_observation_qualifies_only_the_wrapper_bound_case(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            result = subject.qualify_openclaw_final_v3_det01_campaign_observation(
                evidence_cas=self._cas(temporary)
            )
        self.assertEqual(result["case"], {"id": "DET-01", "status": "PASS"})
        self.assertEqual(result["source"], subject._SOURCE)
        self.assertEqual(result["retention"], subject._RETENTION)
        self.assertEqual(result["evidence"], subject._EVIDENCE)
        eligibility = {
            key: value
            for key, value in result["decision"].items()
            if key.endswith("_eligible")
        }
        self.assertGreaterEqual(len(eligibility), 10)
        self.assertTrue(all(value is False for value in eligibility.values()))
        self.assertIs(eligibility["det_01_eligible"], False)
        self.assertEqual(
            result["bindings"]["nonce_association"],
            "HOST_WRAPPER_INVOCATION_NOT_COLLECTOR_NONCE_OBSERVATION",
        )
        for ceiling in (
            "CAMPAIGN_NONCE_BOUND_BY_WRAPPER_NOT_ECHOED_BY_NATIVE_COLLECTOR",
            "LOCAL_DOCKER_DAEMON_OBSERVATION_NOT_EXTERNAL_ATTESTATION",
            "PARENT_SNAPSHOTS_DO_NOT_ESTABLISH_AN_EXCLUSIVE_RUNTIME_VOLUME_LEASE",
            "NO_CAMPAIGN_EXECUTION_RESUME_ANTI_REPLAY_OR_AGGREGATE_PASS",
        ):
            self.assertIn(ceiling, result["limitations"])

    def test_missing_and_tampered_cas_evidence_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            with self.assertRaises(AdmissionEvidenceError):
                subject.qualify_openclaw_final_v3_det01_campaign_observation(
                    evidence_cas=cas
                )
            changed = self.raw.replace(
                b"HOST_WRAPPER_INVOCATION", b"NATIVE_COLLECTOR_ECHO", 1
            )
            self.assertNotEqual(changed, self.raw)
            with (
                patch.object(cas, "read", return_value=changed),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.qualify_openclaw_final_v3_det01_campaign_observation(
                    evidence_cas=cas
                )

    def test_signed_source_and_retention_parent_drift_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            cas = self._cas(temporary)
            for identity in (subject._SOURCE, subject._RETENTION):
                with (
                    self.subTest(commit=identity["commit"]),
                    patch.dict(identity, {"parent": "0" * 40}),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    subject.qualify_openclaw_final_v3_det01_campaign_observation(
                        evidence_cas=cas
                    )

    def test_internal_authority_and_lifecycle_changes_fail_closed(self) -> None:
        mutations = (
            (("decision", "phase3_exit_eligible"), True),
            (("decision", "det_01_eligible"), 1),
            (("campaign_binding", "association"), "NATIVE_COLLECTOR_NONCE_ATTESTATION"),
            (("request_binding", "native_execution_enabled"), True),
            (("cleanup", "container_absent"), 1),
            (("cleanup", "volume_absent"), False),
            (("parent_before", "cleanup", "daemon_reachable"), False),
            (("parent_after", "running_users_after"), ["f" * 64]),
            (("namespace_before", "containers"), ["f" * 64]),
        )
        for path, replacement in mutations:
            value = deepcopy(self.evidence)
            node = value
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(AdmissionEvidenceError):
                subject._verify_observation(value)

    def test_source_closure_missing_duplicated_or_changed_entry_is_rejected(
        self,
    ) -> None:
        for mutation in ("missing", "duplicate", "digest"):
            value = deepcopy(self.evidence)
            files = value["source"]["files"]
            if mutation == "missing":
                files.pop()
            elif mutation == "duplicate":
                files.append(deepcopy(files[0]))
            else:
                files[0]["digest"] = "sha256:" + "0" * 64
            with (
                self.subTest(mutation=mutation),
                patch.object(subject, "_load_helpers") as load_helpers,
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject._verify_observation(value)
            load_helpers.assert_not_called()

    def test_signed_source_fifo_is_rejected_without_a_blocking_open(self) -> None:
        original_open = os.open
        source_path = subject._ROOT / self.evidence["source"]["files"][0]["path"]
        opened = []
        with TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "source.fifo"
            os.mkfifo(fifo)

            def redirect_source(path, flags, *args, **kwargs):
                if Path(path) == source_path:
                    self.assertTrue(flags & os.O_NONBLOCK)
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    opened.append(path)
                    return original_open(fifo, flags, *args, **kwargs)
                return original_open(path, flags, *args, **kwargs)

            with (
                patch.object(subject.os, "open", side_effect=redirect_source),
                self.assertRaisesRegex(AdmissionEvidenceError, "working source file"),
            ):
                subject._verify_sources(self.evidence["source"])
        self.assertEqual(opened, [source_path])

    def test_shadowed_helper_origin_is_rejected_before_helper_invocation(self) -> None:
        with (
            patch.object(campaign, "__file__", "/tmp/untrusted-shadow-campaign.py"),
            patch.object(
                campaign, "build_openclaw_final_v3_campaign_contract"
            ) as build,
            self.assertRaisesRegex(AdmissionEvidenceError, "helper module origin"),
        ):
            subject._verify_observation(self.evidence)
        build.assert_not_called()

    def test_bootstrap_origin_and_byte_drift_precede_dependency_invocation(
        self,
    ) -> None:
        source_path = (
            subject._ROOT
            / "src/aragorn/admission_openclaw_final_v3_det01_qualification.py"
        )
        original_open = os.open
        raw = source_path.read_bytes()
        with TemporaryDirectory() as temporary:
            cas = self._cas(temporary)
            changed = Path(temporary) / "changed-bootstrap.py"
            changed.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))

            def redirect_bootstrap(path, flags, *args, **kwargs):
                target = changed if Path(path) == source_path else path
                return original_open(target, flags, *args, **kwargs)

            for mutation in ("origin", "bytes"):
                guard = (
                    patch.object(subject.checks, "__file__", "/tmp/shadow-checks.py")
                    if mutation == "origin"
                    else patch.object(
                        subject.os, "open", side_effect=redirect_bootstrap
                    )
                )
                with (
                    self.subTest(mutation=mutation),
                    guard,
                    patch.object(
                        subject.checks.custody, "_verify_dependencies"
                    ) as verify,
                    self.assertRaisesRegex(AdmissionEvidenceError, "bootstrap module"),
                ):
                    subject.qualify_openclaw_final_v3_det01_campaign_observation(
                        evidence_cas=cas
                    )
                verify.assert_not_called()

    def test_recomputed_request_digests_do_not_bypass_nonce_association(self) -> None:
        value = deepcopy(self.evidence)
        contract = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="f" * 64
        )
        request = campaign.build_openclaw_final_v3_subfixture_request(
            contract, "DET-01"
        )
        value["request_binding"]["request"] = request
        value["request_binding"]["bindings"]["contract_digest"] = _digest(
            canonical_json(contract)
        )
        value["request_binding"]["bindings"]["request_digest"] = _digest(
            canonical_json(request)
        )
        with self.assertRaises(AdmissionEvidenceError):
            subject._verify_observation(value)
        # The collector never echoed this nonce. A fully coherent replacement is
        # rejected by signed retained bytes, not by invented native attestation.
        value["campaign_binding"].update(nonce="f" * 64, fixture_id="f" * 64 + "-00")
        changed_raw = canonical_json(value) + b"\n"
        with TemporaryDirectory() as temporary:
            cas = self._cas(temporary)
            with (
                patch.object(cas, "read", return_value=changed_raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.qualify_openclaw_final_v3_det01_campaign_observation(
                    evidence_cas=cas
                )

    def test_rehashed_native_argv_and_replay_mutations_are_rejected(self) -> None:
        for mutation in ("argv", "replay", "boolean_exit"):
            value = deepcopy(self.evidence)
            native = deepcopy(self.native)
            replay = native["subfixture"]["replay"]
            if mutation == "argv":
                replay["command"]["argv"][-1] = "/tmp/unbound-replay.py"
            elif mutation == "boolean_exit":
                replay["command"]["exit_code"] = False
            else:
                replay["document"]["cases"][0]["replays"][0]["stdout_digest"] = (
                    "sha256:" + "0" * 64
                )
                replay["command"]["stdout"] = _raw_record(replay["document"])
            value["native_capture"] = _raw_record(native)
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject._verify_observation(value)

    def test_cleanup_identity_and_query_substitution_is_rejected(self) -> None:
        for mutation in ("container", "volume", "snapshot_query"):
            value = deepcopy(self.evidence)
            if mutation == "container":
                value["cleanup"]["container_id"] = "f" * 64
                value["cleanup"]["container_query"][-1] = "id=" + "f" * 64
            elif mutation == "volume":
                value["cleanup"]["volume_name"] = (
                    "aragorn-phase3-final-combined-v3-det01-subfixture-1"
                )
            else:
                value["parent_before"]["cleanup"]["commands"][-1]["argv"][-1] = (
                    "{{.Names}}"
                )
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject._verify_observation(value)

    def test_rehashed_parent_contract_and_runtime_snapshots_are_rejected(self) -> None:
        for mutation in (
            "contract_bytes",
            "runtime_tree",
            "raw_content_join",
            "boolean_stat",
        ):
            value = deepcopy(self.evidence)
            before = value["parent_before"]
            if mutation == "contract_bytes":
                record = before["content"]["contract_files"]["configuration"]
                config = json.loads(base64.b64decode(record["content_base64"]))
                config["security"]["installPolicy"]["enabled"] = False
                raw = canonical_json(config) + b"\n"
                record.update(
                    content_base64=base64.b64encode(raw).decode("ascii"),
                    bytes=len(raw),
                    digest=_digest(raw),
                )
                record["stat_before"]["size"] = record["stat_after"]["size"] = len(raw)
            elif mutation == "boolean_stat":
                record = before["content"]["contract_files"]["configuration"]
                record["stat_before"]["nlink"] = record["stat_after"]["nlink"] = True
            else:
                before["content"]["runtime_tree_before"]["tree_digest"] = (
                    "sha256:" + "0" * 64
                )
                before["content"]["runtime_tree_after"] = deepcopy(
                    before["content"]["runtime_tree_before"]
                )
            if mutation != "raw_content_join":
                before["stdout"] = _raw_record(before["content"])
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject._verify_observation(value)


if __name__ == "__main__":
    unittest.main()
