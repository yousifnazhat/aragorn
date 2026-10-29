from __future__ import annotations

import json
import unittest
from copy import deepcopy
from hashlib import sha256
from unittest.mock import patch

from scripts import capture_runtime_response_systemd_check as subject
from scripts import prepare_runtime_response_systemd_check as prep


class ResponseCaptureTests(unittest.TestCase):
    def test_retained_dispatch_binds_two_ordered_publications_and_local_receipts(
        self,
    ) -> None:
        raw = (
            subject._ROOT
            / "benchmark/evidence/phase3-runtime-response-dispatch-development-v1-2026-09-09.json"
        ).read_bytes()
        self.assertEqual(
            sha256(raw).hexdigest(),
            "895c14c168afc9145ebe076a2efae06ecf9d9914ab06a3c2a98574de3f2181cd",
        )
        capture = json.loads(raw)
        self.assertEqual(subject.campaign._canonical(capture), raw)
        check = capture["observation"]["check"]
        proof = check["automatic_dispatch"]
        self.assertIn(
            "aragorn-runtime-revocation-publisher.service start waiting\n",
            proof["second_publisher_waiting_jobs"],
        )
        self.assertEqual(len(proof["invocations"]), 2)
        for generation, status, record, snapshot in zip(
            (2, 3),
            (
                "NO_REVOCATION_FOR_ACTIVE_PROFILE",
                "TERMINATED_AND_REVOKED_FIXED_RUNTIME_PROFILE",
            ),
            proof["invocations"],
            proof["publications"],
            strict=True,
        ):
            envelope = record["response"]["result"]
            result = envelope["response"]
            digest = subject.campaign._digest(subject.campaign._canonical(snapshot))
            self.assertEqual(record["publication"]["result"]["generation"], generation)
            self.assertEqual(
                record["publication"]["result"]["revocations_digest"], digest
            )
            self.assertEqual(result["accepted_revocation"]["generation"], generation)
            self.assertEqual(result["revocation_snapshot_digest"], digest)
            self.assertEqual(result["status"], status)
            self.assertEqual(result["before"], check["before"])
            response_raw = subject.campaign._canonical(result)
            self.assertEqual(
                envelope["evidence"]["digest"], subject.campaign._digest(response_raw)
            )
            self.assertEqual(envelope["evidence"]["bytes"], len(response_raw))
            self.assertTrue(record["retention"]["separate_process_readback"])
            self.assertTrue(record["retention"]["deduplication_checked"])
            self.assertTrue(record["retention"]["blob_and_directory_chain_fsynced"])
            for name in ("publication", "response"):
                self.assertEqual(
                    record[name]["journal"]["_SYSTEMD_INVOCATION_ID"],
                    record[name]["invocation_id"],
                )
                self.assertEqual(
                    json.loads(record[name]["journal"]["MESSAGE"]),
                    record[name]["result"],
                )
            if generation == 2:
                self.assertEqual(result["after"], result["before"])
                self.assertNotIn("future_start_barrier", result)
            else:
                self.assertEqual(len(result["future_start_barrier"]["masks"]), 2)
        for name in ("publication", "response"):
            self.assertEqual(
                len({item[name]["invocation_id"] for item in proof["invocations"]}), 2
            )
        for item in capture["response_overlay"].values():
            committed = subject.existing.acquisition.shared._git(
                ["show", capture["source"]["commit"] + ":" + item["path"]]
            )
            self.assertEqual(subject.campaign._digest(committed), item["digest"])
        self.assertEqual(check["wrong_skill_refusal"]["exit_code"], 126)
        self.assertEqual(check["direct_start_refusal"]["exit_code"], 1)
        self.assertEqual(check["extra_gateway_cgroup_member_exit_code"], -15)
        self.assertTrue(
            all(
                item["status"] == "ABSENT"
                for item in check["cgroups_after_refused_start"]
            )
        )
        self.assertTrue(capture["cleanup"]["container_name_absent"])
        self.assertTrue(capture["cleanup"]["removed_id_absent"])
        for document in (capture, check):
            self.assertFalse(document["phase3_eligible"])
            self.assertFalse(document["run_conformance_eligible"])

    def test_retained_live_evidence_receipt_binds_exact_response_bytes(self) -> None:
        raw = (
            subject._ROOT
            / "benchmark/evidence/phase3-runtime-response-retention-development-v1-2026-09-09.json"
        ).read_bytes()
        self.assertEqual(
            sha256(raw).hexdigest(),
            "d61d9e3df0bd4f46bc6f0348dd95625812b28f965b25c250fa3fef16eab71c81",
        )
        capture = json.loads(raw)
        check = capture["observation"]["check"]
        envelope = json.loads(check["response_invocation"]["stdout"])
        response = subject.campaign._canonical(envelope["response"])
        proof = check["evidence_retention"]
        self.assertEqual(proof["digest"], envelope["evidence"]["digest"])
        self.assertEqual(proof["digest"], "sha256:" + sha256(response).hexdigest())
        self.assertEqual(proof["bytes"], len(response))
        self.assertTrue(proof["separate_process_readback"])
        self.assertTrue(proof["deduplication_checked"])
        self.assertTrue(proof["blob_and_directory_chain_fsynced"])
        self.assertEqual(
            envelope["response"]["status"],
            "TERMINATED_AND_REVOKED_FIXED_RUNTIME_PROFILE",
        )
        for item in capture["response_overlay"].values():
            committed = subject.existing.acquisition.shared._git(
                ["show", capture["source"]["commit"] + ":" + item["path"]]
            )
            self.assertEqual("sha256:" + sha256(committed).hexdigest(), item["digest"])
        self.assertTrue(capture["cleanup"]["container_name_absent"])
        self.assertTrue(capture["cleanup"]["removed_id_absent"])
        self.assertFalse(capture["phase3_eligible"])
        self.assertFalse(capture["run_conformance_eligible"])

    def test_retained_response_observation_keeps_exact_overlay_and_claim_ceiling(
        self,
    ) -> None:
        path = (
            subject._ROOT
            / "benchmark/evidence/phase3-runtime-response-systemd-development-v1-2026-09-09.json"
        )
        raw = path.read_bytes()
        self.assertEqual(
            sha256(raw).hexdigest(),
            "145d990301c2e5ee414dea56c662a93f5189275addbdc35b8320701d6bb75d0e",
        )
        capture = json.loads(raw)
        self.assertEqual(subject.campaign._canonical(capture), raw)
        for item in capture["response_overlay"].values():
            committed = subject.existing.acquisition.shared._git(
                ["show", capture["source"]["commit"] + ":" + item["path"]]
            )
            self.assertEqual("sha256:" + sha256(committed).hexdigest(), item["digest"])
        check = capture["observation"]["check"]
        result = json.loads(check["response_invocation"]["stdout"])
        self.assertEqual(
            result["status"], "TERMINATED_AND_REVOKED_FIXED_RUNTIME_PROFILE"
        )
        self.assertEqual(check["wrong_skill_refusal"]["exit_code"], 126)
        self.assertEqual(check["direct_start_refusal"]["exit_code"], 1)
        self.assertEqual(check["extra_gateway_cgroup_member_exit_code"], -15)
        self.assertTrue(
            all(
                item["status"] == "ABSENT"
                for item in check["cgroups_after_refused_start"]
            )
        )
        self.assertTrue(result["future_start_barrier"]["directory_fsynced"])
        self.assertEqual(len(result["future_start_barrier"]["masks"]), 2)
        self.assertTrue(capture["cleanup"]["container_name_absent"])
        self.assertTrue(capture["cleanup"]["removed_id_absent"])
        self.assertFalse(capture["phase3_eligible"])
        self.assertFalse(capture["run_conformance_eligible"])

    def test_preparation_refuses_native_host_and_accepts_only_docker_systemd(
        self,
    ) -> None:
        with (
            patch.object(prep.sys, "platform", "linux"),
            patch.object(prep.os, "geteuid", return_value=0),
        ):
            for scope in ("/init.scope", "/", "/docker/../init.scope"):
                with (
                    patch.object(prep.response, "_process_cgroup", return_value=scope),
                    self.assertRaises(RuntimeError),
                ):
                    prep._require_fixture()
            with patch.object(
                prep.response,
                "_process_cgroup",
                return_value="/docker/" + "a" * 64 + "/init.scope",
            ):
                prep._require_fixture()

    def test_owned_cleanup_success_failure_and_parent_drift(self) -> None:
        parent = subject.campaign.current_v3_parent_identity()
        before = {
            "image_inspect": {"id": parent["image_id"]},
            "volume_inspect": {"name": parent["runtime_volume"]},
            "content": {
                "runtime_tree_before": {"digest": "fixed"},
                "runtime_tree_after": {"digest": "fixed"},
                "contract_files": {"config": {"content_base64": "e30="}},
            },
        }
        observation = {
            "check": {
                "status": "OBSERVED",
                "phase3_eligible": False,
                "run_conformance_eligible": False,
            }
        }
        for case in (None, "dispatch", "create", "exec", "parent", "claim"):
            dispatch = case == "dispatch"
            failure = None if dispatch else case
            with self.subTest(failure=failure, dispatch=dispatch):
                after = deepcopy(before)
                if failure == "parent":
                    after["content"]["runtime_tree_after"]["digest"] = "changed"

                def docker(
                    *arguments: str,
                    failure: str | None = failure,
                    dispatch: bool = dispatch,
                ) -> bytes:
                    if arguments[0] == failure:
                        raise RuntimeError("fixture command failed")
                    if arguments[:2] == ("image", "inspect"):
                        layers = (
                            ["base", "child"]
                            if arguments[2] == subject._IMAGE
                            else ["base"]
                        )
                        return json.dumps(
                            [{"Id": arguments[2], "RootFS": {"Layers": layers}}]
                        ).encode()
                    if arguments[0] == "create":
                        return ("c" * 64).encode()
                    if arguments[:2] == ("container", "inspect"):
                        return json.dumps(
                            [
                                {
                                    "Id": "c" * 64,
                                    "Name": "/aragorn-runtime-response-check-"
                                    + "a" * 16,
                                    "Image": subject._IMAGE,
                                    "Config": {
                                        "Labels": {
                                            "dev.aragorn.snapshot-owner": "a" * 64
                                        }
                                    },
                                    "HostConfig": {"NetworkMode": "none"},
                                    "Mounts": [
                                        {
                                            "Destination": "/runtime",
                                            "Name": parent["runtime_volume"],
                                            "RW": False,
                                        }
                                    ],
                                }
                            ]
                        ).encode()
                    if arguments[0] == "exec" and any(
                        item.endswith("prepare_runtime_response_systemd_check.py")
                        for item in arguments
                    ):
                        self.assertEqual(arguments[-1] == "--dispatch", dispatch)
                        result = deepcopy(observation)
                        if failure == "claim":
                            result["check"]["phase3_eligible"] = True
                        return subject.campaign._canonical(result) + b"\n"
                    return b""

                with (
                    patch.object(
                        subject.existing,
                        "_source_identity",
                        return_value={"commit": "b" * 40},
                    ),
                    patch.object(
                        subject.existing.acquisition,
                        "_tree_file",
                        return_value={"bytes": 1, "digest": "test"},
                    ),
                    patch.object(subject.secrets, "token_hex", return_value="a" * 64),
                    patch.object(
                        subject.parent_snapshot,
                        "snapshot_parent",
                        side_effect=[before, after],
                    ),
                    patch.object(
                        subject.parent_snapshot,
                        "_cleanup_snapshot",
                        return_value={"container_name_absent": True},
                    ) as cleanup,
                    patch.object(subject, "_docker", side_effect=docker),
                ):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            subject._capture(dispatch=dispatch)
                    else:
                        result = subject._capture(dispatch=dispatch)
                        self.assertEqual(result["observation"], observation)
                        self.assertFalse(result["phase3_eligible"])
                        self.assertEqual(
                            set(result["response_overlay"]),
                            set(subject._OVERLAY)
                            | (set(subject._DISPATCH_OVERLAY) if dispatch else set()),
                        )
                    cleanup.assert_called_once_with(
                        "aragorn-runtime-response-check-" + "a" * 16,
                        "a" * 64,
                        subject._IMAGE,
                    )


if __name__ == "__main__":
    unittest.main()
