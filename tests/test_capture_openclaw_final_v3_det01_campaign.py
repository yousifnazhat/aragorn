from __future__ import annotations

import base64
import json
import tempfile
import unittest
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from aragorn.cas import CAS, CASError
from scripts import capture_openclaw_final_v3_det01_campaign as subject


class Det01CampaignCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(
            self.stack.enter_context(tempfile.TemporaryDirectory())
        ).resolve()
        self.cas = CAS(self.directory / "cas")
        self.contract = subject.campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="a" * 64
        )
        self.request = subject.campaign.build_openclaw_final_v3_subfixture_request(
            self.contract, "DET-01"
        )
        self.native_raw = (
            subject._ROOT / subject.checks._EVIDENCE["path"]
        ).read_bytes()
        self.native = json.loads(self.native_raw)
        self.source = {"commit": "1" * 40, "tree": "2" * 40, "files": []}
        self.parent = {
            "image_inspect": {"Id": "fixed"},
            "volume_inspect": {"Name": "fixed"},
            "content": {
                "runtime_tree_before": {"digest": "fixed"},
                "runtime_tree_after": {"digest": "fixed"},
                "contract_files": {},
            },
        }
        self.invoked_outputs = []

        def invoke(path: Path) -> dict:
            self.invoked_outputs.append(path)
            path.write_bytes(self.native_raw)
            return {"exit_code": 0, "argv": ["/bin/sh", subject._RECIPE]}

        self.source_mock = self.stack.enter_context(
            patch.object(subject, "_source_identity", return_value=self.source)
        )
        self.namespace = self.stack.enter_context(
            patch.object(
                subject,
                "_namespace_state",
                return_value={"containers": [], "volumes": []},
            )
        )
        self.invoke = self.stack.enter_context(
            patch.object(subject, "_invoke", side_effect=invoke)
        )
        self.verify = self.stack.enter_context(
            patch.object(subject, "_verify_capture", return_value=self.native)
        )
        self.cleanup = self.stack.enter_context(
            patch.object(
                subject,
                "_verify_cleanup",
                return_value={"container_absent": True, "volume_absent": True},
            )
        )
        self.snapshot = self.stack.enter_context(
            patch.object(subject.snapshot, "snapshot_parent", return_value=self.parent)
        )
        self.put = self.stack.enter_context(
            patch.object(self.cas, "put_expected", wraps=self.cas.put_expected)
        )
        self.stack.enter_context(
            patch.object(
                subject.acquisition,
                "_run",
                side_effect=AssertionError("Docker forbidden"),
            )
        )

    def capture(self, request: dict | None = None) -> dict:
        return subject.capture_det01(
            self.contract,
            self.request if request is None else request,
            evidence_cas=self.cas,
        )

    def test_exact_observed_result_is_retained_read_back_and_wrapper_only(self) -> None:
        captured = self.capture()
        document, result = captured["document"], captured["result"]
        raw = subject._canonical(document) + b"\n"
        digest = subject._digest(raw)
        self.assertEqual(
            result,
            {
                "case_id": "DET-01",
                "fixture_id": self.request["case"]["fixture_id"],
                "parent_identity_digest": self.request["frozen_parent"]["digest"],
                "fresh": True,
                "destroyed": True,
                "outcome": "OBSERVED",
                "evidence_refs": [digest],
            },
        )
        self.assertEqual(self.cas.read(digest, max_bytes=subject._MAX_BYTES), raw)
        self.assertEqual(document["request_binding"]["request"], self.request)
        self.assertEqual(
            document["campaign_binding"],
            {
                "nonce": "a" * 64,
                "fixture_id": "a" * 64 + "-00",
                "association": "HOST_WRAPPER_INVOCATION_NOT_COLLECTOR_NONCE_OBSERVATION",
            },
        )
        self.assertTrue(
            all(
                value is False
                for key, value in document["decision"].items()
                if key.endswith("_eligible")
            )
        )
        self.assertNotEqual(document["decision"]["status"], "PASS")
        self.assertIn(
            "ONE_CASE_ONLY_NOT_31_CASE_CAMPAIGN_EXECUTION_OR_RESUME",
            document["limitations"],
        )
        self.assertTrue(all(not path.parent.exists() for path in self.invoked_outputs))
        self.invoke.assert_called_once()
        self.cleanup.assert_called_once()
        self.put.assert_called_once()

    def test_invalid_or_coherently_substituted_request_prevents_effects(self) -> None:
        changed = deepcopy(self.request)
        changed["case"]["ordinal"] = False
        other = subject.campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="b" * 64
        )
        coherent = subject.campaign.build_openclaw_final_v3_subfixture_request(
            other, "DET-01"
        )
        for request in (changed, coherent):
            with (
                self.subTest(request=request["campaign_nonce"]),
                self.assertRaises(subject.CaptureError),
            ):
                self.capture(request)
        self.source_mock.assert_not_called()
        self.snapshot.assert_not_called()
        self.invoke.assert_not_called()
        self.put.assert_not_called()

    def test_failure_seams_never_publish_cas_success(self) -> None:
        for target, name in (
            (subject, "_source_identity"),
            (subject, "_invoke"),
            (subject, "_verify_capture"),
            (subject, "_verify_cleanup"),
            (subject.snapshot, "snapshot_parent"),
        ):
            with (
                self.subTest(name=name),
                patch.object(target, name, side_effect=subject.CaptureError(name)),
            ):
                with self.assertRaises(subject.CaptureError):
                    self.capture()
                self.put.assert_not_called()
        with (
            patch.object(
                subject.binding,
                "bind_openclaw_final_v3_det01_request",
                side_effect=subject.campaign.CampaignContractError("binding"),
            ),
            self.assertRaises(subject.campaign.CampaignContractError),
        ):
            self.capture()
        self.put.assert_not_called()

    def test_parent_or_signed_source_drift_prevents_publication(self) -> None:
        for field in (
            "image_inspect",
            "volume_inspect",
            "runtime_tree_after",
            "contract_files",
        ):
            after = deepcopy(self.parent)
            target = after if field in after else after["content"]
            target[field] = (
                {"configuration": {"content_base64": "changed"}}
                if field == "contract_files"
                else {"changed": True}
            )
            with (
                self.subTest(field=field),
                patch.object(
                    subject.snapshot,
                    "snapshot_parent",
                    side_effect=[self.parent, after],
                ),
            ):
                with self.assertRaises(subject.CaptureError):
                    self.capture()
                self.put.assert_not_called()
        with (
            patch.object(
                subject,
                "_source_identity",
                side_effect=[self.source, {**self.source, "commit": "3" * 40}],
            ),
            self.assertRaises(subject.CaptureError),
        ):
            self.capture()
        self.put.assert_not_called()

    def test_cas_write_or_readback_failure_returns_no_success(self) -> None:
        with (
            patch.object(self.cas, "put_expected", side_effect=CASError("unavailable")),
            self.assertRaises(CASError),
        ):
            self.capture()
        with (
            patch.object(self.cas, "read", return_value=b"changed"),
            self.assertRaises(subject.CaptureError),
        ):
            self.capture()
        self.put.assert_called_once()


class Det01CaptureAndParentValidationTests(unittest.TestCase):
    def test_parent_snapshot_timeout_cleans_only_the_owned_container(self) -> None:
        snapshot = subject.snapshot
        parent = subject.campaign.current_v3_parent_identity()
        owner = "a" * 64
        name = "aragorn-v3-parent-snapshot-" + owner[:32]
        container = "b" * 64
        inspected = {
            "Id": container,
            "Name": "/" + name,
            "Image": parent["image_id"],
            "Config": {
                "Image": parent["image_id"],
                "Labels": {"dev.aragorn.snapshot-owner": owner},
            },
        }
        image = {
            "Id": parent["image_id"],
            "RootFS": {"Type": "layers", "Layers": ["fixed"]},
        }
        responses = [
            subject._canonical([image]),
            subject._canonical([subject.acquisition._EXPECTED_VOLUME]),
            b"",
            subject.subprocess.TimeoutExpired("docker", 120),
            (container + "\n").encode(),
            subject._canonical([inspected]),
            b"",
            b"29\n",
            b"",
            b"",
        ]
        with (
            patch.object(snapshot.secrets, "token_hex", return_value=owner),
            patch.object(subject.acquisition, "_run", side_effect=responses) as run,
        ):
            with self.assertRaises(subject.subprocess.TimeoutExpired):
                snapshot.snapshot_parent(parent)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(
                commands.count(
                    [
                        *subject.acquisition._DOCKER,
                        "container",
                        "rm",
                        "--force",
                        container,
                    ]
                ),
                1,
            )
            self.assertIn("id=" + container, commands[-1])
        for field in ("owner", "name", "image"):
            changed = deepcopy(inspected)
            if field == "owner":
                changed["Config"]["Labels"]["dev.aragorn.snapshot-owner"] = "c" * 64
            else:
                changed["Name" if field == "name" else "Image"] = "unrelated"
            with (
                self.subTest(field=field),
                patch.object(
                    subject.acquisition,
                    "_run",
                    side_effect=[
                        (container + "\n").encode(),
                        subject._canonical([changed]),
                    ],
                ) as run,
            ):
                with self.assertRaises(subject.campaign.CampaignContractError):
                    snapshot._cleanup_snapshot(name, owner, parent["image_id"])
                self.assertFalse(
                    any("rm" in call.args[0] for call in run.call_args_list)
                )
        with (
            patch.object(
                subject.acquisition,
                "_run",
                side_effect=[b"", subject.CaptureError("daemon unavailable")],
            ),
            self.assertRaises(subject.CaptureError),
        ):
            snapshot._cleanup_snapshot(name, owner, parent["image_id"])

    def test_retained_native_capture_recomputes_and_rejects_source_or_argv_drift(
        self,
    ) -> None:
        contract = subject.campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="a" * 64
        )
        request = subject.campaign.build_openclaw_final_v3_subfixture_request(
            contract, "DET-01"
        )
        raw = (subject._ROOT / subject.checks._EVIDENCE["path"]).read_bytes()
        native = json.loads(raw)
        artifacts = native["source_artifacts"]
        records = [
            artifacts[name] for name in ("capture_recipe", "collector", "dockerfile")
        ] + artifacts["pinned_sources"]
        source = {
            "commit": native["harness"]["document"]["source_commit"],
            "files": [
                {
                    "path": item["path"].removeprefix("/src/"),
                    "bytes": item["bytes"],
                    "digest": item["digest"],
                    "mode": "100755" if item["stat"]["mode"] == "0555" else "100644",
                }
                for item in records
            ],
        }
        invocation = {
            "started_at": "2026-09-03T18:27:27Z",
            "completed_at": "2026-09-03T18:27:31Z",
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            bundle = directory / "bundle"
            subject.materializer.materialize_openclaw_final_v3_det01(bundle)
            bound = subject.binding.bind_openclaw_final_v3_det01_request(
                contract, request, bundle_root=bundle
            )
            with patch.object(
                subject.acquisition,
                "_run",
                side_effect=AssertionError("Docker forbidden"),
            ):
                self.assertEqual(
                    subject._verify_capture(raw, source, bound, invocation, directory),
                    native,
                )
                changed = deepcopy(bound)
                changed["descriptor"]["argv"][1] = "/tmp/unrelated.py"
                with self.assertRaises(subject.CaptureError):
                    subject._verify_capture(raw, source, changed, invocation, directory)
                with self.assertRaises(subject.CaptureError):
                    subject._verify_capture(
                        raw,
                        {**source, "commit": "0" * 40},
                        bound,
                        invocation,
                        directory,
                    )

    def test_parent_content_uses_real_contract_bytes_and_rejects_changes(self) -> None:
        snapshot = subject.snapshot
        parent = subject.campaign.current_v3_parent_identity()
        content = {
            "helper": subject.acquisition._helper_input()[1],
            "runtime_tree_before": deepcopy(subject.acquisition._RUNTIME_TREE),
            "runtime_tree_after": deepcopy(subject.acquisition._RUNTIME_TREE),
            "mount": {
                "path": "/runtime",
                "ready": True,
                "read_only": True,
                "explicit": True,
                "error": None,
                "records": [{"mount_point": "/runtime", "mount_options": ["ro"]}],
            },
            "contract_files": {},
        }
        for ordinal, (name, (filename, size, digest)) in enumerate(
            snapshot._CONTRACT_FILES.items(), 1
        ):
            raw = (
                subject._ROOT / "benchmark/admission/openclaw-v2026.7.1" / filename
            ).read_bytes()
            metadata = {
                "device": 1,
                "inode": ordinal,
                "uid": 0,
                "gid": 0,
                "mode": "0444",
                "nlink": 1,
                "type": "file",
                "size": size,
            }
            content["contract_files"][name] = {
                "path": snapshot._SOURCE_ROOT + filename,
                "bytes": size,
                "digest": digest,
                "content_base64": base64.b64encode(raw).decode(),
                "stat_before": metadata,
                "stat_after": dict(metadata),
            }
        snapshot._validate_content(content, parent)
        for mutation in ("configuration", "runtime_tree", "mount"):
            changed = deepcopy(content)
            if mutation == "configuration":
                record = changed["contract_files"]["configuration"]
                raw = base64.b64decode(record["content_base64"])
                record["content_base64"] = base64.b64encode(b"[" + raw[1:]).decode()
            elif mutation == "runtime_tree":
                for key in ("runtime_tree_before", "runtime_tree_after"):
                    changed[key]["tree_digest"] = "sha256:" + "0" * 64
            else:
                changed["mount"]["records"][0]["mount_options"] = ["rw"]
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(subject.campaign.CampaignContractError),
            ):
                snapshot._validate_content(changed, parent)


if __name__ == "__main__":
    unittest.main()
