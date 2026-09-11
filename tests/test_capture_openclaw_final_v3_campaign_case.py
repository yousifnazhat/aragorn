from __future__ import annotations

import hashlib
import json
import os
import unittest
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import admission_openclaw_final_v3_core_updater_qualification as retained
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_openclaw_final_v3_campaign_dispatch import (
    dispatch_openclaw_final_v3_campaign_case,
)
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_json
from scripts import capture_openclaw_final_v3_campaign_case as subject
from scripts import openclaw_final_v3_core_updater_case as core

_ROOT = Path(__file__).resolve().parents[1]
_CORE = "ADM-02/update/core-updater-plugin-replacement"


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _historical_source() -> dict:
    files = []
    for source_path in sorted(core._SOURCE_PATHS):
        path = str(source_path).removeprefix("/src/")
        entry = retained._git(["ls-tree", "-z", retained._SOURCE["commit"], "--", path])
        metadata, name = entry[:-1].split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        if name.decode() != path or kind != "blob":
            raise AssertionError("historical source fixture changed")
        raw = retained._git(["cat-file", "blob", blob])
        files.append(
            {
                "path": path,
                "mode": mode,
                "blob": blob,
                "bytes": len(raw),
                "digest": _digest(raw),
            }
        )
    return {**retained._SOURCE, "files": files}


class CampaignCaseExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(TemporaryDirectory())).resolve()
        self.cas = CAS(self.directory / "cas")
        self.contract = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="a" * 64
        )
        self.request = campaign.build_openclaw_final_v3_subfixture_request(
            self.contract, _CORE
        )
        self.source = {"commit": "1" * 40, "tree": "2" * 40, "files": []}
        self.parent = {
            "image_inspect": {"Id": "fixed"},
            "volume_inspect": {"Name": "fixed"},
            "content": {
                "runtime_tree_before": {"digest": "fixed"},
                "runtime_tree_after": {"digest": "fixed"},
                "contract_files": {"configuration": {"content_base64": "e30K"}},
            },
        }
        self.harness = {
            "container_id": "c" * 64,
            "route_input_volume_identity": {
                "name": subject._PREFIX + "-route-input-42",
            },
        }
        self.events = []
        self.outputs = []
        self.actual_source = subject._source_identity
        self.actual_namespace = subject._namespace_state
        self.actual_cleanup = subject._verify_cleanup
        self.actual_read = subject._read_output
        self.actual_invoke = subject._invoke

        def event(name, value):
            def observe(*_args, **_kwargs):
                self.events.append(name)
                return deepcopy(value)

            return observe

        def invoke(output, *, case_id=_CORE):
            self.events.append("invoke")
            self.outputs.append(output)
            output.write_bytes(b"{}\n")
            backend, _ = subject._BACKENDS[case_id]
            return {"argv": ["/bin/sh", backend._RECIPE], "exit_code": 0}

        original_put = self.cas.put_expected

        def put(stream, **kwargs):
            self.assertEqual(self.events[-1], "source")
            self.assertIn("cleanup", self.events)
            self.assertTrue(all(not path.parent.exists() for path in self.outputs))
            self.events.append("publish")
            return original_put(stream, **kwargs)

        self.source_mock = self.stack.enter_context(
            patch.object(
                subject, "_source_identity", side_effect=event("source", self.source)
            )
        )
        self.prepare = self.stack.enter_context(
            patch.object(
                core,
                "prepare_case",
                side_effect=event(
                    "prepare",
                    {
                        "contract": self.contract,
                        "request": self.request,
                        "decision": {"phase3_exit_eligible": False},
                    },
                ),
            )
        )
        self.snapshot = self.stack.enter_context(
            patch.object(
                subject.det01.snapshot,
                "snapshot_parent",
                side_effect=event("parent", self.parent),
            )
        )
        self.namespace = self.stack.enter_context(
            patch.object(
                subject,
                "_namespace_state",
                side_effect=event("namespace", {"containers": [], "volumes": []}),
            )
        )
        self.invoke = self.stack.enter_context(
            patch.object(subject, "_invoke", side_effect=invoke)
        )
        self.verify = self.stack.enter_context(
            patch.object(
                core,
                "verify_capture",
                side_effect=event(
                    "verify",
                    {
                        "harness": self.harness,
                        "proof": {"observed": True},
                    },
                ),
            )
        )
        self.cleanup = self.stack.enter_context(
            patch.object(
                subject,
                "_verify_cleanup",
                side_effect=event(
                    "cleanup",
                    {
                        "container_absent": True,
                        "volume_absent": True,
                    },
                ),
            )
        )
        self.put = self.stack.enter_context(
            patch.object(self.cas, "put_expected", side_effect=put)
        )
        self.stack.enter_context(
            patch.object(
                subject.det01.acquisition,
                "_run",
                side_effect=AssertionError("Docker forbidden"),
            )
        )

    def capture(self):
        return subject.capture_case(self.contract, _CORE, evidence_cas=self.cas)

    def test_observed_core_result_publishes_only_after_cleanup_and_revalidation(
        self,
    ) -> None:
        captured = self.capture()
        self.assertEqual(
            self.events,
            [
                "source",
                "prepare",
                "parent",
                "namespace",
                "invoke",
                "verify",
                "cleanup",
                "namespace",
                "parent",
                "source",
                "publish",
            ],
        )
        document, result = captured["document"], captured["result"]
        self.assertEqual(document["request"], self.request)
        self.assertEqual(
            result,
            {
                "case_id": _CORE,
                "fixture_id": self.request["case"]["fixture_id"],
                "parent_identity_digest": self.request["frozen_parent"]["digest"],
                "fresh": True,
                "destroyed": True,
                "outcome": "OBSERVED",
                "evidence_refs": [_digest(canonical_json(document) + b"\n")],
            },
        )
        self.assertNotEqual(document["decision"]["status"], "PASS")
        self.assertTrue(
            all(
                value is False
                for key, value in document["decision"].items()
                if key.endswith("_eligible")
            )
        )
        self.assertIn(
            "CAMPAIGN_NONCE_HOST_ASSOCIATED_NOT_NATIVE_COLLECTOR_ECHOED",
            document["limitations"],
        )
        self.assertIn(
            "CAPTURE_SIDE_SEMANTIC_CHECKS_NOT_INDEPENDENT_QUALIFICATION",
            document["limitations"],
        )
        self.assertEqual(
            self.cas.read(result["evidence_refs"][0], max_bytes=subject._MAX_BYTES),
            canonical_json(document) + b"\n",
        )
        self.put.assert_called_once()

    def test_unsupported_or_changed_contract_rejects_before_effects(self) -> None:
        for case in ("ADM-02/direct-write", "UNKNOWN", True):
            with self.subTest(case=case), self.assertRaises(subject.CaptureError):
                subject.capture_case(self.contract, case, evidence_cas=self.cas)
        changed = deepcopy(self.contract)
        changed["decision"]["phase3_exit_eligible"] = True
        with self.assertRaises(campaign.CampaignContractError):
            subject.capture_case(changed, _CORE, evidence_cas=self.cas)
        self.assertEqual(self.events, [])
        self.put.assert_not_called()

    def test_workshop_selects_only_its_backend_and_cleanup_namespace(self) -> None:
        self._check_selected_backend(subject._WORKSHOP_CASE, subject.workshop)

    def test_proposal_selects_only_its_backend_and_cleanup_namespace(self) -> None:
        self._check_selected_backend(
            "ADM-02/update/workshop-proposal-apply", subject.proposal
        )

    def _check_selected_backend(self, case, backend) -> None:
        request = campaign.build_openclaw_final_v3_subfixture_request(
            self.contract, case
        )
        with (
            patch.object(
                backend, "prepare_case", return_value={"request": request}
            ) as prepare,
            patch.object(
                backend,
                "verify_capture",
                return_value={"harness": self.harness, "proof": {"observed": True}},
            ) as verify,
        ):
            captured = subject.capture_case(self.contract, case, evidence_cas=self.cas)
        self.prepare.assert_not_called()
        self.verify.assert_not_called()
        self.assertEqual(prepare.call_args.args, (self.contract, request))
        self.assertEqual(verify.call_args.kwargs["source"], self.source)
        self.assertEqual(captured["document"]["request"], request)
        self.assertEqual(captured["result"]["case_id"], case)
        self.assertEqual(captured["result"]["outcome"], "OBSERVED")
        self.assertEqual(self.invoke.call_args.kwargs, {"case_id": case})
        self.assertEqual(self.cleanup.call_args.kwargs, {"case_id": case})
        self.assertTrue(
            all(
                call.kwargs == {"case_id": case}
                for call in self.namespace.call_args_list
            )
        )
        self.put.assert_called_once()

    def test_curator_selects_only_its_backend_and_cleanup_namespace(self) -> None:
        self._check_selected_backend(
            "ADM-02/update/curator-restore-activation", subject.curator
        )

    def test_native_recipe_and_resource_namespaces_are_case_specific(self) -> None:
        for case, (backend, stem) in subject._BACKENDS.items():
            with self.subTest(case=case):
                with patch.object(subject.det01.acquisition, "_run", return_value=b""):
                    state = self.actual_namespace(case_id=case)
                self.assertEqual(
                    state["commands"]["containers"][-1],
                    "name=^/aragorn-phase3-final-combined-v3-" + stem + "-[0-9]+$",
                )
                self.assertEqual(
                    state["commands"]["volumes"][-1],
                    "label=dev.aragorn.role=final-combined-v3-" + stem + "-route-input",
                )
                with patch.object(subject.subprocess, "Popen") as launch:
                    launch.return_value.returncode = 0
                    observation = self.actual_invoke(
                        self.directory / "native.json", case_id=case
                    )
                self.assertEqual(observation["argv"][1], str(_ROOT / backend._RECIPE))
                self.assertEqual(launch.call_args.args[0], observation["argv"])

    def test_config_entry_selects_only_its_backend_and_cleanup_namespace(self) -> None:
        self._check_selected_backend(
            "ADM-02/update/config-entry-activation", subject.config_entry
        )

    def test_plugin_enable_selects_only_its_backend_and_cleanup_namespace(self) -> None:
        self._check_selected_backend(
            "ADM-02/update/plugin-enable-activation", subject.plugin_enable
        )

    def test_fresh_session_selects_only_its_backend_and_cleanup_namespace(self) -> None:
        self._check_selected_backend(
            "ADM-02/reload/fresh-session-reset", subject.fresh_session
        )

    def test_det01_delegates_only_the_exact_contract_request_and_cas(self) -> None:
        expected = campaign.build_openclaw_final_v3_subfixture_request(
            self.contract, "DET-01"
        )
        with patch.object(
            subject.det01, "capture_det01", return_value={"delegated": True}
        ) as delegated:
            self.assertEqual(
                subject.capture_case(self.contract, "DET-01", evidence_cas=self.cas),
                {"delegated": True},
            )
        delegated.assert_called_once_with(
            self.contract, expected, evidence_cas=self.cas
        )
        self.assertEqual(self.events, [])

    def test_failed_capture_seams_never_publish_and_post_execution_checks_run(
        self,
    ) -> None:
        for target, name in (
            (subject, "_source_identity"),
            (core, "prepare_case"),
            (subject.det01.snapshot, "snapshot_parent"),
            (subject, "_namespace_state"),
            (subject, "_invoke"),
            (subject, "_read_output"),
            (core, "verify_capture"),
            (subject, "_verify_cleanup"),
        ):
            self.events.clear()
            with (
                self.subTest(name=name),
                patch.object(target, name, side_effect=subject.CaptureError(name)),
                self.assertRaises(subject.CaptureError),
            ):
                self.capture()
            self.put.assert_not_called()
            if name in {"_invoke", "_read_output", "verify_capture", "_verify_cleanup"}:
                self.assertEqual(self.events[-1], "namespace")

    def test_parent_and_source_drift_prevent_publication(self) -> None:
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
                    subject.det01.snapshot,
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

    def test_cas_failure_or_changed_readback_returns_no_success(self) -> None:
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

    def test_namespace_and_cleanup_reject_leftovers_bad_identity_or_daemon_loss(
        self,
    ) -> None:
        run = subject.det01.acquisition
        for outputs in ([b"foreign\n", b""], [b"", b"foreign-volume\n"]):
            with (
                self.subTest(namespace=outputs),
                patch.object(run, "_run", side_effect=outputs),
                self.assertRaises(subject.CaptureError),
            ):
                self.actual_namespace()
        volume = self.harness["route_input_volume_identity"]["name"]
        for outputs in (
            [b"leftover\n", b"", b"29\n"],
            [b"", (volume + "\n").encode(), b"29\n"],
            [b"", b"", b""],
        ):
            with (
                self.subTest(cleanup=outputs),
                patch.object(run, "_run", side_effect=outputs),
                self.assertRaises(subject.CaptureError),
            ):
                self.actual_cleanup(self.harness)
        for field in ("container", "volume"):
            changed = deepcopy(self.harness)
            if field == "container":
                changed["container_id"] = "unrelated"
            else:
                changed["route_input_volume_identity"]["name"] = "unrelated"
            with self.subTest(identity=field), patch.object(run, "_run") as calls:
                with self.assertRaises(subject.CaptureError):
                    self.actual_cleanup(changed)
                calls.assert_not_called()

    def test_dirty_source_rejects_before_signature_or_execution(self) -> None:
        shared = subject.det01.acquisition.shared
        with (
            patch.object(
                shared,
                "_git",
                side_effect=[str(_ROOT).encode(), b"sha1", b"?? dirty.py\n"],
            ),
            patch.object(shared, "_verify_signature") as signature,
        ):
            with self.assertRaises(subject.CaptureError):
                self.actual_source()
            signature.assert_not_called()
        self.invoke.assert_not_called()
        self.put.assert_not_called()

    def test_output_fifo_or_symlink_is_rejected_without_blocking(self) -> None:
        fifo = self.directory / "output.fifo"
        os.mkfifo(fifo)
        original_open = os.open

        def nonblocking_open(path, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertTrue(flags & os.O_NOFOLLOW)
            return original_open(path, flags, *args, **kwargs)

        with (
            patch.object(subject.os, "open", side_effect=nonblocking_open),
            self.assertRaises(subject.CaptureError),
        ):
            self.actual_read(fifo)
        target = self.directory / "target.json"
        target.write_bytes(b"{}\n")
        symlink = self.directory / "output.json"
        symlink.symlink_to(target)
        with self.assertRaises((OSError, subject.CaptureError)):
            self.actual_read(symlink)


class CoreCasePreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="a" * 64
        )
        cls.request = campaign.build_openclaw_final_v3_subfixture_request(
            cls.contract, _CORE
        )
        cls.raw = (_ROOT / retained._EVIDENCE["path"]).read_bytes()
        cls.native = json.loads(cls.raw)

    def test_core_prepare_binds_exact_request_dispatch_and_six_files(self) -> None:
        with TemporaryDirectory() as temporary:
            prepared = core.prepare_case(
                self.contract, self.request, directory=Path(temporary).resolve()
            )
            self.assertEqual(prepared["contract"], self.contract)
            self.assertEqual(prepared["request"], self.request)
            self.assertEqual(
                prepared["descriptor"],
                dispatch_openclaw_final_v3_campaign_case(_CORE)["descriptor"],
            )
            self.assertEqual(len(prepared["bundle_files"]), 6)
            self.assertTrue(prepared["source_files"])
            self.assertTrue(prepared["path_mapping"])
            self.assertTrue(
                all(
                    value is False
                    for key, value in prepared["decision"].items()
                    if key.endswith("_eligible")
                )
            )

    def test_core_prepare_rejects_substituted_requests_before_materializing(
        self,
    ) -> None:
        coherent = campaign.build_openclaw_final_v3_subfixture_request(
            campaign.build_openclaw_final_v3_campaign_contract(campaign_nonce="b" * 64),
            _CORE,
        )
        malformed = deepcopy(self.request)
        malformed["case"]["ordinal"] = True
        for request in (coherent, malformed):
            with (
                self.subTest(nonce=request["campaign_nonce"]),
                TemporaryDirectory() as temporary,
            ):
                directory = Path(temporary).resolve()
                with self.assertRaises(
                    (AdmissionEvidenceError, campaign.CampaignContractError)
                ):
                    core.prepare_case(self.contract, request, directory=directory)
                self.assertEqual(list(directory.iterdir()), [])

    def test_core_retained_raw_joins_and_rejects_source_argv_or_bundle_drift(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            prepared = core.prepare_case(
                self.contract, self.request, directory=directory
            )
            source = _historical_source()
            invocation = {
                "argv": [
                    "/bin/sh",
                    str(_ROOT / core._RECIPE),
                    str(directory / "native.json"),
                ],
                "started_at": "2026-09-03T00:00:00Z",
                "completed_at": "2026-09-04T00:00:00Z",
                "exit_code": 0,
            }
            observed = core.verify_capture(
                self.raw, prepared, source=source, invocation=invocation
            )
            self.assertEqual(observed["native_capture"], self.native)
            self.assertEqual(observed["harness"], self.native["harness"]["document"])
            self.assertTrue(
                all(
                    value is False
                    for key, value in observed["decision"].items()
                    if key.endswith("_eligible")
                )
            )
            for mutation in (
                "source",
                "source_bytes",
                "argv",
                "bundle",
                "boolean_exit",
                "mapping",
            ):
                native = deepcopy(self.native)
                changed_source = deepcopy(source)
                changed_prepared = deepcopy(prepared)
                if mutation == "source":
                    changed_source["commit"] = "0" * 40
                elif mutation == "source_bytes":
                    changed_source["files"][0]["digest"] = "sha256:" + "0" * 64
                elif mutation == "argv":
                    native["route_observation"]["execution"]["argv"][-3] = (
                        "/tmp/unbound.mjs"
                    )
                elif mutation == "bundle":
                    native["route_observation"]["bundle"][0]["digest"] = (
                        "sha256:" + "0" * 64
                    )
                elif mutation == "boolean_exit":
                    native["route_observation"]["execution"]["exit_code"] = False
                else:
                    changed_prepared["path_mapping"]["native_probe_argv"][1] = (
                        "/tmp/unbound.mjs"
                    )
                with (
                    self.subTest(mutation=mutation),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    core.verify_capture(
                        canonical_json(native) + b"\n",
                        changed_prepared,
                        source=changed_source,
                        invocation=invocation,
                    )


if __name__ == "__main__":
    unittest.main()
