from __future__ import annotations

import base64
import json
import stat
import subprocess
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import openclaw_final_v3_workshop_proposal_apply_case as subject
from tests.test_admission_openclaw_final_v3_workshop_proposal_apply_subfixture import (
    _fresh_document,
    _refresh_commands,
)

_ROOT = Path(__file__).resolve().parents[1]


def _sync_route(native: dict) -> None:
    route = native["route_observation"]
    document = route["document"]
    raw = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()
    route["raw"] = {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "canonical_digest": canonical_digest(document),
        "digest": subject.old._digest(raw),
        "raw_is_canonical_json_lf": False,
    }
    route["route"] = deepcopy(document["routes"][0])


def _sync_harness(native: dict) -> None:
    harness = native["harness"]
    raw = canonical_json(harness["document"])
    harness["digest"] = subject.old._digest(raw)
    harness["file"].update(
        base64=base64.b64encode(raw).decode(),
        bytes=len(raw),
        digest=harness["digest"],
    )
    harness["file"]["stat"]["size"] = len(raw)
    native["composition"]["action"]["harness"] = deepcopy(harness)


class WorkshopProposalApplyCaseTests(unittest.TestCase):
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
        cls.source = {
            **subject.old._SOURCE,
            "files": subject.checks.historical_sources(
                subject.old._SOURCE, subject.SOURCE_PATHS
            ),
        }
        cls.raw = (_ROOT / subject.old._EVIDENCE["path"]).read_bytes()
        cls.native = json.loads(cls.raw)
        # Historical input exercises the verifier; these are not fresh capture times.
        cls.invocation = {
            "argv": [
                "/bin/sh",
                str(_ROOT / subject._RECIPE),
                str(cls.directory / "native.json"),
            ],
            "exit_code": 0,
            "started_at": "2026-08-28T00:00:00Z",
            "completed_at": "2026-08-29T00:00:00Z",
        }

    def verify(self, native: dict) -> dict:
        return subject.verify_capture(
            canonical_json(native) + b"\n",
            self.prepared,
            source=self.source,
            invocation=self.invocation,
        )

    def test_preparation_binds_exact_two_files_and_signed_source_closure(self) -> None:
        self.assertEqual(subject._CASE, "ADM-02/update/workshop-proposal-apply")
        self.assertEqual(self.prepared["request"], self.request)
        self.assertIsNone(self.prepared["descriptor"]["materializer"])
        self.assertEqual(self.prepared["bundle_files"], subject.old._PROBES)
        expected_paths = {
            subject.old._SOURCE_ARTIFACTS[name]["path"]
            for name in subject.old._SIGNED_SOURCE_ARTIFACTS
        } | {item["path"] for item in subject.old._COLLECTOR_ARTIFACTS.values()}
        self.assertEqual(set(subject.SOURCE_PATHS), expected_paths)
        self.assertEqual(self.prepared["source_files"], self.source["files"])
        mapping = self.prepared["path_mapping"]
        self.assertIs(mapping["literal_dispatch_argv_equality"], False)
        self.assertEqual(len(mapping["files"]), 2)
        bundle = self.directory / "bundle"
        self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o555)
        self.assertEqual(
            {path.name for path in bundle.iterdir()},
            {"PROPOSAL.md", "protected-route-probe.mjs"},
        )
        for item, mapped in zip(subject.old._PROBES, mapping["files"], strict=True):
            path = bundle / item["name"]
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            self.assertEqual(len(path.read_bytes()), item["bytes"])
            self.assertEqual(subject.old._digest(path.read_bytes()), item["digest"])
            self.assertEqual(
                mapped["native"], mapping["native_root"] + "/" + item["name"]
            )
            self.assertEqual(
                mapped["provisional"], mapping["provisional_root"] + "/" + item["name"]
            )
            self.assertEqual(
                {key: mapped[key] for key in ("bytes", "digest", "role")},
                {key: item[key] for key in ("bytes", "digest", "role")},
            )

    def test_changed_request_is_rejected_before_materialization(self) -> None:
        for value in (True, 99, "14"):
            with self.subTest(ordinal=value), TemporaryDirectory() as temporary:
                changed = deepcopy(self.request)
                changed["case"]["ordinal"] = value
                directory = Path(temporary).resolve()
                with self.assertRaises(AdmissionEvidenceError):
                    subject.prepare_case(self.contract, changed, directory=directory)
                self.assertEqual(list(directory.iterdir()), [])

    def test_retained_input_is_regression_only_with_all_eligibility_false(self) -> None:
        self.assertEqual(subject.old._digest(self.raw), subject.old._EVIDENCE["digest"])
        result = subject.verify_capture(
            self.raw, self.prepared, source=self.source, invocation=self.invocation
        )
        self.assertEqual(result["native_capture"], self.native)
        self.assertEqual(result["harness"], self.native["harness"]["document"])
        self.assertEqual(
            result["proof"]["native_capture_digest"], subject.old._digest(self.raw)
        )
        self.assertEqual(
            result["proof"]["actual_native_argv"],
            self.native["route_observation"]["execution"]["argv"],
        )
        self.assertEqual(self.native["decision"]["route_pass_count"], 0)
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key.endswith("_eligible")
            )
        )
        self.assertIn(
            "NO_INDEPENDENT_ROUTE_OR_INHERITED_ACTIVATION_QUALIFICATION",
            result["proof"]["limitations"],
        )
        changed = deepcopy(self.native)
        _sync_route(changed)
        self.assertEqual(self.verify(changed)["native_capture"], changed)
        route = changed["route_observation"]
        raw = canonical_json(route["document"]) + b"\n"
        route["raw"].update(
            base64=base64.b64encode(raw).decode(),
            bytes=len(raw),
            digest=subject.old._digest(raw),
            raw_is_canonical_json_lf=True,
        )
        self.assertEqual(self.verify(changed)["native_capture"], changed)
        route["raw"]["raw_is_canonical_json_lf"] = False
        with self.assertRaises(AdmissionEvidenceError):
            self.verify(changed)

    def test_rejects_preparation_source_and_raw_join_drift(self) -> None:
        for mutation in (
            "mapping",
            "source",
            "duplicate_source",
            "bundle",
            "raw",
            "raw_format_claim",
            "document",
            "route",
            "eligibility",
        ):
            with self.subTest(mutation=mutation):
                prepared, source, native = map(
                    deepcopy, (self.prepared, self.source, self.native)
                )
                route = native["route_observation"]
                if mutation == "mapping":
                    prepared["path_mapping"]["native_root"] = "/elsewhere"
                elif mutation == "source":
                    source["files"][0]["digest"] = "sha256:" + "0" * 64
                elif mutation == "duplicate_source":
                    source["files"].append(deepcopy(source["files"][0]))
                elif mutation == "bundle":
                    route["bundle"][0]["bytes"] += 1
                elif mutation == "raw":
                    route["raw"]["base64"] = base64.b64encode(b"{}").decode()
                elif mutation == "raw_format_claim":
                    route["raw"]["raw_is_canonical_json_lf"] = True
                elif mutation == "document":
                    route["document"]["run_nonce"] = "0" * 32
                elif mutation == "route":
                    route["route"]["status"] = "PASS"
                else:
                    native["decision"]["phase3_exit_eligible"] = True
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_capture(
                        canonical_json(native) + b"\n",
                        prepared,
                        source=source,
                        invocation=self.invocation,
                    )

    def test_synthetic_fresh_identity_joins_have_no_capture_authority(self) -> None:
        document = _fresh_document()
        gateway = document["actions"][0]["prerequisites"]["gateway_process"]
        old_host = self.native["harness"]["document"]
        old_pid = self.native["route_observation"]["gateway_pid_binding"]["pid"]
        old_ticks = self.native["route_observation"]["stack_before"]["processes"][
            "aragorn-agent-gateway.service"
        ]["start_time_ticks"]
        gateway["start_time_ticks"] = str(int(old_ticks) + 1)
        container = gateway["hostname"] + "0" * 52
        volume = (
            "aragorn-phase3-final-combined-v3-workshop-proposal-apply-route-input-90001"
        )
        replacements = {
            old_host["container_id"]: container,
            old_host["container_id"][:12]: gateway["hostname"],
            old_host["route_input_volume_identity"]["name"]: volume,
            f"/proc/{old_pid}/": f"/proc/{gateway['pid']}/",
            f"pid={old_pid} ;": f"pid={gateway['pid']} ;",
        }

        def remap(value):
            if type(value) is dict:
                return {key: remap(item) for key, item in value.items()}
            if type(value) is list:
                return [remap(item) for item in value]
            if type(value) is int and value == old_pid:
                return gateway["pid"]
            if type(value) is str:
                if value == str(old_pid):
                    return str(gateway["pid"])
                for old, new in replacements.items():
                    value = value.replace(old, new)
            return value

        native = remap(self.native)
        route, host = native["route_observation"], native["harness"]["document"]
        route["document"] = document
        document["actions"][0]["prerequisites"]["draft"]["mount"]["records"][0][
            "root"
        ] = f"/docker/volumes/{volume}/_data"
        for processes in (
            route["stack_before"]["processes"],
            native["composition"]["action"]["boundaries"]["processes"],
        ):
            processes["aragorn-agent-gateway.service"]["start_time_ticks"] = gateway[
                "start_time_ticks"
            ]
        for state in (
            route["stack_before"]["service_state"],
            native["composition"]["action"]["boundaries"]["service_state"],
        ):
            properties = state["units"]["aragorn-agent-gateway.service"]["properties"]
            start = int(gateway["start_time_ticks"]) * 10_000
            properties["ExecMainStartTimestampMonotonic"] = str(start)
            properties["ActiveEnterTimestampMonotonic"] = str(start + 1_000)
            for entry in state["units"].values():
                raw = "".join(
                    f"{key}={value}\n" for key, value in entry["properties"].items()
                ).encode()
                entry["command"]["stdout"] = {
                    "base64": base64.b64encode(raw).decode(),
                    "bytes": len(raw),
                    "digest": subject.old._digest(raw),
                }
        for record, keys in (
            (route["execution"], ("started_at", "completed_at")),
            (native["composition"], ("recorded_at",)),
            (native, ("recorded_at",)),
        ):
            for key in keys:
                record[key] = (
                    (datetime.fromisoformat(record[key]) + timedelta(days=1))
                    .isoformat()
                    .replace("+00:00", "Z")
                )
        git = subject.checks.old._git
        commit = git(["rev-parse", "HEAD"]).decode().strip()
        source = {
            "commit": commit,
            "parent": git(["rev-parse", commit + "^"]).decode().strip(),
            "tree": git(["rev-parse", commit + "^{tree}"]).decode().strip(),
            "files": self.source["files"],
        }
        host["source_commit"] = source["commit"]
        host["route_input_volume_identity"]["labels"].update(
            {
                "dev.aragorn.capture-owner": source["commit"] + ":90001",
                "dev.aragorn.source-commit": source["commit"],
            }
        )
        signature = host["source_commit_verification"]
        signature["command"] = ["git", "verify-commit", "--raw", source["commit"]]
        verified_commit = subprocess.run(
            signature["command"], cwd=_ROOT, check=True, capture_output=True
        )
        signature["exit_code"] = verified_commit.returncode
        for key, raw in (
            ("commit_object", git(["cat-file", "commit", source["commit"]])),
            ("stdout", verified_commit.stdout),
            ("stderr", verified_commit.stderr),
        ):
            signature[key] = {
                "base64": base64.b64encode(raw).decode(),
                "bytes": len(raw),
                "digest": subject.old._digest(raw),
            }
        _sync_harness(native)
        _sync_route(native)
        result = subject.verify_capture(
            canonical_json(native) + b"\n",
            self.prepared,
            source=source,
            invocation={
                **self.invocation,
                "started_at": "2026-08-29T00:00:00Z",
                "completed_at": "2026-08-30T00:00:00Z",
            },
        )
        self.assertEqual(result["native_capture"], native)
        self.assertEqual(result["proof"]["current_source_commit"], source["commit"])
        self.assertNotEqual(host["container_id"], old_host["container_id"])
        self.assertNotEqual(route["gateway_pid_binding"]["pid"], old_pid)
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key.endswith("_eligible")
            )
        )

    def test_rejects_coherently_reencoded_semantic_and_composition_drift(self) -> None:
        for mutation in (
            "residue",
            "command_join",
            "identities",
            "bindings",
            "profile",
            "artifact",
            "composition_decision",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                composition = native["composition"]
                if mutation == "residue":
                    observations = native["route_observation"]["document"]["actions"][
                        0
                    ]["observations"]
                    observations["target_after_apply"]["skill"]["digest"] = (
                        "sha256:" + "0" * 64
                    )
                    observations["target_final"] = deepcopy(
                        observations["target_after_apply"]
                    )
                elif mutation == "command_join":
                    native["route_observation"]["document"]["actions"][0]["commands"][
                        0
                    ]["pid"] += 1
                elif mutation == "identities":
                    composition["action"]["identities"]["gateway"]["uid"] = 991
                elif mutation == "bindings":
                    composition["bindings"]["sessions"] = "reused"
                elif mutation == "profile":
                    composition["profile"]["before"]["outcomes"]["PASS"] = 1
                    composition["profile"]["after"] = deepcopy(
                        composition["profile"]["before"]
                    )
                elif mutation == "artifact":
                    composition["action"]["artifacts"][
                        "final_combined_v3_workshop_proposal_apply"
                    ]["workshop_proposal_apply_probe"]["runtime"]["stat"][
                        "mode"
                    ] = "0666"
                else:
                    composition["decision"]["status"] = native["decision"]["status"]
                _sync_route(native)
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_load_average_numeric_variation_and_nonfinite_rejection(self) -> None:
        for value in (0, 0.5, True):
            with self.subTest(load_average=value):
                native = deepcopy(self.native)
                document = native["route_observation"]["document"]
                document["actions"][0]["prerequisites"]["system_info"]["response"][
                    "value"
                ]["loadAverage"][0] = value
                _refresh_commands(document)
                _sync_route(native)
                if type(value) is bool:
                    with self.assertRaises(AdmissionEvidenceError):
                        self.verify(native)
                else:
                    self.assertEqual(self.verify(native)["native_capture"], native)
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(nonfinite=value):
                native = deepcopy(self.native)
                document = deepcopy(native["route_observation"]["document"])
                document["actions"][0]["prerequisites"]["system_info"]["response"][
                    "value"
                ]["loadAverage"][0] = value
                _refresh_commands(document)
                # Nonfinite JSON has no canonical document; reject its decoded bytes first.
                raw = (
                    json.dumps(document, indent=2, ensure_ascii=False) + "\n"
                ).encode()
                native["route_observation"]["raw"].update(
                    base64=base64.b64encode(raw).decode(),
                    bytes=len(raw),
                    digest=subject.old._digest(raw),
                )
                with self.assertRaisesRegex(
                    AdmissionEvidenceError, "constant|non-finite"
                ):
                    self.verify(native)

    def test_rejects_execution_pid_environment_and_shape_drift(self) -> None:
        for mutation in (
            "pid",
            "namespace",
            "environment_name",
            "environment_names",
            "argv",
            "extra_route",
            "extra_execution",
            "boolean_exit",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                route = native["route_observation"]
                if mutation == "pid":
                    route["gateway_pid_binding"]["pid"] += 1
                elif mutation == "namespace":
                    route["gateway_pid_binding"]["mount_namespace"] = "/proc/1/ns/mnt"
                elif mutation == "environment_name":
                    route["gateway_pid_binding"]["environment_name"] = "OTHER_PID"
                elif mutation == "environment_names":
                    route["execution"]["environment_names"].append("OPENCLAW_TEST_FAST")
                elif mutation == "argv":
                    route["execution"]["argv"][-1] = (
                        "ADM-02/reload/workshop-invalidation"
                    )
                elif mutation == "extra_route":
                    route["unexpected"] = "unbound"
                elif mutation == "extra_execution":
                    route["execution"]["unexpected"] = "unbound"
                else:
                    route["execution"]["exit_code"] = False
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_coherently_reencoded_host_and_mount_drift(self) -> None:
        for mutation in (
            "host_config",
            "binds",
            "mount_destination",
            "mount_mode",
            "volume_options",
            "volume_scope",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                host = native["harness"]["document"]
                if mutation == "host_config":
                    host["host_config"]["ipc_mode"] = "host"
                elif mutation == "binds":
                    host["host_config"]["binds"].append("/tmp:/extra:ro")
                elif mutation == "mount_destination":
                    host["route_input_mount"]["destination"] = "/elsewhere"
                elif mutation == "mount_mode":
                    host["openclaw_runtime_mount"]["mode"] = "rw"
                elif mutation == "volume_options":
                    host["route_input_volume_identity"]["options"] = {"device": "/tmp"}
                else:
                    host["route_input_volume_identity"]["scope"] = "global"
                _sync_harness(native)
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_composition_and_invocation_chronology_drift(self) -> None:
        for mutation in (
            "composition_before_execution",
            "composition_after_outer",
            "outer_before_execution",
            "invocation",
        ):
            with self.subTest(mutation=mutation):
                native, invocation = map(deepcopy, (self.native, self.invocation))
                if mutation == "composition_before_execution":
                    native["composition"]["recorded_at"] = native["route_observation"][
                        "execution"
                    ]["started_at"]
                elif mutation == "composition_after_outer":
                    native["composition"]["recorded_at"] = "2026-08-28T19:50:16Z"
                elif mutation == "outer_before_execution":
                    native["recorded_at"] = native["route_observation"]["execution"][
                        "started_at"
                    ]
                else:
                    invocation["completed_at"] = invocation["started_at"]
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_capture(
                        canonical_json(native) + b"\n",
                        self.prepared,
                        source=self.source,
                        invocation=invocation,
                    )

    def test_malformed_inputs_fail_with_evidence_error(self) -> None:
        for mutation in (
            "raw",
            "prepared",
            "source",
            "invocation",
            "route",
            "composition",
            "harness",
        ):
            with self.subTest(mutation=mutation):
                raw, prepared, source, invocation = (
                    self.raw,
                    self.prepared,
                    self.source,
                    self.invocation,
                )
                if mutation == "raw":
                    raw = b"[]\n"
                elif mutation == "prepared":
                    prepared = None
                elif mutation == "source":
                    source = None
                elif mutation == "invocation":
                    invocation = None
                else:
                    native = deepcopy(self.native)
                    native[
                        {
                            "route": "route_observation",
                            "composition": "composition",
                            "harness": "harness",
                        }[mutation]
                    ] = None
                    raw = canonical_json(native) + b"\n"
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_capture(
                        raw, prepared, source=source, invocation=invocation
                    )


if __name__ == "__main__":
    unittest.main()
