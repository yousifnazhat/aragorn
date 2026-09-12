from __future__ import annotations

import base64
import json
import stat
import subprocess
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import openclaw_final_v3_missing_prompt_blob_case as subject

_ROOT = Path(__file__).resolve().parents[1]
_WORKER = "aragorn-runtime-action-worker.service"
_GATEWAY = "aragorn-agent-gateway.service"


def _sync_route(native: dict) -> None:
    route = native["route_observation"]
    raw = subject._native_json(route["document"])
    route["raw"] = {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "canonical_digest": canonical_digest(route["document"]),
        "digest": subject.old._digest(raw),
        "raw_is_canonical_json_lf": False,
    }
    route["route"] = deepcopy(route["document"]["route"])


def _sync_harness(native: dict) -> None:
    harness = native["harness"]
    raw = canonical_json(harness["document"])
    harness["digest"] = subject.old._digest(raw)
    harness["file"].update(
        base64=base64.b64encode(raw).decode(), bytes=len(raw), digest=harness["digest"]
    )
    harness["file"]["stat"]["size"] = len(raw)
    native["composition"]["action"]["harness"] = deepcopy(harness)


class MissingPromptBlobCaseTests(unittest.TestCase):
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
        # The signed retained observation is a regression input, not a fresh capture.
        cls.raw = (_ROOT / subject.old._EVIDENCE["path"]).read_bytes()
        cls.native = json.loads(cls.raw)
        cls.invocation = {
            "argv": [
                "/bin/sh",
                str(_ROOT / subject._RECIPE),
                str(cls.directory / "native.json"),
            ],
            "exit_code": 0,
            "started_at": "2026-08-30T00:00:00Z",
            "completed_at": "2026-08-31T00:00:00Z",
        }

    def verify(self, native: dict, **kwargs) -> dict:
        return subject.verify_capture(
            canonical_json(native) + b"\n",
            kwargs.pop("prepared", self.prepared),
            source=kwargs.pop("source", self.source),
            invocation=kwargs.pop("invocation", self.invocation),
            **kwargs,
        )

    def test_exact_two_file_preparation_and_native_mapping(self) -> None:
        self.assertEqual(subject._CASE, "ADM-02/reload/missing-prompt-blob-rebuild")
        self.assertEqual(subject._STEM, "prompt-rebuild")
        self.assertEqual(self.prepared["request"], self.request)
        self.assertIsNone(self.prepared["descriptor"]["materializer"])
        self.assertEqual(self.prepared["bundle_files"], subject.old._PROBE_BUNDLE)
        self.assertEqual(self.prepared["source_files"], self.source["files"])
        self.assertEqual(
            set(subject.SOURCE_PATHS),
            {item[2] for item in subject.old._SOURCE_ARTIFACTS.values()}
            | {item[2] for item in subject.old._COLLECTOR_ARTIFACTS.values()},
        )
        self.assertEqual(
            self.prepared["native_materializer"]["source"],
            next(
                item
                for item in self.source["files"]
                if item["path"] == subject._MATERIALIZER
            ),
        )
        self.assertEqual(
            self.prepared["native_materializer"]["entrypoint"],
            "materialize_openclaw_final_v3_rebound_case",
        )
        for root, argv in (
            (subject._PROVISIONAL_ROOT, self.prepared["descriptor"]["argv"]),
            (subject._NATIVE_ROOT, self.prepared["path_mapping"]["native_probe_argv"]),
        ):
            self.assertEqual(argv, ["/usr/local/bin/node", root + "/" + subject._PROBE])
        self.assertIs(
            self.prepared["path_mapping"]["literal_dispatch_argv_equality"], False
        )
        bundle = self.directory / "bundle"
        self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o555)
        self.assertEqual(
            {p.name for p in bundle.iterdir()},
            {f["name"] for f in subject.old._PROBE_BUNDLE},
        )
        for item in subject.old._PROBE_BUNDLE:
            path = bundle / item["name"]
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            self.assertEqual(len(path.read_bytes()), item["bytes"])
            self.assertEqual(subject.old._digest(path.read_bytes()), item["digest"])
        for ordinal in (True, 99, "23"):
            with self.subTest(ordinal=ordinal), TemporaryDirectory() as temporary:
                request = deepcopy(self.request)
                request["case"]["ordinal"] = ordinal
                directory = Path(temporary).resolve()
                with self.assertRaises(AdmissionEvidenceError):
                    subject.prepare_case(self.contract, request, directory=directory)
                self.assertEqual(list(directory.iterdir()), [])

    def test_retained_utf8_bytes_replay_without_qualification(self) -> None:
        self.assertEqual(subject.old._digest(self.raw), subject.old._EVIDENCE["digest"])
        result = self.verify(self.native)
        self.assertEqual(result["native_capture"], self.native)
        self.assertEqual(
            result["proof"]["native_capture_digest"], subject.old._EVIDENCE["digest"]
        )
        route = self.native["route_observation"]
        raw = base64.b64decode(route["raw"]["base64"], validate=True)
        self.assertEqual(raw, subject._native_json(route["document"]))
        self.assertNotEqual(raw, canonical_json(route["document"]) + b"\n")
        self.assertIs(route["raw"]["raw_is_canonical_json_lf"], False)
        self.assertEqual(self.native["decision"]["route_pass_count"], 0)
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key.endswith("_eligible")
            )
        )

    def test_rejects_preparation_source_raw_and_authority_drift(self) -> None:
        for mutation in (
            "mapping",
            "source",
            "duplicate_source",
            "bundle",
            "raw",
            "marker",
            "canonicalized",
            "document",
            "eligibility",
        ):
            with self.subTest(mutation=mutation):
                native, prepared, source = map(
                    deepcopy, (self.native, self.prepared, self.source)
                )
                route = native["route_observation"]
                if mutation == "mapping":
                    prepared["path_mapping"]["native_root"] = "/elsewhere"
                elif mutation == "source":
                    source["files"][0]["digest"] = "sha256:" + "0" * 64
                elif mutation == "duplicate_source":
                    source["files"].append(deepcopy(source["files"][0]))
                elif mutation == "bundle":
                    route["bundle"][1]["bytes"] += 1
                elif mutation == "raw":
                    route["raw"]["base64"] = base64.b64encode(b"{}").decode()
                elif mutation == "marker":
                    route["raw"]["raw_is_canonical_json_lf"] = True
                elif mutation == "canonicalized":
                    raw = canonical_json(route["document"]) + b"\n"
                    route["raw"].update(
                        base64=base64.b64encode(raw).decode(),
                        bytes=len(raw),
                        digest=subject.old._digest(raw),
                        raw_is_canonical_json_lf=True,
                    )
                elif mutation == "document":
                    route["document"]["run_nonce"] = "f" * 32
                else:
                    native["decision"]["phase3_exit_eligible"] = True
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native, prepared=prepared, source=source)

    def test_rejects_exact_parent_and_lean_artifact_custody_changes(self) -> None:
        for path, value in (
            (("activator", "digest"), "sha256:" + "0" * 64),
            (("activator_source", "stat", "inode"), 0),
            (("preflight", "stat", "mode"), "0666"),
            (("plugin", "index.js", "stat", "device"), True),
            (("plugin", "package.json", "extra"), "unbound"),
            (("skill", "file", "digest"), "sha256:" + "0" * 64),
            (("skill", "parents", 0, "mode"), "0777"),
            (("policy_command", "stat", "nlink"), 2),
            (("config", "file", "source", "stat", "inode"), 0),
            (("profile", "extra"), {}),
            (("collector", "probe", "stat", "inode"), 0),
            (
                ("prompt_rebuild_probe", "runtime_observation_helper", "stat", "mode"),
                "0644",
            ),
            (("prompt_rebuild_probe", "runtime_probe", "extra"), None),
            (("installed_runtime",), {}),
        ):
            with self.subTest(path=path):
                native = deepcopy(self.native)
                target = native["composition"]["action"]["artifacts"][
                    "final_combined_v3_prompt_rebuild"
                ]
                for name in path[:-1]:
                    target = target[name]
                target[path[-1]] = value
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_coherent_host_execution_and_service_identity_changes(self) -> None:
        for mutation in (
            "owner",
            "mount",
            "hostname",
            "binding",
            "argv",
            "environment",
            "execution_extra",
            "pid_extra",
            "pid_missing",
            "pid_join",
            "composition_pid",
            "command_service_pid",
            "chronology",
            "nonce",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                host, route = native["harness"]["document"], native["route_observation"]
                action = route["document"]["action"]
                if mutation == "owner":
                    host["route_input_volume_identity"]["labels"][
                        "dev.aragorn.capture-owner"
                    ] = "unbound"
                elif mutation == "mount":
                    old_volume = host["route_input_volume_identity"]["name"]
                    volume = "aragorn-phase3-final-combined-v3-prompt-rebuild-route-input-90001"
                    native["harness"]["document"] = json.loads(
                        json.dumps(host)
                        .replace(old_volume, volume)
                        .replace(":93201", ":90001")
                    )
                elif mutation == "hostname":
                    for section, key in (
                        ("prerequisites", "gateway_process_before"),
                        ("observations", "gateway_process_after"),
                    ):
                        action[section][key]["hostname"] = "0" * 12
                elif mutation == "binding":
                    route["gateway_pid_binding"]["mount_namespace"] = "/proc/1/ns/mnt"
                elif mutation == "argv":
                    route["execution"]["argv"].append("--route-id")
                elif mutation == "environment":
                    route["execution"]["environment_names"].append("OPENCLAW_TEST_FAST")
                elif mutation == "execution_extra":
                    route["execution"]["extra"] = True
                elif mutation == "pid_extra":
                    route["stack_before"]["pids"]["unbound.service"] = 99999
                elif mutation == "pid_missing":
                    del route["stack_before"]["pids"][_WORKER]
                elif mutation == "pid_join":
                    route["stack_before"]["pids"][_WORKER] = 99999
                elif mutation == "composition_pid":
                    native["composition"]["action"]["boundaries"]["processes"][_WORKER][
                        "pid"
                    ] = 99999
                elif mutation == "command_service_pid":
                    action["commands"][0]["pid"] = route["stack_before"]["pids"][
                        _WORKER
                    ]
                elif mutation == "chronology":
                    route["execution"]["started_at"] = route["document"]["recorded_at"]
                else:
                    route["document"]["run_nonce"] = "f" * 32
                _sync_harness(native)
                _sync_route(native)
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_synthetic_fresh_signed_source_and_input_mount_join(self) -> None:
        native = deepcopy(self.native)
        host = native["harness"]["document"]
        old_volume = host["route_input_volume_identity"]["name"]
        volume = "aragorn-phase3-final-combined-v3-prompt-rebuild-route-input-90001"
        host = json.loads(json.dumps(host).replace(old_volume, volume))
        native["harness"]["document"] = host
        git = subject.checks.old._git
        commit = git(["rev-parse", "HEAD"]).decode().strip()
        source = {
            "commit": commit,
            "parent": git(["rev-parse", commit + "^"]).decode().strip(),
            "tree": git(["rev-parse", commit + "^{tree}"]).decode().strip(),
            "files": self.source["files"],
        }
        host["source_commit"] = commit
        host["route_input_volume_identity"]["labels"].update(
            {
                "dev.aragorn.capture-owner": commit + ":90001",
                "dev.aragorn.source-commit": commit,
            }
        )
        signature = host["source_commit_verification"]
        signature["command"] = ["git", "verify-commit", "--raw", commit]
        verified = subprocess.run(
            signature["command"], cwd=_ROOT, check=True, capture_output=True
        )
        signature["exit_code"] = verified.returncode
        for key, raw in (
            ("commit_object", git(["cat-file", "commit", commit])),
            ("stdout", verified.stdout),
            ("stderr", verified.stderr),
        ):
            signature[key] = {
                "base64": base64.b64encode(raw).decode(),
                "bytes": len(raw),
                "digest": subject.old._digest(raw),
            }
        _sync_harness(native)
        # Updating ownership alone cannot change the observed probe mount.
        with self.assertRaises(AdmissionEvidenceError):
            self.verify(native, source=source)
        route = native["route_observation"]
        route["document"] = json.loads(
            json.dumps(route["document"]).replace(old_volume, volume)
        )
        _sync_route(native)
        result = self.verify(native, source=source)
        self.assertEqual(result["native_capture"], native)
        self.assertEqual(result["proof"]["current_source_commit"], commit)
        self.assertNotEqual(commit, subject.old._SOURCE["commit"])
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key.endswith("_eligible")
            )
        )

    def test_malformed_inputs_raise_evidence_errors(self) -> None:
        for field in (
            "raw",
            "prepared",
            "source",
            "invocation",
            "route_observation",
            "composition",
            "harness",
        ):
            with self.subTest(field=field):
                raw, prepared, source, invocation = (
                    self.raw,
                    self.prepared,
                    self.source,
                    self.invocation,
                )
                if field == "raw":
                    raw = b"[]\n"
                elif field == "prepared":
                    prepared = None
                elif field == "source":
                    source = None
                elif field == "invocation":
                    invocation = None
                else:
                    native = deepcopy(self.native)
                    native[field] = None
                    raw = canonical_json(native) + b"\n"
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_capture(
                        raw, prepared, source=source, invocation=invocation
                    )


if __name__ == "__main__":
    unittest.main()
