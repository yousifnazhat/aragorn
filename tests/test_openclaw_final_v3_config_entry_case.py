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
from scripts import openclaw_final_v3_config_entry_case as subject

_ROOT = Path(__file__).resolve().parents[1]


def _sync_route(native: dict) -> None:
    route = native["route_observation"]
    raw = canonical_json(route["document"]) + b"\n"
    route["raw"] = {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "canonical_digest": canonical_digest(route["document"]),
        "digest": subject.old._digest(raw),
        "raw_is_canonical_json_lf": True,
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


class ConfigEntryCaseTests(unittest.TestCase):
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
        # Signed historical evidence is a regression input, not a fresh capture.
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

    def verify(self, native: dict, **kwargs) -> dict:
        return subject.verify_capture(
            canonical_json(native) + b"\n",
            kwargs.pop("prepared", self.prepared),
            source=kwargs.pop("source", self.source),
            invocation=kwargs.pop("invocation", self.invocation),
            **kwargs,
        )

    def test_preparation_binds_exact_source_probe_and_native_argv(self) -> None:
        self.assertEqual(subject._CASE, "ADM-02/update/config-entry-activation")
        self.assertEqual(self.prepared["request"], self.request)
        self.assertIsNone(self.prepared["descriptor"]["materializer"])
        self.assertEqual(self.prepared["bundle_files"], [subject.old._PROBE])
        self.assertEqual(
            set(subject.SOURCE_PATHS),
            {
                subject.old._SOURCE_ARTIFACTS[name]["path"]
                for name in subject.old._SIGNED_SOURCE_ARTIFACTS
            }
            | {item["path"] for item in subject.old._COLLECTOR_ARTIFACTS.values()},
        )
        self.assertEqual(self.prepared["source_files"], self.source["files"])
        self.assertEqual(
            self.prepared["native_materializer"]["source"],
            next(
                item
                for item in self.source["files"]
                if item["path"] == subject.old._MATERIALIZER["path"]
            ),
        )
        self.assertEqual(
            self.prepared["native_materializer"]["entrypoint"],
            "transformed_final_combined_v2_probe",
        )
        self.assertEqual(
            self.prepared["native_materializer"]["transform"], subject.old._TRANSFORM
        )
        mapping = self.prepared["path_mapping"]
        self.assertIs(mapping["literal_dispatch_argv_equality"], False)
        self.assertEqual(
            self.prepared["descriptor"]["argv"],
            ["/usr/local/bin/node", subject._PROVISIONAL_ROOT + "/" + subject._PROBE],
        )
        self.assertEqual(
            mapping["native_probe_argv"],
            ["/usr/local/bin/node", subject._NATIVE_ROOT + "/" + subject._PROBE],
        )
        self.assertEqual(
            mapping["files"],
            [
                {
                    "provisional": subject._PROVISIONAL_ROOT + "/" + subject._PROBE,
                    "native": subject._NATIVE_ROOT + "/" + subject._PROBE,
                    "bytes": subject.old._PROBE["bytes"],
                    "digest": subject.old._PROBE["digest"],
                    "role": "probe",
                }
            ],
        )
        bundle = self.directory / "bundle"
        probe = bundle / subject._PROBE
        self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o555)
        self.assertEqual([path.name for path in bundle.iterdir()], [subject._PROBE])
        self.assertEqual(stat.S_IMODE(probe.stat().st_mode), 0o444)
        self.assertEqual(len(probe.read_bytes()), subject.old._PROBE["bytes"])
        self.assertEqual(
            subject.old._digest(probe.read_bytes()), subject.old._PROBE["digest"]
        )
        for value in (True, 99, "10"):
            with self.subTest(ordinal=value), TemporaryDirectory() as temporary:
                changed = deepcopy(self.request)
                changed["case"]["ordinal"] = value
                directory = Path(temporary).resolve()
                with self.assertRaises(AdmissionEvidenceError):
                    subject.prepare_case(self.contract, changed, directory=directory)
                self.assertEqual(list(directory.iterdir()), [])

    def test_retained_input_replays_without_granting_eligibility(self) -> None:
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
        native = deepcopy(self.native)
        _sync_route(native)
        self.assertEqual(self.verify(native)["native_capture"], native)
        route = native["route_observation"]
        raw = (json.dumps(route["document"], indent=2) + "\n").encode()
        route["raw"].update(
            base64=base64.b64encode(raw).decode(),
            bytes=len(raw),
            digest=subject.old._digest(raw),
            raw_is_canonical_json_lf=False,
        )
        with self.assertRaises(AdmissionEvidenceError):
            self.verify(native)

    def test_rejects_source_preparation_raw_and_eligibility_drift(self) -> None:
        for mutation in (
            "mapping",
            "source",
            "duplicate_source",
            "bundle",
            "raw",
            "raw_format",
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
                elif mutation == "raw_format":
                    route["raw"]["raw_is_canonical_json_lf"] = False
                elif mutation == "document":
                    route["document"]["run_nonce"] = "0" * 32
                elif mutation == "route":
                    route["route"]["status"] = "PASS"
                else:
                    native["decision"]["phase3_exit_eligible"] = True
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native, prepared=prepared, source=source)

    def test_rejects_coherent_semantic_composition_and_mount_drift(self) -> None:
        for mutation in (
            "command_join",
            "command_service_pid",
            "probe_volume",
            "identity",
            "bindings",
            "profile",
            "composition_decision",
            "activator_digest",
            "preflight_source_mode",
            "installed_runtime",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                composition = native["composition"]
                action = native["route_observation"]["document"]["action"]
                if mutation == "command_join":
                    action["commands"][0]["pid"] += 1
                elif mutation == "command_service_pid":
                    pid = native["route_observation"]["stack_before"]["pids"][
                        "aragorn-runtime-action-worker.service"
                    ]
                    action["commands"][1]["pid"] = pid
                    action["prerequisites"]["system_info_before"]["command"]["pid"] = (
                        pid
                    )
                elif mutation == "probe_volume":
                    for state, key in (
                        (action["prerequisites"], "boundary_before"),
                        (action["observations"], "boundary_after"),
                    ):
                        state[key]["probe"]["records"][0]["root"] = (
                            "/docker/volumes/aragorn-phase3-final-combined-v3-config-entry-activation-route-input-99999/_data"
                        )
                elif mutation == "identity":
                    composition["action"]["identities"]["gateway"]["uid"] = 991
                elif mutation == "bindings":
                    composition["bindings"]["sessions"] = "reused"
                elif mutation == "profile":
                    composition["profile"]["before"]["outcomes"]["PASS"] = 1
                    composition["profile"]["after"] = deepcopy(
                        composition["profile"]["before"]
                    )
                elif mutation == "composition_decision":
                    composition["decision"]["status"] = native["decision"]["status"]
                else:
                    artifact = composition["action"]["artifacts"][
                        "final_combined_v3_config_entry_activation"
                    ]
                    if mutation == "activator_digest":
                        artifact["activator"]["digest"] = "sha256:" + "0" * 64
                    elif mutation == "preflight_source_mode":
                        artifact["preflight_source"]["stat"]["mode"] = "0666"
                    else:
                        artifact["installed_runtime"] = {}
                _sync_route(native)
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_coherently_reencoded_host_drift(self) -> None:
        for mutation in (
            "host_config",
            "binds",
            "mount_destination",
            "mount_mode",
            "volume_options",
            "volume_scope",
            "capture_owner",
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
                elif mutation == "volume_scope":
                    host["route_input_volume_identity"]["scope"] = "global"
                else:
                    host["route_input_volume_identity"]["labels"][
                        "dev.aragorn.capture-owner"
                    ] = subject.old._SOURCE["commit"] + ":1"
                _sync_harness(native)
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_execution_shape_and_chronology_drift(self) -> None:
        for mutation in (
            "pid",
            "namespace",
            "environment",
            "argv",
            "extra_route",
            "extra_execution",
            "boolean_exit",
            "composition_before",
            "composition_after",
            "outer_before",
            "invocation",
        ):
            with self.subTest(mutation=mutation):
                native, invocation = map(deepcopy, (self.native, self.invocation))
                route = native["route_observation"]
                if mutation == "pid":
                    route["gateway_pid_binding"]["pid"] += 1
                elif mutation == "namespace":
                    route["gateway_pid_binding"]["mount_namespace"] = "/proc/1/ns/mnt"
                elif mutation == "environment":
                    route["execution"]["environment_names"].append("OPENCLAW_TEST_FAST")
                elif mutation == "argv":
                    route["execution"]["argv"] += ["--route-id", subject._CASE]
                elif mutation == "extra_route":
                    route["unexpected"] = "unbound"
                elif mutation == "extra_execution":
                    route["execution"]["unexpected"] = "unbound"
                elif mutation == "boolean_exit":
                    route["execution"]["exit_code"] = False
                elif mutation == "composition_before":
                    native["composition"]["recorded_at"] = route["execution"][
                        "started_at"
                    ]
                elif mutation == "composition_after":
                    native["composition"]["recorded_at"] = "2026-08-28T19:03:07Z"
                elif mutation == "outer_before":
                    native["recorded_at"] = route["execution"]["started_at"]
                else:
                    invocation["completed_at"] = invocation["started_at"]
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native, invocation=invocation)

    def test_rejects_unbound_service_pid_maps(self) -> None:
        worker = "aragorn-runtime-action-worker.service"
        for mutation in (
            "missing",
            "extra",
            "replaced",
            "duplicate",
            "boolean",
            "zero",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                pids = native["route_observation"]["stack_before"]["pids"]
                if mutation == "missing":
                    del pids[worker]
                elif mutation == "extra":
                    pids["unbound.service"] = 99999
                else:
                    pids[worker] = {
                        "replaced": 99999,
                        "duplicate": pids["aragorn-agent-gateway.service"],
                        "boolean": True,
                        "zero": 0,
                    }[mutation]
                with self.assertRaisesRegex(AdmissionEvidenceError, "service PID map"):
                    self.verify(native)

    def test_synthetic_fresh_source_and_volume_joins_are_not_capture_authority(
        self,
    ) -> None:
        old_volume = self.native["harness"]["document"]["route_input_volume_identity"][
            "name"
        ]
        volume = (
            "aragorn-phase3-final-combined-v3-config-entry-activation-route-input-90001"
        )

        def remap(value):
            if type(value) is dict:
                return {key: remap(item) for key, item in value.items()}
            if type(value) is list:
                return [remap(item) for item in value]
            return value.replace(old_volume, volume) if type(value) is str else value

        native = remap(self.native)
        host = native["harness"]["document"]
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
        _sync_route(native)
        result = self.verify(native, source=source)
        self.assertEqual(result["native_capture"], native)
        self.assertEqual(result["proof"]["current_source_commit"], commit)
        self.assertNotEqual(commit, subject.old._SOURCE["commit"])
        self.assertNotEqual(volume, old_volume)
        self.assertNotEqual(
            native["route_observation"]["raw"]["digest"],
            self.native["route_observation"]["raw"]["digest"],
        )
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key.endswith("_eligible")
            )
        )

    def test_malformed_inputs_fail_with_evidence_error(self) -> None:
        for mutation in (
            "raw",
            "prepared",
            "source",
            "invocation",
            "route_observation",
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
                    native[mutation] = None
                    raw = canonical_json(native) + b"\n"
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_capture(
                        raw, prepared, source=source, invocation=invocation
                    )


if __name__ == "__main__":
    unittest.main()
