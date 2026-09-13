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
from aragorn import admission_protected_final_combined_v3_plugin_force_reinstall as old
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_openclaw_final_v3_plugin_force_current_parent as build
from scripts import openclaw_final_v3_plugin_force_case as subject

_ROOT = Path(__file__).resolve().parents[1]
_ARTIFACT = "final_combined_v3_plugin_force_reinstall"
_WORKER = "aragorn-runtime-action-worker.service"
_GATEWAY = "aragorn-agent-gateway.service"
_SOURCE = {
    "commit": "a5249377cc3f4ef24e441e58ee98f0828c31e963",
    "parent": "0a4808c330cb2ba090ac7eaa7e3e6fb5b253557b",
    "tree": "641aeaa84b66e4cad535b52da6cd674bc33a76e7",
}
_IMAGE = "sha256:afcdb0862ff0a431a0c8f62ff2b12d242603699bd89f46c008e47005117c123f"
_ADDED_LAYERS = [
    "sha256:43d60978c721011e1c97be4caf06201a00f3cf5b85ed7082d65eedabfb3f1ea9",
    "sha256:14933820acfd52013c131fda22863af24fe7271fd7f4ad818f012b0536a4c953",
    "sha256:9efe8b173097b34d307c9d03b46d583d440dcc44e858dde736965b792d6631d8",
]
_ZERO = "sha256:" + "0" * 64


def _raw(raw: bytes) -> dict:
    return {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "digest": old._digest(raw),
    }


def _sync_route(native: dict) -> None:
    route = native["route_observation"]
    route["raw"] = {
        **_raw(canonical_json(route["document"]) + b"\n"),
        "canonical_digest": canonical_digest(route["document"]),
        "raw_is_canonical_json_lf": True,
    }
    route["route"] = deepcopy(route["document"]["route"])


def _sync_harness(native: dict) -> None:
    harness = native["harness"]
    raw = canonical_json(harness["document"])
    harness["digest"] = old._digest(raw)
    harness["file"].update(_raw(raw))
    harness["file"]["stat"]["size"] = len(raw)
    native["composition"]["action"]["harness"] = deepcopy(harness)


def _set(value: dict, path: tuple, replacement) -> None:
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = replacement


def _synthetic_current_parent(retained: dict) -> dict:
    """Rebind a test envelope, never a captured observation or freshness proof."""
    previous = retained["harness"]["document"]["route_input_volume_identity"]["name"]
    volume = "aragorn-phase3-final-combined-v3-plugin-force-reinstall-route-input-90001"

    def remap(value):
        if type(value) is dict:
            return {key: remap(item) for key, item in value.items()}
        if type(value) is list:
            return [remap(item) for item in value]
        return value.replace(previous, volume) if type(value) is str else value

    native = remap(retained)
    host = native["harness"]["document"]
    parent_layers = deepcopy(host["image_lineage"]["child"]["layers"])
    host["parent_image_id"] = old._IMAGE
    host["image_id"] = host["run_image_reference"] = _IMAGE
    host["image_lineage"] = {
        "added_layers": _ADDED_LAYERS,
        "parent": {"id": old._IMAGE, "layers": parent_layers, "rootfs_type": "layers"},
        "child": {
            "id": _IMAGE,
            "layers": parent_layers + _ADDED_LAYERS,
            "rootfs_type": "layers",
        },
    }
    host["source_commit"] = _SOURCE["commit"]
    host["route_input_volume_identity"]["labels"].update(
        {
            "dev.aragorn.capture-owner": _SOURCE["commit"] + ":90001",
            "dev.aragorn.source-commit": _SOURCE["commit"],
        }
    )
    signature = subprocess.run(
        ["git", "verify-commit", "--raw", _SOURCE["commit"]],
        cwd=_ROOT,
        capture_output=True,
        check=True,
    )
    host["source_commit_verification"] = {
        "command": ["git", "verify-commit", "--raw", _SOURCE["commit"]],
        "commit_object": _raw(
            subject.checks.old._git(["cat-file", "commit", _SOURCE["commit"]])
        ),
        "exit_code": signature.returncode,
        "stdout": _raw(signature.stdout),
        "stderr": _raw(signature.stderr),
    }
    artifact = native["composition"]["action"]["artifacts"][_ARTIFACT]
    for key, name, path in (
        ("capture_recipe", build._RECIPE, "/src/scripts/" + build._RECIPE),
        ("probe", build._COLLECTOR, "/src/scripts/" + build._COLLECTOR),
        ("dockerfile", "Dockerfile", "/src/" + build._DOCKER_DIRECTORY + "/Dockerfile"),
    ):
        record = artifact["collector"][key]
        size, digest = build._OUTPUTS[name]
        record.update(path=path, bytes=size, digest=digest)
        record["stat"]["size"] = size
    native["source_artifacts"]["collector"] = deepcopy(artifact["collector"]["probe"])
    _sync_route(native)
    _sync_harness(native)
    return native


class PluginForceCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name).resolve()
        cls.contract = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="a" * 64
        )
        cls.request = campaign.build_openclaw_final_v3_subfixture_request(
            cls.contract, "ADM-02/update/plugin-force-reinstall"
        )
        cls.prepared = subject.prepare_case(
            cls.contract, cls.request, directory=cls.directory
        )
        cls.source = {
            **_SOURCE,
            "files": subject.checks.historical_sources(_SOURCE, subject.SOURCE_PATHS),
        }
        cls.retained_raw = (_ROOT / old._EVIDENCE["path"]).read_bytes()
        cls.retained = json.loads(cls.retained_raw)
        cls.native = _synthetic_current_parent(cls.retained)
        cls.invocation = {
            "argv": [
                "/bin/sh",
                "/tmp/aragorn-v3-case-logs-test/build/" + build._RECIPE,
                str(_ROOT),
                str(cls.directory / "native.json"),
            ],
            "recipe": next(
                item
                for item in cls.prepared["build_sources"]["files"]
                if item["name"] == build._RECIPE
            ),
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

    def test_exact_current_parent_source_build_and_seven_file_preparation(self) -> None:
        self.assertEqual(subject._SOURCE, _SOURCE)
        self.assertEqual(subject._IMAGE, _IMAGE)
        self.assertEqual(list(subject._ADDED_LAYERS), _ADDED_LAYERS)
        self.assertEqual(subject._CASE, "ADM-02/update/plugin-force-reinstall")
        self.assertEqual(subject._STEM, "plugin-force-reinstall")
        self.assertEqual(self.prepared["request"], self.request)
        self.assertIsNone(self.prepared["descriptor"]["materializer"])
        self.assertEqual(self.prepared["source_files"], self.source["files"])
        self.assertEqual(
            set(subject.SOURCE_PATHS), {build._MATERIALIZER, *build._INPUTS}
        )
        self.assertEqual(
            self.prepared["bundle_files"], self.retained["route_observation"]["bundle"]
        )
        manifest = self.prepared["build_sources"]
        self.assertEqual(manifest["parent_image_id"], old._IMAGE)
        self.assertIsNone(manifest["child_image_id"])
        self.assertIs(manifest["execution_performed"], False)
        self.assertEqual(
            manifest["files"],
            [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in build._OUTPUTS.items()
            ],
        )
        mapping = self.prepared["path_mapping"]
        self.assertIs(mapping["literal_dispatch_argv_equality"], False)
        self.assertEqual(
            mapping["native_probe_argv"],
            ["/usr/local/bin/python3.12", subject._NATIVE_ROOT + "/" + subject._PROBE],
        )
        bundle = self.directory / "bundle"
        self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o555)
        self.assertEqual(
            {str(p.relative_to(bundle)) for p in bundle.rglob("*") if p.is_file()},
            set(build._BUNDLE),
        )
        for path in bundle.rglob("*"):
            self.assertFalse(path.is_symlink())
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode), 0o555 if path.is_dir() else 0o444
            )
            if path.is_file():
                _, size, digest = build._BUNDLE[str(path.relative_to(bundle))]
                self.assertEqual(
                    (len(path.read_bytes()), old._digest(path.read_bytes())),
                    (size, digest),
                )
        for ordinal in (True, 99, "14"):
            with self.subTest(ordinal=ordinal), TemporaryDirectory() as temporary:
                request = deepcopy(self.request)
                request["case"]["ordinal"] = ordinal
                directory = Path(temporary).resolve()
                with self.assertRaises(AdmissionEvidenceError):
                    subject.prepare_case(self.contract, request, directory=directory)
                self.assertEqual(list(directory.iterdir()), [])
        fixed_bundle = deepcopy(subject._BUNDLE)
        with TemporaryDirectory() as first, TemporaryDirectory() as second:
            returned = subject.prepare_case(
                self.contract, self.request, directory=Path(first).resolve()
            )
            returned["bundle_files"][0]["digest"] = _ZERO
            returned["bundle_files"].append({"name": "unbound"})
            self.assertEqual(subject._BUNDLE, fixed_bundle)
            subsequent = subject.prepare_case(
                self.contract, self.request, directory=Path(second).resolve()
            )
            self.assertEqual(subsequent["bundle_files"], fixed_bundle)
            self.assertEqual(subsequent["path_mapping"], self.prepared["path_mapping"])

    def test_synthetic_binding_verifies_but_old_v2_parent_capture_is_rejected(
        self,
    ) -> None:
        self.assertEqual(old._digest(self.retained_raw), old._EVIDENCE["digest"])
        with self.assertRaises(AdmissionEvidenceError):
            self.verify(self.retained)
        result = self.verify(self.native)
        self.assertEqual(result["native_capture"], self.native)
        self.assertEqual(result["harness"]["parent_image_id"], old._IMAGE)
        self.assertEqual(
            result["proof"]["native_capture_digest"],
            old._digest(canonical_json(self.native) + b"\n"),
        )
        self.assertEqual(self.native["decision"]["route_pass_count"], 0)
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key.endswith("_eligible")
            )
        )

    def test_rejects_source_mapping_generated_provenance_and_bundle_drift(self) -> None:
        for mutation in (
            "source",
            "source_missing",
            "source_duplicate",
            "mapping",
            "manifest",
            "bundle_size",
            "bundle_order",
            "bundle_role",
            "old_collector",
            "old_recipe",
            "old_dockerfile",
            "collector_custody",
            "extra_source",
        ):
            with self.subTest(mutation=mutation):
                native, source, prepared = map(
                    deepcopy, (self.native, self.source, self.prepared)
                )
                artifact = native["composition"]["action"]["artifacts"][_ARTIFACT]
                if mutation == "source":
                    source["files"][0]["digest"] = _ZERO
                elif mutation == "source_missing":
                    source["files"].pop()
                elif mutation == "source_duplicate":
                    source["files"].append(deepcopy(source["files"][0]))
                elif mutation == "mapping":
                    prepared["path_mapping"]["native_root"] = "/elsewhere"
                elif mutation == "manifest":
                    prepared["build_sources"]["files"][0]["digest"] = _ZERO
                elif mutation.startswith("bundle_"):
                    bundle = native["route_observation"]["bundle"]
                    if mutation == "bundle_size":
                        bundle[0]["bytes"] += 1
                    elif mutation == "bundle_order":
                        bundle.reverse()
                    else:
                        bundle[0]["role"] = "probe"
                    native["source_artifacts"]["probe_bundle"] = deepcopy(bundle)
                elif mutation.startswith("old_"):
                    key = {
                        "old_collector": "probe",
                        "old_recipe": "capture_recipe",
                        "old_dockerfile": "dockerfile",
                    }[mutation]
                    artifact["collector"][key] = deepcopy(
                        self.retained["composition"]["action"]["artifacts"][_ARTIFACT][
                            "collector"
                        ][key]
                    )
                    if key == "probe":
                        native["source_artifacts"]["collector"] = deepcopy(
                            artifact["collector"][key]
                        )
                elif mutation == "collector_custody":
                    artifact["collector"]["probe"]["stat"]["inode"] = 0
                    native["source_artifacts"]["collector"] = deepcopy(
                        artifact["collector"]["probe"]
                    )
                else:
                    native["source_artifacts"]["unbound"] = {}
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native, source=source, prepared=prepared)

    def test_rejects_parent_and_exact_inherited_artifact_custody_changes(self) -> None:
        for path, value in (
            (("activator", "digest"), _ZERO),
            (("activator_source", "stat", "inode"), 0),
            (("preflight", "stat", "mode"), "0666"),
            (("plugin", "index.js", "stat", "device"), True),
            (("skill", "file", "digest"), _ZERO),
            (("skill", "parents", 0, "mode"), "0777"),
            (("policy_command", "stat", "nlink"), 2),
            (("config", "file", "source", "stat", "inode"), 0),
            (("profile", "extra"), {}),
            (("runtime_lock", "file", "source", "extra"), None),
            (("force_probe", "runtime", "stat", "mode"), "0644"),
            (("force_probe", "source", "digest"), _ZERO),
        ):
            with self.subTest(path=path):
                native = deepcopy(self.native)
                _set(
                    native["composition"]["action"]["artifacts"][_ARTIFACT], path, value
                )
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_coherently_reencoded_host_mount_parent_and_owner_drift(
        self,
    ) -> None:
        for mutation in (
            "old_parent",
            "old_child",
            "layer",
            "ipc",
            "extra_bind",
            "destination",
            "runtime_rw",
            "route_rw",
            "volume_options",
            "owner",
            "source_commit",
            "public_volume",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                host = native["harness"]["document"]
                if mutation == "old_parent":
                    host["parent_image_id"] = host["image_lineage"]["parent"]["id"] = (
                        old._PARENT_IMAGE
                    )
                elif mutation == "old_child":
                    host["image_id"] = host["run_image_reference"] = host[
                        "image_lineage"
                    ]["child"]["id"] = old._IMAGE
                elif mutation == "layer":
                    host["image_lineage"]["added_layers"][-1] = _ZERO
                    host["image_lineage"]["child"]["layers"][-1] = _ZERO
                elif mutation == "ipc":
                    host["host_config"]["ipc_mode"] = "host"
                elif mutation == "extra_bind":
                    host["host_config"]["binds"].append("/tmp:/extra:ro")
                elif mutation == "destination":
                    host["route_input_mount"]["destination"] = "/elsewhere"
                elif mutation in ("runtime_rw", "route_rw"):
                    key = (
                        "openclaw_runtime_mount"
                        if mutation == "runtime_rw"
                        else "route_input_mount"
                    )
                    host[key].update(rw=True, mode="rw")
                elif mutation == "volume_options":
                    host["route_input_volume_identity"]["options"] = {"device": "/tmp"}
                elif mutation == "owner":
                    host["route_input_volume_identity"]["labels"][
                        "dev.aragorn.capture-owner"
                    ] = _SOURCE["commit"] + ":1"
                elif mutation == "source_commit":
                    host["source_commit"] = old._SOURCE["commit"]
                else:
                    action = native["route_observation"]["document"]["action"]
                    for state, key in (
                        ("prerequisites", "boundary_before"),
                        ("observations", "boundary_after"),
                    ):
                        action[state][key]["route_input_mount"]["records"][0][
                            "root"
                        ] = "/docker/volumes/aragorn-phase3-final-combined-v3-plugin-force-reinstall-route-input-90002/_data"
                    _sync_route(native)
                _sync_harness(native)
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_argv_execution_and_service_pid_join_drift(self) -> None:
        for mutation in (
            "argv",
            "interpreter",
            "environment",
            "uid",
            "namespace",
            "gateway_pid",
            "missing_pid",
            "extra_pid",
            "duplicate_pid",
            "boolean_pid",
            "process_pid",
            "process_groups",
            "coherent_worker_pid",
            "composition_pid",
            "command_service_pid",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                route = native["route_observation"]
                stack, execution = route["stack_before"], route["execution"]
                if mutation == "argv":
                    execution["argv"].append("--route-id")
                elif mutation == "interpreter":
                    execution["argv"][-2] = "/usr/local/bin/node"
                elif mutation == "environment":
                    execution["environment_names"].append("OPENCLAW_TEST_FAST")
                elif mutation == "uid":
                    execution["effective_identity"]["uid"] = 0
                elif mutation == "namespace":
                    route["gateway_pid_binding"]["mount_namespace"] = "/proc/1/ns/mnt"
                elif mutation == "gateway_pid":
                    route["gateway_pid_binding"]["pid"] += 1
                elif mutation == "missing_pid":
                    del stack["pids"][_WORKER]
                elif mutation == "extra_pid":
                    stack["pids"]["unbound.service"] = 99999
                elif mutation == "duplicate_pid":
                    stack["pids"][_WORKER] = stack["pids"][_GATEWAY]
                elif mutation == "boolean_pid":
                    stack["pids"][_WORKER] = True
                elif mutation == "process_pid":
                    stack["processes"][_WORKER]["pid"] = 99999
                elif mutation == "process_groups":
                    stack["processes"][_WORKER]["groups"] = [0]
                elif mutation == "coherent_worker_pid":
                    stack["pids"][_WORKER] = stack["processes"][_WORKER]["pid"] = 99999
                    native["composition"]["action"]["boundaries"]["processes"][_WORKER][
                        "pid"
                    ] = 99999
                elif mutation == "composition_pid":
                    native["composition"]["action"]["boundaries"]["processes"][_WORKER][
                        "pid"
                    ] += 1
                else:
                    action = route["document"]["action"]
                    command = action["prerequisites"]["system_info_before"]["command"]
                    command["pid"] = stack["pids"][_WORKER]
                    action["commands"][1] = deepcopy(command)
                    _sync_route(native)
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_raw_binding_and_coherent_semantic_drift(self) -> None:
        for mutation in (
            "base64",
            "marker",
            "pretty",
            "duplicate",
            "document",
            "force_exit",
            "target",
            "extra_route",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                route = native["route_observation"]
                action = route["document"]["action"]
                if mutation == "base64":
                    route["raw"]["base64"] = base64.b64encode(b"{}").decode()
                elif mutation == "marker":
                    route["raw"]["raw_is_canonical_json_lf"] = False
                elif mutation in ("pretty", "duplicate"):
                    raw = (
                        (json.dumps(route["document"], indent=2) + "\n").encode()
                        if mutation == "pretty"
                        else b'{"schema":"duplicate",'
                        + canonical_json(route["document"])[1:]
                        + b"\n"
                    )
                    route["raw"].update(_raw(raw), raw_is_canonical_json_lf=False)
                elif mutation == "document":
                    route["document"]["run_nonce"] = "0" * 32
                elif mutation == "force_exit":
                    command = action["observations"]["native_force_reinstall"][
                        "command"
                    ]
                    command["exit_code"] = 0
                    action["commands"][4] = deepcopy(command)
                    _sync_route(native)
                elif mutation == "target":
                    action["observations"]["native_force_reinstall"][
                        "target_plugin_id"
                    ] = "unbound-plugin"
                    _sync_route(native)
                else:
                    route["extra"] = {}
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_invocation_chronology_and_qualification_claims(self) -> None:
        for mutation in (
            "recipe_digest",
            "recipe_path",
            "checkout",
            "invocation_exit",
            "completed",
            "composition_before",
            "outer_before",
            "boolean_exit",
            "eligibility",
            "pass_count",
        ):
            with self.subTest(mutation=mutation):
                native, invocation = map(deepcopy, (self.native, self.invocation))
                route = native["route_observation"]
                if mutation == "recipe_digest":
                    invocation["recipe"]["digest"] = _ZERO
                elif mutation == "recipe_path":
                    invocation["argv"][1] = "/tmp/unbound.sh"
                elif mutation == "checkout":
                    invocation["argv"][2] = "/elsewhere"
                elif mutation == "invocation_exit":
                    invocation["exit_code"] = False
                elif mutation == "completed":
                    invocation["completed_at"] = invocation["started_at"]
                elif mutation == "composition_before":
                    native["composition"]["recorded_at"] = route["execution"][
                        "started_at"
                    ]
                elif mutation == "outer_before":
                    native["recorded_at"] = route["execution"]["started_at"]
                elif mutation == "boolean_exit":
                    route["execution"]["exit_code"] = False
                elif mutation == "eligibility":
                    native["decision"]["phase3_exit_eligible"] = True
                else:
                    native["decision"]["route_pass_count"] = 1
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native, invocation=invocation)


if __name__ == "__main__":
    unittest.main()
