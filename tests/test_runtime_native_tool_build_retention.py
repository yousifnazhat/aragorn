"""Fixed report checks only; no build, reference execution, or attestation."""

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from aragorn.artifact_closure import canonical_json

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = (
    "benchmark/evidence/phase3-native-tool-runtime-build-development-v1-2026-09-13.json"
)
REFERENCE = "benchmark/evidence/reference/native-tool-read-callback-development-v1-2026-09-13.mjs.txt"
ARTIFACT_PIN = (
    30193,
    "af23bde8b997ec4e6e8f18cf05159d6aa6ac8c3e34f4b60e77e81eab43f6405a",
)
REFERENCE_PIN = (
    7378,
    "54efb0fa9f4d8f0f661451c1f03fdb7b3846b5d8539ed7044ce719a28814c560",
)
PREFIX = "/runtime/lib/node_modules/openclaw/"
VOLUMES = (
    "aragorn-native-build-3f59777-behwtstv-source",
    "aragorn-native-build-3f59777-behwtstv-out",
    "aragorn-native-runtime-4339c83-behwtstv-v1",
)
LIMITS = {
    "build_execution_independently_attested",
    "common_profile_activation",
    "complete_dynamic_import_closure",
    "durable_receipt_in_read_check",
    "general_release_qualification",
    "hostile_same_process_boundary",
    "independent_build_reproduction",
    "installed_build_dependency_bytes_independently_verified",
    "mandatory_native_capture",
    "native_causation",
    "performance_qualification",
    "phase3_eligible",
    "pnpm_archive_integrity_independently_verified",
    "production_activation_eligible",
    "real_native_client_in_read_check",
    "real_native_credential_projection",
    "run_conformance_eligible",
    "runtime_tree_covers_directory_ownership_or_external_symlink_referents",
}
# Earlier plain-package bytes joined to reported installed bytes, not execution.
COMPILED = """
agent-tools.before-tool-call-CtV_fW99.js 80308 7b3491137688feb782f8505a3721dda55a6b0346872cd5d9a748779512494f69
tool-split-CILNwU1m.js 14740 116dfcf60c80a2754c7863a6596f23a496f7fcde29c0fd72346145e8b80b63e1
agent-tools-1egbMBnJ.js 61852 ed87514d61ac979e65e04457f3c6ed91d58709b1b8eec692d2da343dd0c76aa9
selection-N6bDOw2l.js 673592 28c1792c5d247e74d75357fbf9a284b75677cc0907791d350db1a1fafbb73f89
tool-search-BZ7yP35g.js 60337 df273766df64690ecb0953ee39bbf7c3c1f3214347e45f79b3b921c2e1142976
gateway-D3xfXAqS.js 24432 663c265311327717f9e267f4a218bbfdb5173f0dda0872b2c18825e89dd020c7
build-info.json 87 6bbed5c2510d821e582972d7fd5f99d326458897d313cf571dae8a2ac0fb3fc1
""".strip().splitlines()


def _pin(raw, expected):
    if (
        type(raw) is not bytes
        or (len(raw), hashlib.sha256(raw).hexdigest()) != expected
    ):
        raise ValueError("fixed retained bytes changed")


def _read(name, expected):
    with (ROOT / name).open("rb") as stream:
        raw = stream.read(expected[0] + 1)
    _pin(raw, expected)
    return raw


def _load(raw, reference):
    _pin(raw, ARTIFACT_PIN)
    _pin(reference, REFERENCE_PIN)  # Both pins precede the first JSON parse.
    document = json.loads(raw)
    if raw != canonical_json(document) + b"\n":
        raise ValueError("expected canonical JSON plus one LF")
    return document


def _record_pin(record):
    return record["bytes"], record["digest"].removeprefix("sha256:")


class NativeToolBuildRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = _read(ARTIFACT, ARTIFACT_PIN)
        cls.reference = _read(REFERENCE, REFERENCE_PIN)
        cls.document = _load(cls.raw, cls.reference)

    def test_fixed_bytes_preparse_rejection_and_scope(self):
        for raw, reference in (
            (self.raw[:-1] + b" ", self.reference),
            (self.raw + b"\n", self.reference),
            (self.raw, self.reference[:-1] + b" "),
        ):
            with patch.object(json, "loads") as parser:
                with self.assertRaises(ValueError):
                    _load(raw, reference)
                parser.assert_not_called()
        d, eq = self.document, self.assertEqual
        eq(d["status"], "OBSERVED")
        eq(set(d["proof_limits"]), LIMITS)
        self.assertTrue(all(value is False for value in d["proof_limits"].values()))
        reference = d["read_check_reference"]
        eq((reference["path"], _record_pin(reference)), (REFERENCE, REFERENCE_PIN))
        self.assertIs(reference["reference_execution_attested"], False)
        check = d["read_callback_check"]
        eq(check["authority"], "RECORDING_TEST_DOUBLE_CALLBACK_COMPATIBILITY_ONLY")
        eq(check["public_export"], "openclaw/plugin-sdk/agent-harness")
        eq((check["callback_count"], check["integration_test_double_loads"]), (1, 1))
        for key in (
            "owned_temp_removed",
            "owned_text_file_unchanged",
            "frozen_detached_params_accepted",
            "result_owns_undefined_details",
        ):
            self.assertIs(check[key], True)
        for key in (
            "complete_import_closure_verified",
            "credentials_or_socket_exercised",
            "native_causation_verified",
            "phase3_eligible",
            "production_activation_eligible",
            "real_native_client_exercised",
            "receipt_retention_verified",
            "run_eligible",
        ):
            self.assertIs(check[key], False)

    def test_retained_isolation_cleanup_and_source_runtime_joins(self):
        d, eq = self.document, self.assertEqual
        containers = d["containers"]
        eq(len(containers), 7)
        eq(len({item["id"] for item in containers}), 7)
        isolation = {
            "network_mode": "none",
            "cap_add": None,
            "cap_drop": ["ALL"],
            "readonly_rootfs": True,
            "security_opt": ["no-new-privileges"],
        }
        for index, item in enumerate(containers):
            state = item["state"]
            eq((state["Status"], state["ExitCode"], state["Error"]), ("exited", 0, ""))
            for key in ("Dead", "OOMKilled", "Paused", "Restarting", "Running"):
                self.assertIs(state[key], False)
            eq({key: item["host"][key] for key in isolation}, isolation)
            eq(item["user"], "1000:1000")
            expected = (
                {"/source": VOLUMES[0], "/out": VOLUMES[1]}
                if index < 3
                else {"/runtime": VOLUMES[2]}
            )
            if index == 3:
                expected["/out"] = VOLUMES[1]
            eq(len(item["mounts"]), len(expected))
            eq({m["destination"]: m["name"] for m in item["mounts"]}, expected)
            for mount in item["mounts"]:
                eq(mount["type"], "volume")
                self.assertIs(mount["read_write"], index < 4)
        cleanup = d["cleanup"]
        eq(cleanup["removed_container_ids"], [item["id"] for item in containers])
        eq(cleanup["retained_volumes"], list(VOLUMES))
        eq(cleanup["running_containers"], 0)
        eq(cleanup["vm_status"], "Stopped")
        eq(cleanup["default_profile_status"], "Stopped")
        eq(d["source"]["commit"], "4339c83262c488487ab12192f919e7d99a6035cb")
        eq(d["upstream"]["commit"], "7fa98d8e21b6d5937f25a7f19445ff683bb980bf")
        materializer = d["source"]["materializer"]
        _read(materializer["path"], _record_pin(materializer))
        eq(
            _record_pin(d["package"]),
            (
                19923434,
                "c3e205d360710249fda5aee71a652299f6f3325864096b7e70211123939a3809",
            ),
        )
        self.assertIs(d["package"]["superseded_plain_pack"]["installed"], False)
        eq(d["package"]["bundled_workspace_dependency"], "@openclaw/ai@2026.7.1")
        runtime, final = d["runtime_measurement"], d["final_runtime_measurement"]
        eq(runtime["before"], runtime["after"])
        eq(runtime["before"], final["tree"])
        eq(
            final["tree"]["tree_digest"],
            "sha256:06335e3b80e89aa0157b037b1eea0d4078b40bf35d3c3960640a35a215d5bcd3",
        )
        eq(runtime["mount"], final["mount"])
        self.assertIs(final["read_only"], True)
        self.assertIs(runtime["mount"]["read_only"], True)
        eq(d["runtime_volume"], VOLUMES[2])
        eq(
            runtime["mount"]["records"][0]["root"],
            f"/docker/volumes/{VOLUMES[2]}/_data",
        )
        files = {item["path"]: item for item in runtime["files"]}
        for row in COMPILED:
            name, size, digest = row.split()
            eq(_record_pin(files[PREFIX + "dist/" + name]), (int(size), digest))
        upstream = {item["path"]: item for item in d["upstream"]["files"]}
        eq(
            _record_pin(files[PREFIX + "npm-shrinkwrap.json"]),
            _record_pin(upstream["npm-shrinkwrap.json"]),
        )
        eq(
            _record_pin(files[PREFIX + "package.json"]),
            _record_pin(d["read_callback_check"]["package_json"]),
        )
        overlay = {item["path"]: item for item in d["overlay_files"]}
        eq(runtime["companion"], overlay[runtime["companion"]["path"]])
        for key in (
            "phase3_eligible",
            "production_activation_eligible",
            "run_conformance_eligible",
        ):
            self.assertIs(runtime[key], False)


if __name__ == "__main__":
    unittest.main()
