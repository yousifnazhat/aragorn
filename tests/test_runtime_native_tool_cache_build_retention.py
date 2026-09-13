"""Fixed retained report joins; no build execution or independent attestation."""

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from aragorn.artifact_closure import canonical_json

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = (
    "benchmark/evidence/phase3-native-tool-runtime-build-development-v2-2026-09-13.json"
)
PIN = (40591, "a1d302431804f760299e1bcbd16aa269214ce0f35e2b8996c9f0cd3d03658877")
VOLUMES = (
    "aragorn-native-cache-source-79ed6eb-v1",
    "aragorn-native-cache-out-79ed6eb-v1",
    "aragorn-native-cache-runtime-79ed6eb-v1",
)
DEPENDENCY = "aragorn-native-build-3f59777-behwtstv-source"
OWNER = {"dev.aragorn.capture-owner": "native-cache-build-79ed6eb-v1"}
TREE = {
    "algorithm": "aragorn/runtime-tree/v1",
    "entry_count": 31988,
    "file_count": 31970,
    "symlink_count": 18,
    "total_bytes": 289776316,
    "tree_digest": "sha256:4e6e94cf4fb8a2527ec1cd789b20a7ddf6c84f03973b3579ded64ef8e2ef96c3",
}
LIMITS = {
    "build_execution_independently_attested",
    "common_profile_activation",
    "complete_dynamic_import_closure",
    "hostile_same_process_boundary",
    "independent_build_reproduction",
    "installed_build_dependency_bytes_independently_verified",
    "live_warm_cache_native_receipts",
    "mandatory_native_capture",
    "native_causation",
    "performance_qualification",
    "phase3_eligible",
    "pnpm_archive_integrity_independently_verified",
    "production_activation_eligible",
    "run_conformance_eligible",
}


def _pin(raw, expected):
    if type(raw) is not bytes or len(raw) != expected[0]:
        raise ValueError("fixed retained byte length or type changed")
    if hashlib.sha256(raw).hexdigest() != expected[1]:
        raise ValueError("fixed retained digest changed")


def _read(name, expected):
    with (ROOT / name).open("rb") as stream:
        raw = stream.read(expected[0] + 1)
    _pin(raw, expected)
    return raw


def _load(raw):
    _pin(raw, PIN)
    document = json.loads(raw)
    if raw != canonical_json(document) + b"\n":
        raise ValueError("fixed canonical JSON and final LF changed")
    return document


def _record_pin(record):
    return record["bytes"], record["digest"].removeprefix("sha256:")


class NativeToolCacheBuildRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = _read(ARTIFACT, PIN)
        cls.document = _load(cls.raw)

    def test_bounded_exact_pin_preparse_and_unqualified_scope(self):
        for raw in (bytearray(self.raw), self.raw[:-1], self.raw + b"\n"):
            with (
                patch.object(hashlib, "sha256") as digest,
                patch.object(json, "loads") as parser,
            ):
                with self.assertRaises(ValueError):
                    _load(raw)
                digest.assert_not_called()
                parser.assert_not_called()
        with patch.object(json, "loads") as parser, self.assertRaises(ValueError):
            _load(self.raw[:-1] + b" ")
        parser.assert_not_called()
        # Even a supplied matching pin cannot make noncanonical bytes acceptable.
        changed = self.raw[:-1] + b" "
        with (
            patch(
                __name__ + ".PIN", (len(changed), hashlib.sha256(changed).hexdigest())
            ),
            self.assertRaises(ValueError),
        ):
            _load(changed)
        with patch.object(
            Path, "open", unittest.mock.mock_open(read_data=self.raw)
        ) as opened:
            self.assertEqual(_read(ARTIFACT, PIN), self.raw)
            opened.return_value.read.assert_called_once_with(PIN[0] + 1)
        d = self.document
        self.assertEqual(
            d["schema"], "aragorn/phase3-native-tool-runtime-build-development/v2"
        )
        self.assertEqual(d["status"], "OBSERVED")
        self.assertEqual(
            d["authority"],
            "OPERATOR_OBSERVED_ISOLATED_CACHE_COMPATIBILITY_BUILD_NOT_DEPLOYMENT_OR_RUN_AUTHORITY",
        )
        self.assertEqual(set(d["proof_limits"]), LIMITS)
        self.assertTrue(all(value is False for value in d["proof_limits"].values()))
        self.assertEqual(len(d["checks"]), 8)
        self.assertTrue(all(value == "PASSED" for value in d["checks"].values()))
        self.assertIs(
            d["dependencies"]["source_archive_ownership_and_mode_equivalence"], False
        )
        # Historical evidence remains exact, not rewritten as the new build.
        _read(
            ARTIFACT.replace("development-v2", "development-v1"),
            (30193, "af23bde8b997ec4e6e8f18cf05159d6aa6ac8c3e34f4b60e77e81eab43f6405a"),
        )

    def test_retained_runtime_source_dependency_isolation_and_cleanup_joins(self):
        d, eq = self.document, self.assertEqual
        eq(d["source"]["commit"], "79ed6ebe170a4926081874a141ae149d4cd0db6c")
        eq(d["upstream"]["commit"], "7fa98d8e21b6d5937f25a7f19445ff683bb980bf")
        eq(d["source"]["signature_check"], "GOOD_LOCAL_GIT_SIGNATURE")
        eq(len(d["source"]["materializers"]), 2)
        for record in d["source"]["materializers"]:
            _read(record["path"], _record_pin(record))
        overlays = {
            record.get("path", record.get("name")): record
            for record in d["overlay_files"]
        }
        eq(len(overlays), 5)
        eq(
            _record_pin(overlays["src/plugins/tools.ts"]),
            (47899, "d9bb350dfae70081e86b219e285bfc55470afc8d6775b999146859710b96e156"),
        )
        integration = overlays[
            "/usr/lib/aragorn/openclaw/aragorn-runtime-native-tool-client/integration.cjs"
        ]
        _read(
            "packaging/openclaw/aragorn-runtime-native-tool-client/integration.cjs",
            _record_pin(integration),
        )
        eq(d["package"]["size"], d["package"]["archive"]["bytes"])
        eq(
            _record_pin(d["package"]["archive"]),
            (
                19921213,
                "9923017c01a2905a4cc953f817e5ea2dfb75ece462f6376d589a664bfdbb4df2",
            ),
        )
        eq(d["package"]["bundled"], ["@openclaw/ai"])
        runtime, final = d["runtime_measurement"], d["final_runtime_measurement"]
        eq(runtime["before"], TREE)
        eq(runtime["after"], TREE)
        eq(final["tree"], TREE)
        eq(runtime["mount"], final["mount"])
        self.assertIs(final["read_only"], True)
        self.assertIs(runtime["mount"]["read_only"], True)
        eq(
            runtime["mount"]["records"][0]["root"],
            f"/docker/volumes/{VOLUMES[2]}/_data",
        )
        eq(runtime["identity"], {"uid": 1000, "gid": 1000, "groups": [1000]})
        eq(
            runtime["cli"],
            {
                "signal": None,
                "status": 0,
                "stderr": "",
                "stdout": "OpenClaw 2026.7.1\n",
            },
        )
        for name in (
            "phase3_eligible",
            "production_activation_eligible",
            "run_conformance_eligible",
        ):
            self.assertIs(runtime[name], False)
        files = {
            item["path"].removeprefix("/runtime/lib/node_modules/openclaw/"): item
            for item in runtime["files"]
        }
        eq(len(files), 6)
        upstream = {item["path"]: item for item in d["upstream"]["files"]}
        eq(
            _record_pin(files["npm-shrinkwrap.json"]),
            _record_pin(upstream["npm-shrinkwrap.json"]),
        )
        eq(
            _record_pin(files["openclaw.mjs"]),
            (23463, "f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"),
        )
        eq(
            _record_pin(files["dist/tools-Bo-ay9Al.js"]),
            (38779, "e22d574c1b0940016900fe26e7af1dd0c48ccab54d1bb173fa75ff7e68a87a6d"),
        )
        eq(d["runtime_volume"], VOLUMES[2])
        eq(d["runtime_volume_inspect"]["Name"], VOLUMES[2])
        eq(d["runtime_volume_inspect"]["Labels"], OWNER)
        dependencies = d["dependencies"]
        eq(dependencies["build_cache_source_volume"], DEPENDENCY)
        for name in (
            "build_cache_source_mounted_read_only",
            "package_openclaw_namespace_private_tmpfs",
            "install_lifecycle_scripts_enabled",
            "source_archive_freshly_extracted",
        ):
            self.assertIs(dependencies[name], True)
        self.assertIs(dependencies["npm_optional_dependencies_omitted"], False)
        containers, failures = d["containers"], d["failed_attempts"]
        eq((len(containers), len(failures)), (6, 3))
        eq(
            [item["cause"] for item in failures],
            [
                "FRESH_VOLUME_OWNER_CHANGED_DURING_DOCKER_POPULATION",
                "TAR_COMPARISON_INCLUDED_EXPECTED_NONROOT_METADATA_DIFFERENCES",
                "PACKAGE_HELPER_REQUIRES_PRIVATE_WRITABLE_OPENCLAW_NAMESPACE",
            ],
        )
        all_containers = containers + [item["container"] for item in failures]
        for index, container in enumerate(all_containers):
            state, host = container["state"], container["host"]
            eq((state["Status"], state["Error"]), ("exited", ""))
            eq(state["ExitCode"], 0 if index < 6 else (2, 1, 1)[index - 6])
            for name in ("Dead", "OOMKilled", "Paused", "Restarting", "Running"):
                self.assertIs(state[name], False)
            eq(container["user"], "1000:1000")
            eq(container["labels"], OWNER)
            eq(host["network_mode"], "none")
            eq(host["cap_drop"], ["ALL"])
            self.assertIsNone(host["cap_add"])
            self.assertIs(host["readonly_rootfs"], True)
            eq(host["security_opt"], ["no-new-privileges"])
            configured = {item["Target"]: item for item in host["configured_mounts"]}
            actual = {item["Destination"]: item for item in container["mounts"]}
            eq(set(configured), set(actual))
            for target, mounted in configured.items():
                eq(mounted["Type"], "volume")
                self.assertIn(mounted["Source"], (*VOLUMES, DEPENDENCY))
                eq(actual[target]["Name"], mounted["Source"])
                eq(actual[target]["Type"], "volume")
                self.assertIs(actual[target]["RW"], not mounted.get("ReadOnly", False))
                if mounted["Source"] == DEPENDENCY:
                    self.assertIs(mounted["ReadOnly"], True)
                    if target == "/source/node_modules":
                        eq(mounted["VolumeOptions"]["Subpath"], "node_modules")
                if index < 6:
                    self.assertIs(mounted["VolumeOptions"]["NoCopy"], True)
        pack = containers[2]
        eq(
            pack["host"]["tmpfs"]["/source/node_modules/@openclaw"],
            "rw,nosuid,nodev,size=128m,mode=755,uid=1000,gid=1000",
        )
        for container in containers[4:]:
            eq(len(container["mounts"]), 1)
            self.assertIs(container["mounts"][0]["RW"], False)
            eq(container["mounts"][0]["Name"], VOLUMES[2])
        cleanup = d["cleanup"]
        ids = {container["id"] for container in all_containers}
        eq(len(ids), 9)
        eq(len(cleanup["owned_containers_removed"]), 9)
        eq(set(cleanup["owned_containers_removed"]), ids)
        self.assertIs(
            cleanup["absence_verified"], True
        )  # Retained operator report only.
        eq(cleanup["remaining_container_count"], 78)
        eq(cleanup["running_containers"], 0)
        eq(cleanup["volumes_retained"], list(VOLUMES))


if __name__ == "__main__":
    unittest.main()
