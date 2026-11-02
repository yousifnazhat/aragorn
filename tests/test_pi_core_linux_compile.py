"""One registered real compiler-only build; no Node/worker/provider execution.

This stage is deliberately separate from the inert assembler tests. It must be
scheduled once by the reviewed Phase 3 pipeline, whose failed-fingerprint gate
prohibits an unchanged automatic retry. Missing tools/artifacts fail, never skip.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest
import uuid

_ROOT = Path(__file__).resolve().parents[1]
_RECORD = _ROOT / "packaging/pi-core/linux-build-toolchain-v1.json"
_SPEC = importlib.util.spec_from_file_location("pi_linux_compile_builder", _ROOT / "scripts/build_pi_core_linux.py")
assert _SPEC and _SPEC.loader
builder = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(builder)


class PiCoreLinuxCompileTests(unittest.TestCase):
    def test_pinned_linux_compiler_builds_connected_sources_once(self) -> None:
        record_raw = builder.regular_bytes(_RECORD)
        record = json.loads(record_raw)
        self.assertEqual(record["schema"], "aragorn/pi-core-linux-build-toolchain/v1")
        self.assertEqual(record["purpose"], "LOCAL_COMPILER_ONLY_BUILD_NOT_RUNTIME_EXECUTION_OR_OS_QUALIFICATION")
        docker = record["docker"]
        self.assertEqual(docker["executable"], builder.DOCKER)
        self.assertEqual(docker["context"], builder.CONTEXT)
        self.assertEqual(docker["context"], "colima")
        self.assertEqual(docker["server_os"], "linux")
        self.assertEqual(docker["server_arch"], "arm64")
        self.assertEqual(docker["precondition"], "ALREADY_RUNNING_NO_VM_START_OR_CONTEXT_SWITCH")
        constraints = record["constraints"]
        self.assertEqual(constraints["build_timeout_seconds"], 120)
        self.assertTrue(constraints["compiler_only"])
        self.assertFalse(constraints["node_or_worker_execution"])
        self.assertFalse(constraints["automatic_effect_or_build_retry"])
        self.assertEqual(constraints["runtime_package_occurrences"], 89)
        self.assertEqual(constraints["network"], "none")
        self.assertEqual(constraints["pull"], "never")
        self.assertEqual(set(record["archives"]), {"node", "typescript", "compiler"})
        artifacts: dict[str, Path] = {}

        def verify_bytes() -> None:
            executable = Path(docker["executable"])
            resolved = executable.resolve(strict=True)
            self.assertEqual(str(resolved), docker["resolved_executable"])
            self.assertEqual(builder.sha256(builder.regular_bytes(resolved)), docker["sha256"])
            for name, item in record["archives"].items():
                path = _ROOT / item["path"]
                self.assertEqual(path.absolute(), path.resolve(strict=True), "linked compiler archive path")
                self.assertTrue(path.is_relative_to(_ROOT / ".aragorn/pi-core-build-inputs"))
                raw = builder.regular_bytes(path)
                self.assertEqual(len(raw), item["bytes"])
                self.assertEqual(builder.sha256(raw), item["sha256"])
                artifacts[name] = path
            self.assertEqual(builder.regular_bytes(_RECORD), record_raw, "reviewed toolchain record changed")

        verify_bytes()
        # Reuse the builder's clean environment, explicit context, bounded output
        # and deadline handling for read-only preflight metadata. This never calls
        # colima start, context use, daemon activation or the historical VM.
        preflight = builder.DockerBuild(_ROOT, timeout=60)
        endpoint = preflight.command(["context", "inspect", "colima", "--format", "{{json .Endpoints.docker.Host}}"])
        self.assertEqual(endpoint.returncode, 0, endpoint.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(json.loads(endpoint.stdout), docker["endpoint"])
        version = preflight.command([
            "version", "--format",
            "{{json .Client.Version}}|{{json .Server.Version}}|{{json .Server.Os}}|{{json .Server.Arch}}",
        ])
        self.assertEqual(version.returncode, 0, version.stderr.decode("utf-8", errors="replace"))
        self.assertEqual([json.loads(item) for item in version.stdout.decode("ascii").strip().split("|")],
                         [docker["client_version"], docker["server_version"], docker["server_os"], docker["server_arch"]])
        output = _ROOT / ".aragorn/pi-core-build" / ("d2-" + uuid.uuid4().hex)
        print(json.dumps({"compiler_build_output": str(output), "context": "colima",
                          "toolchain_record_sha256": builder.sha256(record_raw)}), flush=True)
        # One invocation, never catch-and-retry. Failure leaves the owned output
        # directory/log and the pipeline's failed fingerprint for diagnosis.
        receipt = builder.build(_ROOT, output, artifacts["node"], artifacts["typescript"],
                                artifacts["compiler"], timeout=120)
        verify_bytes()
        self.assertEqual(receipt["schema"], "aragorn/pi-core-linux-build/v1")
        self.assertEqual(receipt["status"], "COMPILED_NOT_DEPLOYED_OR_OS_QUALIFIED")
        self.assertFalse(receipt["runtime_executed"])
        self.assertFalse(receipt["install_scripts_executed"])
        self.assertTrue(receipt["cleanup"]["owned_container_absent"])
        self.assertTrue(receipt["cleanup"]["owned_image_absent"])
        self.assertEqual(receipt["inputs"]["runtime_package_occurrences"], 89)
        self.assertEqual(receipt["deployment_tree_sha256"],
                         builder.sha256(builder.canonical(receipt["deployment_inventory"])))
        self.assertEqual(json.loads(builder.regular_bytes(output / "build-receipt.json")), receipt)
        print(json.dumps({"receipt": str(output / "build-receipt.json"),
                          "deployment_tree_sha256": receipt["deployment_tree_sha256"],
                          "status": receipt["status"], "runtime_executed": False}), flush=True)


if __name__ == "__main__":
    unittest.main()
