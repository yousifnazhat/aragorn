"""New Pi bootstrap/entrypoint checks, not live or deployment qualification."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = _ROOT / "packaging/pi-core"
_NODE = Path("/opt/homebrew/bin/node")
_NODE_VERSION = "v26.3.1"
_SPEC = importlib.util.spec_from_file_location(
    "pi_entrypoint_inventory", _ROOT / "scripts/build_pi_core_linux.py"
)
assert _SPEC and _SPEC.loader
_build = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_build)


def _dependency_digest() -> str:
    # Reuse only inert inventory helpers; never call compiler/container assembly.
    return _build.sha256(_build.canonical(_build.tree_inventory(_PACKAGE / "node_modules")))


class PiCoreEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        manifest = json.loads((_PACKAGE / "offline-toolchain-v1.json").read_bytes())
        if manifest["schema"] != "aragorn/pi-core-offline-toolchain/v1":
            raise AssertionError("unexpected offline toolchain schema")
        if manifest["node"]["executable"] != str(_NODE) or manifest["node"]["version"] != _NODE_VERSION:
            raise AssertionError("unexpected pinned offline Node toolchain")
        cls.node_digest = hashlib.sha256(_NODE.read_bytes()).hexdigest()
        if cls.node_digest != manifest["node"]["sha256"]:
            raise AssertionError("Node bytes differ from the reviewed toolchain")
        cls.lock_digest = hashlib.sha256((_PACKAGE / "package-lock.json").read_bytes()).hexdigest()
        if cls.lock_digest != manifest["preparation"]["package_lock_sha256"]:
            raise AssertionError("package lock differs from the reviewed offline preparation")
        cls.dependency_digest = _dependency_digest()
        if cls.dependency_digest != manifest["dependency_tree_sha256"]:
            raise AssertionError("dependency bytes differ from the reviewed toolchain")
        cls.temporary = tempfile.TemporaryDirectory(prefix="aragorn-pi-entrypoint-inert-")
        cls.addClassCleanup(cls.temporary.cleanup)
        # No inherited credentials, proxies, HOME settings, NODE_OPTIONS/loaders.
        cls.environment = {
            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "HOME": cls.temporary.name, "TMPDIR": cls.temporary.name,
        }
        version = subprocess.run(
            [str(_NODE), "--version"], cwd=_ROOT, env=cls.environment,
            capture_output=True, timeout=5, check=False,
        )
        if version.returncode or version.stdout.decode("ascii").strip() != _NODE_VERSION:
            raise AssertionError("the pinned Node version check failed")
        cls.fixtures: dict[str, dict] = {}

    @classmethod
    def tearDownClass(cls) -> None:
        if hashlib.sha256(_NODE.read_bytes()).hexdigest() != cls.node_digest:
            raise AssertionError("Node changed during the offline entrypoint checks")
        if hashlib.sha256((_PACKAGE / "package-lock.json").read_bytes()).hexdigest() != cls.lock_digest:
            raise AssertionError("lock changed during the offline entrypoint checks")
        if _dependency_digest() != cls.dependency_digest:
            raise AssertionError("dependencies changed during the offline entrypoint checks")

    def case(self, name: str) -> dict:
        if name not in self.fixtures:
            completed = subprocess.run(
                [str(_NODE), "--no-warnings", str(_ROOT / "tests/fixtures/pi_core_entrypoint_offline.mjs"), name],
                cwd=_ROOT, env=self.environment, capture_output=True, timeout=8, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
            self.assertLessEqual(len(completed.stdout), 2 * 1024 * 1024)
            fixture = json.loads(completed.stdout)
            self.assertEqual(fixture["selected"], name)
            self.assertEqual(fixture["nodeVersion"], _NODE_VERSION)
            self.assertEqual(fixture["fixture"], "PI_ENTRYPOINT_IN_MEMORY_BOOTSTRAP_AND_SCRIPTED_PI_NOT_DEPLOYMENT_EVIDENCE")
            self.assertEqual(fixture["liveIO"], [], "entrypoint attempted prohibited live I/O")
            self.assertEqual(fixture["remappedWorkerImports"], 1, "source fixture must remap only its worker import")
            self.fixtures[name] = fixture
        return self.fixtures[name]["result"]

    def refused(self, name: str, message: str) -> dict:
        result = self.case(name)
        self.assertIsNone(result["value"])
        self.assertEqual(result["error"]["name"], "TypeError")
        self.assertIn(message, result["error"]["message"])
        return result

    def test_parse_copies_exact_start_without_native_activation(self) -> None:
        result = self.case("parse")
        self.assertIsNone(result["error"])
        value = result["value"]
        self.assertEqual(set(value), {"schema", "activation_id", "system_prompt", "task", "model", "limits", "relay", "provider_status"})
        self.assertEqual(value["activation_id"], "a" * 32)
        self.assertEqual(value["limits"]["maxTurns"], 2)
        self.assertEqual(value["provider_status"], "UNAVAILABLE")

    def test_well_formed_unicode_prompt_is_lossless(self) -> None:
        result = self.case("unicode")
        self.assertIsNone(result["error"])
        self.assertEqual(result["value"]["task"], "café 😀\n")

    def test_ready_provider_cannot_enable_native_execution(self) -> None:
        self.refused("unknownProvider", "Unsupported bootstrap schema or provider route")

    def test_extra_secret_or_configuration_fields_are_rejected(self) -> None:
        self.refused("extraField", "Invalid bootstrap fields")

    def test_activation_identifier_rejects_trailing_newline(self) -> None:
        self.refused("trailingId", "Invalid bootstrap identifier")

    def test_unpaired_utf16_text_is_rejected(self) -> None:
        self.refused("unpairedText", "Invalid bootstrap text")

    def test_individual_text_budget_is_enforced(self) -> None:
        self.refused("excessiveText", "Invalid bootstrap text")

    def test_canonical_expansion_cannot_exceed_total_wire_budget(self) -> None:
        self.refused("totalWireLimit", "Bootstrap frame limit")

    def test_unsafe_integer_does_not_round_into_authority(self) -> None:
        self.refused("unsafeInteger", "Invalid bootstrap integer")

    def test_run_budget_cannot_exceed_thirty_seconds(self) -> None:
        self.refused("excessiveDeadline", "Invalid bootstrap integer")

    def test_fractional_model_cost_is_not_silently_rounded(self) -> None:
        self.refused("fractionalCost", "Invalid bootstrap integer")

    def test_relay_path_traversal_is_rejected(self) -> None:
        self.refused("relayTraversal", "Invalid bootstrap relay")

    def test_gateway_and_relay_worker_cannot_share_uid(self) -> None:
        self.refused("relaySameUid", "Invalid bootstrap relay")

    def test_model_configuration_cannot_carry_provider_credentials(self) -> None:
        self.refused("modelCredential", "Invalid bootstrap fields")

    def test_accessor_is_rejected_without_invocation(self) -> None:
        result = self.refused("accessor", "Invalid bootstrap fields")
        self.assertNotIn("accessor invoked", result["error"]["message"])

    def test_duplicate_json_keys_are_not_accepted_as_canonical(self) -> None:
        self.refused("duplicateKey", "Noncanonical bootstrap frame")

    def test_whitespace_variant_cannot_bypass_canonical_bytes(self) -> None:
        self.refused("noncanonical", "Noncanonical bootstrap frame")

    def test_raw_unsafe_wire_integer_is_rejected(self) -> None:
        self.refused("rawUnsafeInteger", "non-canonical JSON number")

    def test_truncated_length_prefixed_frame_is_rejected(self) -> None:
        self.refused("truncated", "Invalid bootstrap frame")

    def test_oversized_frame_is_rejected_before_json_parsing(self) -> None:
        self.refused("oversizedFrame", "Bootstrap frame limit")

    def test_non_ascii_wire_encoding_is_rejected(self) -> None:
        self.refused("rawNonAscii", "Invalid bootstrap frame")

    def test_same_channel_stays_alive_until_correlated_release(self) -> None:
        result = self.case("channel")
        self.assertIsNone(result["error"])
        self.assertEqual(result["report"], {"activationId": "a" * 32, "status": "PROVIDER_UNAVAILABLE", "released": True})
        self.assertEqual(result["reads"], 2)
        self.assertEqual(result["order"], ["aragorn/pi-core-bootstrap-hello/v1", "read-1", "aragorn/pi-core-bootstrap-result/v1", "read-2"])
        self.assertEqual(result["writes"][0], {"schema": "aragorn/pi-core-bootstrap-hello/v1", "worker_nonce": "b" * 32})
        self.assertEqual(result["writes"][1], {
            "schema": "aragorn/pi-core-bootstrap-result/v1", "activation_id": "a" * 32,
            "status": "PROVIDER_UNAVAILABLE", "authority": "BOOTSTRAP_STATUS_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
        })

    def test_channel_rejects_unimplemented_provider_after_hello_only(self) -> None:
        result = self.case("channelUnknownProvider")
        self.assertIsNone(result["report"])
        self.assertEqual(result["error"]["name"], "TypeError")
        self.assertIn("provider route", result["error"]["message"])
        self.assertEqual(len(result["writes"]), 1)
        self.assertEqual(result["reads"], 1)

    def test_wrong_activation_release_cannot_report_success(self) -> None:
        result = self.case("channelWrongRelease")
        self.assertIsNone(result["report"])
        self.assertEqual(result["error"]["message"], "Invalid bootstrap release")
        self.assertEqual(len(result["writes"]), 2)
        self.assertEqual(result["reads"], 2)

    def test_missing_release_expires_without_reconnect(self) -> None:
        result = self.case("channelMissingRelease")
        self.assertIsNone(result["report"])
        self.assertIn("deadline", result["error"]["message"])
        self.assertEqual(result["reads"], 2)
        self.assertEqual(len(result["writes"]), 2)

    def test_explicit_composition_binds_actual_pi_and_stops_after_one_inert_request(self) -> None:
        result = self.case("compose")
        self.assertIsNone(result["error"])
        self.assertEqual(result["providerCalls"], 1)
        self.assertEqual(len(result["requests"]), 1)
        request = result["requests"][0]
        self.assertEqual(request["session_id"], "a" * 32)
        self.assertEqual(request["run_id"], "a" * 32)
        self.assertEqual(request["target_name"], "entry-fixture.txt")
        report = result["report"]
        self.assertEqual(report["status"], "STOPPED")
        self.assertEqual(report["stopReason"], "RELAY_NOT_SUBMITTED")
        self.assertEqual(report["authority"], "ADAPTER_CORRELATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY")
        self.assertEqual(report["correlation"], {"sessionId": "a" * 32, "runId": "a" * 32})
        self.assertEqual(report["toolCalls"], 1)
        self.assertEqual(report["results"][0]["transportStatus"], "NOT_SUBMITTED")
        self.assertIsNone(report["results"][0]["sourceResult"]["broker_result"])
        messages = result["contexts"][0]["messages"]
        self.assertEqual(messages[0]["content"], "Owned offline fixture; only the supplied request tool exists.")
        self.assertEqual(messages[1]["content"], [{"type": "text", "text": "Issue one inert request."}])

    def test_original_composition_deadline_bounds_uncooperative_provider(self) -> None:
        result = self.case("composeDeadline")
        self.assertIsNone(result["error"])
        self.assertEqual(result["providerCalls"], 1)
        self.assertEqual(result["requests"], [])
        self.assertEqual(result["report"]["status"], "STOPPED")
        self.assertEqual(result["report"]["stopReason"], "DEADLINE_EXCEEDED")
        self.assertFalse(result["report"]["agentSettled"])

    def test_composition_requires_explicit_provider_not_fallback(self) -> None:
        result = self.case("composeMissingProvider")
        self.assertIsNone(result["report"])
        self.assertEqual(result["error"]["name"], "TypeError")
        self.assertEqual(result["providerCalls"], 0)
        self.assertEqual(result["requests"], [])

    def test_expired_original_deadline_prevents_provider_and_relay(self) -> None:
        result = self.case("composeExpired")
        self.assertIsNone(result["report"])
        self.assertEqual(result["error"]["message"], "Invalid original Pi deadline")
        self.assertEqual(result["providerCalls"], 0)
        self.assertEqual(result["requests"], [])


if __name__ == "__main__":
    unittest.main()
