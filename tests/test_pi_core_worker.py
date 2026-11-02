"""Pinned Pi loop with scripted model/relay, not live enforcement qualification."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_worker import _worker_request

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = _ROOT / "packaging" / "pi-core"
_NODE = Path("/opt/homebrew/bin/node")
_NODE_VERSION = "v26.3.1"


def _dependency_tree_digest(root: Path) -> str:
    """Hash every dependency file/link; no execution or symlink traversal."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("the pinned dependency directory is unavailable")
    rows: list[dict[str, object]] = []

    def visit(directory: Path) -> None:
        for path in directory.iterdir():
            mode = path.lstat().st_mode
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(mode):
                rows.append({"path": relative, "kind": "symlink", "target": os.readlink(path)})
            elif stat.S_ISDIR(mode):
                visit(path)
            elif stat.S_ISREG(mode):
                raw = path.read_bytes()
                rows.append({
                    "path": relative, "kind": "file", "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                })
            else:
                raise ValueError(f"unsupported dependency entry: {relative}")

    visit(root)
    if not rows:
        raise ValueError("the pinned dependency directory is empty")
    rows.sort(key=lambda row: row["path"])
    raw = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


class PiCoreWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Missing or changed tools fail setup; never silently skip this stage.
        manifest = json.loads((_PACKAGE / "offline-toolchain-v1.json").read_bytes())
        if manifest["schema"] != "aragorn/pi-core-offline-toolchain/v1":
            raise AssertionError("unexpected offline toolchain schema")
        if manifest["node"]["executable"] != str(_NODE):
            raise AssertionError("unexpected pinned Node executable")
        if manifest["node"]["version"] != _NODE_VERSION:
            raise AssertionError("unexpected pinned Node version")
        node_digest = hashlib.sha256(_NODE.read_bytes()).hexdigest()
        if node_digest != manifest["node"]["sha256"]:
            raise AssertionError("Node bytes differ from the reviewed toolchain")
        dependency_digest = _dependency_tree_digest(_PACKAGE / "node_modules")
        if dependency_digest != manifest["dependency_tree_sha256"]:
            raise AssertionError("dependency bytes differ from the reviewed toolchain")
        cls.node_digest = node_digest
        cls.dependency_digest = dependency_digest
        cls.temporary = tempfile.TemporaryDirectory(prefix="aragorn-pi-inert-")
        cls.addClassCleanup(cls.temporary.cleanup)
        # Do not inherit provider secrets, proxies, Node loaders or user HOME.
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
            raise AssertionError("Node changed during the offline fixture")
        if _dependency_tree_digest(_PACKAGE / "node_modules") != cls.dependency_digest:
            raise AssertionError("dependencies changed during the offline fixture")

    def raw_case(self, name: str) -> dict:
        # Lazy per-case execution permits later affected-method-only selections.
        if name not in self.fixtures:
            completed = subprocess.run(
                [str(_NODE), "--no-warnings", str(_ROOT / "tests/fixtures/pi_core_worker_offline.mjs"), name],
                cwd=_ROOT, env=self.environment, capture_output=True, timeout=8, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
            self.assertLessEqual(len(completed.stdout), 2 * 1024 * 1024)
            fixture = json.loads(completed.stdout)
            self.assertEqual(fixture["selected"], name)
            self.assertEqual(fixture["liveIO"], [], "the adapter attempted forbidden live I/O")
            self.fixtures[name] = fixture
        return self.fixtures[name]["result"]

    def case(self, name: str) -> dict:
        result = self.raw_case(name)
        self.assertIsNone(result["error"], result["error"])
        self.assertIsInstance(result["report"], dict)
        return result

    def stopped(self, name: str, relay_calls: int) -> dict:
        result = self.case(name)
        self.assertEqual(result["report"]["status"], "STOPPED")
        self.assertTrue(result["report"]["stopReason"])
        self.assertEqual(len(result["requests"]), relay_calls)
        return result

    def test_actual_loop_report_has_no_enforcement_authority(self) -> None:
        result = self.case("create")
        fixture = self.fixtures["create"]
        self.assertEqual(fixture["nodeVersion"], _NODE_VERSION)
        self.assertEqual(
            fixture["fixture"],
            "ACTUAL_PI_LOOP_SCRIPTED_MODEL_IN_MEMORY_RELAY_NOT_ENFORCEMENT_EVIDENCE",
        )
        report = result["report"]
        self.assertEqual(report["schema"], "aragorn/pi-core-worker-report/v1")
        self.assertEqual(report["authority"], "ADAPTER_CORRELATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY")
        self.assertEqual(report["status"], "COMPLETED")
        self.assertIsNone(report["stopReason"])
        self.assertTrue(report["agentSettled"])
        self.assertTrue(report["transcriptComplete"])
        self.assertEqual(result["providerCalls"], 2)
        self.assertEqual(report["providerCalls"], 2)
        self.assertEqual(report["toolCalls"], 1)

    def test_create_request_matches_existing_python_protocol(self) -> None:
        result = self.case("create")
        self.assertEqual(len(result["requests"]), 1)
        captured = result["requests"][0]
        request, payload = _worker_request(captured["value"])
        self.assertEqual(payload, b"fixture payload")
        self.assertEqual(request["target_name"], "output.txt")
        self.assertEqual(request["session_id"], "session-fixture")
        self.assertEqual(request["run_id"], "run-fixture")
        self.assertEqual(canonical_json(request), captured["canonical"].encode("ascii"))
        self.assertEqual(canonical_digest(request), captured["digest"])
        retained = result["report"]["results"][0]
        self.assertEqual(retained["requestDigest"], captured["digest"])
        self.assertEqual(retained["toolCallDigest"], request["tool_call_digest"])
        self.assertEqual(retained["sourceResult"]["request_digest"], captured["digest"])

    def test_unicode_payload_and_opaque_tool_id_match_python_bytes(self) -> None:
        result = self.case("unicode")
        captured = result["requests"][0]
        request, payload = _worker_request(captured["value"])
        self.assertEqual(payload, "café 😀\n\x00".encode("utf-8"))
        expected = "sha256:" + hashlib.sha256("call-é-😀".encode("utf-8")).hexdigest()
        self.assertEqual(request["tool_call_digest"], expected)
        self.assertEqual(canonical_json(request).decode("ascii"), captured["canonical"])
        self.assertEqual(canonical_digest(request), captured["digest"])

    def test_provider_receives_only_supplied_context_and_one_request_tool(self) -> None:
        result = self.case("create")
        first = result["providerContexts"][0]
        self.assertEqual(set(first), {"messages"})
        self.assertEqual(len(first["messages"]), 2)
        system = first["messages"][0]
        self.assertEqual(system["role"], "system")
        self.assertEqual(system["content"], "Offline fixture: only the supplied broker-request tool exists.")
        self.assertEqual([tool["name"] for tool in system["toolsAdded"]], ["aragorn_runtime_create"])
        self.assertEqual(first["messages"][1]["role"], "user")
        self.assertEqual(result["report"]["correlation"], {
            "sessionId": "session-fixture", "runId": "run-fixture",
        })

    def test_completed_block_is_retained_without_effect_retry(self) -> None:
        result = self.stopped("blocked", 1)
        self.assertEqual(result["providerCalls"], 1)
        record = result["report"]["results"][0]
        self.assertEqual(record["transportStatus"], "COMPLETED")
        self.assertEqual(record["sourceResult"]["broker_result"]["verdict"], "BLOCK")
        self.assertEqual(record["sourceResult"]["broker_result"]["effect_status"], "NOT_PERFORMED")

    def test_not_submitted_stops_without_second_same_turn_call(self) -> None:
        result = self.stopped("notSubmitted", 1)
        self.assertEqual(result["report"]["results"][0]["transportStatus"], "NOT_SUBMITTED")
        self.assertEqual(result["providerCalls"], 1)

    def test_indeterminate_stops_same_turn_and_future_calls(self) -> None:
        result = self.stopped("indeterminate", 1)
        self.assertEqual(result["report"]["results"][0]["transportStatus"], "INDETERMINATE")
        self.assertEqual(result["providerCalls"], 1)

    def test_malformed_reply_is_indeterminate_without_retry(self) -> None:
        result = self.stopped("malformedRelay", 1)
        self.assertEqual(result["report"]["results"][0]["transportStatus"], "INDETERMINATE")

    def test_wrong_reply_request_digest_is_not_accepted(self) -> None:
        result = self.stopped("wrongDigest", 1)
        self.assertEqual(result["report"]["results"][0]["transportStatus"], "INDETERMINATE")

    def test_noncanonical_reply_and_unsafe_integer_refuse(self) -> None:
        for name in ("noncanonicalRelay", "unsafeInteger"):
            with self.subTest(name=name):
                result = self.stopped(name, 1)
                self.assertEqual(result["report"]["results"][0]["transportStatus"], "INDETERMINATE")

    def test_unclassified_relay_exception_is_not_false_not_submitted(self) -> None:
        result = self.stopped("relayFailure", 1)
        self.assertEqual(result["report"]["results"][0]["transportStatus"], "INDETERMINATE")

    def test_invalid_tool_inputs_never_reach_relay(self) -> None:
        for name in ("badTarget", "extraArgument", "oversizedPayload"):
            with self.subTest(name=name):
                result = self.stopped(name, 0)
                self.assertEqual(result["report"]["results"], [])

    def test_unknown_tool_cannot_invoke_general_execution(self) -> None:
        result = self.stopped("unknownTool", 0)
        self.assertEqual(result["report"]["stopReason"], "UNKNOWN_TOOL")
        self.assertEqual(result["providerCalls"], 1)

    def test_unpaired_utf16_content_and_tool_ids_never_reach_relay(self) -> None:
        for name in ("unpairedContentHigh", "unpairedContentLow", "unpairedCallIdHigh", "unpairedCallIdLow"):
            with self.subTest(name=name):
                result = self.stopped(name, 0)
                self.assertEqual(result["report"]["results"], [])

    def test_duplicate_tool_call_id_does_not_resubmit(self) -> None:
        result = self.stopped("duplicateId", 1)
        self.assertEqual(result["report"]["stopReason"], "DUPLICATE_TOOL_CALL")

    def test_same_action_under_new_tool_id_does_not_resubmit(self) -> None:
        result = self.stopped("duplicateAction", 1)
        self.assertEqual(result["report"]["stopReason"], "DUPLICATE_ACTION")

    def test_call_budget_stops_extra_same_turn_effect(self) -> None:
        result = self.stopped("callLimit", 0)
        self.assertEqual(result["report"]["stopReason"], "TOOL_CALL_LIMIT")

    def test_provider_turn_budget_is_bounded(self) -> None:
        result = self.stopped("turnLimit", 1)
        self.assertEqual(result["providerCalls"], 1)
        self.assertEqual(result["report"]["providerCalls"], 1)

    def test_same_turn_tools_are_sequential_and_individually_bound(self) -> None:
        result = self.case("sequential")
        self.assertEqual(len(result["requests"]), 2)
        self.assertEqual(result["maxActiveRelays"], 1)
        self.assertEqual(result["order"], ["start:first.txt", "end:first.txt", "start:second.txt", "end:second.txt"])
        self.assertNotEqual(result["requests"][0]["digest"], result["requests"][1]["digest"])

    def test_preaborted_activation_never_contacts_provider_or_relay(self) -> None:
        result = self.stopped("preAborted", 0)
        self.assertEqual(result["providerCalls"], 0)

    def test_abort_after_relay_entry_never_retries_effect(self) -> None:
        result = self.stopped("abortDuringRelay", 1)
        self.assertEqual(result["providerCalls"], 1)
        self.assertNotEqual(result["report"]["status"], "COMPLETED")

    def test_provider_error_stops_without_implicit_fallback(self) -> None:
        result = self.stopped("providerFailure", 0)
        self.assertEqual(result["providerCalls"], 1)

    def test_provider_ignoring_abort_has_bounded_unsettled_outcome(self) -> None:
        result = self.stopped("providerDeadline", 0)
        self.assertFalse(result["report"]["agentSettled"])
        self.assertFalse(result["report"]["transcriptComplete"])
        self.assertEqual(result["providerCalls"], 1)

    def test_relay_ignoring_abort_has_bounded_indeterminate_outcome(self) -> None:
        result = self.stopped("relayDeadline", 1)
        self.assertFalse(result["report"]["agentSettled"])
        self.assertFalse(result["report"]["transcriptComplete"])
        self.assertEqual(result["providerCalls"], 1)
        self.assertEqual(result["report"]["results"][0]["transportStatus"], "INDETERMINATE")

    def test_native_relay_rejects_invalid_config_and_wrong_uid_without_socket(self) -> None:
        for name in ("nativeInvalid", "nativeWrongUid"):
            with self.subTest(name=name):
                result = self.raw_case(name)
                self.assertIsNotNone(result["error"])

    def test_oversized_completed_provider_output_is_bounded(self) -> None:
        result = self.stopped("oversizedCompletedOutput", 0)
        self.assertFalse(result["report"]["transcriptComplete"])
        self.assertEqual(result["report"]["stopReason"], "PROVIDER_OUTPUT_LIMIT")
        self.assertEqual(result["providerCalls"], 1)
        self.assertLessEqual(len(json.dumps(result["report"]).encode("utf-8")), 1024 * 1024)

    def test_oversized_partial_provider_output_prevents_later_tool_dispatch(self) -> None:
        result = self.stopped("oversizedPartialOutput", 0)
        self.assertFalse(result["report"]["transcriptComplete"])
        self.assertEqual(result["report"]["stopReason"], "PROVIDER_OUTPUT_LIMIT")
        self.assertEqual(result["providerCalls"], 1)
        self.assertLessEqual(len(json.dumps(result["report"]).encode("utf-8")), 1024 * 1024)

    def test_invalid_configuration_rejects_before_provider_or_relay(self) -> None:
        for name in ("missingProvider", "missingRelay", "extraConfig", "unsafeLimits", "badCorrelation", "oversizedPrompt", "unpairedPrompt", "unpairedTask"):
            with self.subTest(name=name):
                result = self.raw_case(name)
                self.assertIsNotNone(result["error"])
                self.assertIsNone(result["report"])
                self.assertEqual(result["providerCalls"], 0)
                self.assertEqual(result["requests"], [])


if __name__ == "__main__":
    unittest.main()
