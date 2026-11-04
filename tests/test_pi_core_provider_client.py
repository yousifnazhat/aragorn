"""Focused source provider-client checks, never live data/effect authorization.

Real pinned Pi and codecs run only with mocked OS metadata and in-memory peers.
The pure Python validator checks emitted canonical bytes; no service is started.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn import pi_core_provider_mediation as mediation
from tests import test_pi_core_entrypoint as offline


class PiCoreProviderClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = json.loads((offline._PACKAGE / "offline-toolchain-v1.json").read_bytes())
        if (manifest["schema"] != "aragorn/pi-core-offline-toolchain/v1" or
                manifest["node"]["executable"] != str(offline._NODE) or
                manifest["node"]["version"] != offline._NODE_VERSION):
            raise AssertionError("unexpected reviewed offline toolchain")
        cls.node_digest = hashlib.sha256(offline._NODE.read_bytes()).hexdigest()
        cls.lock_digest = hashlib.sha256((offline._PACKAGE / "package-lock.json").read_bytes()).hexdigest()
        cls.dependency_digest = offline._dependency_digest()
        if (cls.node_digest != manifest["node"]["sha256"] or
                cls.lock_digest != manifest["preparation"]["package_lock_sha256"] or
                cls.dependency_digest != manifest["dependency_tree_sha256"]):
            raise AssertionError("offline toolchain bytes differ from reviewed pins")
        cls.temporary = tempfile.TemporaryDirectory(prefix="aragorn-pi-provider-inert-")
        cls.addClassCleanup(cls.temporary.cleanup)
        # Do not inherit credentials, proxies, NODE_OPTIONS or user settings.
        cls.environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                           "HOME": cls.temporary.name, "TMPDIR": cls.temporary.name}
        version = subprocess.run([str(offline._NODE), "--version"], cwd=offline._ROOT,
            env=cls.environment, capture_output=True, timeout=5, check=False)
        if version.returncode or version.stdout.decode("ascii").strip() != offline._NODE_VERSION:
            raise AssertionError("pinned offline Node version differs")
        cls.fixtures = {}

    @classmethod
    def tearDownClass(cls):
        if (hashlib.sha256(offline._NODE.read_bytes()).hexdigest() != cls.node_digest or
                hashlib.sha256((offline._PACKAGE / "package-lock.json").read_bytes()).hexdigest() != cls.lock_digest or
                offline._dependency_digest() != cls.dependency_digest):
            raise AssertionError("offline toolchain changed during provider checks")

    def case(self, name):
        if name not in self.fixtures:
            completed = subprocess.run([str(offline._NODE), "--no-warnings",
                str(offline._ROOT / "tests/fixtures/pi_core_provider_client_offline.mjs"), name],
                cwd=offline._ROOT, env=self.environment,
                capture_output=True, timeout=8, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
            self.assertLessEqual(len(completed.stdout), 2 * 1024 * 1024)
            fixture = json.loads(completed.stdout)
            self.assertEqual(fixture["fixture"], "REAL_PI_MOCKED_PROVIDER_CHANNEL_NOT_DATA_OR_EFFECT_AUTHORITY")
            self.assertEqual(fixture["selected"], name)
            self.assertEqual(fixture["nodeVersion"], offline._NODE_VERSION)
            self.assertEqual(fixture["liveIO"], [])
            imports = {(item["parent"], item["specifier"]) for item in fixture["remappedImports"]}
            self.assertIn(("entrypoint.ts", "./worker.js"), imports)
            if name in {"composeText", "composeTool"}:
                self.assertIn(("entrypoint.ts", "./provider.js"), imports)
            self.assertLessEqual(imports, {("entrypoint.ts", "./worker.js"),
                                          ("entrypoint.ts", "./provider.js"),
                                          ("provider.ts", "./worker.js")})
            self.fixtures[name] = fixture
        return self.fixtures[name]

    def build_refused(self, name):
        fixture = self.case(name)
        self.assertIsNone(fixture["result"]["value"])
        self.assertIsNotNone(fixture["result"]["error"])
        self.assertEqual(fixture["connections"], [])
        return fixture

    def failed(self, name, *, connections=0, requests=0, outcome=None):
        fixture = self.case(name)
        result = fixture["result"]
        if result["error"] is None:
            self.assertIn(result["value"]["message"]["stopReason"], {"error", "aborted"})
            self.assertEqual(result["value"]["events"][-1]["type"], "error")
            failure = result["value"]["message"]["errorMessage"]
        else:
            self.assertIsNone(result["value"])
            failure = result["error"]["message"]
        if outcome is not None:
            self.assertIn(outcome, failure)
        self.assertEqual(len(fixture["connections"]), connections)
        self.assertEqual(len(fixture["requests"]), requests)
        self.assertNotIn("FIXTURE_SECRET_NOT_A_REAL_CREDENTIAL", json.dumps(result))
        return fixture

    def test_actual_pi_normalized_transcript_reaches_only_protected_provider_socket(self):
        fixture = self.case("composeText")
        result = fixture["result"]
        self.assertIsNone(result["error"])
        self.assertEqual(result["report"]["status"], "COMPLETED")
        self.assertEqual(result["report"]["providerCalls"], 1)
        self.assertEqual(result["report"]["toolCalls"], 0)
        self.assertEqual(fixture["connections"], [{"path": "/run/aragorn-pi-bootstrap/provider/provider.sock", "allowHalfOpen": True}])
        request = fixture["requests"][0]["value"]
        self.assertEqual(request["activation_id"], "a" * 32)
        self.assertEqual(request["route_digest"], "sha256:" + "b" * 64)
        self.assertEqual(request["sequence"], 1)
        messages = request["payload"]["messages"]
        self.assertEqual([message["role"] for message in messages], ["system", "user"])
        self.assertEqual([message["timestamp"] for message in messages], [0, 0])
        self.assertEqual(messages[0]["toolsAdded"][0]["name"], "aragorn_runtime_create")
        self.assertEqual(messages[1]["content"], [{"type": "text", "text": "Owned public question: café 🛡."}])

    def test_real_pi_tool_completion_uses_fixed_action_relay_and_never_second_provider_turn(self):
        fixture = self.case("composeTool")
        result = fixture["result"]
        self.assertIsNone(result["error"])
        self.assertEqual(result["report"]["providerCalls"], 1)
        self.assertEqual(result["report"]["toolCalls"], 1)
        self.assertEqual(result["report"]["stopReason"], "RELAY_NOT_SUBMITTED")
        self.assertEqual([item["path"] for item in fixture["connections"]], [
            "/run/aragorn-pi-bootstrap/provider/provider.sock",
            "/run/aragorn-pi-bootstrap/requests/request.sock"])
        self.assertEqual(fixture["requests"][1]["value"]["session_id"], "a" * 32)

    def test_projected_bytes_are_canonical_ascii_and_bound_to_exact_request_digest(self):
        sent = self.case("composeText")["requests"][0]
        self.assertEqual(canonical_json(sent["value"]), sent["canonical"].encode("ascii"))
        self.assertEqual(canonical_digest(sent["value"]), sent["digest"])
        self.assertEqual(sent["frameBytes"], len(sent["canonical"].encode("ascii")) + 4)
        self.assertLessEqual(len(canonical_json(sent["value"]["payload"])), 48 * 1024)

    def test_actual_pi_wire_and_authored_replies_match_python_pure_contract(self):
        for name in ("composeText", "composeTool"):
            with self.subTest(name=name):
                fixture = self.case(name)
                sent = fixture["requests"][0]
                request = mediation.validate_provider_request(sent["value"])
                self.assertEqual(canonical_json(request), sent["canonical"].encode("ascii"))
                result = fixture["replies"][0]["value"]
                self.assertEqual(mediation.validate_provider_result(result, sent["digest"]), result)
                self.assertEqual(request["authority"], "PI_PROVIDER_REQUEST_ONLY_NOT_DATA_AUTHORITY")

    def test_builder_copies_full_semantic_payload_and_normalizes_only_timestamps(self):
        result = self.case("build")["result"]
        self.assertIsNone(result["error"])
        self.assertEqual(result["value"]["payload"]["messages"][0]["content"], "Owned public instructions.")
        self.assertEqual([message["timestamp"] for message in result["value"]["payload"]["messages"]], [0, 0])
        changed = self.case("buildSemanticMutation")["result"]
        self.assertNotEqual(canonical_digest(changed["value"]["payload"]), canonical_digest(changed["changed"]["payload"]))

    def test_assistant_continuation_is_not_implicitly_data_authorized(self):
        self.build_refused("buildContinuation")

    def test_images_are_outside_the_initial_text_profile(self):
        self.build_refused("buildImage")

    def test_unknown_or_changed_tool_declarations_are_refused(self):
        for name in ("buildUnknownTool", "buildChangedTool"):
            with self.subTest(name=name): self.build_refused(name)

    def test_unsafe_timestamps_cannot_be_silently_normalized(self):
        self.build_refused("buildUnsafeTimestamp")

    def test_credentials_and_context_options_cannot_enter_payload(self):
        for name in ("buildCredentials", "buildContextExtra"):
            with self.subTest(name=name): self.build_refused(name)

    def test_model_accessors_are_rejected_without_invocation(self):
        for name in ("buildModelAccessor", "buildContextAccessor"):
            with self.subTest(name=name):
                fixture = self.build_refused(name)
                self.assertNotIn("accessor invoked", fixture["result"]["error"]["message"])

    def test_request_payload_and_unicode_bounds_are_fail_closed(self):
        for name in ("buildOversized", "buildLoneSurrogate"):
            with self.subTest(name=name): self.build_refused(name)

    def test_client_cannot_select_an_alternate_socket(self):
        self.failed("clientEndpointInjection")

    def test_real_and_effective_worker_identity_are_required(self):
        for name in ("clientWrongUid", "clientWrongEgid"):
            with self.subTest(name=name): self.failed(name)

    def test_supplementary_groups_cannot_broaden_provider_access(self):
        self.failed("clientExtraGroups")

    def test_linux_identity_boundary_is_explicit(self):
        self.failed("clientNonLinux")

    def test_worker_identity_is_rechecked_when_stream_is_called(self):
        self.failed("clientIdentityChanged")

    def test_preaborted_call_opens_no_channel(self):
        self.failed("clientPreAbort")

    def test_expired_original_deadline_opens_no_channel(self):
        self.failed("clientExpired")

    def test_protected_socket_owner_group_and_mode_are_required(self):
        for name in ("clientWrongOwner", "clientWrongGroup", "clientWritableSocket"):
            with self.subTest(name=name): self.failed(name)

    def test_protected_ancestors_cannot_be_writable_or_linked(self):
        for name in ("clientWritableAncestor", "clientLinkedAncestor"):
            with self.subTest(name=name): self.failed(name)

    def test_client_does_not_claim_portable_kernel_peer_authentication(self):
        # This source deliberately authenticates protected endpoint metadata,
        # not an optional nonportable Node extension. Server-side Pi identity
        # authentication remains a separate prerequisite, not fixture proof.
        fixture = self.case("clientWrongPeer")
        self.assertIsNone(fixture["result"]["error"])
        self.assertEqual(fixture["result"]["value"]["message"]["stopReason"], "stop")
        self.assertEqual(len(fixture["requests"]), 1)

    def test_socket_replacement_before_send_never_submits(self):
        self.failed("clientReplaceBeforeSend", connections=1)

    def test_socket_replacement_after_reply_stays_indeterminate(self):
        self.failed("clientReplaceAfterResponse", connections=1, requests=1, outcome="INDETERMINATE")

    def test_factory_is_one_use_after_success(self):
        fixture = self.case("clientOneUse")
        result = fixture["result"]
        self.assertIsNone(result["error"])
        self.assertEqual(result["value"]["message"]["stopReason"], "stop")
        self.assertEqual(result["second"]["message"]["stopReason"], "error")
        self.assertEqual(len(fixture["requests"]), 1)

    def test_concurrent_calls_cannot_duplicate_provider_submission(self):
        fixture = self.case("clientConcurrent")
        self.assertIsNone(fixture["result"]["error"])
        self.assertCountEqual([item["message"]["stopReason"] for item in fixture["result"]["value"]], ["stop", "error"])
        self.assertEqual(len(fixture["connections"]), 1)
        self.assertEqual(len(fixture["requests"]), 1)

    def test_malformed_first_call_still_spends_the_single_request_budget(self):
        fixture = self.case("clientRefusedThenRetry")
        self.assertIsNone(fixture["result"]["error"])
        for field in ("value", "second"):
            self.assertEqual(fixture["result"][field]["message"]["stopReason"], "error")
            self.assertIn("NOT_SUBMITTED", fixture["result"][field]["message"]["errorMessage"])
        self.assertEqual(fixture["connections"], [])

    def test_internal_pi_options_are_never_forwarded_or_invoked(self):
        fixture = self.case("clientOptionsSecret")
        self.assertIsNone(fixture["result"]["error"])
        self.assertEqual(fixture["result"]["value"]["message"]["stopReason"], "stop")
        self.assertNotIn("FIXTURE_SECRET_NOT_A_REAL_CREDENTIAL", fixture["requests"][0]["canonical"])
        self.assertEqual(set(fixture["requests"][0]["value"]),
            {"schema", "authority", "activation_id", "route_digest", "sequence", "payload"})

    def test_bounded_text_completion_is_adapted_to_real_pi_stream_protocol(self):
        fixture = self.case("clientText")
        result = fixture["result"]
        self.assertIsNone(result["error"])
        self.assertEqual([event["type"] for event in result["value"]["events"]], ["start", "done"])
        message = result["value"]["message"]
        self.assertEqual(message["stopReason"], "stop")
        self.assertEqual(message["content"], [{"type": "text", "text": "Owned public fixture reply."}])
        self.assertEqual((message["usage"]["input"], message["usage"]["output"]), (5, 7))
        self.assertIn("destroy", fixture["socketEvents"])

    def test_remote_not_submitted_and_indeterminate_are_distinct(self):
        self.failed("clientNotSubmitted", connections=1, requests=1, outcome="NOT_SUBMITTED")
        self.failed("clientIndeterminate", connections=1, requests=1, outcome="INDETERMINATE")

    def test_wrong_response_digest_is_indeterminate_without_retry(self):
        self.failed("clientWrongDigest", connections=1, requests=1, outcome="INDETERMINATE")

    def test_truncated_or_extra_framing_is_indeterminate(self):
        for name in ("clientTruncated", "clientTrailingBytes"):
            with self.subTest(name=name): self.failed(name, connections=1, requests=1, outcome="INDETERMINATE")

    def test_completion_requires_eof_within_original_deadline(self):
        for name in ("clientMissingEOF", "clientDeadline"):
            with self.subTest(name=name): self.failed(name, connections=1, requests=1, outcome="INDETERMINATE")

    def test_late_reply_cannot_be_promoted_to_success(self):
        fixture = self.failed("clientLateReply", connections=1, requests=1, outcome="INDETERMINATE")
        self.assertEqual(fixture["syntheticClockAdvanceMs"], 2000)

    def test_abort_after_send_is_indeterminate_without_retry(self):
        self.failed("clientAbortAfterSend", connections=1, requests=1, outcome="INDETERMINATE")

    def test_response_cannot_invent_an_unknown_tool(self):
        self.failed("clientUnknownTool", connections=1, requests=1, outcome="INDETERMINATE")

    def test_response_usage_requires_safe_integers(self):
        self.failed("clientInvalidUsage", connections=1, requests=1, outcome="INDETERMINATE")

    def test_oversized_completion_is_never_delivered(self):
        self.failed("clientOversizedContent", connections=1, requests=1, outcome="INDETERMINATE")

    def test_raw_provider_and_transport_errors_are_redacted(self):
        for name in ("clientSecretError", "clientTransportError"):
            with self.subTest(name=name): self.failed(name, connections=1, requests=1, outcome="INDETERMINATE")

    def test_protected_composition_cannot_inject_provider_or_action_callbacks(self):
        for name in ("composeInjectedStream", "composeInjectedRelay"):
            with self.subTest(name=name):
                fixture = self.case(name)
                self.assertIsNotNone(fixture["result"]["error"])
                self.assertEqual(fixture["connections"], [])

    def test_native_bootstrap_still_never_activates_provider_or_action(self):
        fixture = self.case("nativeBootstrapUnavailable")
        result = fixture["result"]
        self.assertEqual(result["report"]["status"], "PROVIDER_UNAVAILABLE")
        self.assertTrue(result["report"]["released"])
        self.assertEqual(result["reads"], 2)
        self.assertEqual(len(result["writes"]), 2)
        self.assertEqual(fixture["connections"], [])


if __name__ == "__main__":
    unittest.main()
