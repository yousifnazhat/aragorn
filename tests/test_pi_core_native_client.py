"""New native START/client checks only; all Node OS boundaries are mocked.

The real pinned Pi loop and frozen request codec/client run against authored
in-memory root replies. These checks are not kernel, provider or effect proof.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import subprocess
import tempfile
import unittest

from aragorn.oci_worker_protocol import canonical_json
from tests import test_pi_core_confined_launch as producer
from tests import test_pi_core_entrypoint as offline


class PiCoreNativeClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the existing inert dependency inventory function, not its tests.
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
            raise AssertionError("offline Node/dependency bytes differ from reviewed pins")
        cls.temporary = tempfile.TemporaryDirectory(prefix="aragorn-pi-native-client-inert-")
        cls.addClassCleanup(cls.temporary.cleanup)
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
            raise AssertionError("offline toolchain changed during native client checks")

    def case(self, name, *, data=None):
        if name not in self.fixtures:
            completed = subprocess.run([str(offline._NODE), "--no-warnings",
                str(offline._ROOT / "tests/fixtures/pi_core_native_client_offline.mjs"), name],
                cwd=offline._ROOT, env=self.environment, input=data,
                capture_output=True, timeout=8, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
            self.assertLessEqual(len(completed.stdout), 2 * 1024 * 1024)
            fixture = json.loads(completed.stdout)
            self.assertEqual(fixture["fixture"], "REAL_PI_FROZEN_CLIENT_MOCKED_NATIVE_BOUNDARIES_NOT_ENFORCEMENT_EVIDENCE")
            self.assertEqual(fixture["selected"], name)
            self.assertEqual(fixture["nodeVersion"], offline._NODE_VERSION)
            self.assertEqual(fixture["remappedWorkerImports"], 1)
            self.assertEqual(fixture["liveIO"], [])
            self.fixtures[name] = fixture
        return self.fixtures[name]

    def refused(self, name, *, status=None, connections=0, requests=0):
        fixture = self.case(name)
        result = fixture["result"]
        self.assertIsNone(result["value"])
        self.assertIsNotNone(result["error"])
        if status is not None:
            self.assertEqual(result["error"]["status"], status)
        self.assertEqual(len(fixture["connections"]), connections)
        self.assertEqual(len(fixture["requests"]), requests)
        return result

    def test_native_start_is_closed_copied_and_has_no_legacy_relay(self):
        fixture = self.case("parseNative")
        result = fixture["result"]
        self.assertIsNone(result["error"])
        value = result["value"]
        self.assertEqual(value["schema"], "aragorn/pi-core-bootstrap-start/v2")
        self.assertEqual(set(value), {"schema", "activation_id", "system_prompt", "task", "model", "limits", "native_request", "provider_status"})
        self.assertEqual(value["native_request"], {"schema": "aragorn/pi-core-native-request-endpoint/v1",
            "socket_path": "/run/aragorn-pi-bootstrap/requests/request.sock", "worker_uid": 1101,
            "worker_gid": 1102, "supervisor_uid": 0, "max_requests": 1})
        self.assertEqual(value["limits"]["maxToolCalls"], 1)
        self.assertEqual(fixture["connections"], [])

    def test_python_native_start_roundtrips_through_exact_typescript_parser(self):
        config = producer.configuration()
        config = replace(config, native_request=True, limits={**config.limits, "maxToolCalls": 1})
        prepared = producer.prepared_for(producer.profile_for(config))
        raw = producer.confined._start(config, prepared)
        value = json.loads(raw)
        self.assertEqual(value["schema"], "aragorn/pi-core-bootstrap-start/v2")
        self.assertEqual(canonical_json(value), raw)
        result = self.case("pythonStart", data=raw)["result"]
        self.assertIsNone(result["error"])
        self.assertEqual(result["value"], value)

    def test_native_start_rejects_legacy_route_injection(self):
        self.refused("parseExtraRelay")

    def test_native_start_requires_endpoint(self):
        self.refused("parseMissingEndpoint")

    def test_native_endpoint_requires_root_supervisor(self):
        self.refused("parseNonRootSupervisor")

    def test_native_endpoint_refuses_root_worker(self):
        self.refused("parseRootWorker")

    def test_native_worker_ids_must_be_safe_integers(self):
        self.refused("parseUnsafeWorkerId")

    def test_native_endpoint_cannot_select_arbitrary_socket(self):
        self.refused("parseWrongSocket")

    def test_native_endpoint_is_exactly_one_request(self):
        self.refused("parseMultipleRequests")

    def test_native_start_is_exactly_one_tool_call(self):
        self.refused("parseMultipleTools")

    def test_native_endpoint_cannot_contain_extra_authority(self):
        self.refused("parseEndpointExtra")

    def test_native_endpoint_accessor_is_refused_without_invocation(self):
        result = self.refused("parseEndpointAccessor")
        self.assertNotIn("accessor invoked", result["error"]["message"])

    def test_changed_union_parser_preserves_exact_legacy_start(self):
        result = self.case("parseLegacy")["result"]
        self.assertIsNone(result["error"])
        value = result["value"]
        self.assertEqual(set(value), {"schema", "activation_id", "system_prompt", "task", "model", "limits", "relay", "provider_status"})
        self.assertEqual(value["schema"], "aragorn/pi-core-bootstrap-start/v1")
        self.assertEqual(value["limits"]["maxToolCalls"], 2)
        self.assertEqual(value["relay"], {"expectedGatewayUid": 1101, "expectedGatewayGid": 1102,
            "expectedWorkerUid": 1103, "workerSocketPath": "/run/legacy/worker.sock"})

    def test_legacy_start_cannot_mix_native_endpoint_authority(self):
        self.refused("parseLegacyMixed")

    def test_actual_frozen_client_sends_one_canonical_bound_frame_to_root_endpoint(self):
        fixture = self.case("clientValid")
        result = fixture["result"]
        self.assertIsNone(result["error"])
        self.assertEqual(result["value"]["status"], "NOT_SUBMITTED")
        self.assertEqual(fixture["connections"], [{"path": "/run/aragorn-pi-bootstrap/requests/request.sock"}])
        self.assertEqual(len(fixture["requests"]), 1)
        sent = fixture["requests"][0]
        self.assertEqual(sent["value"]["session_id"], "a" * 32)
        self.assertEqual(sent["value"]["run_id"], "a" * 32)
        self.assertEqual(sent["frameBytes"], len(sent["canonical"].encode("ascii")) + 4)
        self.assertEqual(result["value"]["request_digest"], sent["digest"])
        self.assertIn("destroy", fixture["socketEvents"])

    def test_native_client_preserves_completed_block_as_authored_evidence_only(self):
        fixture = self.case("clientCompletedBlock")
        result = fixture["result"]
        self.assertIsNone(result["error"])
        self.assertEqual(result["value"]["status"], "COMPLETED")
        self.assertEqual(result["value"]["broker_result"]["effect_status"], "NOT_PERFORMED")
        self.assertIsNone(result["value"]["broker_result"]["decision"])

    def test_native_factory_is_one_use_even_after_known_not_submitted_reply(self):
        fixture = self.case("clientOneUse")
        self.assertIsNone(fixture["result"]["error"])
        self.assertIsNone(fixture["result"]["second"]["value"])
        self.assertEqual(fixture["result"]["second"]["error"]["status"], "NOT_SUBMITTED")
        self.assertEqual(len(fixture["connections"]), 1)

    def test_concurrent_calls_cannot_duplicate_native_submission(self):
        fixture = self.case("clientConcurrent")
        self.assertIsNone(fixture["result"]["error"])
        values = fixture["result"]["value"]
        self.assertEqual(sum(item["value"] is not None for item in values), 1)
        self.assertEqual(sum(item["error"] is not None for item in values), 1)
        self.assertEqual(len(fixture["connections"]), 1)
        self.assertEqual(len(fixture["requests"]), 1)

    def test_native_real_uid_is_enforced(self):
        self.refused("clientWrongUid", status="NOT_SUBMITTED")

    def test_native_effective_uid_is_enforced(self):
        self.refused("clientWrongEuid", status="NOT_SUBMITTED")

    def test_native_primary_gid_is_enforced(self):
        self.refused("clientWrongGid", status="NOT_SUBMITTED")

    def test_extra_groups_cannot_broaden_worker_access(self):
        self.refused("clientExtraGroups", status="NOT_SUBMITTED")

    def test_primary_group_may_be_reported_as_supplementary(self):
        self.assertIsNone(self.case("clientPrimaryGroup")["result"]["error"])

    def test_identity_is_rechecked_after_factory_creation(self):
        self.refused("clientIdentityChanged", status="NOT_SUBMITTED")

    def test_native_client_requires_linux(self):
        self.refused("clientNonLinux", status="NOT_SUBMITTED")

    def test_expired_original_deadline_never_opens_socket(self):
        self.refused("clientExpired")

    def test_preaborted_native_request_never_opens_socket(self):
        self.refused("clientPreAbort", status="NOT_SUBMITTED")

    def test_original_deadline_aborts_inflight_transport_without_retry(self):
        result = self.refused("clientOriginalDeadline", status="INDETERMINATE", connections=1, requests=1)
        self.assertLess(result["elapsedMs"], 500)

    def test_abort_after_submission_is_indeterminate(self):
        self.refused("clientAbortAfterSend", status="INDETERMINATE", connections=1, requests=1)

    def test_synchronous_metadata_crossing_deadline_cannot_report_success(self):
        self.refused("clientSlowMetadata", status="INDETERMINATE", connections=1, requests=1)
        self.assertEqual(self.case("clientSlowMetadata")["syntheticClockAdvanceMs"], 2000)

    def test_wrong_activation_correlation_never_submits(self):
        self.refused("clientWrongCorrelation", status="NOT_SUBMITTED")

    def test_root_socket_owner_is_enforced_by_frozen_client(self):
        self.refused("clientWrongSocketOwner", status="NOT_SUBMITTED")

    def test_endpoint_group_must_match_worker(self):
        self.refused("clientWrongSocketGroup", status="NOT_SUBMITTED")

    def test_endpoint_write_permissions_are_not_widened(self):
        self.refused("clientUnsafeSocketMode", status="NOT_SUBMITTED")

    def test_writable_fixed_ancestor_is_refused(self):
        self.refused("clientUnsafeAncestor", status="NOT_SUBMITTED")

    def test_linked_fixed_ancestor_is_refused(self):
        self.refused("clientLinkedAncestor", status="NOT_SUBMITTED")

    def test_available_root_peer_credentials_are_checked(self):
        self.refused("clientWrongRootPeer", status="NOT_SUBMITTED", connections=1)

    def test_endpoint_replacement_before_send_is_not_submitted(self):
        self.refused("clientReplaceBeforeSend", status="NOT_SUBMITTED", connections=1)

    def test_endpoint_replacement_after_send_is_indeterminate(self):
        self.refused("clientReplaceAfterSend", status="INDETERMINATE", connections=1, requests=1)

    def test_protected_ancestor_replacement_after_response_is_indeterminate(self):
        self.refused("clientReplaceAncestorAfterSend", status="INDETERMINATE", connections=1, requests=1)

    def test_wrong_root_result_digest_is_indeterminate(self):
        self.refused("clientWrongResponseDigest", status="INDETERMINATE", connections=1, requests=1)

    def test_truncated_root_response_is_indeterminate(self):
        self.refused("clientTruncatedResponse", status="INDETERMINATE", connections=1, requests=1)

    def test_real_pi_loop_uses_native_factory_and_frozen_client_without_injected_relay(self):
        fixture = self.case("composeNative")
        result = fixture["result"]
        self.assertIsNone(result["error"])
        self.assertEqual(result["providerCalls"], 1)
        self.assertEqual(len(fixture["connections"]), 1)
        self.assertEqual(len(fixture["requests"]), 1)
        self.assertEqual(result["report"]["stopReason"], "RELAY_NOT_SUBMITTED")
        self.assertEqual(result["report"]["toolCalls"], 1)
        self.assertEqual(result["report"]["correlation"], {"sessionId": "a" * 32, "runId": "a" * 32})
        self.assertEqual(result["report"]["authority"], "ADAPTER_CORRELATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY")

    def test_native_entry_cannot_accept_an_injected_relay(self):
        fixture = self.case("composeInjectedRelay")
        self.assertIsNotNone(fixture["result"]["error"])
        self.assertEqual(fixture["result"]["providerCalls"], 0)
        self.assertEqual(fixture["connections"], [])

    def test_native_start_cannot_use_legacy_entrypoint(self):
        fixture = self.case("composeLegacyEntry")
        self.assertIsNotNone(fixture["result"]["error"])
        self.assertEqual(fixture["result"]["providerCalls"], 0)
        self.assertEqual(fixture["connections"], [])

    def test_native_provider_must_be_explicit(self):
        fixture = self.case("composeMissingProvider")
        self.assertIsNotNone(fixture["result"]["error"])
        self.assertEqual(fixture["result"]["providerCalls"], 0)

    def test_expired_native_entry_deadline_prevents_model_or_client(self):
        fixture = self.case("composeExpired")
        self.assertIsNotNone(fixture["result"]["error"])
        self.assertEqual(fixture["result"]["providerCalls"], 0)
        self.assertEqual(fixture["connections"], [])

    def test_native_bootstrap_remains_provider_unavailable_and_opens_no_effect_channel(self):
        fixture = self.case("nativeBootstrapUnavailable")
        result = fixture["result"]
        self.assertEqual(result["report"]["status"], "PROVIDER_UNAVAILABLE")
        self.assertTrue(result["report"]["released"])
        self.assertEqual(result["reads"], 2)
        self.assertEqual(len(result["writes"]), 2)
        self.assertEqual(fixture["connections"], [])


if __name__ == "__main__":
    unittest.main()
