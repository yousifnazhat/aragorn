"""New additive protected START checks; authored fixtures are not qualification.

No service/kernel/provider activation. Real pinned Pi runs with in-memory peers;
the independently held native caller and effect verifier remain separate gates.
"""

import dataclasses
import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_confined_launch as confined
from aragorn import pi_core_native_provider as native_provider
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_confined_launch as fixtures
from tests import test_pi_core_entrypoint as offline


def configuration():
    profile = {"schema": "aragorn/pi-core-node-source-profile/v1",
        "pins": {key: fixtures.digest("d") for key in ("gate_digest", "node_digest",
            "producer_digest", "node_observer_digest", "source_inventory_digest", "loader_inventory_digest")},
        "sources": [{"path": "/opt/aragorn/pi-runtime/pi-core/entrypoint.js", "digest": fixtures.digest("e")}],
        "required_sources": ["/opt/aragorn/pi-runtime/pi-core/entrypoint.js"],
        "loader_files": [{"path": "/opt/aragorn/pi-runtime/pi-core/package.json", "digest": fixtures.digest("f")}]}
    return dataclasses.replace(fixtures.configuration(), native_request=True,
        source_observation=profile, source_observation_digest=canonical_digest(profile),
        provider_route_digest=fixtures.digest("b"))


def result():
    return {"schema": "aragorn/pi-core-bootstrap-result/v2", "activation_id": "a" * 32,
        "status": "WORKER_COMPLETED", "authority": confined._RESULT_AUTHORITY,
        "worker": {"status": "COMPLETED", "stop_reason": None, "provider_calls": 1,
                   "tool_calls": 0, "agent_settled": True, "transcript_complete": True}}


class ProviderStartContractTests(fixtures.InertTests):
    def setUp(self):
        super().setUp()
        self.config = configuration()
        self.profile = fixtures.profile_for(self.config)
        self.prepared = fixtures.prepared_for(self.profile)

    def test_enabled_start_exact_prepared_fields_and_fixed_routes(self):
        raw = confined._start(self.config, self.prepared)
        start = json.loads(raw)
        self.assertEqual(set(start), {"schema", "activation_id", "system_prompt", "task",
            "model", "limits", "provider_status", "provider", "native_request"})
        self.assertEqual(start["schema"], "aragorn/pi-core-bootstrap-start/v3")
        self.assertEqual(start["provider_status"], "PROTECTED")
        self.assertEqual(start["provider"], {"route_digest": self.config.provider_route_digest,
            "max_requests": 1, "request_timeout_ms": self.config.limits["maxRunMs"]})
        self.assertEqual(start["system_prompt"], self.prepared.system_prompt)
        self.assertEqual(start["task"], self.config.task)
        self.assertEqual(start["model"], self.config.model)
        self.assertEqual(start["native_request"]["socket_path"], "/run/aragorn-pi-bootstrap/requests/request.sock")
        self.assertEqual(raw, canonical_json(start))

    def test_no_provider_pin_preserves_exact_unavailable_v1_and_v2(self):
        for native in (False, True):
            config = dataclasses.replace(fixtures.configuration(), native_request=native)
            expected = {"schema": "aragorn/pi-core-bootstrap-start/v2" if native else "aragorn/pi-core-bootstrap-start/v1",
                "activation_id": self.prepared.activation_id, "system_prompt": self.prepared.system_prompt,
                "task": config.task, "model": config.model, "limits": config.limits, "provider_status": "UNAVAILABLE"}
            expected["native_request" if native else "relay"] = (
                {"schema": "aragorn/pi-core-native-request-endpoint/v1",
                 "socket_path": "/run/aragorn-pi-bootstrap/requests/request.sock", "worker_uid": 1101,
                 "worker_gid": 1102, "supervisor_uid": 0, "max_requests": 1} if native else config.relay)
            with self.subTest(native=native):
                self.assertEqual(confined._start(config, self.prepared), canonical_json(expected))

    def test_enabled_requires_source_observation_and_native_requests(self):
        for change in ({"native_request": False}, {"source_observation": None, "source_observation_digest": None}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "source observation"):
                dataclasses.replace(self.config, **change)

    def test_enabled_route_pin_is_exact_digest_not_truthy_opt_in(self):
        from aragorn.runtime_action_broker import RuntimeActionBrokerError

        for route in (True, False, "", "sha256:" + "g" * 64, fixtures.digest("b") + "\n", {}):
            with self.subTest(route=route), self.assertRaises(RuntimeActionBrokerError):
                dataclasses.replace(self.config, provider_route_digest=route)

    def test_enabled_budgets_reject_multiple_calls_and_boolean_limits(self):
        for key in ("maxTurns", "maxToolCalls"):
            for value in (0, 2, True):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    dataclasses.replace(self.config, limits={**self.config.limits, key: value})

    def test_timeout_is_derived_bounded_and_configuration_bound(self):
        original = confined.confined_configuration_digest(self.config)
        changed = dataclasses.replace(self.config, limits={**self.config.limits, "maxRunMs": 101})
        self.assertNotEqual(original, confined.confined_configuration_digest(changed))
        self.assertEqual(json.loads(confined._start(changed, self.prepared))["provider"]["request_timeout_ms"], 101)
        for value in (0, True, 30_001):
            with self.subTest(value=value), self.assertRaises(ValueError):
                dataclasses.replace(self.config, limits={**self.config.limits, "maxRunMs": value})

    def test_configuration_digest_pins_route_and_exact_task_model(self):
        expected = {"schema": "aragorn/pi-core-confined-configuration/v4",
            **{key: str(getattr(self.config, key)) for key in ("root_directory", "runtime_directory", "activation_directory")},
            **{key: getattr(self.config, key) for key in ("root_closure_digest", "compiled_receipt_digest",
                "worker_uid", "worker_gid", "task", "model", "limits", "relay", "source_observation", "source_observation_digest")},
            "provider_status": "PROTECTED", "provider": {"route_digest": self.config.provider_route_digest,
                "max_requests": 1, "request_timeout_ms": self.config.limits["maxRunMs"]},
            "native_request": json.loads(confined._start(self.config, self.prepared))["native_request"]}
        digest = confined.confined_configuration_digest(self.config)
        self.assertEqual(digest, canonical_digest(expected))
        for change in ({"provider_route_digest": fixtures.digest("c")}, {"task": "different task"},
                       {"model": {**self.config.model, "id": "different-model"}}):
            with self.subTest(change=change):
                self.assertNotEqual(digest, confined.confined_configuration_digest(dataclasses.replace(self.config, **change)))

    def test_provider_socket_cannot_be_legacy_mask_target(self):
        for path in ("/run/aragorn-pi-bootstrap/provider", "/run/aragorn-pi-bootstrap/provider/provider.sock"):
            changed = dataclasses.replace(self.config, relay={**self.config.relay, "workerSocketPath": path})
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "overlap"):
                confined._start(changed, self.prepared)

    def test_worker_completion_is_correlation_only_and_can_have_no_effect(self):
        observed = result()
        confined._validate_provider_result(observed, activation_id=self.prepared.activation_id)
        self.assertEqual(observed["worker"]["tool_calls"], 0)
        self.assertEqual(observed["authority"], "BOOTSTRAP_STATUS_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY")

    def test_stopped_unsettled_outcome_remains_honest(self):
        observed = result()
        observed.update(status="WORKER_STOPPED")
        observed["worker"].update(status="STOPPED", stop_reason="DEADLINE_EXCEEDED",
            agent_settled=False, transcript_complete=False)
        confined._validate_provider_result(observed, activation_id=self.prepared.activation_id)

    def test_worker_result_rejects_changed_identity_status_and_extra_authority(self):
        changes = ({"schema": "aragorn/pi-core-bootstrap-result/v1"}, {"activation_id": "c" * 32},
            {"status": "WORKER_STOPPED"}, {"authority": "QUALIFIED"}, {"effect_verified": True})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                confined._validate_provider_result({**result(), **change}, activation_id=self.prepared.activation_id)

    def test_worker_result_rejects_false_completion_and_summary_expansion(self):
        changes = ({"provider_calls": 0}, {"provider_calls": True}, {"provider_calls": 2},
            {"tool_calls": 2}, {"agent_settled": False}, {"stop_reason": "PROVIDER_FAILED"},
            {"transcript_complete": 1}, {"messages": []})
        for change in changes:
            observed = result()
            observed["worker"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                confined._validate_provider_result(observed, activation_id=self.prepared.activation_id)

    def test_enabled_exchange_refuses_absent_or_duck_typed_dispatch_before_io(self):
        plan = confined.PiConfinedLaunchPlan(self.prepared, self.profile, 1101, 1102,
            "aragorn-pi-" + "c" * 32 + ".service", (), self.config.activation_directory / ("a" * 32 + ".json"),
            confined._start(self.config, self.prepared), 20.0, fixtures.digest(), fixtures.digest(), confined._PlanLease())
        with mock.patch.object(confined.os, "geteuid", return_value=0), \
                mock.patch.object(confined, "_read_bootstrap") as read, \
                mock.patch.object(confined, "_send_frame") as send:
            for dispatch in (None, mock.Mock(owned=mock.Mock(plan=plan))):
                with self.subTest(dispatch=dispatch), self.assertRaisesRegex(ValueError, "exact held native"):
                    confined.exchange_prepared_pi_bootstrap(plan, mock.sentinel.connection,
                        expected_pid=1234, provider_dispatch=dispatch)
            read.assert_not_called()
            send.assert_not_called()


class ProviderStartNodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse toolchain custody only, never inherit/run old behavioral checks.
        offline.PiCoreEntrypointTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        offline.PiCoreEntrypointTests.tearDownClass.__func__(cls)

    def case(self, name):
        if name not in self.fixtures:
            completed = subprocess.run([str(offline._NODE), "--no-warnings",
                str(offline._ROOT / "tests/fixtures/pi_core_provider_start_offline.mjs"), name],
                cwd=offline._ROOT, env=self.environment, capture_output=True, timeout=8, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
            self.assertLessEqual(len(completed.stdout), 2 * 1024 * 1024)
            output = json.loads(completed.stdout)
            self.assertEqual(output["fixture"], "PROTECTED_START_REAL_PI_INERT_PEERS_NOT_QUALIFICATION")
            self.assertEqual(output["selected"], name)
            self.assertEqual(output["nodeVersion"], offline._NODE_VERSION)
            self.assertEqual(output["liveIO"], [])
            imports = {(item["parent"], item["specifier"]) for item in output["remappedImports"]}
            self.assertIn(("entrypoint.ts", "./worker.js"), imports)
            self.assertLessEqual(imports, {("entrypoint.ts", "./worker.js"),
                ("entrypoint.ts", "./provider.js"), ("provider.ts", "./worker.js")})
            self.fixtures[name] = output
        return self.fixtures[name]

    def refused(self, name):
        output = self.case(name)
        self.assertIsNone(output["result"]["value"])
        self.assertIsNotNone(output["result"]["error"])
        self.assertEqual(output["connections"], [])
        self.assertEqual(output["requests"], [])

    def test_exact_v3_parse_copies_prepared_data(self):
        output = self.case("parse")
        self.assertIsNone(output["result"]["error"])
        self.assertEqual(output["result"]["value"]["task"], "Save the sum of 1 and 2.")
        self.assertEqual(output["connections"], [])

    def test_schema_and_opt_in_must_match(self):
        for name in ("enabledV1", "enabledV2", "disabledV3", "missingProvider"):
            with self.subTest(name=name): self.refused(name)

    def test_endpoint_callback_credentials_and_legacy_relay_injection_refuse(self):
        for name in ("unknownEndpoint", "credentials", "callback", "callerRelay"):
            with self.subTest(name=name): self.refused(name)

    def test_exact_route_and_derived_timeout_cannot_change(self):
        for name in ("badRoute", "widenedTimeout", "routeOverride"):
            with self.subTest(name=name): self.refused(name)

    def test_only_single_provider_and_tool_budgets_are_accepted(self):
        for name in ("moreRequests", "booleanRequests", "moreTurns", "moreTools"):
            with self.subTest(name=name): self.refused(name)

    def test_legacy_bootstrap_does_not_connect_any_client(self):
        for name in ("unavailableV1", "unavailableV2"):
            output = self.case(name)
            with self.subTest(name=name):
                self.assertIsNone(output["result"]["error"])
                self.assertEqual(output["result"]["value"]["status"], "PROVIDER_UNAVAILABLE")
                self.assertEqual(output["connections"], [])
                self.assertEqual(output["writes"][1]["schema"], "aragorn/pi-core-bootstrap-result/v1")
                self.assertNotIn(("entrypoint.ts", "./provider.js"),
                    {(item["parent"], item["specifier"]) for item in output["remappedImports"]})

    def test_enabled_bootstrap_uses_fixed_provider_and_exact_prompt_model(self):
        output = self.case("text")
        self.assertIsNone(output["result"]["error"])
        self.assertEqual(output["result"]["value"]["status"], "WORKER_COMPLETED")
        self.assertEqual(output["connections"], [{"path": "/run/aragorn-pi-bootstrap/provider/provider.sock", "allowHalfOpen": True}])
        request = output["requests"][0]["value"]
        # Compare the actual Pi/client projection with the independent root
        # reconstruction from the same prepared START; reuse this fixture run.
        self.assertEqual(request, native_provider._expected_request(
            SimpleNamespace(start_bytes=canonical_json(output["originalStart"]))))
        self.assertEqual(request["route_digest"], fixtures.digest("b"))
        self.assertEqual(request["activation_id"], "a" * 32)
        self.assertEqual(request["sequence"], 1)
        self.assertEqual(request["payload"]["model"]["id"], "offline-provider")
        messages = request["payload"]["messages"]
        self.assertEqual([message["timestamp"] for message in messages], [0, 0])
        self.assertEqual(messages[0]["content"], "Calculate the sum of these fabricated numbers.")
        self.assertEqual(messages[1]["content"][0]["text"], "Save the sum of 1 and 2.")
        self.assertEqual(messages[0]["toolsAdded"][0]["name"], "aragorn_runtime_create")
        result_wire = output["writes"][1]
        confined._validate_provider_result(result_wire, activation_id="a" * 32)
        self.assertEqual(set(result_wire["worker"]), {"status", "stop_reason", "provider_calls",
            "tool_calls", "agent_settled", "transcript_complete"})
        self.assertNotIn("Fixture-only reply.", json.dumps(result_wire))
        self.assertEqual(result_wire["worker"]["tool_calls"], 0)

    def test_broker_refusal_is_not_success_and_does_not_repeat_effect(self):
        output = self.case("toolRefused")
        self.assertIsNone(output["result"]["error"])
        self.assertEqual(output["result"]["value"]["status"], "WORKER_STOPPED")
        self.assertEqual([item["path"] for item in output["requests"]], [
            "/run/aragorn-pi-bootstrap/provider/provider.sock", "/run/aragorn-pi-bootstrap/requests/request.sock"])
        summary = output["writes"][1]["worker"]
        self.assertEqual(summary["provider_calls"], 1)
        self.assertEqual(summary["tool_calls"], 1)
        self.assertEqual(summary["stop_reason"], "RELAY_NOT_SUBMITTED")
        confined._validate_provider_result(output["writes"][1], activation_id="a" * 32)

    def test_authored_completed_tool_uses_both_fixed_clients_without_continuation(self):
        output = self.case("toolCompleted")
        self.assertIsNone(output["result"]["error"])
        self.assertEqual(output["result"]["value"]["status"], "WORKER_COMPLETED")
        self.assertEqual([item["path"] for item in output["requests"]], [
            "/run/aragorn-pi-bootstrap/provider/provider.sock", "/run/aragorn-pi-bootstrap/requests/request.sock"])
        effect = output["requests"][1]["value"]
        self.assertEqual(effect["target_name"], "result.json")
        self.assertEqual(effect["session_id"], "a" * 32)
        self.assertEqual(effect["run_id"], "a" * 32)
        summary = output["writes"][1]["worker"]
        self.assertEqual(summary["provider_calls"], 1)
        self.assertEqual(summary["tool_calls"], 1)
        self.assertIsNone(summary["stop_reason"])
        confined._validate_provider_result(output["writes"][1], activation_id="a" * 32)
        self.assertNotIn("broker_result", output["writes"][1])

    def test_provider_failure_or_ambiguous_outcome_never_calls_tool_or_retries(self):
        for name in ("providerFailure", "providerIndeterminate"):
            output = self.case(name)
            with self.subTest(name=name):
                self.assertIsNone(output["result"]["error"])
                self.assertEqual(output["result"]["value"]["status"], "WORKER_STOPPED")
                self.assertEqual(len(output["requests"]), 1)
                self.assertEqual(output["writes"][1]["worker"]["tool_calls"], 0)

    def test_missing_response_aborts_only_owned_client_and_keeps_uncertainty(self):
        output = self.case("missingProviderResponse")
        self.assertEqual(len(output["requests"]), 1)
        self.assertTrue(output["socketEvents"])
        self.assertTrue(all(event["path"] == "/run/aragorn-pi-bootstrap/provider/provider.sock"
                            for event in output["socketEvents"]))
        if output["result"]["error"] is None:
            self.assertEqual(output["result"]["value"]["status"], "WORKER_STOPPED")
            self.assertEqual(output["writes"][1]["worker"]["tool_calls"], 0)
        else:
            self.assertIsNone(output["result"]["value"])
            self.assertEqual(len(output["writes"]), 1)

    def test_expired_original_deadline_never_starts_provider(self):
        self.refused("expired")

    def test_wrong_release_never_claims_completed_lifecycle_or_retries(self):
        output = self.case("wrongRelease")
        self.assertIsNone(output["result"]["value"])
        self.assertIn("release", output["result"]["error"]["message"])
        self.assertEqual(len(output["requests"]), 1)
        self.assertEqual(len(output["writes"]), 2)
