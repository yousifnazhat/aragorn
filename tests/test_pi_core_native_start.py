"""Focused native START/configuration checks; all native edges remain inert.

Fixture setup is reused without importing or inheriting historical TestCases.
No service, process, socket, provider, or effect is activated by these checks.
"""

import dataclasses
import json
import os
import socket
import subprocess
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_confined_launch as confined
from aragorn import pi_core_native_request as route
from aragorn import pi_core_native_supervisor as native
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_confined_launch as fixtures
from tests import test_pi_core_identity_supervisor as native_fixtures
from tests import test_pi_core_request_wiring as wiring_fixtures


def configuration(*, native_request=True):
    return dataclasses.replace(fixtures.configuration(), native_request=native_request)


def endpoint(config):
    return {"schema": "aragorn/pi-core-native-request-endpoint/v1",
        "socket_path": "/run/aragorn-pi-bootstrap/requests/request.sock",
        "worker_uid": config.worker_uid, "worker_gid": config.worker_gid,
        "supervisor_uid": 0, "max_requests": 1}


def legacy_configuration_document(config):
    # Authored pre-change shape, not a call to the implementation under test.
    return {"schema": "aragorn/pi-core-confined-configuration/v1",
        "root_directory": str(config.root_directory), "root_closure_digest": config.root_closure_digest,
        "runtime_directory": str(config.runtime_directory), "compiled_receipt_digest": config.compiled_receipt_digest,
        "activation_directory": str(config.activation_directory),
        "worker_uid": config.worker_uid, "worker_gid": config.worker_gid,
        "task": config.task, "model": config.model, "limits": config.limits,
        "relay": config.relay, "provider_status": "UNAVAILABLE"}


class InertTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(confined.time, "monotonic", return_value=10.0))
        self.stack.enter_context(mock.patch.object(confined.time, "monotonic_ns", return_value=10_000_000_000))
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("native process/socket operation forbidden")))
        for name in ("open", "close", "mkdir", "rmdir", "unlink", "stat", "fstat", "fsync"):
            self.stack.enter_context(mock.patch.object(os, name,
                side_effect=AssertionError("unmocked filesystem operation forbidden")))
        for name in ("fork", "posix_spawn", "posix_spawnp", "pidfd_open"):
            self.stack.enter_context(mock.patch.object(os, name, create=True,
                side_effect=AssertionError("process/PIDFD operation forbidden")))
        for name in ("_read_virtual_file", "open_peer_pidfd", "measure_runtime_process_profile", "require_live_pidfd"):
            self.stack.enter_context(mock.patch.object(native.process, name,
                side_effect=AssertionError("live process measurement forbidden")))
        self.config = configuration()
        self.profile = fixtures.profile_for(self.config)
        self.prepared = fixtures.prepared_for(self.profile)


class NativeStartContractTests(InertTests):
    def test_native_mode_is_last_default_false_field_and_strict_bool(self):
        self.assertEqual(tuple(confined.PiConfinedLaunchConfig.__dataclass_fields__)[-1], "native_request")
        self.assertIs(fixtures.configuration().native_request, False)
        for invalid in (None, 0, 1, "true", {}, []):
            with self.subTest(invalid=invalid), self.assertRaises(confined.PiConfinedLaunchError):
                dataclasses.replace(self.config, native_request=invalid)

    def test_legacy_start_retains_exact_v1_shape(self):
        config = configuration(native_request=False)
        expected = {"schema": "aragorn/pi-core-bootstrap-start/v1",
            "activation_id": self.prepared.activation_id, "system_prompt": self.prepared.system_prompt,
            "task": config.task, "model": config.model, "limits": config.limits,
            "relay": config.relay, "provider_status": "UNAVAILABLE"}
        self.assertEqual(confined._start(config, self.prepared), canonical_json(expected))

    def test_native_start_has_exact_v2_endpoint_instead_of_relay(self):
        start = json.loads(confined._start(self.config, self.prepared))
        self.assertEqual(set(start), {"schema", "activation_id", "system_prompt", "task", "model",
                                      "limits", "native_request", "provider_status"})
        self.assertEqual(start["schema"], "aragorn/pi-core-bootstrap-start/v2")
        self.assertEqual(start["native_request"], endpoint(self.config))
        self.assertEqual(start["provider_status"], "UNAVAILABLE")
        self.assertNotIn("relay", start)

    def test_native_tool_call_budget_must_be_one(self):
        for invalid in (0, 2, 8, True):
            config = dataclasses.replace(self.config, limits={**self.config.limits, "maxToolCalls": invalid})
            with self.subTest(invalid=invalid), self.assertRaises(confined.PiConfinedLaunchError):
                confined._start(config, self.prepared)

    def test_legacy_tool_call_budget_is_not_narrowed(self):
        config = dataclasses.replace(configuration(native_request=False),
            limits={**self.config.limits, "maxToolCalls": 8})
        self.assertEqual(json.loads(confined._start(config, self.prepared))["limits"]["maxToolCalls"], 8)

    def test_legacy_configuration_digest_is_byte_shape_compatible(self):
        config = configuration(native_request=False)
        self.assertEqual(confined.confined_configuration_digest(config),
                         canonical_digest(legacy_configuration_document(config)))

    def test_native_configuration_digest_binds_mode_endpoint_and_denied_relay(self):
        expected = {**legacy_configuration_document(self.config),
            "schema": "aragorn/pi-core-confined-configuration/v2", "native_request": endpoint(self.config)}
        observed = confined.confined_configuration_digest(self.config)
        self.assertEqual(observed, canonical_digest(expected))
        self.assertNotEqual(observed, confined.confined_configuration_digest(configuration(native_request=False)))
        altered = dataclasses.replace(self.config,
            relay={**self.config.relay, "workerSocketPath": "/run/different-denied/worker.sock"})
        self.assertNotEqual(observed, confined.confined_configuration_digest(altered))
        self.assertEqual(confined._start(self.config, self.prepared), confined._start(altered, self.prepared))

    def test_endpoint_worker_identity_is_derived_and_pinned(self):
        config = dataclasses.replace(self.config, worker_uid=2101, worker_gid=2102,
            relay={**self.config.relay, "expectedGatewayUid": 2101, "expectedGatewayGid": 2102})
        self.assertEqual(json.loads(confined._start(config, self.prepared))["native_request"], endpoint(config))
        self.assertNotEqual(confined.confined_configuration_digest(config),
                            confined.confined_configuration_digest(self.config))

    def test_endpoint_cannot_be_supplied_in_config_relay_or_limits(self):
        with self.assertRaises(TypeError):
            dataclasses.replace(self.config, socket_path="/tmp/override.sock")
        for field in ("relay", "limits"):
            config = dataclasses.replace(self.config,
                **{field: {**getattr(self.config, field), "native_request": endpoint(self.config)}})
            with self.subTest(field=field), self.assertRaises(confined.PiConfinedLaunchError):
                confined._start(config, self.prepared)

    def test_denied_relay_cannot_alias_or_mask_protected_endpoint_ancestors(self):
        paths = ("/run", "/run/aragorn-pi-bootstrap", "/run/aragorn-pi-bootstrap/bootstrap.sock",
                 "/run/aragorn-pi-bootstrap/requests", "/run/aragorn-pi-bootstrap/requests/request.sock",
                 "/run/aragorn-pi-bootstrap/./requests/request.sock",
                 "/run/aragorn-pi-bootstrap/requests/../bootstrap.sock",
                 "/run//aragorn-pi-bootstrap/bootstrap.sock")
        for enabled in (False, True):
            for path in paths:
                config = dataclasses.replace(self.config, native_request=enabled,
                    relay={**self.config.relay, "workerSocketPath": path})
                with self.subTest(native=enabled, path=path), self.assertRaises(confined.PiConfinedLaunchError):
                    confined._start(config, self.prepared)

    def test_similarly_named_denied_relay_is_not_a_protected_ancestor(self):
        config = dataclasses.replace(self.config,
            relay={**self.config.relay, "workerSocketPath": "/run/aragorn-pi-bootstrap-other/socket"})
        self.assertEqual(json.loads(confined._start(config, self.prepared))["native_request"], endpoint(config))

    def test_native_mode_keeps_exact_legacy_relay_identity_constraints(self):
        for key, value in (("expectedGatewayUid", 0), ("expectedGatewayGid", 9999),
                           ("expectedWorkerUid", self.config.worker_uid)):
            config = dataclasses.replace(self.config, relay={**self.config.relay, key: value})
            with self.subTest(key=key), self.assertRaises(confined.PiConfinedLaunchError):
                confined._start(config, self.prepared)


class NativeProtectedPlanTests(InertTests):
    def setUp(self):
        super().setUp()

        @contextmanager
        def held(*args, **kwargs):
            yield self.prepared

        self.hold = self.stack.enter_context(mock.patch.object(confined, "hold_prepared_pi_bundle", side_effect=held))
        self.open_root = self.stack.enter_context(mock.patch.object(confined.lineage, "_open_protected_root", side_effect=[11, 12, 13]))
        self.close = self.stack.enter_context(mock.patch.object(confined.os, "close"))
        self.stack.enter_context(mock.patch.object(confined, "_tree", side_effect=[
            ({"files": [{"path": "usr/bin/env", "executable": True}]}, confined._EMPTY_MOUNTPOINTS,
             self.config.root_closure_digest), (fixtures.runtime_manifest(), (), fixtures.digest("e"))]))

    def plan(self, *, pins=None):
        pins = pins if pins is not None else {"os_profile": self.config.root_closure_digest,
            "configuration": confined.confined_configuration_digest(self.config),
            "runtime_commit_or_image": self.profile.runtime_digest}
        return confined.hold_confined_pi_launch_plan(object(), {}, profile=self.profile, grant={},
            protected_root=Path("/var/lib/aragorn/admitted"), runtime_conformance_digest=fixtures.digest(),
            deployment=pins, revoked_context_ids=(), now_unix=1, deadline=20.0, config=self.config)

    def test_native_plan_emits_bound_start_and_keeps_legacy_endpoint_masked(self):
        with self.plan() as plan:
            self.assertEqual(plan.start_bytes, confined._start(self.config, self.prepared))
            self.assertIn("--property=InaccessiblePaths=-/run/aragorn-relay/worker.sock"
                          " -/dev/shm -/dev/hugepages -/dev/pts", plan.systemd_run_argv)
            self.assertIn("--property=BindReadOnlyPaths=/run/aragorn-pi-bootstrap:/run/aragorn-pi-bootstrap",
                          plan.systemd_run_argv)
            self.assertFalse(any("request.sock" in arg for arg in plan.systemd_run_argv))
        self.assertFalse(plan._lease.active)
        self.assertEqual(self.close.call_args_list, [mock.call(13), mock.call(12), mock.call(11)])

    def test_native_plan_rejects_v1_configuration_pin_before_admission_or_root_open(self):
        pins = {"os_profile": self.config.root_closure_digest,
            "configuration": confined.confined_configuration_digest(configuration(native_request=False)),
            "runtime_commit_or_image": self.profile.runtime_digest}
        with self.assertRaises(confined.PiConfinedLaunchError), self.plan(pins=pins):
            self.fail("unbound native mode yielded a plan")
        self.hold.assert_not_called()
        self.open_root.assert_not_called()

    def test_native_start_snapshot_does_not_change_with_mutable_caller_inputs(self):
        with self.plan() as plan:
            raw = plan.start_bytes
            self.config.model["name"] = "changed caller model"
            self.config.limits["maxToolCalls"] = 8
            self.config.relay["workerSocketPath"] = "/run/aragorn-pi-bootstrap/requests/request.sock"
            self.assertEqual(plan.start_bytes, raw)
            self.assertEqual(json.loads(raw)["limits"]["maxToolCalls"], 1)


class NativeModeSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = native_fixtures.IdentitySupervisorTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.config = configuration()
        self.fixture.plan = dataclasses.replace(self.fixture.plan,
            start_bytes=confined._start(self.config, self.fixture.plan.prepared))
        self.channels = route.PiNativeRequestChannels(mock.Mock(), mock.Mock(),
            (500, 2201, 2202), (600, 2301, 2302), mock.sentinel.binding)
        self.observation = {"status": "NO_REQUEST", "cleanup": "NOT_ATTEMPTED", "phase3_exit_eligible": False}
        self.dispatch = SimpleNamespace(observation=self.observation, read_bootstrap_result=mock.Mock())

        @contextmanager
        def held(*args, **kwargs):
            self.fixture.events.append("request_open")
            try:
                yield self.dispatch
            finally:
                self.fixture.events.append("request_close")
                self.observation["cleanup"] = "VERIFIED_OWNED_REQUEST_CLEANUP"

        self.hold = self.enterContext(mock.patch.object(route, "hold_native_pi_request_dispatch", side_effect=held))

    def run_worker(self, *, config=None, channels=mock.sentinel.default):
        return native.run_native_pi_worker(object(), {}, profile=self.fixture.plan.profile, grant={},
            protected_root=Path("/var/lib/aragorn/admitted"), runtime_conformance_digest=fixtures.digest(),
            deployment={}, revoked_context_ids=(), now_unix=1, deadline=120.0,
            config=self.config if config is None else config,
            request_channels=self.channels if channels is mock.sentinel.default else channels)

    def test_native_mode_without_channels_refuses_before_prerequisites(self):
        with self.assertRaises(native.PiNativeSupervisorError):
            self.run_worker(channels=None)
        self.fixture.prereq.assert_not_called()
        self.fixture.hold.assert_not_called()

    def test_legacy_mode_with_channels_refuses_before_prerequisites(self):
        with self.assertRaises(native.PiNativeSupervisorError):
            self.run_worker(config=configuration(native_request=False))
        self.fixture.prereq.assert_not_called()
        self.fixture.hold.assert_not_called()

    def test_truthy_nonboolean_mode_refuses_before_prerequisites(self):
        with self.assertRaises(native.PiNativeSupervisorError):
            self.run_worker(config=SimpleNamespace(native_request=1))
        self.fixture.prereq.assert_not_called()

    def test_plain_channel_mapping_refuses_before_prerequisites(self):
        with self.assertRaises(native.PiNativeSupervisorError):
            self.run_worker(channels={"authorized": True})
        self.fixture.prereq.assert_not_called()

    def test_default_legacy_mode_does_not_create_native_request_resources(self):
        self.fixture.plan = dataclasses.replace(self.fixture.plan,
            start_bytes=confined._start(configuration(native_request=False), self.fixture.plan.prepared))
        result = self.run_worker(config=configuration(native_request=False), channels=None)
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertEqual(result["request_channel"], {"status": "NOT_REQUESTED"})
        self.hold.assert_not_called()
        self.assertNotIn("read_result", self.fixture.exchange.call_args.kwargs)

    def test_native_mode_connects_existing_dispatch_and_records_no_request_not_effect_success(self):
        result = self.run_worker()
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertEqual(result["request_channel"], self.observation)
        self.assertEqual(result["bootstrap"]["status"], "PROVIDER_UNAVAILABLE")
        self.assertIs(self.fixture.exchange.call_args.kwargs["read_result"], self.dispatch.read_bootstrap_result)
        self.assertEqual(self.hold.call_args.kwargs["deadline"], 115.0)
        self.assertEqual(self.hold.call_args.kwargs["cleanup_deadline"], 120.0)
        self.assertLess(self.fixture.events.index("request_close"), self.fixture.events.index("RELEASE"))
        self.channels.broker_connection.close.assert_not_called()
        self.channels.sensor_connection.close.assert_not_called()

    def test_native_mode_rejects_held_legacy_start_before_resources_or_start(self):
        self.fixture.plan = dataclasses.replace(self.fixture.plan,
            start_bytes=confined._start(configuration(native_request=False), self.fixture.plan.prepared))
        with self.assertRaises(native.PiNativeSupervisorError):
            self.run_worker()
        self.fixture.state.assert_not_called()
        self.fixture.command.assert_not_called()
        self.hold.assert_not_called()

    def test_native_mode_rejects_tampered_held_endpoint_before_resources_or_start(self):
        start = json.loads(self.fixture.plan.start_bytes)
        start["native_request"]["socket_path"] = "/tmp/override.sock"
        self.fixture.plan = dataclasses.replace(self.fixture.plan, start_bytes=canonical_json(start))
        with self.assertRaises(native.PiNativeSupervisorError):
            self.run_worker()
        self.fixture.state.assert_not_called()
        self.fixture.command.assert_not_called()

    def test_native_mode_rejects_changed_held_worker_identity(self):
        self.fixture.plan = dataclasses.replace(self.fixture.plan, worker_uid=9999)
        with self.assertRaises(native.PiNativeSupervisorError):
            self.run_worker()
        self.fixture.state.assert_not_called()
        self.fixture.command.assert_not_called()

    def test_native_mode_rejects_provider_ready_in_held_start(self):
        start = json.loads(self.fixture.plan.start_bytes)
        start["provider_status"] = "READY"
        self.fixture.plan = dataclasses.replace(self.fixture.plan, start_bytes=canonical_json(start))
        with self.assertRaises(native.PiNativeSupervisorError):
            self.run_worker()
        self.fixture.state.assert_not_called()
        self.fixture.command.assert_not_called()


def load_tests(loader, tests, pattern):
    """Add only the five old checks whose native configuration contract changed."""
    tests.addTests(loader.loadTestsFromTestCase(wiring_fixtures.NativeRequestIntegrationTests))
    return tests
