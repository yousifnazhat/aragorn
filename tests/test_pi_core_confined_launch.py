"""Inert checks for guarded plans/bootstrap; no systemd, sockets or processes.

Kernel custody and installed roots are mocked authored fixtures. These checks
are not Linux confinement, provider integration, or Phase 3 acceptance proof.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import os
import socket
import struct
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_bundle_launch as bundle
from aragorn import pi_core_confined_launch as confined
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_process_profile import RuntimeProcessProfile


def digest(char="a"):
    return "sha256:" + char * 64


def runtime_manifest():
    names = ["node/bin/node", "openclaw/aragorn-runtime-action-worker/index.js",
             "openclaw/aragorn-runtime-action-worker/package.json", "pi-core/entrypoint.js",
             "pi-core/node_modules/example/index.js", "pi-core/package.json", "pi-core/worker.js"]
    return {"files": [{"path": name, "size": 5, "digest": digest(str(index)),
                       "executable": name == "node/bin/node"}
                      for index, name in enumerate(names)]}


def receipt(manifest):
    rows = [{"path": entry["path"], "kind": "file", "bytes": entry["size"],
             "sha256": entry["digest"][7:]} for entry in manifest["files"]]
    return {"schema": "aragorn/pi-core-linux-build/v1", "target": "linux-arm64-glibc",
            "status": "COMPILED_NOT_DEPLOYED_OR_OS_QUALIFIED", "node_version": "24.22.2",
            "typescript_version": "7.0.2", "runtime_executed": False,
            "install_scripts_executed": False, "deployment_inventory": rows,
            "deployment_tree_sha256": canonical_digest(rows)[7:]}


def configuration():
    manifest = runtime_manifest()
    compiled = receipt(manifest)
    return confined.PiConfinedLaunchConfig(
        root_directory=Path("/var/lib/aragorn/pi-os"), root_closure_digest=digest("b"),
        runtime_directory=Path("/var/lib/aragorn/pi-runtime"), compiled_receipt=compiled,
        compiled_receipt_digest=canonical_digest(compiled),
        activation_directory=Path("/var/lib/aragorn/pi-activations"),
        worker_uid=1101, worker_gid=1102, task="inert task",
        model={"id": "fixture", "name": "fixture", "api": "openai-responses",
               "provider": "fixture", "baseUrl": "https://invalid.example",
               "reasoning": False, "input": ["text"], "contextWindow": 100,
               "maxTokens": 10, "cost": {key: 0 for key in ("input", "output", "cacheRead", "cacheWrite")}},
        limits={"maxTurns": 1, "maxToolCalls": 1, "maxRunMs": 100},
        relay={"expectedGatewayUid": 1101, "expectedGatewayGid": 1102,
               "expectedWorkerUid": 1200, "workerSocketPath": "/run/aragorn-relay/worker.sock"},
    )


def profile_for(config):
    return RuntimeProcessProfile(
        "sha256:" + config.compiled_receipt["deployment_tree_sha256"], digest("0"),
        "/system.slice/aragorn-pi-" + "c" * 32 + ".service",
        Path("/var/lib/aragorn/admitted/.aragorn-versions/example/version/SKILL.md"), digest("d"))


def prepared_for(profile):
    return bundle.PreparedPiBundle(
        activation_id="a" * 32, system_prompt="admitted instructions",
        members=(("SKILL.md", b"admitted instructions"),), context_digest=digest(),
        manifest_digest=digest(), tree_digest=digest(), active_record_digest=digest(),
        skill_digest=digest(), deployment_digest=digest(), policy_digest=digest(),
        expires_at_monotonic_ns=20_000_000_000, profile_digest=profile.digest,
        runtime_digest=profile.runtime_digest, executable_digest=profile.executable_digest,
        skill_path=profile.skill_path, _lease=bundle._Lease())


class InertTests(unittest.TestCase):
    def setUp(self):
        super().setUp()
        traps = ExitStack()
        self.addCleanup(traps.close)
        for owner, name in ((subprocess, "Popen"), (subprocess, "run"),
                            (socket, "socket"), (socket, "create_connection"),
                            (os, "system"), (bundle, "open_peer_pidfd"),
                            (bundle, "measure_runtime_process_profile")):
            traps.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("native process/socket/identity operation forbidden in inert checks")))
        for name in ("fork", "posix_spawn", "posix_spawnp"):
            if hasattr(os, name):
                traps.enter_context(mock.patch.object(os, name,
                    side_effect=AssertionError("native process activation forbidden in inert checks")))


class ConfinedPlanTests(InertTests):
    def setUp(self):
        super().setUp()
        self.config = configuration()
        self.profile = profile_for(self.config)
        self.prepared = prepared_for(self.profile)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(confined.os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(confined.time, "monotonic", return_value=10.0))
        self.stack.enter_context(mock.patch.object(confined.time, "monotonic_ns", return_value=10_000_000_000))
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.fds = []

        def open_root(_path, uid):
            self.assertEqual(uid, 0)
            fd = os.open(self.temp, os.O_RDONLY | os.O_DIRECTORY)
            self.fds.append(fd)
            return fd

        self.open_root = self.stack.enter_context(mock.patch.object(
            confined.lineage, "_open_protected_root", side_effect=open_root))
        os_manifest = {"files": [{"path": "usr/bin/env", "executable": True}]}
        self.tree = self.stack.enter_context(mock.patch.object(confined, "_tree", side_effect=[
            (os_manifest, confined._EMPTY_MOUNTPOINTS, self.config.root_closure_digest),
            (runtime_manifest(), (), digest("e")),
        ]))

        @contextmanager
        def prepared(*args, **kwargs):
            self.preparation_kwargs = kwargs
            yield self.prepared

        self.hold = self.stack.enter_context(mock.patch.object(
            confined, "hold_prepared_pi_bundle", side_effect=prepared))

    def plan(self, config=None, profile=None, pins=None, deadline=20.0):
        config = config or self.config
        profile = profile or self.profile
        pins = pins or {"os_profile": config.root_closure_digest,
            "configuration": confined.confined_configuration_digest(config),
            "runtime_commit_or_image": profile.runtime_digest}
        return confined.hold_confined_pi_launch_plan(object(), {}, profile=profile,
            grant={}, protected_root=Path("/var/lib/aragorn/admitted"),
            runtime_conformance_digest=digest(), deployment=pins,
            revoked_context_ids=(), now_unix=1, deadline=deadline, config=config)

    def test_plan_holds_existing_admission_and_closes_descriptors(self):
        with self.plan() as plan:
            self.assertIs(plan.prepared, self.prepared)
            self.assertTrue(plan._lease.active)
            self.assertEqual(self.preparation_kwargs["deadline"], 20)
            self.assertEqual(plan.runtime_inventory_digest, self.profile.runtime_digest)
            self.assertEqual(plan.activation_path.name, "a" * 32 + ".json")
            self.assertEqual(json.loads(plan.start_bytes)["provider_status"], "UNAVAILABLE")
            for fd in self.fds:
                os.fstat(fd)
        self.assertFalse(plan._lease.active)
        for fd in self.fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_plan_argv_is_fixed_confined_and_not_an_execution_claim(self):
        with self.plan() as plan:
            args = plan.systemd_run_argv
            self.assertEqual(args[0], "/usr/bin/systemd-run")
            self.assertIn("--property=RootDirectory=" + str(self.config.root_directory), args)
            for property in ("Restart=no", "Delegate=no", "NoNewPrivileges=yes",
                             "CapabilityBoundingSet=", "AmbientCapabilities=",
                             "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX"):
                self.assertIn("--property=" + property, args)
            self.assertIn("--property=InaccessiblePaths=-/run/aragorn-relay/worker.sock"
                          " -/dev/shm -/dev/hugepages -/dev/pts", args)
            self.assertIn("--property=BindReadOnlyPaths=" + str(self.profile.skill_path.parent) +
                          ":" + str(self.profile.skill_path.parent), args)
            self.assertNotIn(self.config.task, args)
            self.assertEqual(args[-2:], ("/opt/aragorn/pi-runtime/node/bin/node",
                                       "/opt/aragorn/pi-runtime/pi-core/entrypoint.js"))
            self.assertIn("NOT_NATIVE_LAUNCH", plan.authority)

    def test_nonroot_refuses_before_preparation(self):
        with mock.patch.object(confined.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(ValueError, "protected supervisor"), self.plan():
                pass
        self.hold.assert_not_called()

    def test_invalid_deadlines_refuse_before_preparation(self):
        for deadline in (True, 10, 41, float("nan"), float("inf")):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError), self.plan(deadline=deadline):
                pass
        self.hold.assert_not_called()

    def test_missing_or_unbound_root_closure_refuses(self):
        for value in (None, "", digest("f")):
            config = dataclasses.replace(self.config, root_closure_digest=value)
            pins = {"os_profile": self.config.root_closure_digest,
                    "configuration": confined.confined_configuration_digest(config)}
            with self.subTest(value=value), self.assertRaises((ValueError, RuntimeError)), self.plan(config, pins=pins):
                pass
        self.open_root.assert_not_called()

    def test_unbound_configuration_refuses(self):
        pins = {"os_profile": self.config.root_closure_digest, "configuration": digest()}
        with self.assertRaisesRegex(ValueError, "deployment-bound"), self.plan(pins=pins):
            pass

    def test_overlap_and_unsafe_paths_refuse(self):
        for path in (Path("relative"), Path("/"), self.config.runtime_directory,
                     self.config.runtime_directory / "inside", Path("/unsafe space")):
            with self.subTest(path=path), self.assertRaises(ValueError), self.plan(
                    dataclasses.replace(self.config, root_directory=path)):
                pass
        self.hold.assert_not_called()

    def test_rootfs_mismatch_refuses_and_releases_fds(self):
        self.tree.side_effect = [({"files": []}, (), digest("f")), (runtime_manifest(), (), digest())]
        with self.assertRaisesRegex(ValueError, "OS closure differs"), self.plan():
            pass
        for fd in self.fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_missing_root_directory_is_not_synthesized(self):
        self.open_root.side_effect = FileNotFoundError("OS root not provisioned")
        with self.assertRaises(FileNotFoundError), self.plan():
            pass
        self.tree.assert_not_called()

    def test_rootfs_requires_pinned_env_entrypoint(self):
        self.tree.side_effect = [({"files": []}, confined._EMPTY_MOUNTPOINTS, self.config.root_closure_digest),
                                 (runtime_manifest(), (), digest())]
        with self.assertRaisesRegex(ValueError, "env entrypoint"), self.plan():
            pass

    def test_compiled_node_digest_must_join_profile(self):
        bad = dataclasses.replace(self.profile, executable_digest=digest("f"))
        with self.assertRaisesRegex(ValueError, "process-profile-bound"), self.plan(profile=bad):
            pass

    def test_cgroup_must_be_exact_dedicated_service(self):
        for cgroup in ("/system.slice/other.service", "/user.slice/aragorn-pi-" + "c" * 32 + ".service", "/"):
            with self.subTest(cgroup=cgroup), self.assertRaises(ValueError):
                confined._systemd_plan(self.config, self.prepared, dataclasses.replace(self.profile, cgroup=cgroup))

    def test_start_is_detached_from_mutable_caller_config(self):
        with self.plan() as plan:
            self.config.model["name"] = "mutated"
            self.config.limits["maxRunMs"] = 1
            self.assertEqual(json.loads(plan.start_bytes)["model"]["name"], "fixture")
            self.assertEqual(json.loads(plan.start_bytes)["limits"]["maxRunMs"], 100)

    def test_only_provider_unavailable_is_in_start(self):
        raw = confined._start(self.config, self.prepared)
        document = json.loads(raw)
        self.assertEqual(document["provider_status"], "UNAVAILABLE")
        self.assertNotIn("streamFn", document)
        self.assertNotIn("apiKey", document)

    def test_bad_worker_uid_gid_refuse(self):
        for field in ("worker_uid", "worker_gid"):
            for value in (True, 0, -1, 2**32):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError), self.plan(
                        dataclasses.replace(self.config, **{field: value})):
                    pass
        self.hold.assert_not_called()

    def test_relay_must_join_worker_and_stay_separate(self):
        for field, value in (("expectedGatewayUid", 99), ("expectedGatewayGid", 99),
                             ("expectedWorkerUid", self.config.worker_uid),
                             ("workerSocketPath", confined._BOOTSTRAP)):
            config = dataclasses.replace(self.config, relay={**self.config.relay, field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                confined._start(config, self.prepared)

    def test_task_and_model_cannot_inject_callbacks_or_credentials(self):
        for model in ({**self.config.model, "headers": {}}, {**self.config.model, "apiKey": "no"},
                      {**self.config.model, "input": ["image"]}):
            with self.subTest(model=model), self.assertRaises(ValueError):
                confined._start(dataclasses.replace(self.config, model=model), self.prepared)

    def test_canonical_costs_are_nonnegative_safe_integers(self):
        for value in (True, -1, 0.1, 2**53):
            model = copy.deepcopy(self.config.model)
            model["cost"]["input"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                confined._start(dataclasses.replace(self.config, model=model), self.prepared)

    def test_start_frame_combined_limit_is_enforced(self):
        prepared = dataclasses.replace(self.prepared, system_prompt="x" * 32 * 1024)
        config = dataclasses.replace(self.config, task="y" * 32 * 1024)
        with self.assertRaisesRegex(ValueError, "frame limit"):
            confined._start(config, prepared)

    def test_invalid_utf8_and_empty_text_refuse(self):
        for task in ("", "\ud800", "x" * (32 * 1024 + 1)):
            with self.subTest(task=repr(task[:10])), self.assertRaises(ValueError):
                confined._start(dataclasses.replace(self.config, task=task), self.prepared)


class CompiledInventoryTests(InertTests):
    def test_exact_compiled_receipt_matches_inventory(self):
        manifest = runtime_manifest()
        compiled = receipt(manifest)
        self.assertEqual(confined._runtime_inventory(manifest, compiled, canonical_digest(compiled)),
                         "sha256:" + compiled["deployment_tree_sha256"])

    def test_changed_receipt_pin_refuses(self):
        with self.assertRaisesRegex(ValueError, "receipt pin"):
            confined._runtime_inventory(runtime_manifest(), receipt(runtime_manifest()), digest())

    def test_runtime_execution_claim_and_wrong_target_refuse(self):
        for key, value in (("runtime_executed", True), ("install_scripts_executed", True),
                           ("target", "darwin-arm64"), ("node_version", "different"),
                           ("typescript_version", "different"), ("status", "QUALIFIED")):
            compiled = {**receipt(runtime_manifest()), key: value}
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "unsupported"):
                confined._runtime_inventory(runtime_manifest(), compiled, canonical_digest(compiled))

    def test_changed_installed_bytes_or_inventory_refuse(self):
        manifest = runtime_manifest()
        compiled = receipt(manifest)
        for field, value in (("digest", digest("f")), ("size", 99)):
            changed = copy.deepcopy(manifest)
            changed["files"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "differs"):
                confined._runtime_inventory(changed, compiled, canonical_digest(compiled))

    def test_incomplete_layout_refuses_even_with_matching_receipt(self):
        manifest = runtime_manifest()
        for missing in ("pi-core/entrypoint.js", "pi-core/node_modules/example/index.js"):
            altered = {"files": [entry for entry in manifest["files"] if entry["path"] != missing]}
            compiled = receipt(altered)
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "incomplete"):
                confined._runtime_inventory(altered, compiled, canonical_digest(compiled))

    def test_real_inert_tree_uses_complete_inventory_and_ownership_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "plain").write_bytes(b"inert")
            (root / "plain").chmod(0o444)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                original = confined.os.stat

                def fixture_root_owner(*args, **kwargs):
                    observed = original(*args, **kwargs)
                    # Test-only ownership mapping; not an installed root proof.
                    return SimpleNamespace(**{**{name: getattr(observed, name)
                        for name in dir(observed) if name.startswith("st_")}, "st_uid": 0})

                with mock.patch.object(confined.os, "stat", side_effect=fixture_root_owner):
                    manifest, directories, closure = confined._tree(fd)
                self.assertEqual(manifest["files"][0]["path"], "plain")
                self.assertEqual(directories, ())
                self.assertEqual(closure, canonical_digest({"schema": "aragorn/pi-core-protected-tree/v1",
                    "files": manifest["files"], "directories": []}))
            finally:
                os.close(fd)

    def test_writable_file_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "plain").write_bytes(b"inert")
            (root / "plain").chmod(0o644)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(ValueError, "immutable"):
                    confined._tree(fd)
            finally:
                os.close(fd)

    def test_symlink_file_refuses_without_following_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "link").symlink_to("/not-accessed")
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    confined._tree(fd)
            finally:
                os.close(fd)


class BootstrapCompositionTests(InertTests):
    def setUp(self):
        super().setUp()
        self.config = configuration()
        self.profile = profile_for(self.config)
        self.prepared = prepared_for(self.profile)
        self.plan = confined.PiConfinedLaunchPlan(
            self.prepared, self.profile, 1101, 1102, "aragorn-pi-" + "c" * 32 + ".service", (),
            self.config.activation_directory / ("a" * 32 + ".json"),
            confined._start(self.config, self.prepared), 20.0, digest(), digest(), confined._PlanLease())
        self.connection = mock.sentinel.accepted_after_exec_connection
        self.hello = {"schema": "aragorn/pi-core-bootstrap-hello/v1", "worker_nonce": "b" * 32}
        self.result = {"schema": "aragorn/pi-core-bootstrap-result/v1", "activation_id": "a" * 32,
                       "status": "PROVIDER_UNAVAILABLE", "authority": confined._RESULT_AUTHORITY}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(confined.os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(confined.time, "monotonic", return_value=10.0))
        self.stack.enter_context(mock.patch.object(confined.time, "monotonic_ns", return_value=10_000_000_000))
        self.read = self.stack.enter_context(mock.patch.object(confined, "_read_bootstrap", side_effect=[self.hello, self.result]))
        self.send = self.stack.enter_context(mock.patch.object(confined, "_send_frame"))
        self.bind = self.stack.enter_context(mock.patch.object(confined, "bind_pi_worker_activation", return_value={"fixture": "activation"}))

    def exchange(self):
        return confined.exchange_prepared_pi_bootstrap(self.plan, self.connection, expected_pid=1234)

    def test_bind_then_start_result_release_without_cleanup_claim(self):
        calls = mock.Mock()
        calls.attach_mock(self.read, "read")
        calls.attach_mock(self.bind, "bind")
        calls.attach_mock(self.send, "send")
        observed = self.exchange()
        self.assertEqual([call[0] for call in calls.mock_calls], ["read", "bind", "send", "read", "send"])
        self.assertIs(self.bind.call_args.args[1], self.connection)
        self.assertEqual(self.bind.call_args.kwargs["expected_pid"], 1234)
        self.assertEqual(self.bind.call_args.kwargs["activation_path"], self.plan.activation_path)
        self.assertEqual(self.send.call_args_list[0].args[1], self.plan.start_bytes)
        self.assertEqual(json.loads(self.send.call_args_list[1].args[1])["schema"], "aragorn/pi-core-bootstrap-release/v1")
        for call in self.send.call_args_list + self.read.call_args_list:
            self.assertEqual(call.args[-1], 20)
        self.assertTrue(observed["release_sent"])
        for name in ("process_exit_observed", "activation_withdrawn", "native_cleanup_verified"):
            self.assertFalse(observed[name])

    def test_untrusted_hello_cannot_supply_pid_or_authority(self):
        self.read.side_effect = [{**self.hello, "pid": 1234}]
        with self.assertRaisesRegex(ValueError, "HELLO"):
            self.exchange()
        self.bind.assert_not_called()
        self.send.assert_not_called()

    def test_admission_expiry_can_only_shorten_original_deadline(self):
        self.plan = dataclasses.replace(self.plan, prepared=dataclasses.replace(
            self.prepared, expires_at_monotonic_ns=15_000_000_000))
        self.exchange()
        for call in self.send.call_args_list + self.read.call_args_list:
            self.assertEqual(call.args[-1], 15)

    def test_bad_nonce_refuses_before_bind(self):
        self.read.side_effect = [{**self.hello, "worker_nonce": "b" * 32 + "\n"}]
        with self.assertRaisesRegex(ValueError, "HELLO"):
            self.exchange()
        self.bind.assert_not_called()

    def test_peer_bind_failure_never_sends_start_or_retries(self):
        self.bind.side_effect = RuntimeError("peer is not supervisor child")
        with self.assertRaisesRegex(RuntimeError, "peer"):
            self.exchange()
        self.send.assert_not_called()
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.exchange()
        self.bind.assert_called_once()

    def test_unexpected_result_never_claims_effect_or_releases(self):
        self.read.side_effect = [self.hello, {**self.result, "status": "COMPLETED"}]
        with self.assertRaisesRegex(ValueError, "no effect authority"):
            self.exchange()
        self.send.assert_called_once()

    def test_result_must_join_activation_and_have_exact_fields(self):
        self.read.side_effect = [self.hello, {**self.result, "activation_id": "d" * 32}]
        with self.assertRaises(ValueError):
            self.exchange()
        self.send.assert_called_once()

    def test_expired_or_exited_lease_refuses_before_any_socket_io(self):
        self.plan._lease.active = False
        with self.assertRaisesRegex(ValueError, "inactive"):
            self.exchange()
        self.read.assert_not_called()

    def test_expired_prepared_bundle_refuses_before_any_socket_io(self):
        self.prepared._lease.active = False
        with self.assertRaisesRegex(ValueError, "no longer active"):
            self.exchange()
        self.read.assert_not_called()

    def test_release_send_failure_is_not_cleanup_success(self):
        self.send.side_effect = [None, TimeoutError("release not delivered")]
        with self.assertRaisesRegex(TimeoutError, "release not delivered"):
            self.exchange()
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.exchange()

    def test_bootstrap_reader_reuses_canonical_receiver_without_eof(self):
        raw = canonical_json(self.hello)
        # Bypass only the higher-level fixture patch; no socket is opened.
        with mock.patch.object(confined, "_receive_exact", side_effect=[struct.pack("!I", len(raw)), raw]) as receive:
            # The real function is preserved before setUp's mock at module load.
            result = REAL_READ(self.connection, 20)
        self.assertEqual(result, self.hello)
        self.assertEqual(receive.call_count, 2)

    def test_zero_and_oversize_bootstrap_frames_refuse_before_body_read(self):
        for length in (0, 65537):
            with self.subTest(length=length), mock.patch.object(confined, "_receive_exact", return_value=struct.pack("!I", length)) as receive:
                with self.assertRaisesRegex(ValueError, "frame size"):
                    REAL_READ(self.connection, 20)
                receive.assert_called_once()

    def test_noncanonical_json_and_duplicate_keys_refuse(self):
        for raw in (b'{ "schema": "hello" }', b'{"a":1,"a":1}'):
            with self.subTest(raw=raw), mock.patch.object(confined, "_receive_exact", side_effect=[struct.pack("!I", len(raw)), raw]):
                with self.assertRaises(RuntimeError):
                    REAL_READ(self.connection, 20)


REAL_READ = confined._read_bootstrap


if __name__ == "__main__":
    unittest.main()
