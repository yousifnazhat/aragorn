"""New pre-exec launch contracts only: authored fixtures, no native activation.

ELF fixtures below test input rejection, not a compiled gate or live Node proof.
Existing inert fixture setup is reused without collecting its historical tests.
"""
from __future__ import annotations

import copy
import dataclasses
import importlib
import struct
import unittest
from pathlib import Path
from unittest import mock

from aragorn import pi_core_confined_launch as confined
from aragorn import pi_core_native_supervisor as native
from aragorn import pi_core_source_observer as source
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.runtime_action_broker import RuntimeActionBrokerError
from tests import test_pi_core_confined_launch as launch_fixture
from tests import test_pi_core_linux_build as build_fixture
from tests import test_pi_core_native_supervisor as native_fixture

build = build_fixture.build
GATE = "/opt/aragorn/pi-runtime/observer/source-gate"
NODE = "/opt/aragorn/pi-runtime/node/bin/node"
ENTRY = "/opt/aragorn/pi-runtime/pi-core/entrypoint.js"


def profile():
    return {"schema": "aragorn/pi-core-node-source-profile/v1",
            "pins": {name: launch_fixture.digest(str(index)) for index, name in enumerate((
                "gate_digest", "node_digest", "producer_digest", "node_observer_digest",
                "source_inventory_digest", "loader_inventory_digest"), 1)},
            "sources": [{"path": ENTRY, "digest": launch_fixture.digest("7")},
                        {"path": "/opt/aragorn/pi-runtime/pi-core/worker.js", "digest": launch_fixture.digest("8")}],
            "required_sources": [ENTRY],
            "loader_files": [{"path": "/usr/lib/libc.so.6", "digest": launch_fixture.digest("9")}]}


def observed(config, document=None):
    document = profile() if document is None else document
    return dataclasses.replace(config, source_observation=document,
                               source_observation_digest=canonical_digest(document))


def fixture(test, cls):
    value = cls()
    value.setUp()
    test.addCleanup(value.doCleanups)
    return value


class SourceProfileTests(unittest.TestCase):
    def setUp(self):
        self.config = launch_fixture.configuration()

    def test_legacy_configuration_does_not_opt_in(self):
        self.assertIsNone(self.config.source_observation)
        self.assertIsNone(self.config.source_observation_digest)
        self.assertEqual(confined.confined_configuration_digest(self.config),
                         confined.confined_configuration_digest(dataclasses.replace(self.config)))

    def test_observer_profile_changes_protected_configuration_pin(self):
        configured = observed(self.config)
        self.assertNotEqual(confined.confined_configuration_digest(self.config),
                            confined.confined_configuration_digest(configured))

    def test_profile_and_pin_are_required_together(self):
        for values in ({"source_observation_digest": launch_fixture.digest()},
                       {"source_observation": profile()}):
            with self.subTest(values=values), self.assertRaises((ValueError, RuntimeActionBrokerError)):
                dataclasses.replace(self.config, **values)

    def test_changed_profile_under_stale_pin_is_refused(self):
        configured = observed(self.config)
        configured.source_observation["required_sources"].append("/new.js")
        with self.assertRaisesRegex(ValueError, "pin or schema"):
            confined.confined_configuration_digest(configured)

    def test_unknown_profile_fields_and_schema_are_refused(self):
        for key, value in (("schema", "other"), ("extra", True)):
            document = profile()
            document[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                observed(self.config, document)

    def test_missing_extra_or_bad_inventory_pins_are_refused(self):
        for mutation in (lambda pins: pins.pop("producer_digest"),
                         lambda pins: pins.update(extra=launch_fixture.digest()),
                         lambda pins: pins.update(gate_digest="sha256:bad")):
            document = profile()
            mutation(document["pins"])
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, RuntimeActionBrokerError)):
                observed(self.config, document)

    def test_required_source_set_is_nonempty_unique_and_in_inventory(self):
        for required in ([], [ENTRY, ENTRY], ["/unlisted.js"], [7]):
            document = profile()
            document["required_sources"] = required
            with self.subTest(required=required), self.assertRaises(ValueError):
                observed(self.config, document)

    def test_source_and_loader_roles_cannot_overlap(self):
        document = profile()
        document["loader_files"] = [copy.deepcopy(document["sources"][0])]
        with self.assertRaisesRegex(ValueError, "roles overlap"):
            observed(self.config, document)

    def test_inventory_rows_are_bounded_exact_unique_and_absolute(self):
        for rows in ([], profile()["sources"] * 257,
                     [profile()["sources"][0]] * 2,
                     *[[{"path": path, "digest": launch_fixture.digest()}] for path in
                       ("relative.js", "/", "//a", "/a//b", "/a/../b", "/a/./b",
                        "/a\n", "/a\x00", "/a\x7f", "/" + "a" * 4096)],
                     [{"path": ENTRY, "digest": launch_fixture.digest(), "extra": 1}]):
            document = profile()
            document["sources"] = rows
            with self.subTest(rows=len(rows)), self.assertRaises(ValueError):
                observed(self.config, document)

    def test_inventory_data_paths_allow_scoped_packages_and_spaces(self):
        document = profile()
        path = "/opt/aragorn/pi-runtime/pi-core/node_modules/@scope/pi agent/index.js"
        document["sources"][0]["path"] = path
        document["required_sources"] = [path]
        configured = observed(self.config, document)
        self.assertEqual(configured.source_observation["sources"][0]["path"], path)

    def test_gate_is_fixed_additive_command_and_does_not_enable_provider(self):
        configured = observed(self.config)
        process_profile = launch_fixture.profile_for(configured)
        prepared = launch_fixture.prepared_for(process_profile)
        _, argv = confined._systemd_plan(configured, prepared, process_profile)
        self.assertEqual(argv[-3:], (GATE, NODE, ENTRY))
        self.assertIn("--property=KillSignal=SIGKILL", argv)
        self.assertIn("--property=PrivateNetwork=yes", argv)
        self.assertIn("--property=Restart=no", argv)
        self.assertIn(b'"provider_status":"UNAVAILABLE"', confined._start(configured, prepared))


class ObservedUnitReadbackTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, native_fixture.InertTests)
        configured = observed(launch_fixture.configuration())
        original = native_fixture.plan()
        _, argv = confined._systemd_plan(configured, original.prepared, original.profile)
        self.plan = dataclasses.replace(original, systemd_run_argv=argv,
            source_observation=configured.source_observation,
            source_observation_digest=configured.source_observation_digest)
        self.signal = ["i", "9"]
        self.property = self.f.stack.enter_context(mock.patch.object(native, "_property",
            side_effect=lambda unit, name, deadline: self.signal if name == "KillSignal" else
            native_fixture.compound(self.plan, name)))

    def test_observed_immediate_owned_stop_is_read_back_and_digest_bound(self):
        result = native._readback(self.plan, native_fixture.running(self.plan), 120)
        self.assertTrue(result.startswith("sha256:"))
        self.assertIn(mock.call(self.plan.unit_name, "KillSignal", 120), self.property.call_args_list)

    def test_missing_wrong_or_untyped_stop_signal_refuses(self):
        for value in ([], ["i", "15"], ["s", "SIGKILL"], ["u", "9"]):
            self.signal = value
            with self.subTest(value=value), self.assertRaisesRegex(native.PiNativeSupervisorError, "stop signal"):
                native._readback(self.plan, native_fixture.running(self.plan), 120)

    def test_missing_observed_launch_signal_contract_refuses(self):
        altered = dataclasses.replace(self.plan,
            systemd_run_argv=tuple(arg for arg in self.plan.systemd_run_argv if "KillSignal=" not in arg))
        with self.assertRaisesRegex(native.PiNativeSupervisorError, "stop contract"):
            native._readback(altered, native_fixture.running(altered), 120)
        self.property.assert_not_called()

    def test_legacy_plan_does_not_acquire_new_stop_semantics(self):
        self.plan = native_fixture.plan()
        self.assertFalse(any("KillSignal=" in arg for arg in self.plan.systemd_run_argv))
        native._readback(self.plan, native_fixture.running(self.plan), 120)
        self.assertFalse(any(call.args[1] == "KillSignal" for call in self.property.call_args_list))


class HeldGatePlanTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, launch_fixture.ConfinedPlanTests)
        self.manifest = launch_fixture.runtime_manifest()
        self.manifest["files"].append({"path": "observer/source-gate", "size": 5,
            "digest": launch_fixture.digest("a"), "executable": True})
        self.compiled = launch_fixture.receipt(self.manifest)
        self.compiled["inputs"] = {"source_gate": {"schema": "aragorn/pi-core-source-gate-build/v1",
            "target": "linux-arm64-static", "source_sha256": "b" * 64, "elf_sha256": "a" * 64,
            "compiler_sha256": "c" * 64, "build_command_sha256": "d" * 64,
            "runtime_executed": False, "receipt_digest": launch_fixture.digest("e")}}
        self.document = profile()
        self.document["pins"].update(gate_digest=launch_fixture.digest("a"), node_digest=launch_fixture.digest("0"))

    def configure(self):
        self.f.config = observed(dataclasses.replace(self.f.config, compiled_receipt=self.compiled,
            compiled_receipt_digest=canonical_digest(self.compiled)), self.document)
        self.f.profile = launch_fixture.profile_for(self.f.config)
        self.f.prepared = launch_fixture.prepared_for(self.f.profile)
        self.f.tree.side_effect = [({"files": [{"path": "usr/bin/env", "executable": True}]},
            confined._EMPTY_MOUNTPOINTS, self.f.config.root_closure_digest),
            (self.manifest, (), launch_fixture.digest("e"))]

    def test_held_plan_binds_gate_and_detaches_mutable_profile(self):
        self.configure()
        with self.f.plan() as held:
            self.assertEqual(held.systemd_run_argv[-3:], (GATE, NODE, ENTRY))
            self.assertEqual(held.source_observation_digest, canonical_digest(held.source_observation))
            self.document["required_sources"].clear()
            self.assertEqual(held.source_observation["required_sources"], [ENTRY])

    def test_gate_absence_cannot_fall_back_to_direct_node(self):
        self.manifest["files"].pop()
        self.compiled = launch_fixture.receipt(self.manifest)
        self.configure()
        with self.assertRaisesRegex(ValueError, "gate artifact"), self.f.plan():
            pass

    def test_substituted_gate_pin_refuses(self):
        self.document["pins"]["gate_digest"] = launch_fixture.digest("f")
        self.configure()
        with self.assertRaisesRegex(ValueError, "gate artifact"), self.f.plan():
            pass

    def test_gate_must_be_an_executable_inventory_member(self):
        self.manifest["files"][-1]["executable"] = False
        self.configure()
        with self.assertRaisesRegex(ValueError, "gate artifact"), self.f.plan():
            pass

    def test_node_gate_profile_cannot_disagree_with_process_profile(self):
        self.document["pins"]["node_digest"] = launch_fixture.digest("f")
        self.configure()
        with self.assertRaisesRegex(ValueError, "gate artifact"), self.f.plan():
            pass

    def test_malformed_gate_build_inputs_refuse_without_type_confusion(self):
        self.compiled["inputs"] = []
        self.configure()
        with self.assertRaisesRegex(ValueError, "gate artifact"), self.f.plan():
            pass

    def test_gate_provenance_binary_pin_must_join_inventory(self):
        self.compiled["inputs"]["source_gate"]["elf_sha256"] = "f" * 64
        self.configure()
        with self.assertRaisesRegex(ValueError, "gate artifact"), self.f.plan():
            pass

    def test_gate_provenance_nonstring_pin_refuses(self):
        self.compiled["inputs"]["source_gate"]["elf_sha256"] = 7
        self.configure()
        with self.assertRaisesRegex(ValueError, "provenance pin"), self.f.plan():
            pass


class StaticGateInputTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, build_fixture.LinuxBuildTests)
        self.binary = self.f.root / "gate.elf"
        self.receipt_path = self.f.root / "gate.json"
        self.source = Path(__file__).resolve().parents[1] / "packaging/pi-core/source-gate.c"
        self.f.write(self.f.root / build.PACKAGE / "source-gate.c", self.source.read_bytes())
        self.raw = bytearray(128)
        self.raw[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", self.raw, 16, 2, 183)
        struct.pack_into("<QQ", self.raw, 24, 0x400078, 64)
        struct.pack_into("<HH", self.raw, 54, 56, 1)
        struct.pack_into("<IIQQQQQQ", self.raw, 64, 1, 5, 0, 0x400000, 0, 128, 128, 4096)

    def inputs(self, **changes):
        receipt = {"schema": "aragorn/pi-core-source-gate-build/v1", "target": "linux-arm64-static",
            "source_sha256": build.sha256(self.source.read_bytes()), "elf_sha256": build.sha256(self.raw),
            "compiler_sha256": "a" * 64, "build_command_sha256": "b" * 64, "runtime_executed": False}
        receipt.update(changes)
        self.f.write(self.binary, bytes(self.raw))
        raw = build.canonical(receipt)
        self.f.write(self.receipt_path, raw)
        return self.f.root, self.binary, self.receipt_path, "sha256:" + build.sha256(raw)

    def test_exact_pinned_static_input_is_ingested_without_execution(self):
        raw, info = build.source_gate_input(*self.inputs())
        self.assertEqual(raw, self.raw)
        self.assertFalse(info["runtime_executed"])
        self.assertEqual(info["elf_sha256"], build.sha256(self.raw))

    def test_source_or_binary_changes_refuse(self):
        args = self.inputs()
        self.f.write(self.binary, bytes(self.raw) + b"changed")
        with self.assertRaisesRegex(build.BuildError, "source or binary differs"):
            build.source_gate_input(*args)

    def test_source_provenance_must_match_reviewed_source(self):
        with self.assertRaisesRegex(build.BuildError, "source or binary differs"):
            build.source_gate_input(*self.inputs(source_sha256="c" * 64))

    def test_unpinned_or_changed_receipt_refuses(self):
        args = self.inputs()
        for pin in (None, "", "sha256:" + "f" * 64):
            with self.subTest(pin=pin), self.assertRaises(build.BuildError):
                build.source_gate_input(*args[:3], pin)

    def test_receipt_rejects_execution_claim_or_missing_provenance(self):
        for changes in ({"runtime_executed": True}, {"compiler_sha256": ""}, {"extra": True}):
            with self.subTest(changes=changes), self.assertRaises(build.BuildError):
                build.source_gate_input(*self.inputs(**changes))

    def test_dynamic_interpreter_and_dynamic_segments_refuse(self):
        for segment in (2, 3):
            struct.pack_into("<I", self.raw, 64, segment)
            with self.subTest(segment=segment), self.assertRaises(build.BuildError):
                build.source_gate_input(*self.inputs())

    def test_wrong_architecture_or_relocatable_executable_refuses(self):
        for offset, value in ((18, 62), (16, 3)):
            previous = struct.unpack_from("<H", self.raw, offset)[0]
            struct.pack_into("<H", self.raw, offset, value)
            with self.subTest(offset=offset), self.assertRaises(build.BuildError):
                build.source_gate_input(*self.inputs())
            struct.pack_into("<H", self.raw, offset, previous)

    def test_writable_executable_load_segment_refuses(self):
        struct.pack_into("<I", self.raw, 68, 7)
        with self.assertRaisesRegex(build.BuildError, "permissions"):
            build.source_gate_input(*self.inputs())

    def test_entrypoint_outside_file_bytes_refuses(self):
        struct.pack_into("<Q", self.raw, 24, 0x400080)
        with self.assertRaisesRegex(build.BuildError, "entrypoint"):
            build.source_gate_input(*self.inputs())

    def test_gate_option_partial_input_refuses_before_output_creation(self):
        output = self.f.root / ".aragorn/pi-core-build/refused"
        with self.assertRaisesRegex(build.BuildError, "supplied together"):
            build.prepare(self.f.root, output, Path("unused"), Path("unused"), Path("unused"), source_gate=self.binary)
        self.assertFalse(output.exists())

    def test_optional_gate_is_staged_and_recorded_by_existing_preparation(self):
        output, node, typescript, compiler = self.f.fixture()
        args = self.inputs()
        result = build.prepare(self.f.root, output, node, typescript, compiler,
            source_gate=self.binary, source_gate_receipt=self.receipt_path, source_gate_receipt_digest=args[-1])
        staged = output / "deployment/observer/source-gate"
        self.assertEqual(staged.read_bytes(), self.raw)
        self.assertEqual(staged.stat().st_mode & 0o777, 0o555)
        self.assertEqual(result["source_gate"]["receipt_digest"], args[-1])

    def test_gate_source_closes_inherited_descriptors_before_single_stop_and_exec(self):
        text = self.source.read_text()
        self.assertLess(text.index("call3(436, 3, 0xffffffffUL, 2)"), text.index("call3(129, pid, 19, 0)"))
        self.assertLess(text.index("call3(129, pid, 19, 0)"), text.index("call3(221,"))
        self.assertEqual(text.count("call3(221,"), 1)
        self.assertIn('static const char node[] = "' + NODE + '";', text)


class ObservedLaunchOrderingTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, native_fixture.NativeOrchestrationTests)
        document = profile()
        self.f.plan = dataclasses.replace(self.f.plan, source_observation=document,
            source_observation_digest=canonical_digest(document))
        module = importlib.import_module("aragorn.pi_core_node_source_observer")
        self.observer = source.PiSourceObserver(source._SEAL)
        self.f.stack.enter_context(mock.patch.object(source.PiSourceObserver, "observation",
            new_callable=mock.PropertyMock, return_value={"fixture": "source acquisition only"}))
        self.health_snapshot = {"fixture": "last actual boundary only"}
        self.f.stack.enter_context(mock.patch.object(source.PiSourceObserver, "health_observation",
            new_callable=mock.PropertyMock, return_value=self.health_snapshot))
        self.order = []
        capture = self.f.capture.side_effect
        def captured(owned, deadline):
            self.order.append("capture")
            capture(owned, deadline)
        self.f.capture.side_effect = captured
        def arm(owned, document, **budgets):
            self.order.append("arm")
            self.assertEqual(budgets, {"operation_deadline": 115.0, "cleanup_deadline": 120.0})
            self.observer._owned = owned
            return self.observer
        self.arm = self.f.stack.enter_context(mock.patch.object(module, "start_node_observer", side_effect=arm))
        def accept():
            self.order.append("accept")
            self.assertIs(self.f.owned.source_observer, self.observer)
            return self.f.connection, ""
        self.f.listener.accept.side_effect = accept

    def test_capture_and_arm_precede_any_hello_accept(self):
        result = self.f.run_worker()
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertEqual(self.order, ["capture", "arm", "accept"])
        self.assertIn("NOT_V8_EXECUTION", result["source_observation"]["authority"])
        self.assertEqual(result["source_observation"]["latest_health_capture"], self.health_snapshot)
        self.arm.assert_called_once()
        self.f.command.assert_called_once()

    def test_changed_held_profile_refuses_before_arm_or_hello(self):
        self.f.plan.source_observation["required_sources"].clear()
        result = self.f.run_worker()
        self.assertEqual(result["status"], "REFUSED")
        self.arm.assert_not_called()
        self.f.listener.accept.assert_not_called()

    def test_factory_failure_retains_exact_observer_for_cleanup(self):
        def fail(owned, *args, **kwargs):
            self.observer._owned = owned
            raise source.PiSourceObserverError("armed failure", self.observer)
        self.arm.side_effect = fail
        result = self.f.run_worker()
        self.assertEqual(result["status"], "REFUSED")
        self.assertIs(self.f.cleanup.call_args.args[0].source_observer, self.observer)
        self.f.listener.accept.assert_not_called()
        self.arm.assert_called_once()

    def test_factory_wrong_custody_refuses_without_hello(self):
        self.arm.side_effect = None
        self.arm.return_value = self.observer
        result = self.f.run_worker()
        self.assertEqual(result["status"], "REFUSED")
        self.f.listener.accept.assert_not_called()

    def test_legacy_launch_never_arms_observer(self):
        self.f.plan = dataclasses.replace(self.f.plan, source_observation=None, source_observation_digest=None)
        self.f.listener.accept.side_effect = None
        result = self.f.run_worker()
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.arm.assert_not_called()
        self.assertIsNone(result["source_observation"])


class ObservedCleanupTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, native_fixture.NativeCleanupTests)
        self.observer = source.PiSourceObserver(source._SEAL)
        self.observer._owned = self.f.owned
        self.f.owned.source_observer = self.observer
        self.order = []
        self.begin = self.f.stack.enter_context(mock.patch.object(source.PiSourceObserver, "begin_owned_stop",
            side_effect=lambda deadline: self.order.append(("begin", deadline))))
        self.drain = self.f.stack.enter_context(mock.patch.object(source.PiSourceObserver, "shutdown_after_owned_stop",
            side_effect=lambda deadline: self.order.append(("drain", deadline))))
        self.f.command.side_effect = lambda args, deadline: (self.order.append(("stop", deadline)) or (0, b""))
        self.close = self.f.stack.enter_context(mock.patch.object(native.os, "close"))

    def test_owned_stop_is_announced_then_tracer_drained_before_exit_wait(self):
        result = self.f.cleanup()
        self.assertEqual(result["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(self.order, [("begin", 105), ("stop", 105), ("drain", 105)])
        self.assertTrue(self.f.owned.source_observer_closed)
        native._close_handles(self.f.owned)
        self.assertTrue(self.close.called)

    def test_observer_shutdown_failure_holds_and_preserves_native_handles(self):
        self.drain.side_effect = RuntimeError("tracer thread has not exited")
        result = self.f.cleanup()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        with self.assertRaisesRegex(native.PiNativeSupervisorError, "preserve native handles"):
            native._close_handles(self.f.owned)
        self.close.assert_not_called()
        self.f.command.assert_called_once()
        self.f.unlink.assert_not_called()

    def test_stop_failure_does_not_retry_or_drain_as_if_accepted(self):
        self.f.command.side_effect = None
        self.f.command.return_value = (1, b"")
        self.assertEqual(self.f.cleanup()["status"], "CLEANUP_HOLD")
        self.f.command.assert_called_once()
        self.drain.assert_not_called()
        self.assertFalse(self.f.owned.source_observer_closed)

    def test_foreign_observer_cannot_stop_owned_unit(self):
        self.observer._owned = object()
        self.assertEqual(self.f.cleanup()["status"], "CLEANUP_HOLD")
        self.begin.assert_not_called()
        self.f.command.assert_not_called()

    def test_original_deadline_is_not_extended_for_tracer_shutdown(self):
        self.assertEqual(native._cleanup(self.f.owned, 102, 5)["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(self.order, [("begin", 102), ("stop", 102), ("drain", 102)])

    def test_already_absent_unit_still_requires_tracer_exit_drain(self):
        self.f.state.side_effect = [native_fixture.absent(self.f.plan.unit_name)] * 2
        self.f.exited.side_effect = [True]
        self.assertEqual(self.f.cleanup()["status"], "VERIFIED_OWNED_CLEANUP")
        self.f.command.assert_not_called()
        self.drain.assert_called_once_with(105)


if __name__ == "__main__":
    unittest.main()
