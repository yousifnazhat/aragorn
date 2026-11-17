"""Focused gate-installation checks with inert bytes and mocked root custody.

Temporary files exercise copying and modes, never target execution or installed
protection. Reuse existing fixtures without collecting their historical suites.
"""

import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import stat
import unittest
from unittest import mock

from aragorn import pi_core_os_provision as provision
from aragorn.runtime_action_broker import RuntimeActionBrokerError
from tests import test_pi_core_confined_launch as launch_cases
from tests import test_pi_core_os_provision as install_cases
from tests import test_pi_core_preexec_launch as gate_cases


class GateProvisionTests(unittest.TestCase):
    def setUp(self):
        self.f = gate_cases.fixture(self, install_cases.PiOsProvisionTests)
        self.gate = self.f.runtime / "observer/source-gate"
        self.raw = b"inert pinned gate; never executed"
        self.f.write(self.gate, self.raw, executable=True)
        self.gate_build = {
            "schema": "aragorn/pi-core-source-gate-build/v1", "target": "linux-arm64-static",
            "source_sha256": "a" * 64, "elf_sha256": hashlib.sha256(self.raw).hexdigest(),
            "compiler_sha256": "b" * 64, "build_command_sha256": "c" * 64,
            "runtime_executed": False, "receipt_digest": "sha256:" + "d" * 64,
        }
        self.refresh_receipt()

    def refresh_receipt(self):
        self.f.compiled = launch_cases.receipt(self.f.inventory(self.f.runtime))
        self.f.compiled["inputs"] = {"source_gate": copy.deepcopy(self.gate_build)}

    def refuse_before_creation(self, message):
        with self.assertRaisesRegex((ValueError, RuntimeActionBrokerError), message):
            self.f.install()
        self.assertFalse((self.f.parent / "d2-fixture").exists())

    def test_exact_pinned_gate_is_installed_executable_without_broadening_other_modes(self):
        receipt = self.f.install()
        runtime = Path(receipt["runtime_root"])
        files = self.f.inventory(runtime)["files"]
        self.assertEqual([row["path"] for row in files if row["executable"]],
                         ["node/bin/node", "observer/source-gate"])
        self.assertEqual((runtime / "observer/source-gate").read_bytes(), self.raw)
        self.assertEqual(stat.S_IMODE((runtime / "observer/source-gate").stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((runtime / "pi-core/node_modules/example/cli").stat().st_mode), 0o444)
        self.assertEqual(receipt["runtime_executable_policy"],
                         "ONLY_NODE_AND_PINNED_SOURCE_GATE_EXECUTABLE_OTHER_RUNTIME_FILES_0444")
        self.assertEqual(json.loads((runtime.parent / "provision-receipt.json").read_bytes()), receipt)
        self.assertFalse(receipt["activation_performed"])
        self.assertFalse(receipt["runtime_executed"])
        self.assertFalse(receipt["phase3_exit_eligible"])

    def test_installed_manifest_reaches_existing_held_gate_plan(self):
        receipt = self.f.install()
        runtime = self.f.inventory(Path(receipt["runtime_root"]))
        os_tree = self.f.inventory(Path(receipt["os_root"]))
        files = {row["path"]: row for row in runtime["files"]}
        f = gate_cases.fixture(self, launch_cases.ConfinedPlanTests)
        document = gate_cases.profile()
        document["pins"].update(gate_digest=files["observer/source-gate"]["digest"],
                                node_digest=files["node/bin/node"]["digest"])
        f.config = gate_cases.observed(dataclasses.replace(f.config,
            root_directory=Path(receipt["os_root"]), runtime_directory=Path(receipt["runtime_root"]),
            root_closure_digest=receipt["os_closure_digest"], compiled_receipt=self.f.compiled,
            compiled_receipt_digest=receipt["compiled_receipt_digest"]), document)
        f.profile = dataclasses.replace(launch_cases.profile_for(f.config),
                                       executable_digest=files["node/bin/node"]["digest"])
        f.prepared = launch_cases.prepared_for(f.profile)
        f.tree.side_effect = [(os_tree, tuple(os_tree["directories"]), receipt["os_closure_digest"]),
                             (runtime, tuple(runtime["directories"]), receipt["runtime_protected_tree_digest"])]
        with f.plan() as held:
            self.assertEqual(held.systemd_run_argv[-3:], (gate_cases.GATE, gate_cases.NODE, gate_cases.ENTRY))
            self.assertEqual(held.runtime_inventory_digest, receipt["runtime_inventory_digest"])
            self.assertIn("NOT_NATIVE_LAUNCH", held.authority)

    def test_provenance_without_gate_refuses_before_creation(self):
        self.gate.unlink()
        self.gate.parent.rmdir()
        self.refresh_receipt()
        self.refuse_before_creation("gate artifact")

    def test_gate_without_provenance_refuses_before_creation(self):
        self.f.compiled.pop("inputs")
        self.refuse_before_creation("gate artifact")

    def test_malformed_inputs_refuse_before_creation(self):
        for inputs in (None, [], "source_gate", {"source_gate": None}):
            with self.subTest(inputs=inputs):
                self.refresh_receipt()
                self.f.compiled["inputs"] = inputs
                self.refuse_before_creation("gate artifact")

    def test_malformed_provenance_contract_refuses_before_creation(self):
        changes = ({"schema": "other"}, {"target": "linux-x64-static"},
                   {"runtime_executed": True}, {"runtime_executed": 0}, {"extra": "unbound"})
        for change in changes:
            with self.subTest(change=change):
                self.refresh_receipt()
                self.f.compiled["inputs"]["source_gate"].update(change)
                self.refuse_before_creation("gate artifact")
        self.refresh_receipt()
        self.f.compiled["inputs"]["source_gate"].pop("compiler_sha256")
        self.refuse_before_creation("gate artifact")

    def test_invalid_provenance_pins_refuse_before_creation(self):
        for field in ("source_sha256", "elf_sha256", "compiler_sha256", "build_command_sha256", "receipt_digest"):
            for value in (None, 7, "not-a-pin", "A" * 64):
                with self.subTest(field=field, value=value):
                    self.refresh_receipt()
                    self.f.compiled["inputs"]["source_gate"][field] = value
                    self.refuse_before_creation("pin|digest")

    def test_gate_digest_must_match_compiled_provenance(self):
        self.f.compiled["inputs"]["source_gate"]["elf_sha256"] = "e" * 64
        self.refuse_before_creation("gate artifact")

    def test_changed_gate_bytes_under_existing_compiled_pin_refuse(self):
        self.gate.write_bytes(b"substituted source")
        self.refuse_before_creation("compiled inventory")

    def test_gate_source_must_already_be_executable(self):
        self.gate.chmod(0o644)
        self.refuse_before_creation("gate artifact")

    def test_other_executable_gate_names_remain_nonexecutable(self):
        self.f.write(self.f.runtime / "observer/source-gate-other", b"unapproved alternate", executable=True)
        self.refresh_receipt()
        receipt = self.f.install()
        other = Path(receipt["runtime_root"]) / "observer/source-gate-other"
        self.assertEqual(stat.S_IMODE(other.stat().st_mode), 0o444)

    def test_gate_write_failure_retains_partial_destination_without_retry(self):
        original = provision._copy_file
        attempts = []

        def copy_file(source, destination, entry, deadline):
            if entry["path"] == "observer/source-gate":
                attempts.append(entry["path"])
                raise OSError("inert gate copy failure")
            return original(source, destination, entry, deadline)

        with mock.patch.object(provision, "_copy_file", side_effect=copy_file):
            with self.assertRaisesRegex(OSError, "gate copy failure") as caught:
                self.f.install()
        target = self.f.parent / "d2-fixture"
        self.assertEqual(attempts, ["observer/source-gate"])
        self.assertTrue((target / "runtime/node/bin/node").is_file())
        self.assertFalse((target / "provision-receipt.json").exists())
        self.assertFalse(caught.exception.pi_provisioning_observation["completed"])
        self.assertFalse(caught.exception.pi_provisioning_observation["rollback_performed"])

    def test_receipt_failure_retains_installed_gate_and_no_receipt(self):
        original = os.open

        def opening(path, flags, *args, **kwargs):
            if path == "provision-receipt.json":
                raise OSError("inert receipt failure")
            return original(path, flags, *args, **kwargs)

        with mock.patch.object(provision.os, "open", side_effect=opening):
            with self.assertRaisesRegex(OSError, "receipt failure"):
                self.f.install()
        target = self.f.parent / "d2-fixture"
        self.assertEqual((target / "runtime/observer/source-gate").read_bytes(), self.raw)
        self.assertEqual(stat.S_IMODE((target / "runtime/observer/source-gate").stat().st_mode), 0o555)
        self.assertFalse((target / "provision-receipt.json").exists())

    def test_existing_destination_is_not_adopted_for_valid_gate(self):
        target = self.f.parent / "d2-fixture"
        target.mkdir()
        marker = target / "user-data"
        marker.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            self.f.install()
        self.assertEqual(marker.read_bytes(), b"preserve")
        self.assertFalse((target / "runtime").exists())

    def test_source_modes_and_caller_receipt_are_not_mutated(self):
        before = copy.deepcopy(self.f.compiled)
        source_mode = self.gate.stat().st_mode
        self.f.install()
        self.assertEqual(self.f.compiled, before)
        self.assertEqual(self.gate.stat().st_mode, source_mode)


def load_tests(loader, tests, pattern):
    selected = unittest.TestSuite(loader.loadTestsFromTestCase(GateProvisionTests))
    selected.addTest(install_cases.PiOsProvisionTests("test_runtime_execution_bits_are_reduced_to_node_only"))
    selected.addTests(loader.loadTestsFromTestCase(gate_cases.HeldGatePlanTests))
    return selected
