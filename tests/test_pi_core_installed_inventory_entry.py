"""Inert checks for the fixed installed-view caller, not VM qualification."""

import copy
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_installed_inventory_entry as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


def pin(character="a"):
    return "sha256:" + character * 64


def identity(inode):
    return dict(device=1, inode=inode, mode=stat.S_IFDIR | 0o755, nlink=2,
                uid=0, gid=0, size=4096, mtime_ns=1, ctime_ns=1)


def prepared_inputs():
    source = dict(schema=subject.inventory.PLAN_SCHEMA,
        pins={name: pin() for name in ("gate_digest", "node_digest", "producer_digest", "node_observer_digest")},
        sources=[dict(path="/opt/aragorn/pi-runtime/entry.mjs", digest=pin("b"))],
        required_sources=["/opt/aragorn/pi-runtime/entry.mjs"],
        loader_files=[dict(path="/lib/loader.so", digest=pin("c"))])
    plan = dict(schema=subject.SCHEMA, host_profile_digest=pin("d"),
        source_plan=dict(path="/var/lib/pi/source-plan.json", digest=canonical_digest(source)),
        worker_view=dict(path="/var/lib/pi/installed-view", identity=identity(11)),
        observer_root_identity=identity(12))
    return plan, source


def prepared_artifacts(plan, source):
    sources = dict(schema=subject.inventory.node.SOURCE_SCHEMA, sources=[{
        **source["sources"][0], "identity": identity(21), "readonly_view": True}])
    loaders = dict(schema=subject.inventory.node.LOADER_SCHEMA, loaders=[{
        **source["loader_files"][0], "identity": identity(22), "readonly_view": True}])
    profile = dict(schema=subject.inventory.node.PROFILE_SCHEMA, **{name: copy.deepcopy(source[name])
        for name in ("pins", "sources", "required_sources", "loader_files")})
    profile["pins"].update(source_inventory_digest=canonical_digest(sources),
                           loader_inventory_digest=canonical_digest(loaders))
    receipt = dict(schema=subject.inventory.RECEIPT_SCHEMA, authority=subject.inventory.AUTHORITY,
        phase3_exit_eligible=False, expected_manifest_digest=canonical_digest(source),
        source_inventory_digest=canonical_digest(sources), loader_inventory_digest=canonical_digest(loaders),
        profile_digest=canonical_digest(profile), worker_root_identity=plan["worker_view"]["identity"],
        observer_root_identity=plan["observer_root_identity"], code=[], source_files=1, loader_files=1)
    return subject.inventory.PreparedPiSourceInventories(
        *(canonical_json(document) for document in (sources, loaders, profile, receipt)))


class InertTests(unittest.TestCase):
    def setUp(self):
        super().setUp()
        for target in ("os.open", "os.close", "os.system", "subprocess.run", "subprocess.Popen",
                       "socket.socket", "socket.socketpair", "socket.create_connection"):
            self.enterContext(mock.patch(target, side_effect=AssertionError("no live operation")))
        self.enterContext(mock.patch.object(subject.os, "geteuid", return_value=0))
        self.enterContext(mock.patch.object(subject.os, "getegid", return_value=0))
        self.enterContext(mock.patch.object(subject.coordinator.time, "monotonic", return_value=100.0))
        self.enterContext(mock.patch.object(subject.coordinator.time, "monotonic_ns", return_value=100_000_000_000))


class InstalledInventoryEntryTests(InertTests):
    def setUp(self):
        super().setUp()
        self.plan, self.source = prepared_inputs()
        self.events = []
        path = subject._SOURCE_PATH
        self.loader = SimpleNamespace(source_digests={path: pin("e")})
        self.source_records = [dict(module=subject.__name__, path=path, digest=pin("e"))]
        self.host = object()
        self.custody = self.enterContext(mock.patch.object(subject.coordinator, "_custody",
            return_value=(pin("d"), self.source_records, {"host_profile_digest": pin("d")})))
        self.inputs = mock.Mock(cleanup_uncertainty=[])
        def read(path, expected, maximum):
            self.assertEqual(path, Path("/var/lib/pi/plan.json"))
            self.assertEqual(maximum, subject.coordinator._PLAN_LIMIT)
            subject.coordinator._require(expected == canonical_digest(self.plan), "wrong expected plan")
            return copy.deepcopy(self.plan)
        def ref(value):
            self.events.append("source-intent")
            subject.coordinator._require(value["digest"] == canonical_digest(self.source), "wrong source pin")
            return copy.deepcopy(self.source)
        self.inputs.read.side_effect = read
        self.inputs.ref.side_effect = ref
        self.enterContext(mock.patch.object(subject.coordinator, "_Inputs", return_value=self.inputs))
        self.views = mock.Mock(worker=31, observer=32, cleanup_uncertainty=[])
        self.views.acquire.side_effect = lambda *args: self.events.append("acquire-views")
        self.views.close.side_effect = lambda: self.events.append("close-views")
        self.inputs.close.side_effect = lambda: self.events.append("close-inputs")
        self.views_type = self.enterContext(mock.patch.object(subject, "_Views", return_value=self.views))
        self.prepared = prepared_artifacts(self.plan, self.source)
        self.prepare = self.enterContext(mock.patch.object(subject.inventory, "prepare_pi_source_inventories",
                                                         return_value=self.prepared))
        self.managed = self.enterContext(mock.patch.object(subject.coordinator.managed,
            "run_native_pi_service_bootstrap", side_effect=AssertionError("not a managed launch")))

    def invoke(self, **changes):
        args = dict(deadline_ns=125_000_000_000, source_loader=self.loader, host_custody=self.host)
        args.update(changes)
        return subject.run("/var/lib/pi/plan.json", canonical_digest(self.plan), **args)

    def refuse(self):
        with self.assertRaises(subject.PiInstalledInventoryEntryError) as raised:
            self.invoke()
        result = raised.exception.observation
        self.assertIsNone(result["artifacts"])
        self.assertIsNone(result["artifact_digests"])
        self.assertFalse(result["managed_call_attempted"])
        self.assertIsNone(result["managed_result"])
        self.assertFalse(result["phase3_exit_eligible"])
        self.managed.assert_not_called()
        return result

    def test_one_existing_helper_receives_exact_pins_roots_and_original_deadline(self):
        result = self.invoke()
        self.prepare.assert_called_once()
        self.assertEqual(self.prepare.call_args.args, (canonical_json(self.source),))
        kwargs = self.prepare.call_args.kwargs
        self.assertEqual(set(kwargs), {"expected_manifest_digest", "worker_root_fd", "expected_worker_root_identity",
            "observer_root_fd", "expected_observer_root_identity", "deadline"})
        self.assertEqual(kwargs["expected_manifest_digest"], self.plan["source_plan"]["digest"])
        self.assertEqual(kwargs["expected_worker_root_identity"], self.plan["worker_view"]["identity"])
        self.assertEqual(kwargs["expected_observer_root_identity"], self.plan["observer_root_identity"])
        self.assertEqual((kwargs["worker_root_fd"], kwargs["observer_root_fd"]), (31, 32))
        self.assertLess(kwargs["deadline"], 125.0)
        self.assertEqual(self.events, ["source-intent", "acquire-views", "close-views", "close-inputs"])
        self.assertEqual(result["status"], "INVENTORIES_PREPARED_NOT_QUALIFIED")
        self.assertEqual(result["schema"], "aragorn/pi-core-installed-inventory-result/v1")
        self.assertTrue(result["preparation_attempted"])
        self.assertTrue(result["owned_views_closed"] and result["owned_inputs_closed"])
        self.assertFalse(result["managed_call_attempted"] or result["phase3_exit_eligible"])
        self.assertIsNone(result["managed_result"])
        self.assertIsNone(result["deployment_digest"])
        self.managed.assert_not_called()

    def test_success_retains_canonical_artifacts_exact_digests_and_custody(self):
        result = self.invoke()
        self.assertEqual(set(result["artifacts"]), set(subject._ARTIFACTS))
        self.assertEqual(result["artifact_digests"], {key: canonical_digest(value)
            for key, value in result["artifacts"].items()})
        self.assertEqual(result["plan_digest"], canonical_digest(self.plan))
        self.assertEqual(result["source_before"], self.source_records)
        self.assertEqual(result["source_after"], self.source_records)
        self.assertEqual(result["host_before"], result["host_after"])
        self.assertNotIn("source_plan", result)
        self.assertEqual(result["input_cleanup_uncertainty"], [])

    def test_plan_rejects_extra_fields_before_reference_or_view_acquisition(self):
        self.plan["command"] = "forbidden"
        self.refuse()
        self.inputs.ref.assert_not_called()
        self.views_type.assert_not_called()

    def test_plan_schema_and_host_pin_are_bound(self):
        for key, value in (("schema", "unsupported"), ("host_profile_digest", pin("f"))):
            with self.subTest(key=key):
                self.plan, self.source = prepared_inputs()
                self.plan[key] = value
                self.refuse()
        self.prepare.assert_not_called()

    def test_worker_view_cannot_be_root_relative_or_future_mount_spec(self):
        for value in ("/", "relative/view", "/bad/../view", {"BindReadOnlyPaths": []}):
            self.plan["worker_view"]["path"] = value
            self.refuse()
        self.views_type.assert_not_called()

    def test_root_identities_are_exact_integer_records_not_adopted(self):
        for key in ("worker_view", "observer_root_identity"):
            self.plan, self.source = prepared_inputs()
            record = self.plan[key]["identity"] if key == "worker_view" else self.plan[key]
            record["inode"] = True
            self.refuse()
        self.views_type.assert_not_called()

    def test_missing_root_identity_is_not_discovered(self):
        del self.plan["worker_view"]["identity"]["inode"]
        self.refuse()
        self.views_type.assert_not_called()

    def test_reference_rejects_extra_fields(self):
        self.plan["source_plan"]["readonly"] = True
        self.refuse()
        self.inputs.ref.assert_not_called()

    def test_changed_source_pin_prevents_view_acquisition(self):
        self.source["required_sources"] = []
        result = self.refuse()
        self.assertEqual(result["failure_stage"], "PREPARED_INPUTS")
        self.views_type.assert_not_called()

    def test_source_schema_is_validated_before_view_acquisition(self):
        self.source["required_sources"] = []
        self.plan["source_plan"]["digest"] = canonical_digest(self.source)
        self.refuse()
        self.views_type.assert_not_called()

    def test_current_entry_must_be_consumed_from_exact_source_pin(self):
        self.source_records[0]["digest"] = pin("f")
        self.refuse()
        self.inputs.read.assert_not_called()

    def test_current_entry_module_and_origin_are_required(self):
        for key in ("module", "path"):
            self.source_records[0][key] = "unrelated"
            self.refuse()
        self.inputs.read.assert_not_called()

    def test_unpinned_current_entry_cannot_claim_consumption(self):
        self.loader.source_digests = {}
        self.refuse()
        self.inputs.read.assert_not_called()

    def test_nonroot_and_invalid_deadlines_stop_before_inputs(self):
        with mock.patch.object(subject.os, "geteuid", return_value=1000):
            self.refuse()
        for deadline in (True, 99_000_000_000, 131_000_000_000):
            with self.assertRaises(subject.PiInstalledInventoryEntryError):
                self.invoke(deadline_ns=deadline)
        self.inputs.read.assert_not_called()

    def test_custody_change_before_views_stops_acquisition(self):
        self.custody.side_effect = [(pin("d"), self.source_records, {}), RuntimeError("changed")]
        self.refuse()
        self.views_type.assert_not_called()

    def test_view_identity_failure_closes_only_acquired_ownership(self):
        self.views.acquire.side_effect = RuntimeError("different root")
        result = self.refuse()
        self.assertFalse(result["preparation_attempted"])
        self.assertTrue(result["owned_views_closed"])
        self.prepare.assert_not_called()
        self.views.close.assert_called_once()

    def test_helper_refusal_never_retries_or_returns_artifacts(self):
        self.prepare.side_effect = subject.inventory.PiSourceInventoryPreparationError("not readonly")
        result = self.refuse()
        self.assertTrue(result["preparation_attempted"])
        self.assertEqual(result["failure_stage"], "INVENTORY_PREPARATION")
        self.assertEqual(result["status"], "REFUSED_OR_INDETERMINATE")
        self.prepare.assert_called_once()

    def test_helper_ambiguous_descriptors_are_retained_not_adopted(self):
        self.prepare.side_effect = subject.inventory.PiSourceInventoryPreparationError(
            "uncertain", held_fds=(71, 72), ambiguous_fds=(72,))
        result = self.refuse()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["input_cleanup_uncertainty"], [dict(scope="INVENTORY_HELPER_DESCRIPTORS",
            held_fds=[71, 72], ambiguous_fds=[72])])
        self.assertTrue(result["owned_views_closed"])
        subject.os.close.assert_not_called()
        self.prepare.assert_called_once()

    def test_post_preparation_view_mutation_withholds_artifacts(self):
        self.views.guard.side_effect = RuntimeError("replaced view")
        result = self.refuse()
        self.assertTrue(result["preparation_attempted"])
        self.assertEqual(result["failure_stage"], "POST_CALL_CUSTODY")

    def test_post_preparation_host_mutation_withholds_artifacts(self):
        self.custody.side_effect = [(pin("d"), self.source_records, {})] * 3 + [RuntimeError("host changed")]
        result = self.refuse()
        self.assertTrue(result["preparation_attempted"])
        self.assertEqual(result["failure_stage"], "POST_CALL_CUSTODY")

    def test_owned_view_close_failure_withholds_artifacts_and_closes_inputs(self):
        self.views.close.side_effect = RuntimeError("close unknown")
        self.views.cleanup_uncertainty = [dict(scope="OBSERVER_ROOT_CLOSE", descriptors=[32])]
        result = self.refuse()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertFalse(result["owned_views_closed"])
        self.assertTrue(result["owned_inputs_closed"])
        self.views.close.assert_called_once()

    def test_owned_input_close_failure_withholds_artifacts_after_view_cleanup(self):
        self.inputs.close.side_effect = RuntimeError("close unknown")
        self.inputs.cleanup_uncertainty = [dict(scope="DESCRIPTOR_CLOSE", descriptors=[41])]
        result = self.refuse()
        self.assertEqual(result["failure_stage"], "INPUT_CLEANUP")
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertTrue(result["owned_views_closed"])
        self.assertFalse(result["owned_inputs_closed"])

    def test_result_type_and_canonical_bytes_are_checked(self):
        self.prepare.return_value = {"source_inventory": {}}
        self.refuse()
        self.prepare.return_value = subject.inventory.PreparedPiSourceInventories(
            b'{"schema": "noncanonical"}', self.prepared.loader_inventory_raw,
            self.prepared.profile_raw, self.prepared.preparation_raw)
        self.refuse()

    def test_preparation_receipt_cannot_promote_qualification_or_differ_in_roots(self):
        original = subject.inventory._document(self.prepared.preparation_raw)
        for key, value in (("phase3_exit_eligible", True), ("worker_root_identity", identity(99)),
                           ("expected_manifest_digest", pin("f")), ("profile_digest", pin("f"))):
            document = {**original, key: value}
            self.prepare.return_value = subject.inventory.PreparedPiSourceInventories(
                self.prepared.source_inventory_raw, self.prepared.loader_inventory_raw,
                self.prepared.profile_raw, canonical_json(document))
            self.refuse()


class InstalledViewsTests(InertTests):
    def setUp(self):
        super().setUp()
        self.plan, _ = prepared_inputs()
        self.ancestry = mock.Mock(cleanup_uncertainty=[])
        self.ancestry.directories = [(Path(self.plan["worker_view"]["path"]), [30, 31], [(), ()])]
        self.enterContext(mock.patch.object(subject.coordinator, "_Inputs", return_value=self.ancestry))
        self.open = self.enterContext(mock.patch.object(subject.os, "open", return_value=32))
        self.close = self.enterContext(mock.patch.object(subject.os, "close"))
        self.inheritable = self.enterContext(mock.patch.object(subject.os, "get_inheritable", return_value=False))
        self.enterContext(mock.patch.object(subject.os, "fstat", return_value=object()))
        self.enterContext(mock.patch.object(subject.os, "stat", return_value=object()))
        self.actual = self.enterContext(mock.patch.object(subject.inventory.base, "_file_identity",
            side_effect=lambda info: copy.deepcopy(self.plan["worker_view"]["identity"])))
        self.directory = self.enterContext(mock.patch.object(subject.inventory, "_directory",
            side_effect=lambda fd, readonly: copy.deepcopy(
                self.plan["worker_view"]["identity"] if fd == 31 else self.plan["observer_root_identity"])))
        self.views = subject._Views(125.0)

    def acquire(self):
        self.actual.side_effect = [self.plan["worker_view"]["identity"],
            self.plan["observer_root_identity"]]
        self.views.acquire(self.plan["worker_view"], self.plan["observer_root_identity"])

    def test_named_worker_ancestry_and_fixed_observer_root_are_held(self):
        self.acquire()
        self.ancestry.hold_directory.assert_called_once_with(Path(self.plan["worker_view"]["path"]))
        self.open.assert_called_once_with("/", subject.inventory._DIRECTORY_FLAGS)
        self.assertEqual(self.directory.call_args_list,
                         [mock.call(31, readonly=True), mock.call(32, readonly=False)])
        self.assertEqual((self.views.worker, self.views.observer), (31, 32))
        self.assertEqual(self.views.expected_worker, self.plan["worker_view"]["identity"])

    def test_wrong_worker_identity_does_not_open_observer_or_self_adopt(self):
        self.actual.side_effect = None
        self.actual.return_value = identity(99)
        with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
            self.views.acquire(self.plan["worker_view"], self.plan["observer_root_identity"])
        self.open.assert_not_called()
        self.assertEqual(self.views.expected_worker, identity(11))
        self.views.close()
        self.close.assert_not_called()
        self.ancestry.close.assert_called_once()

    def test_observer_identity_must_match_named_and_held_root(self):
        self.actual.side_effect = [identity(11), identity(99)]
        with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
            self.views.acquire(self.plan["worker_view"], identity(12))
        self.views.close()
        self.close.assert_called_once_with(32)

    def test_inheritable_view_handles_are_refused(self):
        self.inheritable.return_value = True
        with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
            self.views.acquire(self.plan["worker_view"], identity(12))
        self.views.close()
        self.close.assert_called_once_with(32)

    def test_close_revokes_owned_handles_and_never_retries(self):
        self.acquire()
        self.views.close()
        self.close.assert_called_once_with(32)
        self.ancestry.close.assert_called_once()
        with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
            self.views.close()
        with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
            self.views.guard()
        self.close.assert_called_once_with(32)

    def test_failed_observer_close_preserves_uncertainty_and_closes_ancestry(self):
        self.acquire()
        self.close.side_effect = OSError("close uncertain")
        with self.assertRaises(subject.PiInstalledInventoryEntryError):
            self.views.close()
        self.assertEqual(self.views.cleanup_uncertainty, [dict(scope="OBSERVER_ROOT_CLOSE", descriptors=[32])])
        self.ancestry.close.assert_called_once()
        self.close.assert_called_once_with(32)

    def test_partial_ancestry_acquisition_uncertainty_is_not_erased(self):
        self.ancestry.hold_directory.side_effect = RuntimeError("partial acquisition")
        self.ancestry.cleanup_uncertainty = [dict(scope="ANCESTRY_ACQUISITION", path="/var/lib/pi/installed-view")]
        self.ancestry.close.side_effect = RuntimeError("cleanup unconfirmed")
        with self.assertRaises(RuntimeError):
            self.views.acquire(self.plan["worker_view"], identity(12))
        with self.assertRaises(subject.PiInstalledInventoryEntryError):
            self.views.close()
        self.assertEqual(self.views.cleanup_uncertainty, self.ancestry.cleanup_uncertainty)
        self.open.assert_not_called()
        self.close.assert_not_called()

    def test_failed_observer_open_does_not_close_unknown_descriptor(self):
        self.open.side_effect = OSError("root unavailable")
        with self.assertRaises(OSError):
            self.views.acquire(self.plan["worker_view"], identity(12))
        self.views.close()
        self.close.assert_not_called()
        self.ancestry.close.assert_called_once()

    def test_protected_ancestry_guard_is_reused_after_acquisition(self):
        self.acquire()
        self.ancestry.guard.side_effect = RuntimeError("ancestry changed")
        with self.assertRaises(RuntimeError):
            self.views.guard()
        self.views.close()

    def test_post_preparation_readwrite_remount_refuses_with_unchanged_identity(self):
        self.acquire()
        self.directory.side_effect = subject.inventory.PiSourceInventoryPreparationError("not readonly")
        with self.assertRaises(subject.inventory.PiSourceInventoryPreparationError):
            self.views.guard()
        self.directory.assert_called_with(31, readonly=True)
        self.views.close()


if __name__ == "__main__":
    unittest.main()
