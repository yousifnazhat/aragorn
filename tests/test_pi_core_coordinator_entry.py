"""New inert coordinator caller checks; no installed VM or qualification proof."""

import copy
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_coordinator_entry as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


def pin(character="a"):
    return "sha256:" + character * 64


def launch_document(protected=False):
    source = {"schema": "aragorn/pi-core-node-source-profile/v1",
        "pins": {name: pin() for name in ("gate_digest", "node_digest", "producer_digest",
            "node_observer_digest", "source_inventory_digest", "loader_inventory_digest")},
        "sources": [{"path": "/opt/aragorn/pi-runtime/entry.js", "digest": pin()}],
        "required_sources": ["/opt/aragorn/pi-runtime/entry.js"],
        "loader_files": [{"path": "/lib/loader.so", "digest": pin()}]}
    return dict(root_directory="/var/lib/pi/os/root", root_closure_digest=pin(),
        runtime_directory="/var/lib/pi/runtime/root", compiled_receipt={}, compiled_receipt_digest=pin(),
        activation_directory="/var/lib/pi/activations", worker_uid=1001, worker_gid=1001,
        task="fabricated task", model={"id": "not-activated"},
        limits={"maxTurns": 1, "maxToolCalls": 1, "maxRunMs": 1000}, relay={}, native_request=True,
        source_observation=source if protected else None,
        source_observation_digest=canonical_digest(source) if protected else None,
        provider_route_digest=pin("b") if protected else None)


def prepared(protected=False):
    documents = {}
    def ref(name, document):
        path = "/var/lib/pi/prepared/" + name + ".json"
        documents[path] = document
        return {"path": path, "digest": canonical_digest(document)}
    plan = dict(schema=subject.SCHEMA, mode="PROTECTED" if protected else "UNAVAILABLE",
        host_profile_digest=pin("c"), cas_root="/var/lib/pi/cas",
        context=ref("context", {"context": "retained"}),
        deployment=ref("deployment", {"policy": pin("d")}), revoked_context_ids=[],
        runtime_conformance_digest=pin("e"), launch=ref("launch", launch_document(protected)),
        service_runtime=dict(deployment_path="/var/lib/pi/services", receipt_digest=pin(),
            manifest=ref("runtime-manifest", {"manifest": "runtime"}),
            runtime_binding=ref("runtime-binding", {"binding": "runtime"})),
        service_configuration=dict(deployment_path="/var/lib/pi/config", receipt_digest=pin(),
            manifest=ref("config-manifest", {"manifest": "config"}),
            configurations=ref("configs", {"configs": "retained"})),
        provider_inputs=dict(deployment_path="/var/lib/pi/provider", receipt_digest=pin(),
            manifest=ref("public-manifest", {"manifest": "public"})), provider=None)
    if protected:
        plan["provider"] = dict(credential_source="/var/lib/pi/operator/key",
            root_broker_config=ref("root-config", {"root": "existing"}),
            approval_intent=ref("intent", {"intent": "existing"}))
    return plan, documents


class InertTests(unittest.TestCase):
    def setUp(self):
        super().setUp()
        for target in ("os.open", "os.system", "subprocess.run", "subprocess.Popen",
                       "socket.socket", "socket.socketpair", "socket.create_connection"):
            self.enterContext(mock.patch(target, side_effect=AssertionError("no live operation")))
        self.enterContext(mock.patch.object(subject.os, "geteuid", return_value=0))
        self.enterContext(mock.patch.object(subject.os, "getegid", return_value=0))
        self.enterContext(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.enterContext(mock.patch.object(subject.time, "monotonic_ns", return_value=100_000_000_000))
        self.enterContext(mock.patch.object(subject.time, "time", return_value=1000.75))


class CoordinatorEntryTests(InertTests):
    def setUp(self):
        super().setUp()
        self.plan, self.documents = prepared()
        self.events = []
        self.source, self.host = mock.Mock(), mock.Mock()
        self.custody = self.enterContext(mock.patch.object(subject, "_custody",
            return_value=(pin("c"), [{"module": "retained source"}], {"host": "retained"})))
        self.input_holder = mock.Mock()
        self.input_holder.cleanup_uncertainty = []
        def read(path, expected, maximum):
            self.assertEqual(path, Path("/var/lib/pi/plan.json"))
            subject._require(expected == canonical_digest(self.plan), "wrong independent plan pin")
            return copy.deepcopy(self.plan)
        def ref(value):
            self.events.append("read:" + value["path"])
            document = self.documents[value["path"]]
            subject._require(canonical_digest(document) == value["digest"], "wrong referenced input pin")
            return copy.deepcopy(document)
        self.input_holder.read.side_effect = read
        self.input_holder.ref.side_effect = ref
        self.enterContext(mock.patch.object(subject, "_Inputs", return_value=self.input_holder))
        self.cas = self.enterContext(mock.patch.object(subject, "CAS", return_value=object()))
        self.grant = dict(runtime_digest=pin("1"), active_skill_digest=pin("2"),
                          policy_digest=pin("d"), policy_version=1)
        profile = dict(schema=subject.process.PROFILE_SCHEMA, authority=subject.process.PROFILE_AUTHORITY,
            runtime_digest=pin("1"), executable_digest=pin("3"),
            cgroup="/system.slice/aragorn-pi-" + "a" * 32 + ".service",
            skill_path="/var/lib/aragorn/admitted/.aragorn-versions/example/version/SKILL.md")
        self.configs = {"action": {"capability_grant": copy.deepcopy(self.grant)},
            "sensor": {"capability_grant": copy.deepcopy(self.grant),
                       "observation_binding": {"runtime_profile": profile}}}
        self.held = {name: SimpleNamespace() for name in ("runtime", "config", "public", "credential", "approval")}
        self.held["config"].configurations = self.configs
        self.fail_enter = self.fail_close = None
        def holder(name):
            @contextmanager
            def hold(*args, **kwargs):
                self.events.append("enter:" + name)
                if self.fail_enter == name:
                    raise RuntimeError("held prerequisite refused")
                try:
                    yield self.held[name]
                finally:
                    self.events.append("close:" + name)
                    if self.fail_close == name:
                        raise RuntimeError("held cleanup uncertain")
            return hold
        self.runtime_hold = self.enterContext(mock.patch.object(subject.runtime, "hold_pi_service_runtime", side_effect=holder("runtime")))
        self.config_hold = self.enterContext(mock.patch.object(subject.configuration, "hold_pi_service_configuration", side_effect=holder("config")))
        self.public_hold = self.enterContext(mock.patch.object(subject.configuration, "hold_pi_provider_inputs", side_effect=holder("public")))
        self.credential_hold = self.enterContext(mock.patch.object(subject.credentials, "hold_provider_credential", side_effect=holder("credential")))
        self.approval_hold = self.enterContext(mock.patch.object(subject.approvals, "hold_provider_approval", side_effect=holder("approval")))
        self.root_config = object()
        self.enterContext(mock.patch.object(subject, "_broker_config", return_value=self.root_config))
        self.validate_intent = self.enterContext(mock.patch.object(subject.approvals, "validate_intent", side_effect=copy.deepcopy))
        self.managed_result = {"status": "BOOTSTRAP_COMPLETE", "phase3_exit_eligible": False}
        self.call = self.enterContext(mock.patch.object(subject.managed, "run_native_pi_service_bootstrap", return_value=self.managed_result))

    def invoke(self, **changes):
        args = dict(deadline_ns=125_000_000_000, source_loader=self.source, host_custody=self.host)
        args.update(changes)
        return subject.run(Path("/var/lib/pi/plan.json"), canonical_digest(self.plan), **args)

    def refuse(self):
        with self.assertRaises(subject.PiCoordinatorEntryError) as raised:
            self.invoke()
        self.call.assert_not_called()
        return raised.exception.observation

    def test_unavailable_calls_once_with_derived_inputs_and_readonly_cas(self):
        result = self.invoke()
        self.call.assert_called_once()
        args = self.call.call_args.kwargs
        self.assertEqual(args["grant"], self.grant)
        self.assertEqual(args["binding"].policy_digest, self.grant["policy_digest"])
        self.assertEqual(args["profile"].runtime_digest, self.grant["runtime_digest"])
        self.assertEqual(args["now_unix"], 1000)
        self.assertLess(args["deadline"], 125.0)
        self.assertEqual(args["cleanup_timeout_seconds"], 5.0)
        self.assertEqual(args["protected_root"], Path("/var/lib/aragorn/admitted"))
        self.assertNotIn("provider_credential", args)
        self.assertNotIn("provider_approval", args)
        self.cas.assert_called_once_with(Path("/var/lib/pi/cas"), read_only=True)
        self.input_holder.hold_directory.assert_called_once_with(Path("/var/lib/pi/cas"))
        self.assertEqual(result["managed_result"], self.managed_result)
        self.assertFalse(result["phase3_exit_eligible"])
        self.assertTrue(result["owned_inputs_closed"])

    def test_protected_uses_only_existing_metadata_credential_and_approval_holders(self):
        self.plan, self.documents = prepared(True)
        self.invoke()
        kwargs = self.call.call_args.kwargs
        self.assertIs(kwargs["provider_credential"], self.held["credential"])
        self.assertIs(kwargs["provider_approval"], self.held["approval"])
        self.assertEqual(self.credential_hold.call_args.args, (Path("/var/lib/pi/operator/key"),))
        self.assertIs(self.approval_hold.call_args.args[0], self.root_config)
        self.assertEqual([value for value in self.events if value.startswith("close:")],
                         ["close:approval", "close:credential", "close:public", "close:config", "close:runtime"])
        self.assertNotIn("read:/var/lib/pi/operator/key", self.events)

    def test_plan_extras_are_refused_before_opening_references(self):
        self.plan["command"] = "not executed"
        self.refuse()
        self.assertEqual(self.events, [])

    def test_plan_host_pin_must_match_independent_wrapper_custody(self):
        self.plan["host_profile_digest"] = pin("f")
        self.refuse()

    def test_unavailable_cannot_receive_provider_authority(self):
        self.plan["provider"] = {}
        self.refuse()
        self.credential_hold.assert_not_called()

    def test_protected_requires_exact_provider_fields(self):
        self.plan["mode"] = "PROTECTED"
        self.refuse()

    def test_reference_rejects_extra_fields_before_acquisition(self):
        self.plan["context"]["command"] = "forbidden"
        self.refuse()
        self.input_holder.ref.assert_not_called()

    def test_revoked_contexts_reject_duplicate_invalid_and_non_list(self):
        for value in ([pin(), pin()], ["invalid"], (pin(),), [False]):
            self.plan["revoked_context_ids"] = value
            self.refuse()

    def test_credential_source_cannot_be_read_as_a_document(self):
        self.plan, self.documents = prepared(True)
        self.plan["provider"]["credential_source"] = self.plan["context"]["path"]
        self.refuse()
        self.input_holder.ref.assert_not_called()

    def test_changed_referenced_bytes_refuse_before_any_service_holder(self):
        self.documents[self.plan["launch"]["path"]]["task"] = "changed"
        self.refuse()
        self.runtime_hold.assert_not_called()

    def test_launch_mode_and_native_request_are_checked_before_holders(self):
        value = self.documents[self.plan["launch"]["path"]]
        value["native_request"] = False
        self.plan["launch"]["digest"] = canonical_digest(value)
        self.refuse()
        self.runtime_hold.assert_not_called()

    def test_bad_independent_plan_digest_never_self_pins(self):
        with self.assertRaises(subject.PiCoordinatorEntryError):
            subject.run(Path("/var/lib/pi/plan.json"), pin("f"), deadline_ns=125_000_000_000,
                        source_loader=self.source, host_custody=self.host)
        self.call.assert_not_called()

    def test_nonroot_refuses_before_input_access(self):
        with mock.patch.object(subject.os, "geteuid", return_value=1000):
            self.refuse()
        self.input_holder.read.assert_not_called()

    def test_invalid_expired_and_extended_deadlines_refuse(self):
        for value in (True, 100_000_000_000, 131_000_000_000, 2**63):
            with self.subTest(value=value), self.assertRaises(subject.PiCoordinatorEntryError):
                self.invoke(deadline_ns=value)
        self.call.assert_not_called()

    def test_holder_failure_closes_only_successfully_opened_holders(self):
        self.fail_enter = "public"
        self.refuse()
        self.assertEqual([value for value in self.events if value.startswith("close:")],
                         ["close:config", "close:runtime"])

    def test_managed_failure_is_not_retried_and_input_custody_closes(self):
        self.call.side_effect = RuntimeError("retained managed failure")
        with self.assertRaises(subject.PiCoordinatorEntryError) as raised:
            self.invoke()
        self.call.assert_called_once()
        self.input_holder.close.assert_called_once()
        self.assertTrue(raised.exception.observation["managed_call_attempted"])
        self.assertEqual(raised.exception.observation["status"], "REFUSED_OR_INDETERMINATE")

    def test_holder_cleanup_failure_retains_result_and_marks_hold(self):
        self.fail_close = "public"
        with self.assertRaises(subject.PiCoordinatorEntryError) as raised:
            self.invoke()
        self.assertEqual(raised.exception.observation["managed_result"], self.managed_result)
        self.assertEqual(raised.exception.observation["status"], "CLEANUP_HOLD")
        self.call.assert_called_once()

    def test_input_close_failure_never_becomes_success_or_retry(self):
        self.input_holder.close.side_effect = OSError("uncertain close")
        with self.assertRaises(subject.PiCoordinatorEntryError) as raised:
            self.invoke()
        self.assertFalse(raised.exception.observation["owned_inputs_closed"])
        self.assertEqual(raised.exception.observation["status"], "CLEANUP_HOLD")
        self.input_holder.close.assert_called_once()

    def test_caller_does_not_close_borrowed_bootstrap_custody(self):
        self.invoke()
        self.source.close.assert_not_called()
        self.host.close.assert_not_called()

    def test_post_call_input_substitution_retains_result_not_success(self):
        self.input_holder.guard.side_effect = [None, None, RuntimeError("substitution")]
        with self.assertRaises(subject.PiCoordinatorEntryError) as raised:
            self.invoke()
        self.assertEqual(raised.exception.observation["managed_result"], self.managed_result)
        self.call.assert_called_once()

    def test_action_and_sensor_grants_cannot_diverge(self):
        self.configs["sensor"]["capability_grant"]["policy_version"] = 2
        self.refuse()

    def test_cas_ancestor_refusal_prevents_constructor_and_service_holders(self):
        self.input_holder.hold_directory.side_effect = RuntimeError("CAS ancestor changed")
        self.refuse()
        self.cas.assert_not_called()
        self.runtime_hold.assert_not_called()

    def test_returned_managed_refusal_and_cleanup_hold_are_not_success(self):
        for status, expected in (("REFUSED", "REFUSED_OR_INDETERMINATE"), ("CLEANUP_HOLD", "CLEANUP_HOLD")):
            self.call.return_value = {"status": status}
            with self.subTest(status=status):
                self.assertEqual(self.invoke()["status"], expected)


class CoordinatorCustodyTests(InertTests):
    def setUp(self):
        super().setUp()
        path = "opt/aragorn/src/aragorn/pi_core_coordinator_entry.py"
        class Host:
            manifest_digest = pin("c")
            def guard(self, deadline=None):
                pass
            def snapshot(self):
                return {"retained": "host"}
        class Source:
            source_digests = {path: pin()}
            def snapshot(self):
                return [{"module": subject.__name__, "path": path, "digest": pin()}]
        self.host, self.source = Host(), Source()
        self.enterContext(mock.patch.dict(sys.modules, {
            subject._BOOTSTRAP: SimpleNamespace(PiCoordinatorHostCustody=Host),
            subject._SOURCE_BOOTSTRAP: SimpleNamespace(PiServiceSourceLoader=Source)}))

    def test_exact_bootstrap_types_and_consumed_entry_are_required(self):
        result = subject._custody(self.source, self.host, 125.0)
        self.assertEqual(result[0], pin("c"))
        self.assertEqual(result[1][0]["module"], subject.__name__)

    def test_lookalike_host_or_source_cannot_supply_receipts(self):
        for source, host in ((mock.Mock(), self.host), (self.source, mock.Mock())):
            with self.subTest(source=type(source)), self.assertRaises(subject.PiCoordinatorEntryError):
                subject._custody(source, host, 125.0)

    def test_subclass_is_not_bootstrap_custody(self):
        class Other(type(self.host)):
            pass
        with self.assertRaises(subject.PiCoordinatorEntryError):
            subject._custody(self.source, Other(), 125.0)

    def test_unrecorded_or_changed_entry_source_is_refused(self):
        with mock.patch.object(self.source, "snapshot", return_value=[]):
            with self.assertRaises(subject.PiCoordinatorEntryError):
                subject._custody(self.source, self.host, 125.0)

    def test_stale_host_custody_cannot_be_covered_by_source_snapshot(self):
        with mock.patch.object(self.host, "guard", side_effect=RuntimeError("stale")):
            with self.assertRaises(RuntimeError):
                subject._custody(self.source, self.host, 125.0)


class CoordinatorInputTests(InertTests):
    def setUp(self):
        super().setUp()
        self.raw = canonical_json({"prepared": "input"})
        self.metadata = SimpleNamespace(st_dev=1, st_ino=30, st_mode=stat.S_IFREG | 0o400,
            st_nlink=1, st_uid=0, st_gid=0, st_size=len(self.raw), st_mtime_ns=1, st_ctime_ns=1)
        self.parent = SimpleNamespace(st_dev=1, st_ino=20, st_mode=stat.S_IFDIR | 0o700,
            st_nlink=2, st_uid=0, st_gid=0, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
        self.enterContext(mock.patch.object(subject.runtime, "_open_chain", return_value=[20]))
        self.chain_guard = self.enterContext(mock.patch.object(subject.runtime, "_chain_guard"))
        self.open = self.enterContext(mock.patch.object(subject.os, "open", return_value=30))
        original_stat = os.stat
        def named(path, *args, **kwargs):
            if path == "input.json" and kwargs.get("dir_fd") == 20:
                return self.metadata
            return original_stat(path, *args, **kwargs)
        self.enterContext(mock.patch.object(subject.os, "stat", side_effect=named))
        self.enterContext(mock.patch.object(subject.os, "fstat", side_effect=lambda fd: self.parent if fd == 20 else self.metadata))
        self.enterContext(mock.patch.object(subject.os, "get_inheritable", return_value=False))
        self.read = self.enterContext(mock.patch.object(subject.os, "read", side_effect=lambda *args: self.chunks.pop(0)))
        self.close = self.enterContext(mock.patch.object(subject.os, "close"))
        self.inputs = subject._Inputs(125.0)
        self.chunks = [self.raw, b""]

    def acquire(self, expected=None):
        return self.inputs.read(Path("/var/lib/pi/input.json"), expected or canonical_digest({"prepared": "input"}), 65536)

    def test_prepared_document_is_held_nonfollowing_bounded_and_closed_once(self):
        self.assertEqual(self.acquire(), {"prepared": "input"})
        flags = self.open.call_args.args[1]
        self.assertEqual(flags & (os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        self.inputs.guard()
        self.inputs.close()
        self.assertEqual([call.args[0] for call in self.close.call_args_list], [30, 20])
        with self.assertRaises(subject.PiCoordinatorEntryError):
            self.inputs.close()

    def test_unsafe_file_metadata_refuses_before_read(self):
        for key, value in (("st_uid", 1000), ("st_gid", 1000), ("st_nlink", 2),
                           ("st_mode", stat.S_IFREG | 0o600), ("st_size", 65537),
                           ("st_mode", stat.S_IFIFO | 0o400)):
            prior = getattr(self.metadata, key)
            setattr(self.metadata, key, value)
            with self.subTest(key=key), self.assertRaises(subject.PiCoordinatorEntryError):
                self.acquire()
            setattr(self.metadata, key, prior)
        self.read.assert_not_called()

    def test_wrong_external_digest_is_never_replaced_with_observed_digest(self):
        with self.assertRaises(subject.PiCoordinatorEntryError):
            self.acquire(pin("f"))
        self.assertEqual(self.inputs.rows, [])

    def test_noncanonical_or_duplicate_json_is_refused(self):
        for raw in (b'{ "prepared":"input"}', b'{"prepared":1,"prepared":2}'):
            self.metadata.st_size = len(raw)
            self.chunks = [raw, b""]
            with self.subTest(raw=raw), self.assertRaises(subject.broker.RuntimeActionBrokerError):
                self.acquire()

    def test_post_read_replacement_refuses_held_custody(self):
        self.acquire()
        self.metadata.st_ino += 1
        with self.assertRaises(subject.PiCoordinatorEntryError):
            self.inputs.guard()

    def test_same_reference_reuses_bytes_only_under_unchanged_custody(self):
        self.acquire()
        first_reads = self.read.call_count
        self.assertEqual(self.acquire(), {"prepared": "input"})
        self.assertEqual(self.read.call_count, first_reads)
        with self.assertRaises(subject.PiCoordinatorEntryError):
            self.acquire(pin("f"))

    def test_reusing_same_reference_cannot_bypass_a_smaller_byte_bound(self):
        self.acquire()
        with self.assertRaises(subject.PiCoordinatorEntryError):
            self.inputs.read(Path("/var/lib/pi/input.json"), canonical_digest({"prepared": "input"}), len(self.raw) - 1)

    def test_cas_ancestor_chain_remains_held_rechecked_and_owned(self):
        self.inputs.hold_directory(Path("/var/lib/pi/cas"))
        self.inputs.guard()
        self.assertEqual(self.chain_guard.call_args.args[0], Path("/var/lib/pi/cas"))
        self.inputs.close()
        self.close.assert_called_once_with(20)

    def test_total_byte_bound_refuses_before_read(self):
        self.inputs.total = subject._TOTAL_LIMIT
        with self.assertRaises(subject.PiCoordinatorEntryError):
            self.acquire()
        self.read.assert_not_called()

    def test_input_paths_are_normalized_absolute_and_non_root(self):
        for path in ("relative", "/", "/var/../key", "/var//key", "/var/key\n"):
            with self.subTest(path=path), self.assertRaises(subject.PiCoordinatorEntryError):
                subject._path(path)

    def test_partial_file_acquisition_close_failure_remains_a_hold_without_retry(self):
        self.metadata.st_uid = 1000
        self.close.side_effect = OSError("close uncertain")
        with self.assertRaises(subject.runtime.provision.PiOsProvisionError):
            self.acquire()
        self.assertTrue(self.inputs.cleanup_uncertainty)
        attempts = self.close.call_count
        with self.assertRaises(subject.PiCoordinatorEntryError):
            self.inputs.close()
        self.assertEqual(self.close.call_count, attempts)
        with self.assertRaises(subject.PiCoordinatorEntryError):
            self.inputs.guard()

    def test_partial_ancestor_acquisition_cannot_be_reported_as_closed(self):
        with mock.patch.object(subject.runtime, "_open_chain", side_effect=RuntimeError("partial chain uncertain")):
            with self.assertRaises(RuntimeError):
                self.acquire()
        self.assertEqual(self.inputs.cleanup_uncertainty,
            [{"scope": "ANCESTRY_ACQUISITION", "path": "/var/lib/pi"}])
        with self.assertRaises(subject.PiCoordinatorEntryError):
            self.inputs.close()
        self.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
