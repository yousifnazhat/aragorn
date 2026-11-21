"""Inert tests of the protected route; no host opens, trace, worker, unit, or capture."""
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import pi_core_mask_capture_entry as owner


def pin(n):
    return "sha256:" + format(n, "064x")


def ref(name, n):
    return {"path": "/controlled/" + name, "digest": pin(n)}


def native_result(consistent=True):
    return {"schema": "aragorn/pi-core-stopped-mask-supervisor/v1",
            "authority": "RETAINED_CAPTURE_ONLY_NOT_GATE_DENIAL_STORAGE_ADMISSION_OR_PHASE3_QUALIFICATION",
            "status": "CAPTURE_RETAINED_ONLY" if consistent else "CAPTURE_RETAINED_INCONSISTENT",
            "retention": {"capture_digest": pin(301), "receipt_digest": pin(302), "mask_consistent": consistent,
                          "reason": None if consistent else "private-masked-directory",
                          "activation_authorized": False, "installed_isolation_verified": False,
                          "phase3_exit_eligible": False},
            "cleanup": dict(status="VERIFIED_OWNED_CLEANUP", unit_absent=True, process_exit_observed=True,
                            cgroup_empty_or_absent=True, socket_removed=True),
            "pid": 999, "failure": None, "unit": "private-test-unit"}


class CustodyTests(unittest.TestCase):
    def test_exact_host_interpreter_and_consumed_source_rows(self):
        paths = {"opt/aragorn/src/aragorn/" + m + ".py": pin(i + 10) for i, m in enumerate(owner._CORE)}
        rows = [{"module": "aragorn." + m, "path": p, "digest": paths[p]} for m, p in zip(owner._CORE, paths)]
        loader = SimpleNamespace(source_digests=paths)
        host = SimpleNamespace(_expected={owner._PYTHON: {"digest": pin(3)}})
        public = {"python_executable": str(owner._PYTHON)}
        for desc, records, report, valid in (
            ("complete", rows, public, True), ("unconsumed", rows[:-1], public, False),
            ("duplicate", rows + [rows[-1]], public, False),
            ("substitution", rows[:-1] + [dict(rows[-1], digest=pin(6))], public, False),
            ("ambient-python", rows, {"python_executable": "/usr/bin/python3"}, False)):
            with self.subTest(desc), patch.object(owner.entry, "_custody", return_value=(pin(2), records, report)):
                if valid:
                    self.assertEqual(owner._custody(loader, host, 100), (pin(2), pin(3)))
                else:
                    with self.assertRaises(owner.entry.PiCoordinatorEntryError):
                        owner._custody(loader, host, 100)


class EntryTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        def stub(obj, attr, **kw):
            return self.stack.enter_context(patch.object(obj, attr, **kw))
        self.events = []
        self.plan = dict(schema=owner.PLAN, host_profile_digest=pin(1), cas_root="/controlled/cas",
            context=ref("context", 4), deployment=ref("deployment", 5), launch=ref("launch", 6),
            revoked_context_ids=[], runtime_conformance_digest=pin(7),
            service_configuration={"deployment_path": "/controlled/service", "receipt_digest": pin(8),
                                   "manifest": ref("manifest", 9), "configurations": ref("configs", 10)},
            capture={"store": "/evidence/blobs", "receipt_directory": "/evidence/receipts",
                     "volume_device": "8:1", "backing_devices": ["8:0"], "fs_type": "ext4", "attempt_id": "1"*32})
        for fn in ("getuid", "geteuid", "getgid", "getegid"):
            stub(owner.os, fn, return_value=0)
        self.deadline = stub(owner.entry, "_deadline", return_value=25.)
        self.custody = stub(owner, "_custody", return_value=(pin(1), pin(11)))
        self.inputs = Mock()
        self.inputs.read.return_value = self.plan
        self.inputs.ref.side_effect = lambda r: {"from_held": r["path"]}
        self.inputs_type = stub(owner.entry, "_Inputs", return_value=self.inputs)
        self.cas = stub(owner, "CAS")
        self.source = dict(schema=owner.restricted.PROFILE_SCHEMA,
                           pins={"producer_digest": pin(20), "node_observer_digest": pin(21)})
        self.config = SimpleNamespace(worker_uid=41, worker_gid=42, root_directory=Path("/protected/root"),
            runtime_directory=Path("/protected/runtime"), activation_directory=Path("/protected/active"),
            source_observation=self.source, source_observation_digest=owner.canonical_digest(self.source))
        self.launch = stub(owner.entry, "_launch", return_value=self.config)
        self.loader = SimpleNamespace(source_digests={"opt/aragorn/src/aragorn/pi_core_source_observer.py": pin(20),
                               "opt/aragorn/src/aragorn/pi_core_node_source_observer.py": pin(21)})
        self.host = object()
        stub(owner.node, "validate_node_profile")
        self.grant = dict(runtime_profile_digest=pin(30), runtime_digest=pin(31))
        self.held = Mock(identities={"worker": {"uid": 41, "gid": 42}}, configurations={
            "action": {"capability_grant": self.grant.copy()},
            "sensor": {"capability_grant": self.grant.copy(), "observation_binding": {"runtime_profile": "installed"}}})
        self.unwind_failure = False
        @contextmanager
        def hold(**_):
            try:
                yield self.held
            finally:
                if self.unwind_failure:
                    raise ValueError("private-control-store")
        self.hold = stub(owner.entry.configuration, "hold_pi_service_configuration", side_effect=hold)
        self.profile = SimpleNamespace(digest=pin(30), runtime_digest=pin(31))
        stub(owner.entry.process, "runtime_process_profile", return_value=self.profile)
        self.parse = stub(owner, "parse_runtime_capability_grant", return_value=self.grant)
        self.claim = stub(owner.release, "claim_capture_release",
                          side_effect=lambda *a, **kw: self.events.append("claim") or pin(32))
        self.edge = stub(owner.release, "guard_capture_start", side_effect=lambda *a, **kw: self.events.append("edge"))
        self.raw = native_result()
        def fake_dispatch(*a, **kw):
            self.events.append("prepared")
            kw["_before_start"]()
            self.events.append("would-start")
            return self.raw
        self.native = stub(owner.native, "run_native_pi_stopped_mask_capture", side_effect=fake_dispatch)

    def invoke(self, release_pin=None):
        return owner.run("/controlled/plan", pin(2), release_digest=release_pin or pin(3),
                         deadline_ns=24999999999, source_loader=self.loader, host_custody=self.host)

    def refusal(self, release_pin=None):
        with self.assertRaises(owner.entry.PiCoordinatorEntryError) as raised:
            self.invoke(release_pin)
        self.assertNotIn("private", str(raised.exception.observation))
        return raised.exception.observation

    def test_single_spend_guarded_dispatch_and_only_redacted_retention(self):
        result = self.invoke()
        self.assertEqual(self.events, ["claim", "prepared", "edge", "would-start"])
        self.assertEqual(result, dict(schema=owner.REPORT, status="CAPTURE_RETAINED_ONLY",
            capture_attempted=True, claim_confirmed=True, owned_inputs_closed=True, cleanup_verified=True,
            mask_consistent=True, capture_digest=pin(301), receipt_digest=pin(302),
            activation_authorized=False, phase3_exit_eligible=False))
        self.launch.assert_called_once_with({"from_held": "/controlled/launch"}, "UNAVAILABLE")
        self.cas.assert_called_once_with(Path("/controlled/cas"), read_only=True)
        args = self.native.call_args.kwargs
        self.assertIs(args["profile"], self.profile)
        self.assertEqual(args["grant"], self.grant)
        self.assertEqual(args["deployment"], {"from_held": "/controlled/deployment"})
        c = args["capture"]
        self.assertEqual((c.store, c.receipt_directory, c.deployment_digest, c.profile_digest, c.interpreter_digest),
            (Path("/evidence/blobs"), Path("/evidence/receipts"), pin(5), self.config.source_observation_digest, pin(11)))
        self.assertIs(self.claim.call_args.kwargs["capture"], c)
        self.edge.assert_called_once_with(self.inputs, release_digest=pin(3), claim_digest=pin(32), capture=c, deadline=25.)
        self.assertEqual(self.claim.call_args.kwargs["deadline"], args["deadline"])
        self.inputs.close.assert_called_once_with()

    def test_inconsistent_retention_has_no_authority_or_reason_disclosure(self):
        self.raw = native_result(False)
        result = self.invoke()
        self.assertEqual(result["status"], "CAPTURE_RETAINED_INCONSISTENT")
        self.assertIs(result["mask_consistent"], False)
        self.assertNotIn("private", str(result))
        self.assertIs(result["activation_authorized"], False)

    def test_plan_cannot_supply_an_operation_command_or_provider(self):
        self.plan["provider"] = {"command": "invalid"}
        self.assertEqual(self.refusal()["status"], "REFUSED")
        self.claim.assert_not_called()
        self.native.assert_not_called()

    def test_separate_release_pin_is_mandatory(self):
        result = self.refusal(release_pin=pin(2))
        self.inputs_type.assert_not_called()
        self.assertFalse(result["capture_attempted"])

    def test_observer_pin_must_be_an_installed_pin(self):
        self.loader.source_digests["opt/aragorn/src/aragorn/pi_core_source_observer.py"] = pin(23)
        self.assertEqual(self.refusal()["status"], "REFUSED")
        self.claim.assert_not_called()

    def test_grant_must_match_installed_sensor(self):
        self.held.configurations["sensor"]["capability_grant"] = {"runtime_digest": pin(90)}
        self.assertEqual(self.refusal()["status"], "REFUSED")
        self.claim.assert_not_called()

    def test_installed_worker_identity_must_match(self):
        self.held.identities["worker"]["gid"] = 1000
        self.assertEqual(self.refusal()["status"], "REFUSED")
        self.native.assert_not_called()

    def test_release_failure_may_be_ambiguous_and_never_dispatches(self):
        self.claim.side_effect = TimeoutError("private-claim")
        result = self.refusal()
        self.assertEqual((result["status"], result["claim_confirmed"], result["capture_attempted"]),
                         ("CLEANUP_HOLD", False, False))
        self.claim.assert_called_once()
        self.native.assert_not_called()

    def test_withdrawn_release_at_start_edge_does_not_start_or_retry(self):
        self.edge.side_effect = TimeoutError("private-release")
        result = self.refusal()
        self.assertEqual(self.events, ["claim", "prepared"])
        self.assertEqual((result["status"], result["claim_confirmed"], result["capture_digest"]),
                         ("CLEANUP_HOLD", True, None))
        self.native.assert_called_once()
        self.claim.assert_called_once()

    def test_changed_host_at_start_edge_does_not_start(self):
        self.custody.side_effect = [(pin(1), pin(11)), (pin(1), pin(11)), (pin(1), pin(12))]
        self.assertEqual(self.refusal()["status"], "CLEANUP_HOLD")
        self.assertEqual(self.events, ["claim", "prepared"])
        self.edge.assert_not_called()

    def test_expired_installed_grant_at_edge_does_not_start(self):
        self.parse.side_effect = [self.grant, ValueError("stale grant")]
        self.assertEqual(self.refusal()["status"], "CLEANUP_HOLD")
        self.assertEqual(self.events, ["claim", "prepared"])
        self.edge.assert_not_called()

    def test_claim_requires_valid_nonzero_durable_receipt(self):
        self.claim.side_effect = None
        self.claim.return_value = pin(0)
        result = self.refusal()
        self.assertFalse(result["claim_confirmed"])
        self.native.assert_not_called()

    def test_native_success_with_missing_cleanup_is_not_promoted(self):
        self.raw["cleanup"]["process_exit_observed"] = False
        result = self.refusal()
        self.assertEqual((result["status"], result["mask_consistent"], result["receipt_digest"]),
                         ("CLEANUP_HOLD", None, None))

    def test_foreign_authority_claim_in_native_receipt_is_not_retained(self):
        self.raw["retention"]["activation_authorized"] = True
        result = self.refusal()
        self.assertIsNone(result["capture_digest"])
        self.assertFalse(result["activation_authorized"])

    def test_protected_configuration_unwind_after_retention_is_a_hold(self):
        self.unwind_failure = True
        result = self.refusal()
        self.assertEqual((result["status"], result["receipt_digest"]), ("CLEANUP_HOLD", pin(302)))
        self.assertFalse(result["cleanup_verified"])
        self.assertFalse(result["owned_inputs_closed"])
        self.inputs.close.assert_called_once()

    def test_unknown_configuration_acquisition_cannot_claim_clean_refusal(self):
        self.hold.side_effect = OSError("private acquisition")
        result = self.refusal()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertFalse(result["owned_inputs_closed"])
        self.claim.assert_not_called()

    def test_owned_handle_close_failure_never_reports_success(self):
        self.inputs.close.side_effect = OSError("private-fd")
        result = self.refusal()
        self.assertEqual((result["status"], result["owned_inputs_closed"], result["capture_digest"]),
                         ("CLEANUP_HOLD", False, pin(301)))

    def test_native_partial_evidence_survives_interruption_without_retry(self):
        caught = InterruptedError("private-cancel")
        self.raw.update(status="CLEANUP_HOLD", failure="private-error")
        caught.pi_stopped_mask_observation = self.raw
        self.native.side_effect = caught
        result = self.refusal()
        self.assertEqual((result["status"], result["cleanup_verified"], result["receipt_digest"]),
                         ("CLEANUP_HOLD", False, pin(302)))
        self.native.assert_called_once()
