"""The new private caller boundary; all authority, operations and storage are inert."""

from contextlib import contextmanager
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
from unittest import TestCase, mock

from aragorn import pi_core_pilot_retention_entry as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_coordinator_entry as entry_fixtures
from tests import test_pi_core_coordinator_wrapper as wrapper_fixtures


class PilotRetentionEntryTests(TestCase):
    def setUp(self):
        self.events = []
        self.private = {
            "status": "MANAGED_CALL_RETURNED_NOT_QUALIFIED",
            "managed_call_attempted": True,
            "managed_result": {"status": "BOOTSTRAP_COMPLETE", "worker": {
                "pilot_output_observation": {"schema": "aragorn/pi-core-pilot-output-observation/v1"}}},
            "phase3_exit_eligible": False,
        }
        self.options = dict(release_digest="sha256:" + "a" * 64, deadline_ns=123456,
                            source_loader=object(), host_custody=object())
        self.args = ("/etc/aragorn/pilot-plan.json", "sha256:" + "b" * 64)
        self.guard = mock.Mock(side_effect=lambda: self.events.append("guard"))
        self.claim = mock.Mock(side_effect=lambda: self.events.append("claim"))
        self.publish = mock.Mock(side_effect=lambda obs: self.events.append("publish"))

        @contextmanager
        def authority(*args, **kwargs):
            self.events.append("entered")
            try:
                yield self.guard, self.claim, self.publish
            finally:
                self.events.append("closed")

        self.authority = self.enterContext(mock.patch.object(subject, "_authority", side_effect=authority))

        def original(*args, **kwargs):
            self.events.append("caller")
            return self.private

        self.caller = self.enterContext(mock.patch.object(subject.entry, "run", side_effect=original))

    def invoke(self):
        return subject.run(*self.args, **self.options)

    def test_claim_before_original_caller_and_private_publication_before_close(self):
        self.assertIs(self.invoke(), self.private)
        self.claim.assert_called_once()
        self.caller.assert_called_once_with(*self.args, **{k: v for k, v in self.options.items() if k != "release_digest"})
        self.publish.assert_called_once_with(self.private)
        self.assertIs(self.publish.call_args.args[0], self.private)
        self.assertEqual([e for e in self.events if e != "guard"],
                         ["entered", "claim", "caller", "publish", "closed"])

    def test_refused_authority_or_used_claim_never_reaches_caller_or_publication(self):
        for rejected in (self.authority, self.claim):
            with self.subTest(boundary="preflight" if rejected is self.authority else "claim"):
                old = rejected.side_effect
                try:
                    rejected.side_effect = ValueError("not authorized")
                    with self.assertRaises((ValueError, RuntimeError)):
                        self.invoke()
                finally:
                    rejected.side_effect = old
                self.caller.assert_not_called()
                self.publish.assert_not_called()

    def test_failed_private_publication_does_not_retry_caller_or_sink(self):
        self.publish.side_effect = OSError("receipt unavailable")
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            self.invoke()
        self.caller.assert_called_once()
        self.claim.assert_called_once()
        self.publish.assert_called_once_with(self.private)
        self.assertEqual(self.events[-1], "closed")

    def test_typed_late_refusal_can_retain_original_but_cannot_become_success(self):
        self.private["status"] = self.private["managed_result"]["status"] = "CLEANUP_HOLD"
        error = subject.entry.PiCoordinatorEntryError("late failure")
        error.observation = self.private
        self.caller.side_effect = error
        with self.assertRaises(subject.entry.PiCoordinatorEntryError) as raised:
            self.invoke()
        self.assertIs(raised.exception, error)
        self.assertIs(raised.exception.observation, self.private)
        self.assertEqual(self.private["status"], "CLEANUP_HOLD")
        self.publish.assert_called_once_with(self.private)
        self.claim.assert_called_once()
        self.caller.assert_called_once()

    def test_external_exception_with_an_observation_is_not_a_private_source(self):
        error = RuntimeError("untyped exception carries untrusted data")
        error.observation = self.private
        self.caller.side_effect = error
        with self.assertRaises(RuntimeError):
            self.invoke()
        self.publish.assert_not_called()
        self.claim.assert_called_once()
        self.caller.assert_called_once()

    def test_typed_late_failure_is_not_replaced_by_a_second_sink_error(self):
        self.private["status"] = self.private["managed_result"]["status"] = "CLEANUP_HOLD"
        original = subject.entry.PiCoordinatorEntryError("late failure")
        original.observation = self.private
        self.caller.side_effect = original
        self.publish.side_effect = OSError("unknown private receipt state")
        with self.assertRaises(subject.entry.PiCoordinatorEntryError) as raised:
            self.invoke()
        self.assertIs(raised.exception, original)
        self.assertIs(raised.exception.observation, self.private)
        self.publish.assert_called_once_with(self.private)
        self.claim.assert_called_once()
        self.caller.assert_called_once()


class PilotReleaseConnectionTests(TestCase):
    def test_held_release_claims_before_call_and_writes_only_the_original_nested_record(self):
        plan, _ = entry_fixtures.prepared(True)
        descriptor = dict(schema="aragorn/runtime-protected-path/v1", target_name="result.json",
                          root_device=25, root_inode=31)
        source_pins = dict(subject._B109, pi_core_pilot_retention_entry="9" * 64, pi_core_pilot_output_custody="8" * 64)
        rows = [dict(module="aragorn." + name, path="opt/aragorn/src/aragorn/" + name + ".py",
                     digest="sha256:" + digest) for name, digest in source_pins.items()]
        loader = SimpleNamespace(source_digests={r["path"]: r["digest"] for r in rows})
        plan["pilot_output"] = dict(reader_source_digest=loader.source_digests[
            "opt/aragorn/src/aragorn/pi_core_pilot_output_observer.py"], path_descriptor=descriptor)
        runtime = plan["service_runtime"]
        runtime["manifest"]["digest"], runtime["runtime_binding"]["digest"], runtime["receipt_digest"] = subject._SERVICE
        plan_pin, deployment, path_pin = canonical_digest(plan), plan["deployment"]["digest"], canonical_digest(descriptor)
        roots = [[83, i, stat.S_IFDIR | 0o700, 0, 0] for i in (101, 102)]
        release = dict(schema="aragorn/pi-core-pilot-output-local-release/v1", scope=subject.SCOPE,
                       base_payload_digest=subject.sink.B109_PAYLOAD_DIGEST, host_profile_digest=plan["host_profile_digest"],
                       plan_digest=plan_pin, deployment_digest=deployment, path_digest=path_pin, attempt_id="3" * 32,
                       boot_id="1e9eeed1-1422-42ee-a20a-57d81a7c79a7", not_before_unix_ns=3, expires_unix_ns=10,
                       mount_id=79, roots=roots)
        raw = dict(schema="aragorn/pi-core-pilot-output-observation/v1", activation_id="4" * 32,
                   path_descriptor=descriptor, before="ABSENT", after="PRESENT", file_device=25, file_inode=98,
                   payload_bytes=11, payload_hex=b'{"total":3}'.hex(), payload_digest=canonical_digest({"total": 3}))
        result = dict(schema="aragorn/pi-core-coordinator-observation/v1", managed_call_attempted=True,
                      status="MANAGED_CALL_RETURNED_NOT_QUALIFIED", plan_digest=plan_pin,
                      deployment_digest=deployment, phase3_exit_eligible=False,
                      managed_result={"worker": {"pilot_output_observation": raw, "not_for_retention": "private decoy"},
                                      "services": {"pilot_output_observation": {"another": "private decoy"}}})
        inputs = mock.Mock()
        inputs.read.side_effect = [plan, release]
        for key in ("getuid", "geteuid", "getgid", "getegid"):
            self.enterContext(mock.patch.object(subject.os, key, return_value=0))
        for owner, name, value in ((subject.entry, "_Inputs", inputs), (subject.entry, "_deadline", 10.0),
                                   (subject.entry, "_custody", (plan["host_profile_digest"], rows, {})),
                                   (subject, "_location", None)):
            self.enterContext(mock.patch.object(owner, name, return_value=value))
        order, location = [], Path("/etc/aragorn/example-pilot-plan.json")
        take = self.enterContext(mock.patch.object(subject.sink, "preflight", side_effect=lambda **kw: order.append("claim")))
        def call(*args, **kwargs):
            order.append("call")
            return result
        self.enterContext(mock.patch.object(subject.entry, "run", side_effect=call))
        write = self.enterContext(mock.patch.object(subject.sink, "retain", side_effect=lambda **kw: order.append("write")))
        self.assertIs(subject.run(location, plan_pin, release_digest=canonical_digest(release), deadline_ns=10,
                                  source_loader=loader, host_custody=object()), result)
        self.assertEqual(order, ["claim", "call", "write"])
        inputs.close.assert_called_once_with()
        self.assertEqual(inputs.read.call_args_list, [mock.call(location, plan_pin, subject.entry._PLAN_LIMIT),
                                                     mock.call(subject.RELEASE, canonical_digest(release), 4096)])
        args = dict(store=subject.BASE / "cas", receipt_directory=subject.BASE / "receipts",
                    expected_roots=tuple(map(tuple, roots)), attempt_id=release["attempt_id"], expected_path_digest=path_pin,
                    deployment_digest=deployment, plan_digest=plan_pin, release_digest=canonical_digest(release),
                    deadline=10.0, mount_id=release["mount_id"],
                    topology_guard=take.call_args.kwargs["topology_guard"])
        take.assert_called_once_with(**args)
        write.assert_called_once_with(**args, expected_activation_id=raw["activation_id"], observation_raw=canonical_json(raw))


class PilotRetentionWrapperTests(TestCase):
    def test_fixed_retention_flag_dispatches_once_and_never_prints_private_result(self):
        # Reuse inert host/loader and virtual-wrapper setup, not its historical tests.
        f = wrapper_fixtures.CoordinatorWrapperTests()
        self.addCleanup(f.doCleanups)
        f.setUp()
        host, loader = SimpleNamespace(guard=mock.Mock(), close=mock.Mock()), SimpleNamespace(close=mock.Mock())
        original = f.observation()
        original["managed_result"]["worker"]["pilot_output_observation"] = {
            "payload_hex": "PRIVATE_OUTPUT_BYTES", "root_inode": "PRIVATE_SINK_ID"}
        host_pin, plan_pin, release_pin = ("sha256:" + c * 64 for c in "abc")
        plan, deadline = f.root / "plan", int(f.deadline * 1_000_000_000)
        argv = [str(f.wrapper), "--retain-pilot-output", str(f.profile_path), host_pin,
                str(plan), plan_pin, release_pin, str(deadline)]
        with mock.patch.object(f.s, "__file__", str(f.wrapper)), mock.patch.dict(sys.modules):
            sys.modules.pop(f.s._PRIVATE, None)
            with mock.patch.object(f.s, "_hold_host", return_value=host), \
                    mock.patch.object(f.s, "_bootstrap", return_value=loader), \
                    mock.patch.object(subject, "run", return_value=original) as retain, \
                    mock.patch.object(subject.entry, "run", side_effect=AssertionError("wrong route")) as other, \
                    mock.patch.object(sys, "argv", argv), mock.patch("builtins.print") as printed:
                self.assertEqual(f.s.main(), 0)
        retain.assert_called_once_with(plan, plan_pin, release_digest=release_pin, deadline_ns=deadline,
                                       source_loader=loader, host_custody=host)
        other.assert_not_called()
        host.close.assert_called_once_with()
        loader.close.assert_called_once_with()
        printed.assert_called_once()
        raw = printed.call_args.args[0]
        for private in ("pilot_output_observation", "payload_hex", "PRIVATE_", "NEVER_PRINT_ME"):
            self.assertNotIn(private, raw)
        report = json.loads(raw)
        self.assertEqual(report["managed_result_digest"], f.s._digest(f.s._canonical(original["managed_result"])))
        self.assertIs(report["phase3_exit_eligible"], False)
