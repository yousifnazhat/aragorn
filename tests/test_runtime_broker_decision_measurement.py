"""Focused new successor behavior with inert core dependencies; no live runtime."""

from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aragorn import runtime_action_broker as original
from aragorn import runtime_action_broker_v4 as v4
from aragorn import runtime_broker_decision_measurement as subject
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest
from scripts import materialize_runtime_broker_decision_measurement as renderer

PIN = "sha256:" + "1" * 64


def rendered_module(name):
    raw = renderer.base.overlay._read_pinned(
        name, *renderer._INPUTS[name], root=renderer._ROOT
    )
    module = types.ModuleType("aragorn._new_measurement_test_" + Path(name).stem)
    module.__package__ = "aragorn"
    with patch.dict(sys.modules, {module.__name__: module}):
        exec(compile(renderer._render(name, raw), name, "exec"), module.__dict__)  # noqa: S102 - exact-pinned successor definitions, no service main
    return module


class BrokerDecisionMeasurementTests(unittest.TestCase):
    def test_rendered_core_stamps_effective_verdict_before_link_not_cleanup(self):
        self.check_rendered_core(("early-block", "replay-block", "final-block"))

    def test_rendered_core_allow_stamps_before_link(self):
        self.check_rendered_core(("allow",))

    def check_rendered_core(self, modes):
        core = rendered_module(renderer._CORE)
        for mode in modes:
            with self.subTest(mode=mode), ExitStack() as stack:
                request = {"fixture": "inert"}
                request_digest = canonical_digest(request)
                state = {"consumed": [], "effect_journal": None}
                if mode == "replay-block":
                    state["consumed"] = [
                        {"request_digest": request_digest, "observation_digest": PIN}
                    ]
                decision = {
                    "verdict": "BLOCK" if mode == "early-block" else "ALLOW",
                    "reason_codes": ["POLICY_BLOCK"] if mode == "early-block" else [],
                }
                trace = subject.Trace(
                    {
                        "accepted_boottime_ns": 10,
                        "action_request_digest": request_digest,
                    }
                )
                token = subject._CURRENT.set(trace)
                stack.callback(subject._CURRENT.reset, token)
                events = []
                stack.enter_context(patch.object(subject, "broker", core))
                stack.enter_context(
                    patch.object(
                        subject,
                        "_stamp",
                        side_effect=lambda events=events: (
                            events.append("final-stamp") or 20
                        ),
                    )
                )
                # These must never be called from the final-decision hook.
                for name in ("_identity", "_sources", "_inputs"):
                    stack.enter_context(
                        patch.object(
                            subject,
                            name,
                            side_effect=AssertionError("I/O in final boundary"),
                        )
                    )
                functions = {
                    "_validate_config": None,
                    "_request_effect": (request, "inert.txt", b"ok"),
                    "_open_broker_roots": (11, 12, 13),
                    "_open_lock_file": 14,
                    "_acquire_lock": None,
                    "_recover_effect_journal": None,
                    "_action_digests": {key: PIN for key in core._ACTION_DIGEST_FIELDS},
                    "_commit_state": None,
                    "_release_lock_and_close": None,
                }
                for name, value in functions.items():
                    stack.enter_context(patch.object(core, name, return_value=value))
                snapshots = [(state, PIN, decision, [])]
                if mode in {"final-block", "allow"}:
                    snapshots.append(
                        (
                            state,
                            PIN,
                            decision,
                            ["MEDIATOR_UNHEALTHY"] if mode == "final-block" else [],
                        )
                    )
                stack.enter_context(
                    patch.object(core, "_evaluate_snapshot", side_effect=snapshots)
                )
                stack.enter_context(
                    patch.object(core.os, "stat", side_effect=FileNotFoundError)
                )
                stack.enter_context(
                    patch.object(
                        core.os,
                        "fstat",
                        return_value=SimpleNamespace(st_dev=8, st_ino=9),
                    )
                )

                def inert_create(
                    *args,
                    authorize_link,
                    record_pending,
                    record_applied,
                    trace=trace,
                    events=events,
                ):
                    allowed = authorize_link()
                    self.assertIsNotNone(trace.final)
                    self.assertEqual(
                        trace.final["verdict"], "ALLOW" if allowed else "BLOCK"
                    )
                    if allowed:
                        staged = SimpleNamespace(
                            st_gid=os.getegid(), st_dev=1, st_ino=2
                        )
                        name = ".aragorn-runtime-" + "a" * 24
                        record_pending(name, staged)
                        events.append("inert-link")
                        record_applied(name, staged)
                    events.append("staging-cleanup")
                    return allowed

                create = stack.enter_context(
                    patch.object(core, "_atomic_create", side_effect=inert_create)
                )
                result = core._mediate_runtime_create(
                    {},
                    SimpleNamespace(expected_runtime_gid=os.getegid()),
                    clock=lambda: 10,
                    deadline_monotonic=10**20,
                    observed_submission=None,
                )
                self.assertEqual(trace.final["verdict"], result["verdict"])
                self.assertEqual(trace.final["reason_codes"], result["reason_codes"])
                self.assertEqual(events[0], "final-stamp")
                if mode in {"early-block", "replay-block"}:
                    create.assert_not_called()
                elif mode == "final-block":
                    # The provisional policy still says ALLOW; effective broker BLOCK wins.
                    self.assertEqual(result["decision"]["verdict"], "ALLOW")
                    self.assertNotIn("inert-link", events)
                else:
                    self.assertEqual(
                        events, ["final-stamp", "inert-link", "staging-cleanup"]
                    )

    def fixture(self, stack, root):
        process = {
            "boot_id": "00000000-0000-0000-0000-000000000001",
            "uid": os.geteuid(),
        }
        request = {key: PIN for key in subject._MATCH}
        grant = {key: PIN for key in subject._MATCH - {"path_digest", "payload_digest"}}
        grant.update(runtime_profile_digest=PIN, sensor_digest=PIN)
        plan = {
            **request,
            "runtime_profile_digest": PIN,
            "sensor_digest": PIN,
            "grant_digest": canonical_digest(grant),
            "boot_id": process["boot_id"],
        }
        legacy = {
            "envelope": {"request": request},
            "request_digest": canonical_digest(request),
            "sensor_digest": PIN,
        }
        attribution = {"profile_digest": PIN}
        lease = {"fixture": "lease"}
        config = SimpleNamespace(
            broker=SimpleNamespace(
                broker=SimpleNamespace(
                    control_root=root,
                    expected_runtime_digest=PIN,
                    expected_broker_uid=os.geteuid(),
                ),
                expected_runtime_profile_digest=PIN,
            )
        )
        state = {"value": {"status": "AVAILABLE"}}
        order = []
        for name, value in (
            ("_ROOT", root),
            ("_OUTPUT", root / "decision-measurement-evidence"),
            ("_PLAN", plan),
            ("_PROCESS", process),
        ):
            stack.enter_context(patch.object(subject, name, value))
        stack.enter_context(
            patch.object(
                subject,
                "_identity",
                side_effect=lambda: order.append("identity") or process,
            )
        )
        stack.enter_context(
            patch.object(
                subject, "_sources", side_effect=lambda value: order.append("sources")
            )
        )
        stack.enter_context(
            patch.object(
                subject, "_inputs", side_effect=lambda value: order.append("inputs")
            )
        )
        stamps = iter((100, 200, 300, 400))
        stack.enter_context(
            patch.object(
                subject,
                "_stamp",
                side_effect=lambda: order.append("stamp") or next(stamps),
            )
        )

        def locked(config, deadline, function):
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                function(fd)
            finally:
                os.close(fd)

        stack.enter_context(patch.object(v4, "_with_profile_lock", side_effect=locked))
        stack.enter_context(
            patch.object(v4, "_load_state", side_effect=lambda *args: state["value"])
        )
        return SimpleNamespace(
            process=process,
            plan=plan,
            legacy=legacy,
            attribution=attribution,
            grant=grant,
            lease=lease,
            config=config,
            state=state,
            order=order,
        )

    def begin(self, fixture):
        return subject.begin(
            fixture.config,
            fixture.grant,
            fixture.legacy,
            fixture.attribution,
            PIN,
            fixture.lease,
            None,
        )

    def completion_inputs(self, stack, fixture):
        decision = {"verdict": "ALLOW", "reason_codes": []}
        subject.final_decision(
            fixture.legacy["request_digest"], PIN, decision, True, []
        )
        result = {
            "request_digest": fixture.legacy["request_digest"],
            "verdict": "ALLOW",
            "reason_codes": [],
            "observation_digest": PIN,
            "decision": decision,
            "effect_status": "CREATED",
        }
        claim = {
            "grant_digest": fixture.plan["grant_digest"],
            "lease_digest": canonical_digest(fixture.lease),
        }
        receipt = {
            "broker_result": result,
            "runtime_attribution_digest": canonical_digest(fixture.attribution),
            "submission_digest": PIN,
        }
        record = {"profile_result": {"broker_result_digest": canonical_digest(result)}}
        fixture.state["value"] = {
            "status": "CONSUMED",
            "claim": claim,
            "result": record,
        }
        stack.enter_context(
            patch.object(v4, "_load_profile_receipt", return_value=receipt)
        )
        stack.enter_context(patch.object(v4, "_result_record", return_value=record))
        return claim, result

    def test_pending_is_durable_single_use_and_completed_cas_ancestry_is_synced(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            fixture = self.fixture(stack, root)
            trace = self.begin(fixture)
            self.addCleanup(subject.close, trace)
            self.assertEqual(fixture.order[0], "stamp")
            self.assertTrue((root / subject._PENDING).is_file())
            claim, result = self.completion_inputs(stack, fixture)
            synced = []
            original_fsync = os.fsync

            def observe_fsync(fd):
                identity = os.fstat(fd)
                synced.append((identity.st_dev, identity.st_ino))
                return original_fsync(fd)

            with patch.object(subject.os, "fsync", side_effect=observe_fsync):
                subject.retain(trace, fixture.config, claim, result, None)
            for path in (
                subject._OUTPUT,
                subject._OUTPUT / "blobs",
                subject._OUTPUT / "blobs/sha256",
            ):
                info = path.stat()
                self.assertIn((info.st_dev, info.st_ino), synced)
            complete = original._parse_canonical_document(
                (root / subject._COMPLETE).read_bytes(), "new completion"
            )
            evidence = original._parse_canonical_document(
                CAS(subject._OUTPUT, read_only=True).read(complete["evidence_digest"]),
                "new evidence",
            )
            self.assertFalse(evidence["decision"]["quantitative_metrics_eligible"])
            self.assertTrue((root / subject._PENDING).exists())
            # Reset only process context to model a new request; never remove the latch.
            token = subject._CURRENT.set(None)
            try:
                fixture.state["value"] = {"status": "AVAILABLE"}
                with self.assertRaises(original.RuntimeActionBrokerError):
                    self.begin(fixture)
            finally:
                subject._CURRENT.reset(token)

    def test_binding_mismatch_prevents_claim_and_post_effect_retention_failure_is_indeterminate(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            fixture = self.fixture(stack, root)
            fixture.plan["payload_digest"] = "sha256:" + "2" * 64
            with self.assertRaises(original.RuntimeActionBrokerError):
                self.begin(fixture)
            self.assertFalse((root / subject._PENDING).exists())
            fixture.plan["payload_digest"] = PIN
            trace = self.begin(fixture)
            self.addCleanup(subject.close, trace)
            claim, result = self.completion_inputs(stack, fixture)
            with (
                patch.object(
                    subject, "CAS", side_effect=OSError("inert storage fault")
                ),
                self.assertRaises(original.RuntimeActionEffectIndeterminate),
            ):
                subject.retain(trace, fixture.config, claim, result, None)
            self.assertTrue((root / subject._PENDING).exists())
            self.assertFalse((root / subject._COMPLETE).exists())
            self.assertEqual(fixture.state["value"]["status"], "CONSUMED")

    def test_rendered_v4_retains_after_consume_and_never_abandons_post_effect_failure(
        self,
    ):
        grant = rendered_module(renderer._GRANT)
        events = []
        result = {"effect_status": "CREATED"}
        with ExitStack() as stack:
            for name, value in (
                ("_validate_config", {}),
                ("_issued_submission", ({}, {}, {}, PIN, {})),
                ("_build_claim", {}),
                ("_claim_grant", {}),
            ):
                stack.enter_context(patch.object(grant, name, return_value=value))
            stack.enter_context(
                patch.object(
                    grant,
                    "mediate_profiled_runtime_create",
                    side_effect=lambda *args, **kwargs: (
                        events.append("effect") or result
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    grant,
                    "_consume_grant",
                    side_effect=lambda *args: events.append("consume"),
                )
            )
            abandon = stack.enter_context(patch.object(grant, "_abandon_grant"))
            stack.enter_context(
                patch.object(
                    subject,
                    "begin",
                    side_effect=lambda *args: events.append("begin") or object(),
                )
            )
            stack.enter_context(
                patch.object(
                    subject, "close", side_effect=lambda *args: events.append("close")
                )
            )

            def fail_retention(*args):
                events.append("retain")
                raise original.RuntimeActionEffectIndeterminate(
                    "new measurement unavailable"
                )

            stack.enter_context(
                patch.object(subject, "retain", side_effect=fail_retention)
            )
            with self.assertRaises(original.RuntimeActionEffectIndeterminate):
                grant.mediate_granted_profiled_runtime_create(
                    {}, SimpleNamespace(broker=None)
                )
            self.assertEqual(events, ["begin", "effect", "consume", "retain", "close"])
            abandon.assert_not_called()

    def test_clock_failure_and_duplicate_finalization_do_not_create_valid_measurements(
        self,
    ):
        with (
            patch.object(subject.sys, "platform", "darwin"),
            self.assertRaises(original.RuntimeActionBrokerError),
        ):
            subject._stamp()
        trace = subject.Trace(
            {"accepted_boottime_ns": 10, "action_request_digest": PIN}
        )
        token = subject._CURRENT.set(trace)
        try:
            with (
                patch.object(subject, "_stamp", return_value=10),
                self.assertRaises(original.RuntimeActionBrokerError),
            ):
                subject.final_decision(PIN, PIN, None, False, ["POLICY_BLOCK"])
            self.assertIsNone(trace.final)
            with patch.object(subject, "_stamp", return_value=11):
                subject.final_decision(PIN, PIN, None, False, ["POLICY_BLOCK"])
                with self.assertRaises(original.RuntimeActionBrokerError):
                    subject.final_decision(PIN, PIN, None, False, ["POLICY_BLOCK"])
        finally:
            subject._CURRENT.reset(token)


if __name__ == "__main__":
    unittest.main()
