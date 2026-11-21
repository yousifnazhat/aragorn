"""Only the new stopped-handle route. Kernel inputs are inert; private receipt IO is real."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import threading
from types import SimpleNamespace
from unittest import TestCase, mock

from aragorn import pi_core_mask_custody as custody
from aragorn import pi_core_stopped_mask_capture as cap
from aragorn import pi_core_stopped_mask_view as kernel
from aragorn import pi_core_stopped_worker_walk as handles
from aragorn.oci_worker_protocol import canonical_json
from test_pi_core_state_exposure import CWD_PATH, pi_exposure_sample
import test_pi_core_stopped_mask_capture as masks


class WorkerSpineCaptureTests(TestCase):
    def setUp(self):
        self.base = base = masks.StoppedCapture()
        self.addCleanup(base.doCleanups)
        base.setUp()
        base.cfg = replace(base.cfg, worker_spine=True)
        base.session._mask_capture = base.cfg
        base.session.observer._pidfd = 370
        self.pidfd = self.enterContext(mock.patch.object(masks.node.base.process, "require_live_pidfd"))
        self.mount = self.enterContext(mock.patch.object(custody, "_mount_id", return_value=21))
        self.admitted = Path(CWD_PATH) / ("c"*64 + "-" + "e"*64)
        base.session.owned.plan.prepared.skill_path = self.admitted / "SKILL.md"
        base.cfg.preflight(deployment_digest=base.cfg.deployment_digest, profile_digest=base.cfg.profile_digest,
                           deadline=base.deadline)
        base.worker_raw = base.worker_raw.replace(CWD_PATH.encode() + b" ", bytes(self.admitted) + b" ")
        base.view["worker_mountinfo_digest"] = masks.sha(base.worker_raw)
        pi = base.view["worker"]
        walk = pi_exposure_sample(**{k:pi[k] for k in ("pid", "start_ticks", "mount_namespace")})
        obj = dict(root=walk["root"], cwd=walk["cwd"], named_cwd=walk["cwd"], fds=walk["fds"])
        self.spine = dict(schema=handles.SCHEMA, worker=pi, admitted_path=str(self.admitted),
                          opened_boottime_ns=9500, closed_boottime_ns=20500, before=walk["before"],
                          after=walk["after"], objects={"before":obj, "after":deepcopy(obj)})
        self.active, self.topology = False, mock.Mock()
        @contextmanager
        def opened(**kwargs):
            self.active = True
            try:
                yield SimpleNamespace(worker=pi, finish=lambda:(base.view, base.worker_raw, base.manager_raw),
                                      guard_retained_topology=self.topology)
            finally:
                self.active = False
                if base.exit_error:
                    raise base.exit_error
        base.opened.side_effect = opened
        @contextmanager
        def handle_scope(view, *, admitted_path, deadline):
            self.assertEqual((self.active, admitted_path, deadline), (True, self.admitted, base.deadline))
            self.assertEqual(view.worker, pi)
            base.order.append("spine-open")
            def finish():
                base.order.append("spine-close")
                return self.spine
            yield finish
        self.scope = self.enterContext(mock.patch.object(handles, "hold_worker_spine", side_effect=handle_scope))

    def test_actual_owner_brackets_mask_probes_and_publishes_six_original_members(self):
        self.topology.side_effect = lambda w,m: self.assertEqual((self.active,w,m),
            (True,self.base.worker_raw,self.base.manager_raw))
        result = self.base.acquire()
        self.assertEqual(self.base.order, ["spine-open","probe","spine-close"])
        self.assertTrue(result["mask_consistent"], result["reason"])
        self.assertFalse(result["installed_isolation_verified"] or result["phase3_exit_eligible"])
        self.assertGreaterEqual(self.topology.call_count, 6)
        self.assertEqual(self.pidfd.call_count, self.topology.call_count)
        self.assertEqual(self.base.session._guard.call_count, 3)  # full owner guard brackets, not per blob
        keys = self.base.keys(result)
        raw = custody.replay_mask_observation(**keys)
        self.assertEqual(set(raw), {"worker","manager","bindings","vantage","proof","worker_spine"})
        self.assertEqual(raw["worker_spine"], canonical_json(self.spine))
        self.assertEqual(result["worker_spine_digest"],masks.sha(raw["worker_spine"]))
        self.assertEqual(json.loads(raw["bindings"])["admitted_path"], str(self.admitted))
        self.assertEqual(cap.replay_stopped_masks(**keys), result)
        with self.assertRaisesRegex(ValueError, "already attempted"):
            self.base.acquire()
        self.scope.assert_called_once()

    def test_complete_but_mistimed_handle_frame_is_retained_as_a_negative(self):
        self.spine["opened_boottime_ns"] = 11000
        result = self.base.acquire()
        self.assertFalse(result["mask_consistent"])
        self.assertIn("bracket", result["reason"])
        self.assertFalse(result["activation_authorized"])
        self.assertEqual(cap.replay_stopped_masks(**self.base.keys(result)),result)

    def test_raw_spine_substitution_or_downgrade_does_not_yield_a_manager_or_spine_projection(self):
        raw = custody.replay_mask_observation(**self.base.keys(self.base.acquire()))
        b,v,p = (json.loads(raw[k]) for k in ("bindings","vantage","proof"))
        out = {}
        args = (b,v,p,raw["worker"],raw["manager"])
        for original in (None,b"{}",raw["worker_spine"]+b"\n"):
            with self.subTest(original_present=original is not None), self.assertRaises(ValueError):
                cap._verify_slice(*args,worker_spine_raw=original,spine_projection=out)
        self.assertEqual(out,{})
        with self.assertRaisesRegex(ValueError, "mixed worker spine"):
            custody._match_spine({k:v for k,v in raw.items() if k != "worker_spine"})

    def test_lost_topology_during_publication_refuses_without_a_receipt_or_second_capture(self):
        def lose(*args):
            self.assertTrue(self.active)
            if self.topology.call_count == 4:
                raise ValueError("changed worker mount")
        self.topology.side_effect = lose
        with self.assertRaisesRegex(ValueError, "changed worker mount"):
            self.base.acquire()
        self.assertEqual(list(self.base.cfg.receipt_directory.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "already attempted"):
            self.base.acquire()
        self.scope.assert_called_once()

    def test_no_handle_operation_or_custody_when_owner_is_not_the_sole_stopped_gate(self):
        self.base.session.gate_release_seen = True
        with self.assertRaisesRegex(ValueError, "unreleased"):
            self.base.acquire()
        self.scope.assert_not_called()
        self.base.probe.assert_not_called()
        self.topology.assert_not_called()

    def test_different_nominated_mount_id_refuses_before_any_private_write(self):
        self.mount.return_value = 99
        with self.assertRaisesRegex(ValueError, "measured mount"):
            self.base.acquire()
        self.assertEqual(list(self.base.cfg.receipt_directory.iterdir()), [])

    def test_post_publication_close_failure_keeps_pins_but_no_consistency_claim(self):
        self.base.exit_error = OSError("uncertain descriptor closure")
        with self.assertRaisesRegex(OSError, "uncertain descriptor"):
            self.base.acquire()
        retained = self.base.session._mask_receipt
        self.assertFalse(retained["mask_consistent"])
        self.assertIn("post-publication",retained["reason"])
        self.assertEqual(masks.sha(custody.replay_mask_observation(**self.base.keys(retained))["worker_spine"]),
                         retained["worker_spine_digest"])

    def test_publication_guard_rejects_changed_current_namespace_and_a_closed_view(self):
        v = object.__new__(kernel._View)
        v._done, v._ok, v._closed = True, True, False
        v._caller = (threading.get_native_id(), 14)
        v._caller_ticks = 13
        v._ticks, v._mount, v._deadline = 7, 4, self.base.deadline
        v._manager = {"start_ticks":5}
        v._ctx, v._manager_context = {"root":1},{"root":2}
        v._roles = {"worker":(1,10),"manager":(2,11)}
        v._first = {"mounts":{"worker":b"w\n","manager":b"m\n"}}
        v._caller_context = mock.Mock()
        def frame(stack,role,mount,deadline,*,kind,ticks):
            return {},v._ctx if kind == "worker" else v._manager_context,None,None
        live = {10:b"w\n",11:b"m\n",14:b"m\n"}
        with mock.patch.object(kernel,"_frame",side_effect=frame), \
                mock.patch.object(kernel,"_read",side_effect=lambda fd,*a:live[fd]):
            v.guard_retained_topology(b"w\n",b"m\n")
            live[11] = b"other\n"
            with self.assertRaisesRegex(ValueError, "mounting changed"):
                v.guard_retained_topology(b"w\n",b"m\n")
            v._closed = True
            with self.assertRaisesRegex(ValueError, "no longer held"):
                v.guard_retained_topology(b"w\n",b"m\n")
