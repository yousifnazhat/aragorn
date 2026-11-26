"""Task owner health seam: inert observer transitions; no process or sensor launched."""
from copy import deepcopy
import time
import unittest
from unittest.mock import patch

from aragorn import pi_core_task_owner_health as health
from aragorn import pi_core_source_observer as source
from tests.test_pi_core_identity_handoff import activation
from tests.test_pi_core_node_source_observer import build_inert_node_source_capture


class TaskHealthTests(unittest.TestCase):
    def setUp(self):
        self.capture = build_inert_node_source_capture()["record"]
        self.w = self.capture["worker"]
        self.w.update(unit="aragorn-pi-task-worker.service", cgroup="/system.slice/aragorn-pi-task-worker.service")
        self.worker = {k: v for k, v in self.w.items() if k != "cgroup"}
        b = self.capture["bindings"]
        self.activation = activation() | dict(pid=self.w["pid"], uid=self.w["uid"], gid=self.w["gid"],
            start_time_ticks=self.w["start_ticks"], cgroup=self.w["cgroup"], boot_id=self.capture["clock"]["boot_id"],
            runtime_digest=b["runtime_digest"], deployment_digest=b["deployment_digest"], executable_digest=b["node_digest"],
            expires_at_monotonic_ns=time.monotonic_ns()+2_000_000_000)
        self.ticket = dict(request=dict(kind="task", mode="baseline", pair_id="p1",
            **{s+"_digest": b["deployment_digest"] for s in ("host_profile","deployment","collection","task","input")}),
            pi_peer=[self.w[k] for k in ("pid","uid","gid")], clock=self.capture["clock"].copy())
        self.observer = object.__new__(source.PiSourceObserver)
        self.last = self.capture["events"][-1]

    def check(self, capture, observer=None, *, before=None, after=None):
        ticks = [self.last["issued_ns"] if before is None else before,
                 self.last["boottime_ns"], self.last["boottime_ns"] if after is None else after]
        with patch.object(source, "_tick", side_effect=ticks), \
                patch.object(source.PiSourceObserver, "guard_source_health", return_value=capture) as acquire:
            value = health.guard_task_health(self.ticket, source_observer=self.observer if observer is None else observer,
                activation=self.activation, worker=self.worker, deadline=time.monotonic()+2)
            acquire.assert_called_once()
            return value

    def test_baseline_requires_new_source_progress_and_returns_its_raw_evidence(self):
        self.assertEqual(self.check(self.capture), self.capture)
        for captured, obj in ((None, self.observer), (self.capture, self.capture), ({"healthy":True}, self.observer)):
            with self.subTest(obj=type(obj)), self.assertRaises((ValueError, RuntimeError)):
                self.check(captured, obj)

    def test_old_challenge_loss_or_stale_after_validation_refuses(self):
        lost = deepcopy(self.capture)
        lost["accounting"]["events_retained"] -= 1
        for record, times in ((lost, {}), (self.capture, {"before":self.last["issued_ns"]+1}),
                              (self.capture, {"after":self.last["boottime_ns"]+200_000_001})):
            with self.subTest(times=times), self.assertRaises((ValueError, RuntimeError)):
                self.check(record, **times)

    def test_foreign_stopped_generation_clock_or_deployment_refuses(self):
        for mapping, key, value in ((self.worker,"start_ticks",self.worker["start_ticks"]+1),
                                    (self.worker,"invocation_id","b"*32),
                                    (self.ticket["clock"],"time_namespace_inode",98765),
                                    (self.ticket["request"],"deployment_digest","sha256:"+"3"*64)):
            with self.subTest(key=key), patch.dict(mapping,{key:value}), self.assertRaises((ValueError,RuntimeError)):
                self.check(self.capture)

    def test_instrumented_sensor_loss_cannot_be_inferred_from_worker_coverage(self):
        self.ticket["request"]["mode"] = "instrumented"
        with self.assertRaisesRegex(ValueError, "sensor.*loss"):
            self.check(self.capture)
