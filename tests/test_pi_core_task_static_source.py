"""Source intake and receipt replay with held fixture FDs; no tracing or signals."""
from contextlib import nullcontext
from copy import deepcopy
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from types import SimpleNamespace
from unittest import TestCase, mock

from aragorn import pi_core_task_owner_roles as roles, pi_core_task_static_source as static
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


class StaticIntakeTests(TestCase):
    def setUp(self):
        self.record = dict(worker=dict(pid=400,uid=501,gid=501,start_ticks=170,unit=roles.WORKER,invocation_id="a"*32),
            service=dict(pid=403),clock=dict(boot_id="12345678-1234-1234-1234-123456789abc",
            time_namespace_inode=99,clock_id="CLOCK_BOOTTIME"),environment_digest=canonical_digest("environment"),
            ticket_digest=canonical_digest("ticket"))
        self.claim = dict(schema="aragorn/fixed-task-owner-claim/v1",roles=deepcopy(self.record),
            ticket_digest=self.record["ticket_digest"],release_digest=canonical_digest("release"),
            slot=dict(schema="aragorn/fixed-task-slot/v1",collection_digest=canonical_digest("collection"),
                      pair_id="pair-1",mode="baseline"))
        self.claim["commitment_digest"] = canonical_digest(self.claim["slot"])
        self.until = monotonic()+5
        self.temp = Path(self.enterContext(TemporaryDirectory()))
        def held(name):
            f = self.enterContext((self.temp/name).open("w+b"))
            f.write(name.encode())
            f.flush()
            return f.fileno()
        self.files = {p:held(str(i)) for i,p in enumerate(roles._WORKER_PINS)}
        self.h = SimpleNamespace(record=deepcopy(self.record),worker=self.record["worker"] | {"cgroup":"/system.slice/"+roles.WORKER},
            clock=self.record["clock"], files=self.files, pidfd=held("pidfd"),guard=mock.Mock())
        self.enterContext(mock.patch.object(static, "bind_static_worker",return_value=nullcontext(self.h)))
        self.roles = SimpleNamespace(record=deepcopy(self.record))

    def prepare(self):
        return static.bind_task_source_observer(self.roles, claim_raw=canonical_json(self.claim), deadline=self.until)

    def test_accepted_static_package_and_invocation_reach_the_observer_not_a_start(self):
        with self.prepare() as intake:
            o = intake.observer
            self.assertIs(type(o),roles.sources.PiSourceObserver)
            self.assertEqual(o._worker,self.h.worker)
            self.assertTrue(os.path.samestat(os.fstat(o._pidfd),os.fstat(self.h.pidfd)))
            self.assertEqual(o._source_fds[roles.sources.ENTRY_PATH],self.files[roles.sources.ENTRY_PATH])
            rec = intake.receipt()
            self.assertEqual(rec["worker"]["invocation_id"],"a"*32)
            base = Path(__file__).resolve().parents[1]/"packaging/pi-core/task-worker-v1"
            outputs = json.loads((base/"build.json").read_bytes())["outputs"]
            self.assertEqual(rec["files"][str(roles.sources.GATE_PATH)]["digest"],"sha256:"+outputs["source-gate"]["sha256"])
            self.assertEqual(rec["files"][roles.sources.ENTRY_PATH]["digest"],"sha256:"+outputs["entrypoint.js"]["sha256"])
            self.assertFalse(o._attached)
            self.assertFalse(o._executed)
            self.assertEqual(o._bindings["gate_digest"],rec["files"][str(roles.sources.GATE_PATH)]["digest"])
            self.assertEqual(o._sources[0]["digest"],rec["files"][roles.sources.ENTRY_PATH]["digest"])
            with self.assertRaisesRegex(ValueError, "not armed"):
                intake.require_active(o)
            rec["worker"]["invocation_id"]="changed"
            self.assertEqual(intake.receipt()["worker"]["invocation_id"],"a"*32)
        with self.assertRaises(ValueError): intake.receipt()

    def test_reissued_same_pid_or_changed_claim_is_not_the_spent_generation(self):
        for field, value in (("start_ticks",171),("invocation_id","b"*32)):
            with self.subTest(field=field),mock.patch.dict(self.claim["roles"]["worker"],{field:value}),self.assertRaises(ValueError):
                with self.prepare(): self.fail("swapped claim")
        with self.prepare() as intake:
            with self.assertRaises(ValueError):
                intake.require_active(roles.sources.PiSourceObserver(roles.sources._SEAL))


class ConnectedBindingTests(TestCase):
    def test_generation_swap_after_success_invalidates_the_actual_observer_intake(self):
        # Real binding and descriptor duplication; only Linux readbacks are fixture inputs.
        from tests.test_pi_core_task_observer_binding import StaticWorkerBindingTests
        fixture = StaticWorkerBindingTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        record = fixture.held.record
        slot = dict(schema="aragorn/fixed-task-slot/v1",collection_digest=canonical_digest("collection"),
                    pair_id="pair-1",mode="baseline")
        claim = dict(schema="aragorn/fixed-task-owner-claim/v1",roles=record,slot=slot,
            commitment_digest=canonical_digest(slot),ticket_digest=record["ticket_digest"],release_digest=canonical_digest("release"))
        with static.bind_task_source_observer(fixture.held,claim_raw=canonical_json(claim),deadline=fixture.until) as intake:
            self.assertEqual(intake.receipt()["worker"]["start_ticks"],fixture.worker["start_ticks"])
            old = fixture.peer["invocation_id"]
            fixture.peer["invocation_id"] = "f"*32
            with self.assertRaisesRegex(ValueError,"generation changed"): intake.receipt()
            fixture.peer["invocation_id"] = old
            with self.assertRaises(ValueError): intake.receipt()
            self.assertFalse(intake.observer._attached)
