"""Real private claim files; no process signals, service, sensor, or VM."""
from contextlib import nullcontext
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, time_ns
from unittest import TestCase, mock

from aragorn import pi_core_task_owner as owner
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
import test_pi_core_task_service as fixtures


class TaskOwnerTests(TestCase):
    def setUp(self):
        self.store = CAS(Path(self.enterContext(TemporaryDirectory())).resolve())
        self.ticket = fixtures.TaskServiceTests().ticket("BENIGN_JSON_SUM", "baseline")
        self.nom = self.nominate()
        self.peers = dict(schema="held", worker=dict(start_ticks=80), service=dict(start_ticks=90))
        self.held = mock.Mock(record=self.peers)
        self.enterContext(mock.patch.object(owner, "hold_stopped_roles", return_value=nullcontext(self.held)))
        self.inputs = owner._Inputs(monotonic()+6)
        self.inputs.read = lambda *args: deepcopy(self.approval)
        self.refresh()
        self.real_ledger = owner._ledger
        self.enterContext(mock.patch.object(owner, "_ledger", side_effect=lambda *_:nullcontext((self.store, lambda:None))))
        self.health = self.enterContext(mock.patch.object(owner, "guard_task_health", return_value={"source":"observed"}))
        self.service_listener = object()
        self.channels = mock.Mock()
        self.publish = mock.Mock(return_value=({"service.sock":self.service_listener},self.channels))
        self.sender = self.enterContext(mock.patch.object(owner, "_send_release"))
        self.real_measure = owner.task.measure_via_pi
        self.dispatch = self.enterContext(mock.patch.object(owner.task, "measure_via_pi", return_value=b"verified receipt"))
        self.source, self.activation = object(), object()

    def nominate(self):
        t = self.ticket
        n = dict(schema="aragorn/pi-task-guest-nomination/v1", request_digest=canonical_digest(t["request"]),
                 clock=t["clock"], service_invocation_id="1"*32, sensor_invocation_id=None, sensor_pid=0,
                 service_code={k:canonical_digest(k) for k in ("wrapper_digest","interpreter_digest","unit_digest")},
                 **{k:t[k] for k in ("manager_peer","pi_peer","service_peer")})
        t["environment_digest"] = canonical_digest(n)
        return n

    def refresh(self):
        now = time_ns()
        self.approval = dict(schema="aragorn/pi-task-owner-release/v1",ticket_digest=canonical_digest(self.ticket),
            worker_invocation_id="2"*32, claim_directory=dict(dev="8:1",ino=200,mnt_id=44),
            not_before_unix_ns=now-1_000_000_000, expires_unix_ns=now+15_000_000_000)

    def claim(self):
        return owner.hold_task_owner(inputs=self.inputs, release_pin=canonical_digest(self.approval),
                                    ticket=self.ticket, nomination=self.nom, publish=self.publish)

    def handoff(self, held, fd=None):
        held.release(control=object(), source_observer=self.source,
                     activation=self.activation, directory_fd=fd)

    def measure(self, held):
        return held.measure(self.ticket["request"], lambda _:1, pi=object(), witness=object(), retain=lambda _:None)

    def test_stopped_roles_written_to_one_permanent_slot_before_release(self):
        with self.claim() as held:
            self.assertGreaterEqual(self.held.guard.call_args_list.count(mock.call(stopped=True)),2)
            records = list(self.store.root.rglob("*.json"))
            self.assertEqual(len(records),1)
            raw = records[0].read_bytes()
            claim = json.loads(raw)
            self.assertEqual(raw, canonical_json(claim))
            self.assertEqual(claim["roles"], self.peers)
            self.assertEqual(claim["ticket_digest"],canonical_digest(self.ticket))
            self.handoff(held)
            self.assertEqual(self.measure(held), b"verified receipt")
            with self.assertRaises(ValueError):
                self.measure(held)
            self.sender.assert_called_once()
            self.assertIs(self.sender.call_args.kwargs["service_listener"],self.service_listener)
            self.dispatch.assert_called_once()
        self.peers["service"]["start_ticks"] += 1
        self.approval["worker_invocation_id"] = "3"*32
        with self.assertRaisesRegex(Exception, "already claimed"):
            with self.claim(): self.fail("replacement generation acquired a spent slot")

    def test_missing_health_refuses_release_and_spends_slot(self):
        self.health.side_effect = ValueError("missing sensor health")
        with self.claim() as held:
            with self.assertRaisesRegex(ValueError,"missing sensor health"):
                self.handoff(held)
            self.health.side_effect = None
            with self.assertRaises(ValueError):
                self.handoff(held)
            with self.assertRaises(ValueError):
                self.measure(held)
        self.sender.assert_not_called()
        self.dispatch.assert_not_called()
        with self.assertRaisesRegex(ValueError, "already claimed"):
            with self.claim(): self.fail("retry")

    def test_health_is_rechecked_after_collector_mark_before_first_manager_byte(self):
        self.dispatch.side_effect = self.real_measure
        self.enterContext(mock.patch.object(owner.task,"_edge",side_effect=lambda *_:nullcontext(lambda:None)))
        write = self.enterContext(mock.patch.object(owner.task,"_write"))
        mode = self.enterContext(mock.patch.object(owner.guest,"observe_task_guest"))
        def mark(name):
            self.assertEqual(name,"TASK_ACCEPTED")
            self.health.side_effect = ValueError("health lost at send")
            return 123
        with self.claim() as held:
            self.handoff(held)
            with self.assertRaisesRegex(ValueError,"health lost at send"):
                held.measure(self.ticket["request"],mark,pi=object(),witness=object(),retain=lambda _:None)
            with self.assertRaises(ValueError):
                self.measure(held)
        mode.assert_called_once()
        write.assert_not_called()

    def test_named_claim_replacement_invalidates_original_owner(self):
        with self.assertRaisesRegex(ValueError,"claim left custody"):
            with self.claim() as held:
                record, = self.store.root.rglob("*.json")
                original = record.read_bytes()
                record.rename(record.with_suffix(".retained"))
                record.write_bytes(original)
                self.handoff(held)
        self.sender.assert_not_called()
        self.dispatch.assert_not_called()

    def test_failed_receiver_copy_proof_blocks_before_task_and_never_retries(self):
        self.ticket = fixtures.TaskServiceTests().ticket("BENIGN_COPY_READBACK","baseline")
        self.ticket["copy"] = dict(fixture_digest=canonical_digest("fixture"),
            directory_identity=dict(device=1,inode=2,mode=0o700,uid=1300,gid=1300))
        self.nom = self.nominate()
        self.refresh()
        with self.claim() as held, mock.patch.object(owner,"check_source_fd"), \
                mock.patch.object(owner,"resolve_service_copy",side_effect=ValueError("unverified receiver")) as resolve:
            with open(__file__, "rb") as dummy:
                self.handoff(held, dummy.fileno())
                with self.assertRaisesRegex(ValueError,"unverified receiver"):
                    self.measure(held)
                with self.assertRaises(ValueError):
                    self.measure(held)
            self.assertEqual(resolve.call_args.kwargs["service_start_ticks"],90)
            resolve.assert_called_once()
            self.dispatch.assert_not_called()

    def test_role_change_at_claim_readback_never_exposes_dispatch(self):
        self.held.guard.side_effect = [None, ValueError("worker generation changed")]
        with self.assertRaisesRegex(ValueError,"generation changed"):
            with self.claim(): self.fail("exposed dispatch")
        self.assertEqual(len(list(self.store.root.rglob("*.json"))),1)
        self.publish.assert_not_called()
        self.sender.assert_not_called()
        self.dispatch.assert_not_called()

    def test_receiver_replacement_after_initial_proof_refuses_before_first_byte(self):
        self.ticket = fixtures.TaskServiceTests().ticket("BENIGN_COPY_READBACK","baseline")
        self.ticket["copy"] = dict(fixture_digest=canonical_digest("fixture"),
            directory_identity=dict(device=1,inode=2,mode=0o700,uid=1300,gid=1300))
        self.nom = self.nominate()
        self.refresh()
        observer = object.__new__(owner.task.ManagedCopyObserver)
        observer._remote = 57
        observer.observing = mock.Mock(return_value=nullcontext(object()))
        self.dispatch.side_effect = self.real_measure
        with self.claim() as held, open(__file__,"rb") as standin, mock.patch.object(owner,"check_source_fd"), \
                mock.patch.object(owner,"resolve_service_copy",return_value=observer), \
                mock.patch.object(owner.task,"_edge",side_effect=lambda *_:nullcontext(lambda:None)), \
                mock.patch.object(owner.guest,"observe_task_guest"), mock.patch.object(owner.task,"_write") as send, \
                mock.patch.object(owner,"_same_description",return_value=False) as compare:
            self.handoff(held, standin.fileno())
            with self.assertRaisesRegex(ValueError, "service-side copy FD changed"):
                self.measure(held)
            self.assertEqual(compare.call_args.args[::2],(self.ticket["service_peer"][0],57))
            send.assert_not_called()

    def test_only_the_nominated_persistent_ledger_can_issue_a_claim(self):
        root = b"44 44 8:1 / / rw - ext4 /dev/disk rw\n"
        directory = self.approval["claim_directory"]
        with mock.patch.object(owner.ledger.custody,"_roots",return_value=nullcontext((22,lambda:None,()))), \
                mock.patch.object(owner.ledger.view,"_stat",return_value=directory), \
                mock.patch.object(owner.ledger,"_kernel_inputs") as read, mock.patch.object(owner,"CAS") as cas:
            # Use the concrete guard, not the test suite's temporary ledger context.
            read.return_value = self.ticket["clock"]["boot_id"], root
            with self.real_ledger(self.approval,self.ticket,self.inputs.deadline): pass
            cas.assert_called_once_with(owner.CLAIMS,read_only=True)
            for boot,raw in (("other-boot",root),(self.ticket["clock"]["boot_id"],root.replace(b"44 44",b"43 43")),
                             (self.ticket["clock"]["boot_id"],b"44 44 0:3 / / rw - tmpfs tmpfs rw\n"),
                             (self.ticket["clock"]["boot_id"],root + b"45 44 8:1 /other /var/lib/aragorn-task-owner-claims/nested rw - ext4 /dev/disk rw\n")):
                read.return_value = boot,raw
                with self.assertRaises(ValueError):
                    with self.real_ledger(self.approval,self.ticket,self.inputs.deadline): self.fail("wrong ledger")
