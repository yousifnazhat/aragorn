"""Original worker descriptors and inert Linux/systemd records; no attach or VM."""
import os
import select
import threading
from unittest import TestCase, mock

from aragorn import pi_core_task_static_source as static, pi_core_task_tracer_lifetime as scope
from aragorn import pi_core_task_owner_roles as roles
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_task_observer_binding as fixtures


class TracerLifetimeTests(TestCase):
    def setUp(self):
        self.f = fixtures.StaticWorkerBindingTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        self.w = self.enterContext(self.f.hold())
        self.intake = static._Intake(self.w,{"ticket_digest":canonical_digest("ticket")},self.f.until)
        self.o = self.intake.observer
        self.same = self.enterContext(mock.patch.object(scope,"_same_description",create=True,
            side_effect=lambda pid,a,b:pid==os.getpid() and os.path.samestat(os.fstat(a),os.fstat(b))))
        self.life = scope.StaticTracerLifetime(self.intake,deadline=self.f.until)
        self.addCleanup(self.life.retire)

    def traced(self):
        s = self.life.bind()
        self.assertIs(s.owned,self.w)
        self.assertIs(s.observer,self.o)
        self.assertIs(s.thread,threading.current_thread())
        self.assertFalse(self.o._attached)
        self.assertIsNone(self.o._kernel)
        self.f.tracer,self.f.state = threading.get_native_id(),"t"
        # The kernel ABI constructor is not a kernel observation or a launcher.
        with mock.patch.object(static.source._Kernel,"__init__",return_value=None):
            self.life.require_traced(self.o)
        self.assertTrue(self.o._attached)
        self.assertFalse(self.o._executed)
        return s

    def active(self):
        s = self.traced()
        self.o._executed = True
        self.f.exe,self.f.argv = str(roles.sources.NODE_PATH),roles._NODE_ARGV
        self.life.require_active(self.o)
        return s

    def test_one_binding_to_the_original_handles_neither_starts_nor_attaches(self):
        self.assertIs(self.life.bind().owned,self.w)
        self.assertEqual(self.o._state,"STATIC_BOUND")
        self.assertFalse(self.o._attached)
        with self.assertRaises(ValueError): self.life.require_traced(self.o)
        self.f.tracer,self.f.state = threading.get_native_id(),"t"
        with self.assertRaises(ValueError): self.life.require_traced(self.o)

    def test_release_detects_real_tracer_loss_at_same_pid_and_refuses_even_after_restoration(self):
        self.active()
        self.f.tracer = 0
        with self.assertRaises(ValueError): self.life.require_active(self.o)
        self.f.tracer = threading.get_native_id()
        with self.assertRaises(ValueError): self.life.require_active(self.o)

    def test_substituted_held_descriptor_or_tracer_session_is_not_adopted(self):
        self.life.bind()
        self.f.tracer,self.f.state = threading.get_native_id(),"t"
        with mock.patch.object(self.w,"pidfd",self.f.proc),self.assertRaises(ValueError):
            self.life.require_traced(self.o)
        with self.assertRaises(ValueError): self.life.require_traced(self.o)

    def test_foreign_session_or_generation_invalidates_active_lifetime(self):
        self.active()
        with mock.patch.object(self.o,"_node_session",object()),self.assertRaises(ValueError):
            self.life.require_active(self.o)
        with self.assertRaises(ValueError): self.life.require_active(self.o)

    def terminal_readback(self, flags, change=None):
        w = self.w.worker
        unit = roles.binding._active(roles.WORKER,w["pid"],w["invocation_id"],roles.WORKER_UNIT)
        unit.update(ActiveState="inactive",SubState="dead",MainPID="0",ControlPID="0",InvocationID="",ControlGroup="")
        unit.update(change or {})
        show = "".join(f"{key}={value}\n" for key,value in unit.items()).encode()
        reader = self.enterContext(mock.patch.object(roles.binding,"_unit_show",return_value=show))
        poller = mock.Mock()
        fds = []
        poller.register.side_effect = lambda fd,mask:fds.append(fd)
        def poll(timeout):
            self.assertEqual(timeout,0)
            self.assertNotEqual(fds[-1],self.w.pidfd)
            self.assertTrue(os.path.samestat(os.fstat(fds[-1]),os.fstat(self.w.pidfd)))
            return [(fds[-1],flags)] if flags else []
        poller.poll.side_effect = poll
        self.enterContext(mock.patch.object(select,"poll",return_value=poller))
        return reader

    def test_original_pidfd_exit_and_cleared_unit_retire_without_reaping(self):
        self.active()
        reader = self.terminal_readback(select.POLLIN)
        receipt = self.life.terminal()
        reader.assert_called_with(roles.WORKER,self.f.until)
        self.assertEqual(receipt,dict(schema="aragorn/static-task-tracer-terminal/v1",
            worker=self.w.worker,clock=self.w.clock,binding_digest=canonical_digest(self.intake._record),
            pidfd_events=select.POLLIN,unit_state=dict(Id=roles.WORKER,ActiveState="inactive",SubState="dead",
                                                       MainPID="0",ControlPID="0",InvocationID="")))
        with self.assertRaises(ValueError): self.life.require_active(self.o)
        with self.assertRaises(ValueError): self.life.terminal()

    def test_no_waitable_exit_cannot_seal_retirement_and_revocation_is_not_exit(self):
        self.active()
        self.terminal_readback(0)
        with self.assertRaises(ValueError): self.life.terminal()
        with self.assertRaises(ValueError): self.life.require_active(self.o)

    def test_new_unit_invocation_refuses_even_when_original_pidfd_is_terminal(self):
        self.active()
        self.terminal_readback(select.POLLIN,{"InvocationID":"2"*32})
        with self.assertRaises(ValueError): self.life.terminal()
        with self.assertRaises(ValueError): self.life.terminal()

    def test_logical_revoke_alone_never_mints_terminal_record(self):
        self.active()
        self.life.retire()
        with self.assertRaises(ValueError): self.life.terminal()
        with self.assertRaises(ValueError): self.life.require_active(self.o)
