"""Offline receiver-FD observations. No service, syscall, or task is started."""
from contextlib import nullcontext
import os
from tempfile import TemporaryDirectory
from time import monotonic
from unittest import TestCase, mock

from aragorn import pi_core_task_owner_copy as owner
from aragorn.oci_worker_protocol import canonical_digest


class TaskOwnerCopyTests(TestCase):
    def setUp(self):
        self.fd = os.open(self.enterContext(TemporaryDirectory()), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.until = monotonic() + 5
        self.clock = dict(clock_id="CLOCK_BOOTTIME", boot_id="11111111-1111-4111-8111-111111111111", time_namespace_inode=39)
        req = dict(kind="task", mode="baseline", pair_id="pair-1", **{k:canonical_digest(k) for k in
            ("task_digest", "input_digest", "collection_digest", "host_profile_digest", "deployment_digest")})
        peers = dict(pi_peer=[101,1040,1041], service_peer=[102,2040,2041], manager_peer=[os.getpid(),0,0])
        self.nom = dict(schema="aragorn/pi-task-guest-nomination/v1", request_digest=canonical_digest(req), clock=self.clock,
            **peers, service_invocation_id="a"*32, sensor_pid=0, sensor_invocation_id=None,
            service_code={k:canonical_digest(k) for k in ("unit_digest", "wrapper_digest", "interpreter_digest")})
        self.guest = dict(unit="aragorn-pi-task.service", invocation_id="a"*32, pid=102, start_ticks=55, uid=2040,
            gid=2041, boot_id=self.clock["boot_id"], time_ns=39, observer_mount_ns=20, service_mount_ns=21,
            observer_mount_id=22, service_mount_id=22)
        self.directory = owner.copy._identity(os.fstat(self.fd)) | {"uid":2040, "gid":2041}
        self.enterContext(mock.patch.object(owner.copy,"_identity",return_value=self.directory))
        fixture = dict(schema="aragorn/pi-core-task-copy-fixture/v1", request_digest=canonical_digest(req),
                       directory_identity=self.directory, guest=self.guest)
        self.ticket = dict(schema="aragorn/pi-core-task-ticket/v1", request=req, clock=self.clock, **peers,
            environment_digest=canonical_digest(self.nom), copy=dict(directory_identity=self.directory,
                                                                      fixture_digest=canonical_digest(fixture)))
        self.remote = 90 if self.fd != 90 else 91
        self.enterContext(mock.patch.object(owner.copy,"_hold_process",return_value=nullcontext(17)))
        self.live = self.enterContext(mock.patch.object(owner.copy.native.process,"require_live_pidfd"))
        self.names = self.enterContext(mock.patch.object(owner,"_receiver_fds",return_value=[0, self.fd, self.remote]))
        self.kernel_compare = owner._same_description
        self.same = self.enterContext(mock.patch.object(owner,"_same_description",side_effect=lambda _pid,_owner,r:r == self.remote))
        self.read = self.enterContext(mock.patch.object(owner.copy,"_read_guest",return_value=(self.guest, self.directory)))

    def resolve(self):
        return owner.resolve_service_copy(self.ticket, nomination=self.nom, nomination_pin=canonical_digest(self.nom),
            service_start_ticks=55, directory_fd=self.fd, deadline=self.until)

    def test_selects_receiver_open_description_not_the_senders_number(self):
        observer = self.resolve()
        self.assertIs(type(observer), owner.copy.ManagedCopyObserver)
        self.assertEqual(self.read.call_args.args[1:4], (self.fd,self.remote,17))
        self.live.assert_called_once_with(17)

    def test_wrong_source_is_not_lent_and_compute_cannot_receive_a_directory(self):
        with self.assertRaises(ValueError):
            owner.check_source_fd(self.ticket | {"copy": {"directory_identity":self.directory | {"inode":1}}}, self.fd)
        bare = {k:v for k,v in self.ticket.items() if k != "copy"}
        with self.assertRaises(ValueError):
            owner.check_source_fd(bare, self.fd)
        owner.check_source_fd(bare, None)
        for bad in (True, 0, 1, 2, None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                owner.check_source_fd(self.ticket, bad)
        with mock.patch.object(os,"O_PATH",0o10000000,create=True), \
                mock.patch.object(owner.fcntl,"fcntl",return_value=0o10000000), self.assertRaises(ValueError):
            owner.check_source_fd(self.ticket, self.fd)

    def test_missing_aliased_or_unreadable_description_is_not_authority(self):
        for compare in (lambda *_:False, lambda *_:True, PermissionError()):
            with self.subTest(compare=compare), self.assertRaises((ValueError, PermissionError)):
                self.same.side_effect = compare
                self.resolve()
        self.read.assert_not_called()

    def test_substituted_generation_remote_inode_or_ticket_fixture_refuses(self):
        for guest, directory in ((self.guest | {"start_ticks":56},self.directory),
                (self.guest,self.directory | {"inode":self.directory["inode"]+1}),
                (self.guest | {"service_mount_id":42},self.directory),
                (self.guest | {"service_mount_ns":43},self.directory)):
            with self.subTest(guest=guest,directory=directory), self.assertRaises(ValueError):
                self.read.return_value = guest,directory
                self.resolve()

    def test_descriptor_replaced_during_observation_refuses(self):
        def changed(_pid,_owner,remote):
            return remote == self.remote and not self.read.called
        self.same.side_effect = changed
        with self.assertRaises(ValueError):
            self.resolve()

    def test_kernel_comparison_names_both_processes_and_does_not_fall_back(self):
        with mock.patch.object(owner.ctypes, "CDLL") as libc:
            syscall = libc.return_value.syscall
            syscall.return_value = 0
            self.assertTrue(self.kernel_compare(102, self.fd, self.remote))
            self.assertEqual([v.value for v in syscall.call_args.args], [272, os.getpid(),102,0,self.fd,self.remote])
            syscall.return_value = -1
            with self.assertRaises(OSError):
                self.kernel_compare(102,self.fd,self.remote)
