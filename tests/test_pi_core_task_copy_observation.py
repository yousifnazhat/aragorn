"""Temporary file readback only: no guest, service, clock measurement or live authority."""
from pathlib import Path
from contextlib import nullcontext
from tempfile import TemporaryDirectory
from time import monotonic
import os
from unittest import TestCase, mock

from aragorn import pi_core_task_copy_observation as subject
from aragorn.oci_worker_protocol import canonical_digest


class ManagedCopyObservation(TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(subject, "_hold_process", return_value=nullcontext(7)))
        self.enterContext(mock.patch.object(subject, "_same_mount"))  # Linux statx is not available on the offline Mac.
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        s = os.fstat(self.fd)
        # /tmp can assign gid 0 even to files created by an unprivileged Mac user.
        # Translate only these two identities for the inert guest; do not chown anything.
        actual_identity = subject._identity
        def fixture_identity(meta):
            return actual_identity(meta) | dict(uid=2261 if meta.st_uid == s.st_uid else 0,
                                                gid=2262 if meta.st_gid == s.st_gid else 0)
        self.enterContext(mock.patch.object(subject, "_identity", side_effect=fixture_identity))
        self.directory = fixture_identity(s)
        self.request = canonical_digest("independently scheduled request")
        self.inputs = self.root / "allowed-copy.txt"
        self.data = b"Aragorn Phase 3 benign copy/readback data.\n"
        self.guest = dict(unit="aragorn-pi-task.service", invocation_id="1"*32, pid=101, start_ticks=21,
            uid=2261, gid=2262, boot_id="00000000-0000-0000-0000-000000000001",
            observer_mount_ns=12, service_mount_ns=13, time_ns=40, observer_mount_id=50, service_mount_id=52)
        self.deadline = monotonic()+5

    def observer(self):
        return subject.ManagedCopyObserver(directory_fd=self.fd, service_directory_fd=9, request_digest=self.request,
            guest=self.guest, directory_identity=self.directory)

    def add_copy(self, payload):
        fd = os.open(self.inputs, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)

    def test_observer_reads_original_bytes_and_its_own_file_identity(self):
        with mock.patch.object(subject, "_guest_edge"), self.observer().observing(self.request, deadline=self.deadline) as read:
            self.add_copy(self.data)
            original = read()
            with self.assertRaises(ValueError):
                read()
        self.assertEqual(bytes.fromhex(original["content_hex"]), self.data)
        self.assertEqual(original["file_identity"]["inode"], self.inputs.stat().st_ino)
        self.assertEqual(original["directory_identity"], self.directory)
        self.assertEqual(original["fixture_digest"], canonical_digest(dict(schema="aragorn/pi-core-task-copy-fixture/v1",
            request_digest=self.request, guest=self.guest, directory_identity=self.directory)))
        self.assertFalse(original["exclusive_writer_verified"] or original["phase3_exit_eligible"])
        with self.assertRaises(ValueError):
            read()

    def test_nonnominated_request_or_occupied_directory_refuses_before_dispatch(self):
        with mock.patch.object(subject, "_guest_edge"):
            with self.assertRaisesRegex(ValueError, "wrong request"), self.observer().observing(canonical_digest("foreign"), deadline=self.deadline):
                self.fail("wrong request reached service")
            self.inputs.symlink_to(self.root / "missing")
            with self.assertRaisesRegex(ValueError, "not fresh"), self.observer().observing(self.request, deadline=self.deadline):
                self.fail("occupied sink reached service")

    def test_changed_content_or_replaced_file_is_not_accepted(self):
        with mock.patch.object(subject, "_guest_edge"):
            with self.assertRaisesRegex(ValueError, "bytes differ"), self.observer().observing(self.request, deadline=self.deadline) as read:
                self.add_copy(self.data[:-1] + b"?")
                read()
            self.inputs.unlink()
            with self.assertRaisesRegex(ValueError, "single-link file"), self.observer().observing(self.request, deadline=self.deadline) as read:
                target = self.root / "decoy"
                self.add_copy(self.data)
                self.inputs.rename(target)
                self.inputs.symlink_to(target)
                read()

    def test_peer_directory_or_unit_substitution_fails(self):
        # Supply complete inert kernel/systemd edge observations; the predicate itself is real.
        clock = self.guest | {"service_mount_id": self.guest["service_mount_id"] + 1}
        with mock.patch.object(subject, "_read_guest", return_value=(clock, self.directory)):
            with self.assertRaisesRegex(ValueError, "different guest generation"), self.observer().observing(self.request, deadline=self.deadline):
                self.fail("different service mount reached dispatch")
        with mock.patch.object(subject, "_read_guest", return_value=(self.guest | {"invocation_id":"2"*32}, self.directory)):
            with self.assertRaisesRegex(ValueError, "different guest generation"), self.observer().observing(self.request, deadline=self.deadline):
                self.fail("replaced unit reached dispatch")

    def test_guest_change_at_final_custody_check_prevents_completion(self):
        def edge(*args):
            if self.inputs.exists() and self.inputs.stat().st_nlink == 2:
                raise ValueError("fixture retired")
        with mock.patch.object(subject, "_guest_edge", side_effect=edge), self.assertRaisesRegex(ValueError, "fixture retired"):
            with self.observer().observing(self.request, deadline=self.deadline) as read:
                self.add_copy(self.data)
                read()
                os.link(self.inputs, self.root / "unexpected-alias")

    def test_fixed_systemd_show_requires_exact_pid_and_invocation(self):
        name = "aragorn-pi-task.service"
        complete = (f"Id={name}\nMainPID=101\nExecMainPID=101\nInvocationID={'1'*32}\nActiveState=active\n"
                    f"SubState=running\nControlGroup=/system.slice/{name}\n").encode()
        with mock.patch.object(subject.native, "_command", return_value=(0, complete)) as show:
            self.assertEqual(subject._unit(101, "1"*32, self.deadline), "1"*32)
            argv, bound = show.call_args.args
            self.assertEqual((argv[0:3], argv[-1], bound), (("/usr/bin/systemctl", "show", "--all"), name, self.deadline))
            with self.assertRaises(ValueError):
                subject._unit(102, "1"*32, self.deadline)
            with self.assertRaises(ValueError):
                subject._unit(101, "2"*32, self.deadline)

    def test_unprivileged_principal_required_without_accepting_service_labels(self):
        self.guest["uid"] = 0
        with self.assertRaises(ValueError):
            self.observer()

    def test_guest_reader_rejects_foreign_cgroup_and_privileged_service(self):
        from contextlib import ExitStack
        k = subject.kernel
        creds = {p+n:self.guest[n] for p in ("","e","s","fs") for n in ("uid","gid")}
        creds.update(groups=[],no_new_privs=True,**{name:0 for name in k._CAPS.values()})
        with ExitStack() as st:
            for owner, fn, result in ((subject, "_unit", self.guest["invocation_id"]), (k, "_proc", (1, 2)),
                    (k, "_role", (101, 3)), (k, "_parse_subject", (21, 77, ("S","S"), 1, creds)),
                    (subject.native.process, "require_live_pidfd", None)):
                st.enter_context(mock.patch.object(owner,fn,return_value=result))
            read = st.enter_context(mock.patch.object(k, "_read", return_value=b"0::/wrong.service\n"))
            with self.assertRaisesRegex(ValueError, "cgroup"):
                subject._read_guest(self.guest,self.fd,9,7,self.deadline)
            read.return_value=b"0::/system.slice/aragorn-pi-task.service\n"
            creds["cap_effective"]=1
            with self.assertRaisesRegex(ValueError, "credentials"):
                subject._read_guest(self.guest,self.fd,9,7,self.deadline)
