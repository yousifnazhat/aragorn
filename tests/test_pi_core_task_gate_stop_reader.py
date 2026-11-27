"""Synthetic stopped proc records, real local file identity; no guest, target, or signal."""
import os
from tempfile import TemporaryFile
from time import monotonic
from unittest import TestCase, mock

from aragorn import pi_core_task_gate_stop_reader as reader
from aragorn import pi_core_task_owner_roles as roles
from aragorn.pi_core_task_observer_binding import _StaticWorker


class GateStopReaderTests(TestCase):
    def setUp(self):
        self.fd = self.enterContext(TemporaryFile()).fileno()
        self.st = os.fstat(self.fd)
        self.worker = object.__new__(_StaticWorker)
        self.worker._proc, self.worker._mount = 104, 57
        self.worker._record = dict(worker=dict(pid=502,uid=1250,gid=1250,start_ticks=701,
            invocation_id="1"*32,unit=roles.WORKER),clock=dict(clock_id="CLOCK_BOOTTIME",
            boot_id="11111111-1111-4111-8111-111111111111",time_namespace_inode=661))
        self.worker.files = {str(roles.sources.GATE_PATH):self.fd}
        self.worker.guard = mock.Mock()
        self.until = monotonic()+4
        self.page = 4096
        self.enterContext(mock.patch.object(os,"sysconf",side_effect=lambda k:self.page if k=="SC_PAGE_SIZE" else self.fail(k)))
        self.maps = self.mapping()
        self.syscall = b"-1 0xfff0 0x210524\n"
        def read(proc,name,limit,mount,deadline):
            self.assertEqual((proc,mount,deadline),(104,57,self.until))
            return {"syscall":self.syscall,"maps":self.maps}[name]
        self.read = self.enterContext(mock.patch.object(roles.kernel,"_read",side_effect=read))

    def mapping(self, *, addr=None, perms="r-xp", device=None, ino=None, off=0, suffix=""):
        address = addr or f"00210000-{0x210000+self.page:08x}"
        dev = device or f"{os.major(self.st.st_dev):02x}:{os.minor(self.st.st_dev):02x}"
        return f"{address} {perms} {off:08x} {dev} {self.st.st_ino if ino is None else ino} /held/source-gate{suffix}\n".encode()

    def observe(self, phase="stopped"):
        return reader.read_gate_stop(self.worker,phase=phase,deadline=self.until)

    def test_reviewed_post_svc_sites_on_the_original_executable_mapping(self):
        for self.page in (4096,16384,65536):
            self.maps = self.mapping()
            for pc,site in ((0x210524,"first"),(0x21054c,"final")):
                for nr,row in ((-1,f"-1 0xfff0 {pc:#x}\n"),(129,f"129 0x1f6 0x13 0x0 0x0 0x0 0xbc 0xfff0 {pc:#x}\n")):
                    with self.subTest(page=self.page,site=site,nr=nr):
                        self.syscall = row.encode()
                        evidence = self.observe()
                        self.assertEqual((evidence["site"],evidence["instruction_pointer"],evidence["file_offset"],
                                          evidence["syscall_number"]),(site,pc,pc-0x210000,nr))
                        self.assertEqual(evidence["worker"],self.worker.worker)
        self.assertTrue(self.worker.guard.called)

    def test_requires_exact_pc_envelope_and_self_target_when_available(self):
        for row in (b"running\n",b"-1 0xfff0 0x210520\n",b"-1 0xfff0 0x21056c\n",
                    b"-1 0xfff0 0x00210524 trailing\n",b"-1 0x0 0x210524\n",
                    b"129 0x1f7 0x13 0x0 0x0 0x0 0x0 0xfff0 0x210524\n",
                    b"129 0x1f6 0x12 0x0 0x0 0x0 0x0 0xfff0 0x21054c\n"):
            self.syscall = row
            with self.subTest(row=row),self.assertRaises(ValueError): self.observe()
        with self.assertRaises(ValueError): self.observe("node")

    def test_executable_map_must_match_original_gate_and_exact_load_layout(self):
        valid = self.mapping()
        for maps in (self.mapping(perms="rw-p"), self.mapping(ino=self.st.st_ino+1),
                     self.mapping(device="00:00",ino=0),self.mapping(off=0x1000),
                     self.mapping(addr="00200000-00211000"),self.mapping(suffix=" (deleted)"),
                     valid+valid,valid+self.mapping(addr="00220000-00221000"),
                     valid+self.mapping(addr="00220000-00221000",perms="rw-p")):
            self.maps = maps
            with self.subTest(maps=maps),self.assertRaises(ValueError): self.observe()

    def test_sampling_is_bracketed_and_a_moving_site_never_returns(self):
        self.syscall = b"-1 0xfff0 0x210524\n"
        self.observation_phase = "traced-gate"
        e = self.observe(self.observation_phase)
        self.assertEqual(e["site"], "first")
        self.assertEqual(self.worker.guard.call_args_list,[mock.call(phase=self.observation_phase,deadline=self.until)]*2)
        capture = self.read.side_effect
        seen = []
        def changing(*args):
            if args[1]=="syscall" and seen:
                return b"-1 0xfff0 0x21054c\n"
            if args[1]=="syscall": seen.append(1)
            return capture(*args)
        self.read.side_effect = changing
        with self.assertRaises(ValueError): self.observe()
        self.read.side_effect = capture
        self.worker.guard.side_effect = [None,ValueError("late generation substitution")]
        with self.assertRaisesRegex(ValueError,"late generation substitution"): self.observe()
