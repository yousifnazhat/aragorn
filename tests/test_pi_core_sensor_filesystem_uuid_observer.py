"""Inert mounted-filesystem acquisition boundaries; never issue a real ioctl or open a device."""
from contextlib import ExitStack
import errno
import stat
import unittest
from unittest.mock import Mock, patch

from aragorn import pi_core_sensor_state_observer as obs
from test_pi_core_sensor_state_observer import ID, SensorKernel
from test_pi_core_state_mounts import sample_mountinfo


REPLY = bytes.fromhex("1094e6bb606fb24100a57c153bd2e8a0ff")


def fixture(stack, fs="ext4"):
    k = SensorKernel()
    k.install(stack)
    k.storage = dict(device="8:2", backing_devices=["259:0"], fs_type=fs)
    mgr = sample_mountinfo("manager", device="8:2", fs_type=fs)
    for old,new in ((3,70),(4,71),(5,72)):
        mgr = mgr.replace(f"\n{old} ".encode(), f"\n{new} ".encode())
    k.mounts.update({23:mgr,24:mgr})
    k.fs_magic = {"ext4":0xef53, "xfs":0x58465342}[fs]
    inherited = obs.kernel._filesystem
    stack.enter_context(patch.object(obs.kernel, "_filesystem",
        side_effect=lambda fd: k.fs_magic if k.fds[fd] == k.MAN + obs.ANCHOR else inherited(fd)))
    k.io = Mock(return_value=REPLY)
    def ioctl(fd, command, buffer):
        assert k.fds[fd] == k.MAN + obs.ANCHOR
        assert k.flags[fd] == k.O_RDONLY | k.O_DIRECTORY | k.O_NOFOLLOW | k.O_CLOEXEC
        assert command == 0x80111500 and type(buffer) is bytes and buffer == bytes(17)
        return k.io()
    stack.enter_context(patch.object(obs.fcntl, "ioctl", side_effect=ioctl))
    return k


def acquire(**kwargs):
    return obs.capture_sensor_state(identity=ID,guard=lambda **_:dict(ID),deadline=14,**kwargs)


class FilesystemUUIDObserverTests(unittest.TestCase):
    def test_each_supported_filesystem_queries_only_the_same_anchor_once_per_edge(self):
        for fs in ("ext4","xfs"):
            with self.subTest(fs=fs), ExitStack() as s:
                k = fixture(s,fs)
                view, m, sraw = acquire(uuid_storage=k.storage)
                self.assertEqual(view["schema"],"aragorn/pi-core-sensor-state-view/v2")
                self.assertEqual(view["filesystem_uuid_observation"],dict(before=REPLY.hex(),after=REPLY.hex()))
                self.assertEqual(k.io.call_count,2)
                self.assertEqual((m,sraw), (k.mounts[23],k.mounts[73]))
                self.assertFalse(k.fds)
                with obs.hold_sensor_mount_guard(identity=ID,view=view,manager_raw=m,sensor_raw=sraw,
                                                 guard=lambda **_:dict(ID),deadline=14) as guard:
                    guard()
                self.assertEqual(k.io.call_count,2)  # Retention topology never reissues the request.
                self.assertFalse(k.fds)
                self.assertFalse(any(path.startswith("/dev/") for path,_ in k.calls))

    def test_ordinary_observation_does_not_issue_a_uuid_operation(self):
        with ExitStack() as s:
            k = fixture(s)
            view, _, _ = acquire()
            self.assertEqual(view["schema"],obs.SCHEMA)
            self.assertNotIn("filesystem_uuid_observation",view)
            k.io.assert_not_called()
            self.assertFalse(k.fds)

    def test_unsupported_mapping_statx_magic_or_held_mount_refuses_before_ioctl(self):
        def wrong_row(k):
            k.mounts.update({n:k.mounts[n].replace(b"70 2 ",b"80 2 ") for n in (23,24)})
        for name, change in (
            ("wrong filesystem", lambda k: setattr(k,"fs_magic",0x01021994)),
            ("wrong device", lambda k: k.storage.update(device="8:3")),
            ("backing alias", lambda k: k.storage.update(backing_devices=["8:2"])),
            ("wrong mount ID", wrong_row),
            ("root owner", lambda k: k.changed.update({k.MAN+obs.ANCHOR: {"uid":7}})),
            ("bad mode", lambda k: k.changed.update({k.MAN+obs.ANCHOR: {"mode":stat.S_IFDIR|0o755}})),
            ("not held anchor", lambda k: k.renamed.update({k.MAN+obs.ANCHOR+"/.": {"ino":721}})),
        ):
            with self.subTest(name=name), ExitStack() as s:
                k = fixture(s)
                change(k)
                with self.assertRaises(ValueError):
                    acquire(uuid_storage=k.storage)
                k.io.assert_not_called()
                self.assertFalse(k.fds)

    def test_unsupported_short_zero_or_changed_kernel_reply_never_retries(self):
        for name, replies, count in (
            ("unsupported", [OSError(errno.ENOTTY,"not supported")],1),
            ("interrupted", [InterruptedError(errno.EINTR,"interrupted")],1),
            ("wrong length byte",[b"\x0f"+REPLY[1:]],1),
            ("short", [REPLY[:-1]],1),
            ("zero uuid", [b"\x10"+bytes(16)],1),
            ("mutable substitute", [bytearray(REPLY)],1),
            ("different last edge", [REPLY,REPLY[:16]+b"\x06"],2),
        ):
            with self.subTest(name=name), ExitStack() as s:
                k = fixture(s)
                k.io.side_effect = replies
                with self.assertRaises((ValueError,OSError)):
                    acquire(uuid_storage=k.storage)
                self.assertEqual(k.io.call_count,count)
                self.assertFalse(k.fds)

    def test_changed_named_anchor_mount_stream_or_deadline_after_ioctl_refuses(self):
        for name, change in (
            ("replaced named root", lambda k:k.renamed.update({k.MAN+obs.ANCHOR:{"ino":9999}})),
            ("changed observed mount", lambda k:k.mounts.update({23:k.mounts[23]+b"unexpected\n",24:k.mounts[24]+b"unexpected\n"})),
            ("late ioctl", lambda k:setattr(k,"now",14)),
        ):
            with self.subTest(name=name), ExitStack() as s:
                k = fixture(s)
                def change_on_read():
                    change(k)
                    return REPLY
                k.io.side_effect = change_on_read
                with self.assertRaises(ValueError):
                    acquire(uuid_storage=k.storage)
                k.io.assert_called_once()
                self.assertFalse(k.fds)
