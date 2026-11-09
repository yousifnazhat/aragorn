"""New metadata-custody checks; every filesystem edge is simulated."""

from contextlib import ExitStack
from pathlib import Path
import socket
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_provider_credential as subject


def metadata(inode, mode, *, size=0, uid=0, gid=0, links=1):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_nlink=links,
        st_uid=uid, st_gid=gid, st_size=size, st_mtime_ns=10, st_ctime_ns=20)


class PublicInputs:
    def __init__(self):
        self.guard = mock.Mock()


class CredentialCustodyTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.path = Path("/etc/aragorn-keys/openai")
        self.inputs = PublicInputs()
        self.values = {fd: metadata(fd, stat.S_IFDIR | 0o755) for fd in (10, 11, 12)}
        self.values[13] = metadata(13, stat.S_IFREG | 0o400, size=24)
        self.named = {("/", None): 10, ("etc", 10): 11, ("aragorn-keys", 11): 12, ("openai", 12): 13}
        self.stack.enter_context(mock.patch.object(subject.configuration, "PiProviderInputs", PublicInputs))
        self.stack.enter_context(mock.patch.object(subject.provision.sys, "platform", "linux"))
        for name, value in (("geteuid", 0), ("getegid", 0), ("getpid", 800)):
            setattr(self, name, self.stack.enter_context(mock.patch.object(subject.os, name, return_value=value)))
        self.now = self.stack.enter_context(mock.patch.object(subject.provision.time, "monotonic", return_value=100))
        self.open = self.stack.enter_context(mock.patch.object(subject.os, "open", side_effect=self.open_file))
        self.close = self.stack.enter_context(mock.patch.object(subject.os, "close"))
        self.stack.enter_context(mock.patch.object(subject.os, "fstat", side_effect=lambda fd: self.values[fd]))
        self.stack.enter_context(mock.patch.object(subject.os, "stat", side_effect=self.stat_file))
        self.stack.enter_context(mock.patch.object(subject.os, "lstat", side_effect=lambda path: self.values[10]))
        self.inheritable = self.stack.enter_context(mock.patch.object(subject.os, "get_inheritable", return_value=False))
        for owner, name in ((subject.os, "read"), (subject.os, "write"), (subject.os, "fchmod"),
                            (subject.os, "fchown"), (subject.os, "unlink"), (subject.os, "system"),
                            (socket, "socket"), (socket, "socketpair"), (socket, "getaddrinfo"),
                            (subprocess, "run"), (subprocess, "Popen")):
            self.stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("credential bytes and live operations are forbidden")))

    def open_file(self, path, flags, *, dir_fd=None):
        return self.named[(path, dir_fd)]

    def stat_file(self, path, *, dir_fd=None, follow_symlinks=True):
        self.assertFalse(follow_symlinks)
        return self.values[self.named[(path, dir_fd)]]

    def hold(self, **changes):
        options = dict(source=self.path, provider_inputs=self.inputs, deadline=120)
        options.update(changes)
        return subject.hold_provider_credential(**options)

    def test_source_is_descriptor_pinned_without_reading_or_hashing(self):
        with self.hold() as held:
            self.assertIs(type(held), subject.PiProviderCredential)
            self.assertIs(held.provider_inputs, self.inputs)
            self.assertEqual(held.source, "/proc/800/fd/13")
            self.assertEqual(held.deadline, 120)
            self.assertNotIn("openai", str(held.observation))
            self.assertFalse(held.observation["credential_read"])
        self.assertEqual(self.close.call_args_list, [mock.call(13), mock.call(12), mock.call(11), mock.call(10)])
        self.inputs.guard.assert_called_with(deadline=120)

    def test_open_flags_are_readonly_nonblocking_nofollow_and_noninheritable(self):
        with self.hold():
            self.assertEqual(self.open.call_args, mock.call("openai", subject._FILE, dir_fd=12))
            for call in self.open.call_args_list:
                flags = call.args[1]
                self.assertTrue(flags & subject.os.O_NOFOLLOW)
                self.assertTrue(flags & subject.os.O_CLOEXEC)
                self.assertFalse(flags & (subject.os.O_WRONLY | subject.os.O_RDWR | subject.os.O_CREAT))
            self.assertTrue(subject._FILE & subject.os.O_NONBLOCK)

    def test_unsafe_source_paths_refuse_before_filesystem_open(self):
        for path in (Path("relative"), Path("/"), Path("/etc/../key"), Path("/proc/self/fd/4"),
                     Path("/proc/800/fd/4"), Path("/dev/key"), Path("/sys/key"), Path("/etc/key:bad"),
                     Path("/etc/key name"), Path("//etc/key"), Path("/etc/.hidden")):
            with self.subTest(path=path), self.assertRaises(subject.PiProviderCredentialError):
                with self.hold(source=path): pass
        self.open.assert_not_called()

    def test_exact_public_input_holder_required(self):
        with self.assertRaises(subject.PiProviderCredentialError):
            with self.hold(provider_inputs=SimpleNamespace(guard=mock.Mock())): pass
        self.open.assert_not_called()

    def test_public_input_guard_failure_precedes_source_open(self):
        self.inputs.guard.side_effect = RuntimeError("public custody failed")
        with self.assertRaisesRegex(RuntimeError, "public custody"):
            with self.hold(): pass
        self.open.assert_not_called()

    def test_root_linux_requirement_is_not_bypassed(self):
        self.geteuid.return_value = 1000
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.hold(): pass
        self.open.assert_not_called()

    def test_invalid_deadline_refuses_before_open(self):
        for deadline in (True, float("nan"), float("inf"), 100, 701):
            with self.subTest(deadline=deadline), self.assertRaises(subject.provision.PiOsProvisionError):
                with self.hold(deadline=deadline): pass
        self.open.assert_not_called()

    def test_parent_metadata_must_remain_root_protected(self):
        for field, value in (("st_uid", 1000), ("st_gid", 1000), ("st_mode", stat.S_IFDIR | 0o777),
                             ("st_mode", stat.S_IFLNK | 0o755)):
            original = getattr(self.values[11], field)
            setattr(self.values[11], field, value)
            with self.subTest(field=field, value=value), self.assertRaises(subject.provision.PiOsProvisionError):
                with self.hold(): pass
            setattr(self.values[11], field, original)

    def test_source_metadata_rejects_unsafe_mode_type_owner_size_and_links(self):
        for field, value in (("st_uid", 1000), ("st_gid", 1000), ("st_mode", stat.S_IFREG | 0o440),
                             ("st_mode", stat.S_IFREG | 0o600), ("st_mode", stat.S_IFIFO | 0o400),
                             ("st_mode", stat.S_IFLNK | 0o400), ("st_size", 0), ("st_size", 4097), ("st_nlink", 2)):
            original = getattr(self.values[13], field)
            setattr(self.values[13], field, value)
            with self.subTest(field=field, value=value), self.assertRaises(subject.PiProviderCredentialError):
                with self.hold(): pass
            setattr(self.values[13], field, original)

    def test_inheritable_descriptor_is_rejected(self):
        self.inheritable.return_value = True
        with self.assertRaises(subject.PiProviderCredentialError):
            with self.hold(): pass

    def test_changed_source_metadata_is_detected(self):
        for field in ("st_ino", "st_mtime_ns", "st_ctime_ns", "st_size"):
            with self.subTest(field=field), self.assertRaisesRegex(subject.PiProviderCredentialError, "source changed"):
                with self.hold() as held:
                    setattr(self.values[13], field, getattr(self.values[13], field) + 1)
                    held.guard()

    def test_named_source_substitution_is_detected(self):
        with self.assertRaisesRegex(subject.PiProviderCredentialError, "source changed"):
            with self.hold() as held:
                self.values[14] = metadata(14, stat.S_IFREG | 0o400, size=24)
                self.named[("openai", 12)] = 14
                held.guard()

    def test_parent_substitution_is_detected(self):
        with self.assertRaisesRegex(subject.provision.PiOsProvisionError, "ancestor custody"):
            with self.hold() as held:
                self.values[14] = metadata(14, stat.S_IFDIR | 0o755)
                self.named[("aragorn-keys", 11)] = 14
                held.guard()

    def test_owner_process_cannot_change(self):
        with self.assertRaisesRegex(subject.PiProviderCredentialError, "owner process"):
            with self.hold() as held:
                self.getpid.return_value = 801
                held.guard()

    def test_guard_is_bounded_but_cleanup_keeps_original_lease(self):
        with self.hold() as held:
            held.guard(deadline=110)
            self.assertEqual(held.deadline, 120)
            held.guard(deadline=120)
            with self.assertRaisesRegex(subject.PiProviderCredentialError, "extend"):
                held.guard(deadline=121)

    def test_closed_holder_refuses_and_borrowed_inputs_are_not_closed(self):
        with self.hold() as held: pass
        with self.assertRaisesRegex(subject.PiProviderCredentialError, "inactive"):
            held.guard()
        self.assertNotIn("close", vars(self.inputs))

    def test_partial_open_failure_closes_only_owned_descriptors(self):
        self.open.side_effect = lambda path, flags, **kw: (_ for _ in ()).throw(OSError("open refused")) \
            if path == "openai" else self.open_file(path, flags, **kw)
        with self.assertRaisesRegex(OSError, "open refused"):
            with self.hold(): pass
        self.assertEqual(self.close.call_args_list, [mock.call(12), mock.call(11), mock.call(10)])

    def test_body_failure_closes_once_without_deleting_source(self):
        with self.assertRaisesRegex(RuntimeError, "body failed"):
            with self.hold():
                raise RuntimeError("body failed")
        self.assertEqual(self.close.call_count, 4)

    def test_direct_or_forged_holder_refuses(self):
        with self.assertRaisesRegex(subject.PiProviderCredentialError, "factory"):
            subject.PiProviderCredential(object(), self.path, [10, 11, 12], 13, self.inputs, 120)
        forged = object.__new__(subject.PiProviderCredential)
        with self.assertRaisesRegex(subject.PiProviderCredentialError, "inactive"):
            forged.guard()
