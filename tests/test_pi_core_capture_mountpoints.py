import unittest

from scripts import pi_core_capture_mountpoints as layout
from scripts.build_pi_core_linux import BuildError


class CaptureTargets(unittest.TestCase):
    def setUp(self):
        self.entries = [dict(type="dir", path=p, mode=m, uid=0, gid=0) for p, m in
                        (layout.MOUNTPOINTS | dict.fromkeys(layout.WORKER_ROOTS, 0o755)
                         | {"/var/lib/aragorn": 0o755}).items()]
        self.original = [dict(type="D", path=p, mode=0o755, uid=0, gid=0, xattrs=[])
                         for p in ("/", "/var", "/var/lib", "/etc", "/etc/aragorn")]

    def test_no_buried_base_file_symlink_or_shared_ancestor(self):
        layout._check(self.entries, self.original)
        for extra in (dict(path="/var/lib/aragorn-runtime-action/old"),
                      dict(path="/etc/aragorn/approvals"), dict(self.original[0], type="S", path="/var/lib/aragorn"),
                      dict(self.original[0], mode=0o777, path="/var/lib/aragorn")):
            with self.subTest(extra=extra), self.assertRaises(BuildError):
                layout._check(self.entries, [*self.original, extra])

    def test_no_preloaded_approval_or_incorrect_worker_root_modes(self):
        with self.assertRaises(BuildError):
            layout._check([*self.entries, dict(path="/etc/aragorn/approvals/release.json")], self.original)
        with self.assertRaises(BuildError):
            layout._check([dict(row, mode=0o555) if row["path"] == layout.WORKER_ROOTS[0] else row
                           for row in self.entries], self.original)
        with self.assertRaises(BuildError):
            layout._check([row for row in self.entries if row["path"] != "/var/lib/aragorn/admitted"],
                          self.original)
