"""In-memory archive checks of the split layout. No extraction, mount, process or VM."""
import io
from pathlib import PurePosixPath
import tarfile
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_split_worker_payload as split
from scripts.build_pi_core_linux import BuildError


def row(path, data, executable):
    return dict(path=path, size=len(data), digest="sha256:" + split.sha256(data), executable=executable)


class SplitWorker(unittest.TestCase):
    def setUp(self):
        dirs = set(split.launch._EMPTY_MOUNTPOINTS) | {"usr/bin"}
        dirs |= {str(p) for d in dirs for p in PurePosixPath(d).parents if str(p) != "."}
        self.os = dict(directories=sorted(dirs), files=[row("usr/bin/env", b"env", True)])
        self.runtime = dict(files=[row("pi-core/package.json", b"{}", False)])
        self.dirs = dirs | {split.MOUNT + "/" + d for d in split.view.RUNTIME_DIRS}
        self.payload = {"usr/bin/env": (b"env", 0o555), split.MOUNT + "/pi-core/package.json": (b"{}", 0o444)}

    def archive(self, change=None):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:", format=tarfile.USTAR_FORMAT) as tar:
            for info, data in split.b53._entries(dict.fromkeys(self.dirs, 0o555), self.payload):
                if change and info.name == "usr/bin/env":
                    if change == "missing":
                        continue
                    if change == "uid":
                        info.uid = 17
                    if change == "hardlink":
                        info.type, info.linkname, info.size = tarfile.LNKTYPE, "elsewhere", 0
                tar.addfile(info, io.BytesIO(data) if info.isfile() else None)
        return buf.getvalue()

    def test_separate_0755_outer_roots_with_immutable_descendants_and_empty_bind_target(self):
        raw = self.archive()
        m, files = split._split(raw, split.sha256(raw), self.os, self.runtime)
        meta = {r["path"]: r for r in m["entries"]}
        for root in (split.OS_ROOT, split.RUNTIME_ROOT):
            self.assertEqual(meta[root], dict(type="dir", path=root, uid=0, gid=0, mode=0o755))
        mount = split.OS_ROOT + "/" + split.MOUNT
        self.assertEqual(meta[mount]["mode"], 0o555)
        self.assertFalse(any(n.startswith(mount + "/") for n in meta))
        self.assertEqual(files, {split.OS_ROOT + "/usr/bin/env": b"env", split.RUNTIME_ROOT + "/pi-core/package.json": b"{}"})
        self.assertEqual(meta[split.RUNTIME_ROOT + "/pi-core/package.json"]["mode"], 0o444)

    def test_wrong_archive_identity_tampered_bytes_or_metadata_never_yield_a_projection(self):
        raw = self.archive()
        with self.assertRaisesRegex(BuildError, "archive differs"):
            split._split(raw, "0" * 64, self.os, self.runtime)
        for change in ("uid", "hardlink", "missing"):
            raw = self.archive(change)
            with self.subTest(change=change), self.assertRaises(BuildError):
                split._split(raw, split.sha256(raw), self.os, self.runtime)
        self.payload["usr/bin/env"] = (b"xyz", 0o555)
        raw = self.archive()
        with self.assertRaisesRegex(BuildError, "file digest differs"):
            split._split(raw, split.sha256(raw), self.os, self.runtime)

    def test_populated_os_mountpoint_is_not_silently_moved_into_runtime(self):
        self.os["directories"].append(split.MOUNT + "/unapproved")
        raw = self.archive()
        with self.assertRaisesRegex(split.launch.PiConfinedLaunchError, "empty fixed mountpoint"):
            split._split(raw, split.sha256(raw), self.os, self.runtime)

    def test_stale_host_or_plan_refuses_before_reading_worker_inputs(self):
        with patch.object(split.view.worker, "_document") as inputs, self.assertRaisesRegex(BuildError, "B63 host or worker plan"):
            split.prepare(b"stale host", b"stale plan")
        inputs.assert_not_called()
