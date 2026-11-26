"""Offline common-root package and channel ownership checks; no endpoints are opened."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock
import os
import socket
import json
import subprocess
from io import BytesIO
from time import monotonic

from aragorn import pi_core_task_guest_channels as channels
from scripts import prepare_pi_core_task_guest_payload as package


class CommonTaskGuestTests(TestCase):
    def test_private_endpoints_are_not_projected_into_pi(self):
        visible = {p for p, _, _ in channels.ENDPOINTS if p.startswith("aragorn-pi-task-view/")}
        self.assertEqual(visible, {"aragorn-pi-task-view/tasks/" + n for n in ("control.sock","service.sock")})
        self.assertEqual(dict((p,(k,r)) for p,k,r in channels.ENDPOINTS if p not in visible), {
            "aragorn-pi-task-owner/handoff.sock":(socket.SOCK_SEQPACKET,"service"),
            "aragorn-pi-task-owner/witness.sock":(socket.SOCK_STREAM,"service")})
        with mock.patch.object(channels.socket, "socket", side_effect=AssertionError("no live listener")):
            for gids in ((0,17),(17,17),(True,18)):
                with self.subTest(gids=gids), self.assertRaises(ValueError):
                    channels.require_groups(*gids)

    def test_ownership_safe_cleanup_does_not_remove_a_replacement(self):
        with TemporaryDirectory() as t:
            parent = Path(t)
            original = parent / "owned"
            original.mkdir()
            expected = channels.node_id(original.lstat())
            original.rename(parent / "held")
            original.mkdir()
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(ValueError):
                    channels.remove_owned(fd, "owned", expected, directory=True)
            finally:
                os.close(fd)
            self.assertTrue(original.is_dir() and (parent / "held").is_dir())

    def test_absent_owner_guard_refuses_before_opening_guest_run(self):
        with mock.patch.object(channels.sys, "platform", "linux"), mock.patch.object(channels.os,"geteuid",return_value=0), \
                mock.patch.object(channels.os,"getegid",return_value=0), mock.patch.object(channels.os,"open") as opening:
            with self.assertRaisesRegex(ValueError,"owner prerequisite"):
                with channels.hold_task_namespace(deadline=monotonic()+2,guard=lambda: False):
                    self.fail("unauthorized root setup")
        opening.assert_not_called()

    def test_predecessor_collision_and_unapproved_delta_refuse(self):
        parent = dict(path="/etc", type="dir", mode=0o755, uid=0, gid=0)
        old = dict(schema="aragorn/pi-core-immutable-payload/v1", entries=[parent])
        with self.assertRaises(ValueError):
            package.compose(old, {"/etc": b"must not replace"})
        with self.assertRaises(ValueError):
            package.compose(old, {"/etc/systemd/system/multi-user.target.wants/foreign": b"auto-enable"})

    def test_physical_successor_matches_signed_package_and_does_not_shadow_stock_units(self):
        # B112 was the exact B41 stock inventory plus B111. Look up only the new
        # paths/units here; no need to re-decode unchanged disk or launch a guest.
        catalog = package.readback()
        base = package.split._index(package._base()["entries"])
        raw = package.split.image.read(package.OUT/"payload.json", catalog["payload_sha256"], 2 << 20)
        current = package.split._index(json.loads(raw)["entries"])
        delta = current.keys() - base.keys()
        retained = Path(subprocess.check_output(["git","rev-parse","--path-format=absolute","--git-common-dir"],
                                               cwd=package.ROOT,text=True,timeout=5).strip()).parent
        stock = retained / ".aragorn/host-preflight/build-b41/image/59122196cb507ab4182468b525cde753482c3429407ca457585fed6c832af806/inventory.jsonl"
        original = package.split.image.read(stock, "421801ead2c04324f04ab7c7d4d0d7e8f093cfc7fedf82b96d769558e6bf1208", 64 << 20)
        for line in BytesIO(original):
            row = json.loads(line)
            name = row["path"]
            if name in delta:
                # An existing stock directory may be listed as an ancestor. Its identity must not change.
                self.assertEqual((row["type"],row["mode"],row["uid"],row["gid"],row["xattrs"]),
                                 ("D",current[name]["mode"],0,0,[]), name)
                self.assertEqual(current[name]["type"],"dir",name)
            if "/systemd/" in name:
                self.assertNotIn(Path(name).name, (Path(package.UNIT).name,Path(package.PI_UNIT).name))
        for path, key in ((package.UNIT,"unit_digest"),(package.WRAPPER,"wrapper_digest"),(package.PYTHON,"interpreter_digest")):
            self.assertEqual("sha256:"+current[path]["sha256"],catalog["service_code"][key])
        self.assertTrue({package.UNIT,package.PI_UNIT,package.WRAPPER} <= delta)
        self.assertTrue(all(not name.startswith("/run/") and ".wants/" not in name for name in delta))
        with self.assertRaisesRegex(ValueError,"no overwrite"):
            package.prepare()
