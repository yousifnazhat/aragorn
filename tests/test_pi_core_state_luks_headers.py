"""Two synthetic public LUKS2 metadata areas; no actual block, sysfs, proc or provider I/O."""
from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
import hashlib
import json
import os
import stat
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import pi_core_state_luks_headers as h
from test_pi_core_state_mounts import sample_mountinfo


UUID = "ac1fc095-d8de-4ad8-9c6d-a8593cfb1fcc"
_MAGICS = [b"LUKS\xba\xbe", b"SKUL\xba\xbe"]
_BASENAME = "nvme7n1"


def _pin(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _media(uuid=UUID, *, n=16384, alg="sha256", edit=None):
    areas, sums = [], []
    for i in (0, 1):
        # Public synthetic bytes, not real tokens, credentials or a valid
        # semantic configuration. The bounded observer never interprets JSON.
        a = bytearray(n)
        a[0:6] = _MAGICS[i]
        struct.pack_into(">HQQ", a, 6, 2, n, 18)
        a[24:37] = b"private-label"
        a[72:72+len(alg)] = alg.encode()
        a[104:168] = bytes([103+i])*64
        a[168:204] = uuid.encode()
        struct.pack_into(">Q", a, 256, n*i)
        text = b'{"tokens":{"dummy":"private-token"}}'
        a[4096:4096+len(text)] = text
        if edit:
            edit(a, i)
        digest = hashlib.new(alg, a).digest()
        a[448:448+len(digest)] = digest
        areas.append(bytes(a))
        sums.append(digest.hex())
    return areas, sums


def _profile(areas, uuid=UUID):
    return dict(device_basename=_BASENAME, metadata_area_bytes=len(areas[0]), encryption_uuid=uuid,
                primary_sha256=_pin(areas[0]), secondary_sha256=_pin(areas[1]))


def _node(device):
    return dict(device=device, devtmpfs_device="0:51", mount_id=7, inode=883)


def _geometry(seq, n):
    return dict(diskseq_le=seq.to_bytes(8, "little").hex(), size_le=(2*n+4096).to_bytes(8, "little").hex())


def sample_headers(device="259:0", diskseq=19, encryption_uuid=UUID):
    """A fresh (protected profile, sanitized receipt) for offline joined-reader checks."""
    media, sums = _media(encryption_uuid)
    p, n = _profile(media, encryption_uuid), len(media[0])
    geo = _geometry(diskseq, n)
    r = dict(schema="aragorn/pi-core-inline-luks2-metadata/v1", profile_sha256=_pin(h.canonical_json(p)),
             node=_node(device), before=geo.copy(), after=geo.copy())
    for i, role in enumerate(("primary", "secondary")):
        r[role] = dict(magic_hex=_MAGICS[i].hex(), version=2, area_bytes=n, offset_bytes=i*n, seqid=18,
                       uuid=encryption_uuid, algorithm="sha256", self_checksum=sums[i], computed_checksum=sums[i],
                       metadata_region_sha256=_pin(media[i][4096:]), whole_area_sha256=_pin(media[i]))
    return p, r


class Fake:
    def __init__(self, media, seq=19):
        self.media, self.seq, self.n = media, seq, len(media[0])
        self.geometry = []
        self.reads = []
        self.return_short = None
        self.change = None
        self.held_bufs = []

    def ioctl(self, fd, cmd, arg):
        assert fd == 501 and cmd in (0x80081280, 0x80081272) and arg == bytes(8)
        value = self.seq if cmd == 0x80081280 else 2*self.n+4096
        self.geometry.append(cmd)
        if self.change:
            value = self.change(cmd, len(self.geometry), value)
        return value.to_bytes(8, "little")

    def read(self, fd, iov, off):
        assert fd == 501 and len(iov) == 1
        part = iov[0]
        start = off % self.n
        assert 0 <= off and off+len(part) <= 2*self.n and start+len(part) <= self.n
        self.reads.append((off, len(part)))
        part[:] = self.media[off//self.n][start:start+len(part)]
        self.held_bufs.append(part)
        return len(part) if off != self.return_short else len(part)-1

    def run(self, p, *, device="259:0", seq=19):
        with patch.object(h, "_disk", return_value=nullcontext((501, _node(device)))), \
             patch.object(h.kernel, "_check"), patch.object(h.fcntl, "ioctl", side_effect=self.ioctl), \
             patch.object(h.os, "preadv", create=True, side_effect=self.read):
            return h.capture_luks_headers(device, seq, p, deadline=77)


class HeaderChecks(unittest.TestCase):
    def test_exact_two_areas_no_keyslot_reads_and_no_private_material_in_receipt(self):
        p, expected = sample_headers()
        fake = Fake(_media()[0])
        result = fake.run(p)
        self.assertEqual(result, expected)
        self.assertEqual(fake.geometry, [0x80081280, 0x80081272]*2)
        self.assertEqual(fake.reads, [(0, 4096), (4096, 12288), (16384, 4096), (20480, 12288)])
        self.assertEqual(h.verify_luks_headers(result, expected_device="259:0", expected_diskseq=19, profile=p),
                         {"encryption_uuid": UUID, "metadata_area_bytes": 16384})
        self.assertTrue(all(not any(b) for b in fake.held_bufs))
        public = json.dumps(result)
        for s in ("private-token", "private-label", b"private-token".hex(), _BASENAME):
            self.assertNotIn(s, public)

    def test_protected_scope_is_exact_and_never_uses_header_values_as_authority(self):
        p, _ = sample_headers()
        for diff in ({"device_basename": "/dev/vda"}, {"device_basename": "."}, {"device_basename": ".."},
               {"device_basename": ".hidden"}, {"device_basename": "disk/by-uuid/x"}, {"device_basename": "vda\0"},
               {"device_basename": "x"*256}, {"metadata_area_bytes": True}, {"metadata_area_bytes": 8192},
               {"metadata_area_bytes": 49152}, {"metadata_area_bytes": 8<<20},
               {"primary_sha256": "0"*64}, {"secondary_sha256": p["primary_sha256"]},
               {"encryption_uuid": UUID.upper()}, {"allow_repair": True}):
            with self.subTest(fields=diff), patch.object(h, "_disk") as d, self.assertRaises(ValueError):
                try:
                    h.capture_luks_headers("259:0", 19, p | diff, deadline=7)
                finally:
                    d.assert_not_called()
        for s in (1<<14, 1<<18, 1<<22):
            self.assertEqual(h.validate_header_profile(p | {"metadata_area_bytes": s})["metadata_area_bytes"], s)

    def test_only_supported_checksum_families_and_full_padded_bytes(self):
        for alg in ("sha256", "sha384", "sha512"):
            media, _ = _media(n=1<<17, alg=alg)
            f = Fake(media)
            result = f.run(_profile(media))
            self.assertEqual(result["secondary"]["algorithm"], alg)
            self.assertEqual(result["primary"]["metadata_region_sha256"], _pin(media[0][4096:]))
            self.assertEqual(sum(n for _, n in f.reads), 2*len(media[0]))
        media, _ = _media(alg="sha1")
        f = Fake(media)
        with self.assertRaises(ValueError):
            f.run(_profile(media))
        self.assertEqual(f.reads, [(0, 4096)])

    def test_primary_corruption_or_mismatch_stops_before_secondary(self):
        for failure in ("bad checksum", "wrong pin", "truncated", "wrong uuid", "padding corruption",
                        "wrong size", "bad version", "offset", "empty salt", "zero generation", "wrong magic"):
            def edit(a, i):
                if i == 0:
                    if failure == "wrong size": struct.pack_into(">Q", a, 8, 1<<22)
                    if failure == "bad version": struct.pack_into(">H", a, 6, 1)
                    if failure == "offset": struct.pack_into(">Q", a, 256, 16384)
                    if failure == "zero generation": struct.pack_into(">Q", a, 16, 0)
                    if failure == "wrong magic": a[:6] = _MAGICS[1]
                    if failure == "empty salt": a[104:168] = bytes(64)
            media, _ = _media(edit=edit)
            if failure in ("bad checksum", "padding corruption"):
                m = bytearray(media[0])
                m[448 if failure == "bad checksum" else -1] ^= 1
                media[0] = bytes(m)
            p = _profile(media)
            if failure == "wrong pin": p["primary_sha256"] = _pin(b"different")
            if failure == "wrong uuid": p["encryption_uuid"] = "00000000-0000-4000-8000-000000000001"
            f = Fake(media)
            if failure == "truncated": f.return_short = 4096
            with self.subTest(failure=failure), self.assertRaises(ValueError) as error:
                f.run(p)
            self.assertTrue(all(off < 16384 for off, _ in f.reads))
            self.assertTrue(all(not any(b) for b in f.held_bufs))
            self.assertNotIn("private", str(error.exception))

    def test_redundant_metadata_disagreement_refused_even_if_both_individually_pinned(self):
        for offset, replacement in ((4096, b"X"), (23, b"\x13"), (24, b"x"), (104, b"g"*64),
                                    (0, _MAGICS[0]), (256, bytes(8))):
            def edited(a, i):
                if i:
                    a[offset:offset+len(replacement)] = replacement
            media, _ = _media(edit=edited)
            f = Fake(media)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                f.run(_profile(media))
            self.assertTrue(all(o+l <= 32768 for o,l in f.reads))

    def test_wrong_disk_before_reads_or_geometry_drift_after_reads_refused(self):
        for cmd, occurrence, bad in ((0x80081280, 1, 20), (0x80081272, 2, 2000), (0x80081272, 2, 32768),
                                    (0x80081280, 3, 20), (0x80081272, 4, 65536)):
            media, _ = _media()
            f = Fake(media)
            f.change = lambda c, i, v: bad if c == cmd and i == occurrence else v
            with self.subTest(cmd=cmd, occurrence=occurrence), self.assertRaises(ValueError):
                f.run(_profile(media))
            if occurrence <= 2: self.assertFalse(f.reads)

    def test_replay_binds_protected_profile_real_disk_incarnation_and_area_claims(self):
        p, r = sample_headers()
        for which, key, value in (("before", "diskseq_le", "12"*8), ("node", "device", "259:1"),
                ("node", "devtmpfs_device", "8:0"), ("after", "size_le", "ff"*8), ("primary", "offset_bytes", False),
                ("primary", "version", 3), ("secondary", "magic_hex", "00"*6), ("secondary", "seqid", 17),
                ("secondary", "uuid", "other"), ("secondary", "computed_checksum", "ab"*32),
                ("primary", "algorithm", "md5"), ("primary", "metadata_region_sha256", _pin(b"wrong")),
                ("secondary", "whole_area_sha256", p["primary_sha256"]), ("primary", "raw_json", "{}")):
            changed = deepcopy(r)
            changed[which][key] = value
            with self.subTest(where=(which,key)), self.assertRaises(ValueError):
                h.verify_luks_headers(changed,expected_device="259:0",expected_diskseq=19,profile=p)
        for params in ({"expected_diskseq":0}, {"expected_diskseq":20}, {"expected_device":"259:1"},
                       {"profile":p|{"device_basename":"other"}}):
            args = {"expected_device":"259:0","expected_diskseq":19,"profile":p} | params
            with self.assertRaises(ValueError): h.verify_luks_headers(r,**args)

    def test_protected_parent_pinned_readonly_block_inode_and_final_recapture(self):
        rows = sample_mountinfo("manager", device="253:7") + b"7 1 0:51 / /dev rw - devtmpfs devtmpfs rw\n"
        meta = {k:dict(uid=0, gid=6 if k=="node" else 0, mnt_id=1 if k=="root" else 7,
                 dev="7:0" if k=="root" else "0:51", rdev="259:0" if k=="node" else "0:0",
                 ino=883 if k=="node" else 35,mode=stat.S_IFBLK|0o660 if k=="node" else stat.S_IFDIR|0o755)
                for k in ("root","dev","node")}
        for issue in ("none","symlink","wrong rdev","wrong owner","world writable","parent writable",
                      "bind node","fake fs","already mounted","hard link","reopened other","late rename"):
            with self.subTest(issue=issue), ExitStack() as st:
                def fake(name, **kwargs): return st.enter_context(patch.object(h.kernel,name,**kwargs))
                m = deepcopy(meta)
                if issue=="symlink": m["node"]["mode"] = stat.S_IFLNK|0o777
                if issue=="wrong rdev": m["node"]["rdev"]="259:1"
                if issue=="wrong owner": m["node"]["uid"]=444
                if issue=="world writable": m["node"]["mode"] |= 2
                if issue=="parent writable": m["dev"]["mode"] |= 0o020
                raw=rows
                if issue=="bind node":raw+=b"8 7 0:51 /other /dev/nvme7n1 rw - devtmpfs devtmpfs rw\n"
                if issue=="already mounted":raw+=b"8 1 259:0 / /somewhere rw - ext4 /dev/nvme7n1 rw\n"
                fake("_platform"); fake("_check"); fake("_proc",return_value=(10,1))
                fake("_role",side_effect=lambda st,parent,pid,pm:(pid,11)); fake("_proc_child",return_value=12)
                fake("_frame",return_value=(None,{"uid":0},21,{})); fake("_read",return_value=raw)
                fake("_filesystem",return_value=0x9fa0 if issue=="fake fs" else 0x01021994)
                def pin(st, parent, name, directory=False):
                    return {(21,"dev",True):22,(22,_BASENAME,False):23}[parent,name,directory]
                fake("_pin",side_effect=pin)
                def stats(fd, *, owner):
                    k={21:"root",22:"dev",23:"node",501:"node"}[fd]
                    return m[k].copy()|({"ino": 337} if issue=="reopened other" and fd==501 else {})
                fake("_stat",side_effect=stats)
                magic=fake("_magic",return_value=501)
                st.enter_context(patch.object(h.os,"fstat",return_value=SimpleNamespace(st_nlink=2 if issue=="hard link" else 1)))
                st.enter_context(patch.object(h.os,"getpid",return_value=5))
                st.enter_context(patch.object(h.threading,"get_native_id",return_value=6))
                verdict=nullcontext() if issue=="none" else self.assertRaises(ValueError)
                with verdict, h._disk("259:0",_BASENAME,7) as (fd,node):
                    self.assertIn(issue,("none","late rename"))
                    self.assertEqual((fd,node),(501,_node("259:0")))
                    if issue=="late rename": m["node"]["ino"]+=1
                if magic.called:
                    self.assertEqual(magic.call_args.args[1:],(12,"23",os.O_RDONLY|os.O_NONBLOCK|os.O_NOCTTY,1))

    def test_authority_deadline_and_path_close_cannot_be_swallowed(self):
        p, _ = sample_headers()
        # No actual disk is resolved even when invoking the public interface.
        with patch.object(h,"_disk",return_value=nullcontext((5,_node("259:0")))), \
             patch.object(h.kernel,"_check",side_effect=ValueError("deadline")), \
             patch.object(h.fcntl,"ioctl") as ioctl, self.assertRaisesRegex(ValueError,"deadline"):
            h.capture_luks_headers("259:0",19,p,deadline=0)
        ioctl.assert_not_called()
        @contextmanager
        def lost(*_):
            yield 501,_node("259:0")
            raise OSError(5,"private-path","private-path")
        f=Fake(_media()[0])
        with patch.object(h,"_disk",lost),patch.object(h.kernel,"_check"), \
             patch.object(h.fcntl,"ioctl",side_effect=f.ioctl),patch.object(h.os,"preadv",create=True,side_effect=f.read), \
             self.assertRaises(OSError) as caught:
            h.capture_luks_headers("259:0",19,p,deadline=99)
        self.assertNotIn("private",str(caught.exception))
