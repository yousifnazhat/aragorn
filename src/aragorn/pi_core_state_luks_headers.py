"""Read only nominated inline LUKS2 metadata extents. No activation or recovery.

The public receipt compares the authenticated observer's digests with external
commitments. It cannot independently rehash withheld bytes or prove which
header was used for unlock. A synchronous block read needs an external watchdog.
On the approved layout the requested extents exclude binary keyslots. The
reader cannot determine what hostile media actually stores within those bounds.
"""
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import os
import re
import stat
import struct
import threading

from . import pi_core_stopped_mask_view as kernel
from .oci_worker_protocol import canonical_json
from .pi_core_state_admission import _dev, _keys, _need, _pin, _uint, _uuid
from .pi_core_state_mounts import direct_mount_inventory


SCHEMA = "aragorn/pi-core-inline-luks2-metadata/v1"
_DIGEST = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
_MAGIC = (b"LUKS\xba\xbe", b"SKUL\xba\xbe")
_BIN, _CHUNK = 4096, 65536
_SEQ, _SIZE = 0x80081280, 0x80081272  # ARM64 linux/fs.h BLKGETDISKSEQ, BLKGETSIZE64.


def validate_header_profile(p):
    _keys(p, ("device_basename", "metadata_area_bytes", "encryption_uuid", "primary_sha256", "secondary_sha256"))
    _need(type(p["device_basename"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,254}", p["device_basename"]),
          "expected single protected devtmpfs basename")
    n = _uint(p["metadata_area_bytes"], 16384, (4 << 20) + 1)
    _need(n & (n-1) == 0, "invalid LUKS2 metadata area size")
    _uuid(p["encryption_uuid"])
    _need(_pin(p["primary_sha256"]) != _pin(p["secondary_sha256"]), "distinct whole-area commitments required")
    return p.copy()


def _sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _replay_area(r, i, p):
    _keys(r, ("magic_hex", "version", "area_bytes", "offset_bytes", "seqid", "uuid", "algorithm", "self_checksum",
              "computed_checksum", "metadata_region_sha256", "whole_area_sha256"))
    n = p["metadata_area_bytes"]
    _need(r["magic_hex"] == _MAGIC[i].hex() and type(r["version"]) is int and r["version"] == 2
          and type(r["area_bytes"]) is int and r["area_bytes"] == n and type(r["offset_bytes"]) is int and
          r["offset_bytes"] == i*n and r["uuid"] == p["encryption_uuid"], "wrong LUKS2 identity or area")
    _uint(r["seqid"])
    alg = r["algorithm"]
    _need(type(alg) is str and alg in _DIGEST, "unreviewed metadata checksum")
    _need(type(r["self_checksum"]) is str and len(r["self_checksum"]) == 2*_DIGEST[alg]().digest_size
          and re.fullmatch("[0-9a-f]+", r["self_checksum"]) and r["self_checksum"] == r["computed_checksum"],
          "metadata self-checksum differs")
    _pin(r["metadata_region_sha256"])
    _need(r["whole_area_sha256"] == p[("primary_sha256", "secondary_sha256")[i]], "whole-area commitment differs")


def _geometry_raw(r, sequence, n):
    _keys(r, ("diskseq_le", "size_le"))
    _need(all(type(v) is str and re.fullmatch("[0-9a-f]{16}", v) for v in r.values()), "invalid geometry reply")
    seq, size = (int.from_bytes(bytes.fromhex(r[k]), "little") for k in ("diskseq_le", "size_le"))
    _need(seq == sequence and size > 2*n and size % 512 == 0, "different disk incarnation or unusable size")


def verify_luks_headers(record, *, expected_device, expected_diskseq, profile):
    """Replay only approved public observations. No filesystem, storage or key access."""
    p, device, seq = validate_header_profile(profile), _dev(expected_device), _uint(expected_diskseq)
    _keys(record, ("schema", "profile_sha256", "node", "before", "after", "primary", "secondary"))
    _need(record["schema"] == SCHEMA and record["profile_sha256"] == _sha(canonical_json(p)),
          "unexpected header measurement or authority")
    node = record["node"]
    _keys(node, ("device", "devtmpfs_device", "mount_id", "inode"))
    _need(node["device"] == device and type(node["devtmpfs_device"]) is str and
          re.fullmatch(r"0:[1-9][0-9]{0,6}", node["devtmpfs_device"]) and int(node["devtmpfs_device"][2:]) < 1 << 20,
          "invalid observed backing node")
    _uint(node["mount_id"], high=1 << 32)
    _uint(node["inode"])
    for edge in ("before", "after"):
        _geometry_raw(record[edge], seq, p["metadata_area_bytes"])
    _need(record["before"] == record["after"], "changed disk geometry")
    for i, role in enumerate(("primary", "secondary")):
        _replay_area(record[role], i, p)
    _need(all(record["primary"][k] == record["secondary"][k] for k in
              ("algorithm", "seqid", "metadata_region_sha256")), "inconsistent redundant metadata")
    return {"encryption_uuid": record["primary"]["uuid"], "metadata_area_bytes": record["primary"]["area_bytes"]}


def _read_into(fd, data, offset, deadline):
    kernel._check(deadline)
    _need(os.preadv(fd, [data], offset) == len(data), "incomplete bounded metadata read")
    kernel._check(deadline)


def _area(fd, index, p, deadline):
    # Upstream cryptsetup v2.8.4: lib/luks2/luks2.h::luks2_hdr_disk and
    # luks2_disk_metadata.c::hdr_checksum_check. All format integers are BE.
    n, pos = p["metadata_area_bytes"], index*p["metadata_area_bytes"]
    header = bytearray(_BIN)
    chunk = bytearray(min(n - _BIN, _CHUNK))
    try:
        _read_into(fd, header, pos, deadline)
        version, extent, seqid = struct.unpack_from(">HQQ", header, 6)
        offset, = struct.unpack_from(">Q", header, 256)
        _need(header[:6] == _MAGIC[index] and version == 2 and extent == n and offset == pos and seqid > 0,
              "bad fixed header identity, extent, offset or sequence")
        _need(header[168:208] == p["encryption_uuid"].encode("ascii") + bytes(4), "unexpected on-disk UUID")
        observed_uuid = header[168:204].decode("ascii")  # only after full-width equality; never echo unchecked bytes
        alg = next((s for s in _DIGEST if header[72:104] == s.encode().ljust(32, b"\0")), None)
        _need(alg is not None, "unreviewed metadata checksum")
        calc, json_region, whole = _DIGEST[alg](), hashlib.sha256(), hashlib.sha256(header)
        saved = header[448:448+calc.digest_size].hex()
        _need(not any(header[448+calc.digest_size:512]), "unexpected checksum padding")
        # Compare label/subsystem and distinct per-offset salts in memory;
        # neither identifiers nor salt (or their digests) leave this reader.
        private_fields = (_sha(header[24:72] + header[208:256]), _sha(header[104:168]))
        _need(any(header[104:168]), "missing per-header salt")
        header[448:512] = bytes(64)
        calc.update(header)
        for off in range(_BIN, n, _CHUNK):
            part = memoryview(chunk)[:min(_CHUNK, n-off)]
            _read_into(fd, part, pos+off, deadline)
            calc.update(part)
            whole.update(part)
            json_region.update(part)  # opaque, including padding; no JSON decode or token inspection
        result = dict(magic_hex=header[:6].hex(), version=version, area_bytes=extent, offset_bytes=offset,
                      seqid=seqid, uuid=observed_uuid, algorithm=alg, self_checksum=saved,
                      computed_checksum=calc.hexdigest(), metadata_region_sha256="sha256:"+json_region.hexdigest(),
                      whole_area_sha256="sha256:"+whole.hexdigest())
        _replay_area(result, index, p)
        return result, private_fields
    finally:
        header[:] = bytes(len(header))
        chunk[:] = bytes(len(chunk))


def _geometry(fd, seq, n, deadline):
    values = {}
    for key, cmd in (("diskseq_le", _SEQ), ("size_le", _SIZE)):
        kernel._check(deadline)
        raw = fcntl.ioctl(fd, cmd, bytes(8))
        _need(type(raw) is bytes and len(raw) == 8, "incomplete block geometry")
        values[key] = raw.hex()
    _geometry_raw(values, seq, n)
    kernel._check(deadline)
    return values


@contextmanager
def _disk(device, name, deadline):
    kernel._platform()
    kernel._check(deadline)
    with ExitStack() as held:
        proc, pm = kernel._proc(held)
        leader = kernel._role(held, proc, os.getpid(), pm)
        task = kernel._proc_child(held, leader[1], "task", os.O_RDONLY | os.O_DIRECTORY, pm)
        caller = kernel._role(held, task, threading.get_native_id(), pm)

        def frame(stack):
            _, manager, _, _ = kernel._frame(stack, leader, pm, deadline, kind="manager")
            _, thread, root, _ = kernel._frame(stack, caller, pm, deadline, kind="caller")
            _need(all(manager[k] == v for k, v in thread.items() if k not in ("pid", "start_ticks")),
                  "caller and manager containment differ")
            raw = kernel._read(caller[1], "mountinfo", 1 << 20, pm, deadline)
            _need(raw == kernel._read(leader[1], "mountinfo", 1 << 20, pm, deadline), "manager and caller mounts differ")
            rows = direct_mount_inventory(raw)
            parent, row = rows["/"], rows.get("/dev")
            _need(row is not None and row.filesystem == b"devtmpfs" and row.root == "/" and row.parent == parent.mount_id
                  and "/dev/"+name not in rows and all(v.device != device for v in rows.values()),
                  "expected direct devtmpfs and unmounted backing device")
            dev = kernel._pin(stack, root, "dev", directory=True)
            node = kernel._pin(stack, dev, name)
            a, b, c = (kernel._stat(v, owner=True) for v in (root, dev, node))
            for s, m in ((a, parent), (b, row)):
                _need((s["mnt_id"], s["dev"]) == (m.mount_id, m.device) and
                      stat.S_ISDIR(s["mode"]) and not s["mode"] & 0o022 and s["uid"] == s["gid"] == 0,
                      "untrusted device parent")
            _need(kernel._filesystem(dev) in (kernel._TMPFS, 0x858458f6) and stat.S_ISBLK(c["mode"]) and
                  c["uid"] == 0 and not c["mode"] & 0o002 and c["rdev"] == device and
                  (c["mnt_id"], c["dev"]) == (row.mount_id, row.device), "untrusted backing node")
            return (manager, thread, raw, a, b, c), node

        ctx, node = frame(held)
        fds = kernel._proc_child(held, caller[1], "fd", os.O_RDONLY | os.O_DIRECTORY, pm)
        fd = kernel._magic(held, fds, str(node), os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY, pm)
        opened = kernel._stat(fd, owner=True)
        _need(opened == ctx[-1] and os.fstat(fd).st_nlink == 1, "wrong reopened node or hard-link alias")
        yield fd, dict(device=opened["rdev"], devtmpfs_device=opened["dev"], mount_id=opened["mnt_id"],
                       inode=opened["ino"])
        with ExitStack() as last:
            _need(ctx == frame(last)[0] and kernel._stat(fd, owner=True) == opened and os.fstat(fd).st_nlink == 1,
                  "backing device or manager view changed")
        kernel._check(deadline)


def capture_luks_headers(expected_device, expected_diskseq, profile, *, deadline):
    """Only the two preapproved extents on the checked single disk incarnation, once."""
    device, seq, p = _dev(expected_device), _uint(expected_diskseq), validate_header_profile(profile)
    n = p["metadata_area_bytes"]
    try:
        with _disk(device, p["device_basename"], deadline) as (fd, node):
            before = _geometry(fd, seq, n, deadline)
            first, f_private = _area(fd, 0, p, deadline)
            second, s_private = _area(fd, 1, p, deadline)
            _need(f_private[0] == s_private[0] and f_private[1] != s_private[1],
                  "inconsistent header copies or reused salts")
            after = _geometry(fd, seq, n, deadline)
            record = dict(schema=SCHEMA, profile_sha256=_sha(canonical_json(p)), node=node, before=before, after=after,
                          primary=first, secondary=second)
            verify_luks_headers(record, expected_device=device, expected_diskseq=seq, profile=p)
        return record
    except OSError as exc:
        raise OSError(exc.errno, "guarded LUKS2 observation unavailable") from None
