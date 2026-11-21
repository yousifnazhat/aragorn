"""Prepare private configuration-only SquashFS and standalone raw media, without mounting either.

The output does not nominate or approve a device and cannot be added to the
pinned B44 boot configuration. Attachment requires separate approval.
"""
import argparse
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import time

from scripts import pi_core_configuration_delivery_layout as delivery
from scripts import prepare_pi_core_immutable_image as image
from scripts.build_pi_core_linux import canonical, regular_bytes, require, sha256


TOOL_LOCK = "768aa84188abbf43d85771152a01721cafcc98a72cf3d9630ceb384ef9e03325"
CONFIG_LIMIT = 2 << 20
MEDIA_LIMIT = 12 << 20
SECTOR_BYTES = 512
# The retained kernel has CONFIG_SQUASHFS_4K_DEVBLK_SIZE disabled: SquashFS
# reads in at least 1 KiB filesystem-device blocks even on a 512-byte-sector disk.
SQUASHFS_DEV_BLOCK = 1024
_INTERMEDIATES = {"input.pseudo", "readback.pseudo", "config.squashfs"}
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_DIRECTORY


def _dirs(parent):
    require(parent.is_absolute() and parent != Path("/") and parent.resolve(strict=True) == parent,
            "private canonical directory required")
    held = []
    uid = os.geteuid()
    for path in (*reversed(parent.parents), parent):
        s = path.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, uid) and not s.st_mode & 0o022,
                "unsafe directory ancestry")
        held.append((s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode))
    require(s.st_uid == uid and stat.S_IMODE(s.st_mode) == 0o700, "private owner-only directory required")
    return tuple(held)


def _file(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_ctime_ns, s.st_mtime_ns)


def _input(path, expected):
    s = path.lstat()
    ident = _file(s)
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o400
            and s.st_nlink == 1 and 0 < s.st_size <= CONFIG_LIMIT, "private single-link 0400 input required")
    raw = regular_bytes(path, CONFIG_LIMIT)
    require(_file(path.lstat()) == ident and "sha256:" + sha256(raw) == expected, "configuration bytes or identity changed")
    return raw, ident


def _pseudo(members):
    lines, data = [], bytearray()
    for name, (mode, raw) in sorted(members.items()):
        require(name == "/" or (re.fullmatch(r"[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*", name) and
                not {"", ".", ".."}.intersection(name.split("/"))), "invalid configuration member")
        require(type(mode) is int and mode in (0o400, 0o444, 0o555, 0o700, 0o755) and
                (raw is None or type(raw) is bytes), "invalid configuration member metadata")
        meta = f"{image.EPOCH} {mode:o} 0 0"
        if raw is None:
            lines.append(f"{name} D {meta}\n".encode("ascii"))
        else:
            require(len(data) + len(raw) < MEDIA_LIMIT, "configuration data exceeds media budget")
            lines.append(f"{name} R {meta} {len(raw)} {len(data)} 0\n".encode("ascii"))
            data.extend(raw)
    return b"".join(lines) + image.MARKER + bytes(data)


def verify_pseudo(raw, members):
    require(type(raw) is bytes and 0 < len(raw) <= MEDIA_LIMIT, "invalid exported configuration bytes")
    rows, attrs, offset = image.read_pseudo(io.BytesIO(raw))
    require(not attrs and rows.keys() == members.keys(), "export has unknown names or extended attributes")
    extents = []
    for name, (mode, data) in members.items():
        token, kind, meta = rows[name]
        fields = meta.split()
        require(token == name.encode("ascii") and fields[:4] == [str(image.EPOCH).encode(), f"{mode:o}".encode(),
                b"0", b"0"], "wrong configuration name or metadata")
        if data is None:
            require(kind == b"D" and len(fields) == 4, "not the expected directory")
        else:
            require(kind == b"R" and len(fields) == 7 and fields[4] == str(len(data)).encode() and
                    fields[5].isdigit() and fields[6] == b"0", "not the expected regular file")
            first, size = image.raw_extent(meta, offset, len(raw))
            require(raw[first:first + size] == data, "exported configuration bytes differ")
            extents.append((first, first + size))
    cursor = offset
    for first, end in sorted(extents):
        require(first == cursor, "unused or aliased exported bytes")
        cursor = end
    require(cursor == len(raw), "unused trailing exported bytes")


def _limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MEDIA_LIMIT, MEDIA_LIMIT))


def _make_image(work, members, env):
    image_source = _pseudo(members)
    split = work / "input.pseudo"
    _write(work, split.name, image_source)
    def run(tool, args, pass_fds=()):
        subprocess.run([str(image.WORK / "tools" / tool), *args], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=work, env=env,
                       check=True, timeout=30, preexec_fn=_limits, umask=0o077, pass_fds=pass_fds)
    run("mksquashfs", ("-", "config.squashfs", "-pf", split.name, "-noappend", "-comp", "zstd",
                       "-no-duplicates", "-nopad", "-no-progress", "-processors", "1", "-mem", "32M",
                       "-exit-on-error", "-mkfs-time", str(image.EPOCH)))
    path = work / "config.squashfs"
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1 and
                not s.st_mode & 0o077 and 96 <= s.st_size <= MEDIA_LIMIT, "unexpected private media")
        disk = os.pread(fd, s.st_size + 1, 0)
        require(len(disk) == s.st_size and disk[:4] == b"hsqs" and int.from_bytes(disk[40:48], "little") ==
                len(disk), "invalid unpadded SquashFS size")
        require(_file(s) == _file(os.fstat(fd)) == _file(path.lstat()), "private media changed before export")
        # The exporter opens the held file, not a newly resolved work-directory name.
        run("unsquashfs", ("-pf", "readback.pseudo", "-strict-errors", "-no-progress", "-processors", "1",
                           "/dev/fd/" + str(fd)), pass_fds=(fd,))
        verify_pseudo(regular_bytes(work / "readback.pseudo", MEDIA_LIMIT), members)
        require(os.pread(fd, s.st_size + 1, 0) == disk and _file(s) == _file(os.fstat(fd)) ==
                _file(path.lstat()), "private media changed during export")
        return disk
    finally:
        os.close(fd)


def _write(parent, name, raw):
    with (parent / name).open("xb") as out:
        os.fchmod(out.fileno(), 0o400)
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def _verify_disk(logical, raw):
    """Compare the complete stored disk to the logical bytes already inspected by the exporter."""
    require(type(logical) is bytes and 0 < len(logical) <= MEDIA_LIMIT and type(raw) is bytes,
            "invalid configuration image or disk")
    blocks = (len(logical) + SQUASHFS_DEV_BLOCK - 1) // SQUASHFS_DEV_BLOCK
    require(len(raw) == blocks * SQUASHFS_DEV_BLOCK and raw.startswith(logical) and not any(raw[len(logical):]),
            "configuration disk size, logical bytes or zero padding differ")
    return dict(disk_sha256=sha256(raw), disk_bytes=len(raw), sector_bytes=SECTOR_BYTES)


def _read_output(path, maximum):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == os.geteuid()
            and stat.S_IMODE(s.st_mode) == 0o400, "unexpected private output identity")
    data = regular_bytes(path, maximum)
    require(_file(s) == _file(path.lstat()), "private output changed during readback")
    return data, _file(s)


@contextmanager
def _work(out, out_fd):
    os.mkdir("work", mode=0o700, dir_fd=out_fd)
    fd = os.open("work", _FLAGS, dir_fd=out_fd)
    try:
        yield out / "work"
    finally:
        try:
            require(os.path.samestat(os.fstat(fd), os.stat("work", dir_fd=out_fd, follow_symlinks=False)),
                    "uncertain private work directory; preserve it")
            names = os.listdir(fd)
            require(set(names) <= _INTERMEDIATES, "unknown private work files; preserve them")
            for n in names:
                s = os.stat(n, dir_fd=fd, follow_symlinks=False)
                require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == os.geteuid(),
                        "unknown work file identity; preserve it")
            for n in names:
                os.unlink(n, dir_fd=fd)
            os.rmdir("work", dir_fd=out_fd)
        finally:
            os.close(fd)


def prepare(config_path, expected_digest, out):
    require(isinstance(config_path, Path) and isinstance(out, Path) and config_path != out and
            config_path.name not in ("", ".", "..") and out.name not in ("", ".", "..") and
            type(expected_digest) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", expected_digest),
            "canonical private paths and an independent digest are required")
    source_parent, output_parent = _dirs(config_path.parent), _dirs(out.parent)
    require(not os.path.lexists(out), "output already exists; no adoption or retry")
    raw, identity = _input(config_path, expected_digest)
    members, section = delivery.layout(raw, expected_digest, int(time.time()))
    lock_raw = regular_bytes(image.PINS, 16384)
    require(sha256(lock_raw) == TOOL_LOCK, "unreviewed image tools")
    env = image.decoder(image.WORK, json.loads(lock_raw))
    def guard():
        require(_dirs(config_path.parent) == source_parent and _dirs(out.parent) == output_parent and
                _file(config_path.lstat()) == identity, "configuration or destination custody changed")
    guard()
    out.mkdir(mode=0o700)
    fd = os.open(out, _FLAGS)
    try:
        def release():
            guard()
            require(os.path.samestat(os.fstat(fd), out.lstat()) and _dirs(out)[-1][:2] ==
                    (os.fstat(fd).st_dev, os.fstat(fd).st_ino), "private output changed")
            require(delivery.layout(raw, expected_digest, int(time.time())) == (members, section),
                    "configuration no longer current")
        with _work(out, fd) as work:
            logical = _make_image(work, members, env)
        release()
        _write(out, "config.squashfs", logical)
        _write(out, "config.raw", logical + bytes(-len(logical) % SQUASHFS_DEV_BLOCK))
        held = {}
        image_raw, held["config.squashfs"] = _read_output(out / "config.squashfs", MEDIA_LIMIT)
        require(image_raw == logical, "private media readback differs")
        disk_raw, held["config.raw"] = _read_output(out / "config.raw", MEDIA_LIMIT)
        disk = _verify_disk(logical, disk_raw)
        result = dict(schema="aragorn/pi-core-private-configuration-carrier/v2", configurations_digest=expected_digest,
                      image_sha256=sha256(logical), image_bytes=len(logical), service_configuration=section, **disk,
                      mount_target=delivery.ROOT_PATH, current_grant_authority=False,
                      mount_authorized=False, installed_identity_verified=False, phase3_exit_eligible=False)
        _write(out, "pending.json", canonical(result))
        pending_raw, held["pending.json"] = _read_output(out / "pending.json", 16384)
        require(pending_raw == canonical(result), "private outcome readback differs")
        os.fsync(fd)
        release()
        require(set(os.listdir(fd)) == held.keys() and all(
            _file(os.stat(name, dir_fd=fd, follow_symlinks=False)) == ident for name, ident in held.items()),
            "output identity changed before publication")
        # No-replace publication; an interrupted attempt with a pending marker
        # is not complete and must never be adopted or retried automatically.
        os.link("pending.json", "outcome.json", src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.unlink("pending.json", dir_fd=fd)
        os.fsync(fd)
        return result
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="absolute existing private 0400 configuration")
    parser.add_argument("--expected-digest", required=True, help="independently provided sha256: configuration digest")
    parser.add_argument("--output", type=Path, required=True, help="absent absolute directory below a private 0700 parent")
    args = parser.parse_args()
    try:
        prepare(args.config, args.expected_digest, args.output)
    except Exception:
        print("Private configuration carrier refused or incomplete; preserve the attempt.", file=sys.stderr)
        return 1
    print("Private standalone data disk prepared; no device nominated or attachment authorized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
