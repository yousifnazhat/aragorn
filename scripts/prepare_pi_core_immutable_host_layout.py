"""Prepare two Ubuntu payloads and an empty mountpoint; never mount or boot them."""
from contextlib import ExitStack
import os
from pathlib import Path
import stat

from scripts.build_pi_core_linux import regular_bytes, sha256
from scripts.prepare_pi_core_restricted_host_sources import _identity

# Regular members from ./usr/lib/aarch64-linux-gnu of B38's authenticated
# libc6_2.43-2ubuntu2_arm64.deb (SHA-256 6be782d9...c18397c0).
LOADER_SHA = "058b11f959fd1006abfc289a7fa9e2df86892e8a05f2d8b79a137e6a29c11a78"
LIBC_SHA = "4306bea54c5862911d6ed2ee19adc0cdcb092cd1948ceb14a9c1e3592e8487d7"
_PAYLOADS = (("ubuntu-loader.elf", 201872, LOADER_SHA, "usr/lib/ld-linux-aarch64.so.1"),
             ("ubuntu-libc.elf", 1788240, LIBC_SHA, "usr/lib/aarch64-linux-gnu/libc.so.6"))
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def _owned_directory(path):
    info = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise ValueError("unowned, linked or writable host layout directory: " + str(path))
    return info


def prepare(inputs: Path, destination: Path) -> dict:
    """Leave any partial output in place. Never reuse it or modify an existing tree."""
    _owned_directory(inputs)
    parent = _owned_directory(destination.parent)
    if not destination.is_absolute() or destination.name in ("", ".", "..") or os.path.lexists(destination):
        raise ValueError("refuse existing host layout destination")
    payloads = {}
    for name, size, digest, target in _PAYLOADS:
        source = inputs / name
        before = _identity(source)
        if source.stat().st_size != size:
            raise ValueError("unapproved host layout input: " + name)
        raw = regular_bytes(source, size)
        if _identity(source) != before or len(raw) != size or sha256(raw) != digest:
            raise ValueError("unapproved host layout input: " + name)
        payloads[target] = raw

    with ExitStack() as holders:
        def directory(name, parent_fd=None):
            fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
            holders.callback(os.close, fd)
            return fd

        parent_fd = directory(destination.parent)
        if not os.path.samestat(os.fstat(parent_fd), parent):
            raise ValueError("host layout parent changed")
        os.mkdir(destination.name, 0o700, dir_fd=parent_fd)
        dirs = {"": directory(destination.name, parent_fd)}
        for name in ("lib", "usr", "usr/lib", "usr/lib/aarch64-linux-gnu"):
            parent_name, _, leaf = name.rpartition("/")
            os.mkdir(leaf, 0o700, dir_fd=dirs[parent_name])
            dirs[name] = directory(leaf, dirs[parent_name])
        file_states = {}
        for _, size, digest, target in _PAYLOADS:
            parent_name, _, leaf = target.rpartition("/")
            fd = os.open(leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=dirs[parent_name])
            with os.fdopen(fd, "w+b") as stream:
                stream.write(payloads[target])
                stream.flush()
                os.fchmod(fd, 0o555)
                os.fsync(fd)
                stream.seek(0)
                info = os.fstat(fd)
                if (info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o555 or
                        sha256(stream.read(size + 1)) != digest):
                    raise ValueError("host layout file readback differs: " + target)
                file_states[target] = (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                                       info.st_mtime_ns, info.st_ctime_ns)
        # Recheck directory names and the entire tiny namespace. /lib must not
        # be a symlink or a second copy of the loader before the future bind.
        names = set(dirs) | set(payloads)
        for name, fd in dirs.items():
            if (not os.path.samestat(os.fstat(fd), _owned_directory(destination / name)) or
                    set(os.listdir(fd)) != {p.rpartition("/")[2] for p in names
                                           if p and p.rpartition("/")[0] == name}):
                raise ValueError("host layout namespace changed")
        if any(_identity(destination / name) != state for name, state in file_states.items()):
            raise ValueError("host layout file identity changed")
    return {"status": "PREPARED_IMMUTABLE_HOST_LAYOUT_FRAGMENT_NOT_MOUNTED",
            "physical_files": {"/" + target: "sha256:" + digest for _, _, digest, target in _PAYLOADS},
            "required_early_boot_bind": {"source": "/usr/lib", "target": "/lib", "readonly": True},
            "mount_performed": False, "installed_identity_verified": False,
            "bootable_host": False, "phase3_exit_eligible": False}
