"""Static fixed task role. The packager replaces the same source-pin marker as the protected services."""

import os
from pathlib import Path
import stat
import sys
import time
import types

_ARAGORN_SOURCE_DIGESTS = None  # assembled source pins
_LOADER = "/opt/aragorn/src/aragorn/pi_core_service_source.py"
_PRIVATE = "_aragorn_pi_service_source"
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC


def _bootstrap(deadline):
    # The wrapper, interpreter and stdlib are the independently pinned bootstrap TCB.
    import hashlib
    held = []
    loader = None
    try:
        held.append(os.open("/", _DIRECTORY))
        for part in Path(_LOADER).parts[1:-1]:
            held.append(os.open(part, _DIRECTORY, dir_fd=held[-1]))
        for descriptor in held:
            info = os.fstat(descriptor)
            if not (stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                    and not stat.S_IMODE(info.st_mode) & 0o022):
                raise ValueError("unsafe bootstrap directory")
        descriptor = os.open(Path(_LOADER).name, _FILE, dir_fd=held[-1])
        held.append(descriptor)
        before = os.fstat(descriptor)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o444 and before.st_nlink == 1
                and 0 < before.st_size <= 4 * 1024 * 1024):
            raise ValueError("unsafe bootstrap source")
        raw = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise ValueError("bootstrap deadline")
            chunk = os.read(descriptor, min(65536, before.st_size + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > before.st_size:
                raise ValueError("bootstrap source grew")
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        named = os.stat(Path(_LOADER).name, dir_fd=held[-2], follow_symlinks=False)
        if not (len(raw) == before.st_size and
                all(getattr(before, key) == getattr(after, key) == getattr(named, key) for key in fields) and
                "sha256:" + hashlib.sha256(raw).hexdigest() == _ARAGORN_SOURCE_DIGESTS[_LOADER[1:]] and
                _PRIVATE not in sys.modules):
            raise ValueError("bootstrap source differs")
        module = types.ModuleType(_PRIVATE)
        module.__file__ = _LOADER
        sys.modules[_PRIVATE] = module
        try:
            exec(compile(bytes(raw), _LOADER, "exec", dont_inherit=True), module.__dict__)
            loader = module.install(Path("/opt/aragorn/src"), _ARAGORN_SOURCE_DIGESTS, deadline=deadline)
            return loader
        except BaseException:
            sys.modules.pop(_PRIVATE, None)
            raise
    finally:
        failed = False
        for descriptor in reversed(held):
            try:
                os.close(descriptor)
            except BaseException:
                failed = True
        if failed:
            if loader is not None:
                try:
                    loader.close()
                except BaseException:
                    pass  # Both failures retain a hold; neither close is retried.
            raise ValueError("bootstrap cleanup hold")


def main():
    if (sys.platform != 'linux' or len(sys.argv) != 1 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or not isinstance(_ARAGORN_SOURCE_DIGESTS, dict)):
        return 126
    loader = None
    try:
        deadline = time.monotonic()+29
        loader = _bootstrap(deadline)
        from aragorn.pi_core_task_guest_entry import run
        run(loader=loader, deadline=deadline)
        return 0
    except Exception:
        print('FIXED_TASK_REFUSED_OR_CLEANUP_HOLD', file=sys.stderr)
        return 126
    finally:
        if loader is not None:
            loader.close()


if __name__ == '__main__':
    sys.exit(main())
