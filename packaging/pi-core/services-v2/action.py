"""Fixed action service with pinned same-byte Aragorn source loading."""

import math
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
    loader = None
    result = 126
    try:
        if not (sys.platform == "linux" and sys.flags.isolated == 1 and
                sys.flags.no_site == 1 and sys.dont_write_bytecode is True):
            raise ValueError("isolated interpreter required")
        denied = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ssl_cert_file", "ssl_cert_dir",
            "requests_ca_bundle", "curl_ca_bundle", "node_extra_ca_certs", "pythonhttpsverify", "pythonpath",
            "pythonhome", "randfile", "glibc_tunables"}
        if any(key.lower() in denied or key.lower().startswith(("openssl_", "ld_", "dyld_", "openai_"))
               for key in os.environ):
            raise ValueError("unsafe environment")
        if not (len(sys.argv) == 3 and all(value.isascii() and value.isdecimal() and
                0 < int(value) < 2**63 for value in sys.argv[1:]) and type(_ARAGORN_SOURCE_DIGESTS) is dict):
            raise ValueError("bounded startup arguments and assembled pins required")
        deadline = math.nextafter(int(sys.argv[2]) / 1_000_000_000, 0.0)
        loader = _bootstrap(deadline)
        from aragorn.pi_core_service_entry import main as service_main
        result = service_main("action", source_loader=loader)
    except BaseException:
        print("PI_SERVICE_ENTRY_REFUSED_OR_CLEANUP_HOLD", file=sys.stderr)
        result = 126
    finally:
        if loader is not None:
            try:
                loader.close()
            except BaseException:
                print("PI_SERVICE_ENTRY_REFUSED_OR_CLEANUP_HOLD", file=sys.stderr)
                result = 126
    return result


if __name__ == "__main__":
    raise SystemExit(main())

