"""Read a local quickstart result against the caller's operands; never run a worker."""
from contextlib import contextmanager
import os
import stat

from .oci_worker_protocol import canonical_json
from .runtime_action_broker import _directory_identity, _file_identity, require_owned_directory


_NAME = "result.json"
_READ = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC


@contextmanager
def hold_sum_output(out_fd, operands):
    """Bracket one run. The caller keeps out_fd; after() returns only observed bytes."""
    if (type(operands) not in (tuple, list) or len(operands) != 2
            or any(type(n) is not int or not -2**31 <= n < 2**31 for n in operands)):
        raise ValueError("expected two signed 32-bit integer operands")
    expected = canonical_json({"total": operands[0] + operands[1]})

    if type(out_fd) is not int or out_fd < 0:
        raise ValueError("expected an output directory fd")
    meta = require_owned_directory(out_fd, expected_uid=os.geteuid(), require_owner_write=True,
                                   label="sum output directory")
    directory_id = _directory_identity(meta)
    held = os.dup(out_fd)
    used = False

    def check_directory():
        now = os.fstat(held)
        if now.st_nlink < 1 or _directory_identity(now) != directory_id:
            raise ValueError("sum output directory changed")

    try:
        check_directory()
        try:
            os.stat(_NAME, dir_fd=held, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("result.json was not absent before the run")

        def after():
            nonlocal used
            if used:
                raise ValueError("sum observation closed or already used")
            used = True
            check_directory()
            entry = os.stat(_NAME, dir_fd=held, follow_symlinks=False)
            if (not stat.S_ISREG(entry.st_mode) or stat.S_IMODE(entry.st_mode) != 0o400
                    or entry.st_uid != meta.st_uid or entry.st_dev != meta.st_dev
                    or entry.st_nlink != 1 or entry.st_size != len(expected)):
                raise ValueError("unexpected result.json metadata")
            identity = _file_identity(entry)
            fd = os.open(_NAME, _READ, dir_fd=held)
            try:
                if _file_identity(os.fstat(fd)) != identity:
                    raise ValueError("result.json changed before read")
                raw = os.read(fd, len(expected) + 1)
                if raw != expected:
                    raise ValueError("result.json differs from the original operands' sum")
                if not (identity == _file_identity(os.fstat(fd)) ==
                        _file_identity(os.stat(_NAME, dir_fd=held, follow_symlinks=False))):
                    raise ValueError("result.json changed during read")
                check_directory()
                return raw
            finally:
                os.close(fd)

        yield after
    finally:
        used = True
        os.close(held)
