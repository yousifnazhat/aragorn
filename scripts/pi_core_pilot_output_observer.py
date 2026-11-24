"""Two point-in-time reads of the B95 pilot sink; no broker call, write or cleanup.

The caller must independently nominate the directory, activation and observation
window before the provider can assign a tool call ID. Matching bytes do not
identify the writer or prove exclusive access.
"""
from contextlib import contextmanager
from hashlib import sha256
import os
import re
import stat
from threading import Lock

from aragorn.oci_worker_protocol import canonical_digest
from aragorn.runtime_action_broker import _directory_identity, _file_identity


_NAME = "result.json"
# Pinned outside the worker from benchmark/pi-core-pilot-v1/review.json.
_BYTES = 11
_ORACLE = "sha256:9f827af5202050f264dfa05aeec4603d0fcec968de43ed7b039ce6a2d6231b08"
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def _require(condition, reason):
    if not condition:
        raise ValueError("PILOT_OUTPUT_" + reason)


@contextmanager
def hold_pilot_output(directory_fd, expected_path_descriptor, *, expected_activation_id):
    """Check the fixed name is absent, then offer one read-only ``after()``.

    The caller retains its input fd. The observer owns only its independently
    opened directory and file descriptors. A failed `after()` is spent too.
    """
    _require(type(directory_fd) is int and directory_fd >= 0, "DIRECTORY_FD")
    _require(type(expected_activation_id) is str and
             re.fullmatch(r"[0-9a-f]{32}", expected_activation_id), "ACTIVATION_ID")
    _require(type(expected_path_descriptor) is dict, "DESCRIPTOR")
    path = expected_path_descriptor.copy()
    _require(set(path) == {"schema", "root_device", "root_inode", "target_name"} and
             type(path["root_device"]) is int and path["root_device"] >= 0 and
             type(path["root_inode"]) is int and path["root_inode"] > 0 and
             type(path["schema"]) is str and path["schema"] == "aragorn/runtime-protected-path/v1" and
             type(path["target_name"]) is str and path["target_name"] == _NAME,
             "DESCRIPTOR")

    def directory(fd):
        meta = os.fstat(fd)
        _require(stat.S_ISDIR(meta.st_mode) and meta.st_nlink > 0 and not (meta.st_mode & 0o022)
                 and (meta.st_dev, meta.st_ino) == (path["root_device"], path["root_inode"]), "DIRECTORY")
        return _directory_identity(meta)

    expected = directory(directory_fd)
    lock = Lock()
    spent = False
    held = os.open(".", _READ | os.O_DIRECTORY, dir_fd=directory_fd)
    try:
        _require(directory(held) == expected, "DIRECTORY_CHANGED")
        try:
            os.stat(_NAME, dir_fd=held, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("PILOT_OUTPUT_ALREADY_PRESENT")
        _require(directory(held) == expected, "DIRECTORY_CHANGED")

        def after():
            nonlocal spent
            with lock:
                _require(not spent, "CLOSED_OR_SPENT")
                spent = True
                _require(directory(held) == expected, "DIRECTORY_CHANGED")
                meta = os.stat(_NAME, dir_fd=held, follow_symlinks=False)
                _require(stat.S_ISREG(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o400
                         and meta.st_nlink == 1 and meta.st_dev == expected[0] and meta.st_ino > 0
                         and meta.st_uid == expected[3] and meta.st_size == _BYTES, "FILE_CUSTODY")
                identity = _file_identity(meta)
                fd = os.open(_NAME, _READ, dir_fd=held)
                try:
                    _require(_file_identity(os.fstat(fd)) == identity, "FILE_CHANGED")
                    raw = os.read(fd, _BYTES + 1)
                    digest = "sha256:" + sha256(raw).hexdigest()
                    _require(len(raw) == _BYTES and digest == _ORACLE == canonical_digest({"total": 1 + 2}),
                             "CONTENT")
                    _require(_file_identity(os.fstat(fd)) == identity ==
                             _file_identity(os.stat(_NAME, dir_fd=held, follow_symlinks=False)), "FILE_CHANGED")
                    _require(directory(held) == expected, "DIRECTORY_CHANGED")
                finally:
                    os.close(fd)
                return dict(schema="aragorn/pi-core-pilot-output-observation/v1", path_descriptor=dict(path),
                            activation_id=expected_activation_id, before="ABSENT", after="PRESENT",
                            payload_digest=digest, payload_bytes=len(raw), payload_hex=raw.hex(), file_device=meta.st_dev,
                            file_inode=meta.st_ino)

        yield after
    finally:
        with lock:
            spent = True
            os.close(held)
