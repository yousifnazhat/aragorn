"""Two point-in-time reads of the B95 pilot sink; no broker call, write or cleanup.

The caller must independently nominate the directory, activation and observation
window before the provider can assign a tool call ID. Matching bytes do not
identify the writer or prove exclusive access.
"""
from contextlib import contextmanager
from hashlib import sha256
import json
import os
import re
import stat
from threading import Lock
import time

from aragorn.oci_worker_protocol import canonical_digest
from aragorn.runtime_action_broker import _directory_identity, _file_identity


_NAME = "result.json"
# Pinned outside the worker from benchmark/pi-core-pilot-v1/review.json.
_BYTES = 11
_ORACLE = "sha256:9f827af5202050f264dfa05aeec4603d0fcec968de43ed7b039ce6a2d6231b08"
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_MANIFEST = "sha256:e6de9001bdd41e7908d0b9097798d1ab8ae13037c4ad1a7dbceb4cea985ad77f"
_TREE = "sha256:71de288e6e78f24d5fdbc62ff4508f8aadf473b3647a13e43269a53bb872b4ee"
_SKILL = "sha256:9829034f6fa3db850ba63f6a31a770172256a4c4cb354f96781a1a710b3e9c7a"
_TASK = "sha256:0ef53ad4dad36b5ec30b01339c349aad88c215e9ca16cffea3ac2639da9af4ec"


def _require(condition, reason):
    if not condition:
        raise ValueError("PILOT_OUTPUT_" + reason)


def _close_once(fd, primary=None):
    """A close error leaves custody uncertain; never retry a possibly reused fd."""
    try:
        os.close(fd)
    except BaseException as error:
        if primary is None:
            error.pilot_output_close_uncertain = True
            raise
        primary.pilot_output_close_uncertain = True
        primary.add_note("PILOT_OUTPUT_DESCRIPTOR_CLOSE_UNCONFIRMED")


def validate_descriptor(expected_path_descriptor):
    _require(type(expected_path_descriptor) is dict, "DESCRIPTOR")
    path = expected_path_descriptor.copy()
    _require(set(path) == {"schema", "root_device", "root_inode", "target_name"} and
             type(path["root_device"]) is int and 0 <= path["root_device"] < 2**63 and
             type(path["root_inode"]) is int and 0 < path["root_inode"] < 2**63 and
             type(path["schema"]) is str and path["schema"] == "aragorn/runtime-protected-path/v1" and
             type(path["target_name"]) is str and path["target_name"] == _NAME,
             "DESCRIPTOR")
    return path


@contextmanager
def hold_pilot_output(directory_fd, expected_path_descriptor, *, expected_activation_id):
    """Check the fixed name is absent, then offer one read-only ``after()``.

    The caller retains its input fd. The observer owns only its independently
    opened directory and file descriptors. A failed `after()` is spent too.
    """
    _require(type(directory_fd) is int and directory_fd >= 0, "DIRECTORY_FD")
    _require(type(expected_activation_id) is str and
             re.fullmatch(r"[0-9a-f]{32}", expected_activation_id), "ACTIVATION_ID")
    path = validate_descriptor(expected_path_descriptor)

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
                except BaseException as error:
                    _close_once(fd, error)
                    raise
                else:
                    _close_once(fd)
                return dict(schema="aragorn/pi-core-pilot-output-observation/v1", path_descriptor=dict(path),
                            activation_id=expected_activation_id, before="ABSENT", after="PRESENT",
                            payload_digest=digest, payload_bytes=len(raw), payload_hex=raw.hex(), file_device=meta.st_dev,
                            file_inode=meta.st_ino)

        yield after
    except BaseException as error:
        with lock:
            spent = True
            _close_once(held, error)
        raise
    else:
        with lock:
            spent = True
            _close_once(held)


class PilotOutputRequest:
    """One protected caller's nomination. The coordinator owns the borrowed FD."""

    def __init__(self, directory_fd, descriptor):
        _require(type(directory_fd) is int and directory_fd >= 0, "DIRECTORY_FD")
        self._fd = directory_fd
        self._path = validate_descriptor(descriptor)
        self._spent = False
        self._lock = Lock()

    @contextmanager
    def hold(self, *, activation, plan, deadline):
        with self._lock:
            _require(not self._spent, "REQUEST_SPENT")
            self._spent = True
        _require(time.monotonic() < deadline, "DEADLINE")
        # Both inputs are already authenticated by the caller: the actual bound
        # activation and the exact bytes about to be sent, not a worker claim.
        start = json.loads(plan.start_bytes)
        prepared = plan.prepared
        activation_id = activation["activation_id"]
        _require(start["schema"] == "aragorn/pi-core-bootstrap-start/v3" and
                 start["provider_status"] == "PROTECTED" and
                 start["activation_id"] == prepared.activation_id == activation_id and
                 start["limits"]["maxTurns"] == start["limits"]["maxToolCalls"] == 1,
                 "PILOT_START")
        _require(activation["source_manifest_digest"] == prepared.manifest_digest == _MANIFEST and
                 activation["tree_digest"] == prepared.tree_digest == _TREE and
                 activation["active_skill_digest"] == prepared.skill_digest == _SKILL and
                 "sha256:" + sha256(start["system_prompt"].encode("utf-8")).hexdigest() == _SKILL and
                 "sha256:" + sha256(start["task"].encode("utf-8")).hexdigest() == _TASK, "PILOT_INPUT")
        with hold_pilot_output(self._fd, self._path, expected_activation_id=activation_id) as read_once:
            _require(time.monotonic() < deadline, "DEADLINE")

            def after():
                _require(time.monotonic() < deadline, "DEADLINE")
                observation = read_once()
                _require(time.monotonic() < deadline, "DEADLINE")
                return observation

            yield after
