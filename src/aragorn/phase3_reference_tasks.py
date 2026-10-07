"""Four fixed fabricated lab tasks, not an overhead measurement collector.

The input bytes are the decoded values already reviewed in lab-data-v1.json.
The caller retains the actual signed module bytes used for task descriptors.
Copy/readback requires an independently pinned, private fixture directory fd;
this module never resolves a caller-provided pathname or removes output files.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys

from .native_phase3_http_fixture import owned_http_fixture
from .oci_worker_protocol import canonical_json


COPY_TARGET = "allowed-copy.txt"
_INPUTS = {
    "numbers_json": b'{"values":[1,2,3,4,5,6,7]}\n',
    "lines_text": b"amber\nbirch\ncedar\ndelta\n",
    "allowed_copy_text": b"Aragorn Phase 3 benign copy/readback data.\n",
}
_TASK_INPUTS = {
    "BENIGN_JSON_SUM": "numbers_json",
    "BENIGN_LINE_COUNT": "lines_text",
    "BENIGN_SHA256": "lines_text",
    "BENIGN_COPY_READBACK": "allowed_copy_text",
}


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def reference_inputs():
    """Return only the three exact, non-sensitive benign input byte strings."""
    return dict(_INPUTS)


def _expected_output(template_id, raw):
    if template_id == "BENIGN_JSON_SUM":
        return {"sum": 28}
    if template_id == "BENIGN_LINE_COUNT":
        return {"line_count": 4}
    if template_id == "BENIGN_SHA256":
        return {"sha256": hashlib.sha256(raw).hexdigest()}
    return {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "readback_equal": True,
    }


def describe_tasks(source_raw):
    """Bind descriptors to caller-retained actual source; execute no task.

    This pure function cannot attest the provenance of source_raw. The builder
    must obtain it from the reviewed source tree and retain it by digest.
    """
    _require(
        type(source_raw) is bytes and 0 < len(source_raw) <= 1024 * 1024,
        "REFERENCE_TASK_SOURCE_BYTES_REQUIRED",
    )
    source_digest = _digest(source_raw)
    return {
        template_id: {
            "schema": "aragorn/phase3-reference-task/v1",
            "authority": "SOURCE_BOUND_FIXED_LAB_TASK_NOT_MEASUREMENT",
            "template_id": template_id,
            "entrypoint": "execute_reference_task",
            "module_source_digest": source_digest,
            "input": {
                "ref": input_ref,
                "encoding": "UTF-8",
                "bytes": len(_INPUTS[input_ref]),
                "digest": _digest(_INPUTS[input_ref]),
            },
            "output": {
                "expected": _expected_output(template_id, _INPUTS[input_ref]),
                "encoding": "CANONICAL_JSON_ASCII_NO_LF",
                "copy_target": COPY_TARGET
                if template_id == "BENIGN_COPY_READBACK"
                else None,
            },
            "paired_measurement_eligible": False,
            "phase3_exit_eligible": False,
        }
        for template_id, input_ref in _TASK_INPUTS.items()
    }


def _identity(metadata):
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def _guard_directory(descriptor, expected):
    metadata = os.fstat(descriptor)
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and _identity(metadata) == expected
        and expected["mode"] == 0o700
        and expected["uid"] == os.geteuid()
        and expected["gid"] == os.getegid(),
        "REFERENCE_COPY_DIRECTORY_CUSTODY_CHANGED",
    )


def _guard_file(descriptor, directory_fd, expected_identity, size):
    opened = os.fstat(descriptor)
    named = os.stat(COPY_TARGET, dir_fd=directory_fd, follow_symlinks=False)
    _require(
        stat.S_ISREG(opened.st_mode)
        and stat.S_ISREG(named.st_mode)
        and _identity(opened) == _identity(named) == expected_identity
        and opened.st_nlink == named.st_nlink == 1
        and opened.st_size == named.st_size == size
        and opened.st_uid == os.geteuid()
        and opened.st_gid == os.getegid()
        and stat.S_IMODE(opened.st_mode) == 0o600,
        "REFERENCE_COPY_FILE_CUSTODY_CHANGED",
    )


def _copy_readback(raw, directory_fd, expected, fixture):
    _require(
        type(directory_fd) is int and directory_fd >= 0,
        "REFERENCE_COPY_DIRECTORY_FD_REQUIRED",
    )
    _require(
        type(expected) is dict
        and set(expected) == {"device", "inode", "mode", "uid", "gid"}
        and all(type(value) is int and value >= 0 for value in expected.values())
        and expected["inode"] > 0,
        "REFERENCE_COPY_DIRECTORY_IDENTITY_REQUIRED",
    )
    expected = dict(expected)
    descriptors = []
    with owned_http_fixture(fixture) as held:
        try:
            held.guard()
            _guard_directory(directory_fd, expected)
            owned_fd = os.dup(directory_fd)
            descriptors.append(owned_fd)
            _guard_directory(owned_fd, expected)
            target_fd = os.open(
                COPY_TARGET,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=owned_fd,
            )
            descriptors.append(target_fd)
            target_identity = _identity(os.fstat(target_fd))
            _guard_file(target_fd, owned_fd, target_identity, 0)
            offset = 0
            while offset < len(raw):
                written = os.write(target_fd, raw[offset:])
                _require(0 < written <= len(raw) - offset, "REFERENCE_COPY_SHORT_WRITE")
                offset += written
            os.fsync(target_fd)
            os.fsync(owned_fd)
            _guard_file(target_fd, owned_fd, target_identity, len(raw))
            os.lseek(target_fd, 0, os.SEEK_SET)
            copied = os.read(target_fd, len(raw) + 1)
            _require(copied == raw, "REFERENCE_COPY_READBACK_MISMATCH")
            _guard_file(target_fd, owned_fd, target_identity, len(raw))
            held.guard()
            output = {
                "bytes": len(copied),
                "sha256": hashlib.sha256(copied).hexdigest(),
                "readback_equal": True,
            }
        finally:
            primary, cleanup_failed = sys.exception(), False
            try:
                _guard_directory(directory_fd, expected)
                if descriptors:
                    _guard_directory(descriptors[0], expected)
            except BaseException:
                cleanup_failed = True
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except BaseException:
                    cleanup_failed = True
            if cleanup_failed:
                if primary is not None:
                    primary.add_note("REFERENCE_COPY_FINAL_CUSTODY_OR_CLOSE_FAILED")
                else:
                    raise ValueError("REFERENCE_COPY_FINAL_CUSTODY_OR_CLOSE_FAILED")
    return output


def execute_reference_task(
    template_id,
    input_raw,
    *,
    copy_directory_fd=None,
    expected_copy_directory_identity=None,
    expected_fixture=None,
):
    """Execute once on exact reviewed bytes; return no duration or eligibility.

    Copy requires a root-owned 0700 directory inside the caller's independently
    guarded fixture. Expected identity keys are device/inode/mode/uid/gid. The
    sole created file remains retained on success or failure for its owner to
    inspect and clean up. Neither existing files nor symlinks are overwritten.
    """
    _require(
        type(template_id) is str and template_id in _TASK_INPUTS,
        "UNKNOWN_REFERENCE_TASK",
    )
    _require(
        type(input_raw) is bytes and input_raw == _INPUTS[_TASK_INPUTS[template_id]],
        "REFERENCE_TASK_EXACT_REVIEWED_INPUT_REQUIRED",
    )
    if template_id == "BENIGN_COPY_READBACK":
        output = _copy_readback(
            input_raw,
            copy_directory_fd,
            expected_copy_directory_identity,
            expected_fixture,
        )
    else:
        _require(
            copy_directory_fd is None
            and expected_copy_directory_identity is None
            and expected_fixture is None,
            "REFERENCE_PURE_TASK_UNEXPECTED_FIXTURE_ARGUMENTS",
        )
        if template_id == "BENIGN_JSON_SUM":
            output = {"sum": sum(json.loads(input_raw.decode("utf-8"))["values"])}
        elif template_id == "BENIGN_LINE_COUNT":
            output = {"line_count": input_raw.count(b"\n")}
        else:
            output = {"sha256": hashlib.sha256(input_raw).hexdigest()}
    _require(
        output == _expected_output(template_id, input_raw),
        "REFERENCE_TASK_OUTPUT_MISMATCH",
    )
    return {
        "schema": "aragorn/phase3-reference-task-result/v1",
        "authority": "FIXED_LAB_TASK_OUTPUT_NOT_MEASUREMENT",
        "template_id": template_id,
        "input_digest": _digest(input_raw),
        "output": output,
        "output_digest": _digest(canonical_json(output)),
        "paired_measurement_eligible": False,
        "phase3_exit_eligible": False,
    }
