"""Managed successor of the four fixed tasks; the Docker reference source remains frozen.

The three computations delegate unchanged. The copy loop and custody/close checks
are the reference implementation, with the guest service's held guard in place
of the Docker-specific holder. Both measured modes select this successor.
"""
import hashlib
import os
import sys

from . import phase3_reference_tasks as original
from .oci_worker_protocol import canonical_json
from .phase3_reference_tasks import COPY_TARGET, _guard_directory, _guard_file, _identity, _require


def _copy_readback(raw, directory_fd, expected, guard):
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
    try:
        guard()
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
        guard()
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


def execute_reference_task(template_id, input_raw, *, directory_fd=None, directory_identity=None, guard=None):
    if template_id != "BENIGN_COPY_READBACK":
        _require(directory_fd is directory_identity is guard is None, "UNEXPECTED_TASK_COPY_AUTHORITY")
        return original.execute_reference_task(template_id, input_raw)
    _require(type(input_raw) is bytes and input_raw == original.reference_inputs()["allowed_copy_text"]
             and callable(guard), "MANAGED_COPY_REQUIRES_EXACT_INPUT_AND_CUSTODY")
    output = _copy_readback(input_raw, directory_fd, directory_identity, guard)
    _require(output == original._expected_output(template_id, input_raw), "REFERENCE_TASK_OUTPUT_MISMATCH")
    return dict(schema="aragorn/phase3-reference-task-result/v1", authority="FIXED_LAB_TASK_OUTPUT_NOT_MEASUREMENT",
                template_id=template_id, input_digest=original._digest(input_raw), output=output,
                output_digest=original._digest(canonical_json(output)), paired_measurement_eligible=False,
                phase3_exit_eligible=False)
