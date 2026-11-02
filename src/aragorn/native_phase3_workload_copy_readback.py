"""One fixed copy task and post-task retention observation; no product deadline.

Caller supplies protected context and keeps the original directory FD alive.
Freshness, exclusive custody, durable claims and cancellation are coordinator
responsibilities. No retry, overwrite, unlink or alternate copy implementation.
"""

import os
import stat
import sys
import time

from . import phase3_reference_tasks as tasks
from .native_phase3_http_canary_contract import require, validate_fixture
from .native_phase3_http_fixture import owned_http_fixture
from .native_phase3_workload_json_sum_contract import validate_boundaries, validate_request
from .oci_worker_protocol import canonical_digest, canonical_json


def _retained_identity(directory_fd, size):
    metadata = os.stat("allowed-copy.txt", dir_fd=directory_fd, follow_symlinks=False)
    require(
        stat.S_ISREG(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid()
        and metadata.st_nlink == 1 and metadata.st_size == size,
        "COPY_RETAINED_FILE_CHANGED",
    )
    return {
        **tasks._identity(metadata),
        "nlink": metadata.st_nlink, "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns, "ctime_ns": metadata.st_ctime_ns,
    }


def execute(request, mark, *, copy_directory_fd,
            expected_copy_directory_identity, expected_fixture):
    """Call the reference task once between actual collector BOOTTIME marks.

    The task closes its file FD before observation; no continuous inode-custody
    claim follows. Failures retain residue and never return a successful receipt.
    """
    validate_request(request)
    request = dict(request)
    require(sys.platform == "linux" and hasattr(time, "CLOCK_BOOTTIME"),
            "COPY_LINUX_BOOTTIME_REQUIRED")
    require(type(copy_directory_fd) is int and copy_directory_fd >= 0,
            "COPY_DIRECTORY_FD_REQUIRED")
    expected = expected_copy_directory_identity
    require(
        type(expected) is dict
        and set(expected) == {"device", "inode", "mode", "uid", "gid"}
        and all(type(value) is int and value >= 0 for value in expected.values())
        and expected["inode"] > 0,
        "COPY_DIRECTORY_IDENTITY_REQUIRED",
    )
    expected = dict(expected)
    validate_fixture(expected_fixture)
    fixture = dict(expected_fixture)
    with open(tasks.__file__, "rb") as source:
        descriptor = tasks.describe_tasks(source.read(1024 * 1024 + 1))["BENIGN_COPY_READBACK"]
    require(request["task_digest"] == canonical_digest(descriptor)
            and request["input_digest"] == descriptor["input"]["digest"],
            "COPY_TASK_INPUT_BINDING")
    input_raw = tasks.reference_inputs()["allowed_copy_text"]
    owned_fd = None
    with owned_http_fixture(fixture) as held:
        try:
            held.guard()
            tasks._guard_directory(copy_directory_fd, expected)
            owned_fd = os.dup(copy_directory_fd)
            tasks._guard_directory(owned_fd, expected)
            start = mark("TASK_ACCEPTED")
            result = tasks.execute_reference_task(
                "BENIGN_COPY_READBACK", input_raw,
                copy_directory_fd=owned_fd,
                expected_copy_directory_identity=dict(expected),
                expected_fixture=dict(fixture),
            )
            end = mark("TASK_COMPLETED")
            boundaries = {"TASK_ACCEPTED": start, "TASK_COMPLETED": end}
            validate_boundaries(boundaries)
            identity = _retained_identity(owned_fd, len(input_raw))
            receipt = canonical_json({
                "schema": "aragorn/phase3-local-measurement-receipt/v1",
                "request_digest": canonical_digest(request),
                "deployment_digest": request["deployment_digest"],
                "boundaries": boundaries,
                "observation": {
                    "task": descriptor, "result": result,
                    "retained_file": {
                        "basename": "allowed-copy.txt", "directory_identity": expected,
                        "fixture_digest": canonical_digest(fixture), "identity": identity,
                    },
                },
            })
            require(_retained_identity(owned_fd, len(input_raw)) == identity,
                    "COPY_RETAINED_FILE_CHANGED")
        finally:
            primary, failed = sys.exception(), False
            try:
                tasks._guard_directory(copy_directory_fd, expected)
                if owned_fd is not None:
                    tasks._guard_directory(owned_fd, expected)
                held.guard()
            except BaseException:
                failed = True
            if owned_fd is not None:
                try:
                    os.close(owned_fd)
                except BaseException:
                    failed = True
            if failed:
                if primary is not None:
                    primary.add_note("COPY_FINAL_CUSTODY_OR_CLOSE_FAILED")
                else:
                    raise ValueError("COPY_FINAL_CUSTODY_OR_CLOSE_FAILED")
    return receipt
