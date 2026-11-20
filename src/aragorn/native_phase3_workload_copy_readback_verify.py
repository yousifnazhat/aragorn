"""Independent fixed-output and retained-file consumer under caller-pinned custody.

No producer/reference-task import. Observation requires the original still-valid
fixture; validating a receipt alone never establishes that observation.
"""

import hashlib
import json
import os
import re
import stat
import sys

from .native_phase3_http_canary_contract import require, validate_fixture
from .native_phase3_http_fixture import owned_http_fixture
from .native_phase3_workload_json_sum_contract import validate_boundaries, validate_request
from .oci_worker_protocol import canonical_digest, canonical_json

_INPUT = b"Aragorn Phase 3 benign copy/readback data.\n"


def _identity(metadata):
    return {
        "device": metadata.st_dev, "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid, "gid": metadata.st_gid,
    }


def _directory(fd, expected):
    metadata = os.fstat(fd)
    actual = _identity(metadata)
    require(stat.S_ISDIR(metadata.st_mode) and actual == expected
            and expected["mode"] == 0o700
            and expected["uid"] == os.geteuid() and expected["gid"] == os.getegid(),
            "COPY_VERIFY_DIRECTORY_CHANGED")
    return actual


def _file(fd, directory_fd, expected):
    opened = os.fstat(fd)
    named = os.stat("allowed-copy.txt", dir_fd=directory_fd, follow_symlinks=False)
    for metadata in (opened, named):
        actual = {
            **_identity(metadata), "nlink": metadata.st_nlink, "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns, "ctime_ns": metadata.st_ctime_ns,
        }
        require(stat.S_ISREG(metadata.st_mode) and actual == expected
                and actual["mode"] == 0o600 and actual["nlink"] == 1
                and actual["size"] == len(_INPUT)
                and actual["uid"] == os.geteuid() and actual["gid"] == os.getegid(),
                "COPY_VERIFY_FILE_CHANGED")
    return actual


def expected_copy_observation(raw, request, boundaries, *, expected_copy_directory_identity, expected_fixture):
    """Derive expectations only, for comparison to a separately acquired observation."""
    validate_request(request)
    validate_boundaries(boundaries)
    request, boundaries = dict(request), dict(boundaries)
    expected = expected_copy_directory_identity
    require(type(expected) is dict
            and set(expected) == {"device", "inode", "mode", "uid", "gid"}
            and all(type(value) is int and value >= 0 for value in expected.values())
            and expected["inode"] > 0 and expected["mode"] == 0o700, "COPY_VERIFY_DIRECTORY_IDENTITY_REQUIRED")
    expected = dict(expected)
    validate_fixture(expected_fixture)
    fixture = dict(expected_fixture)
    require(type(raw) is bytes and 0 < len(raw) <= 65536, "COPY_VERIFY_RECEIPT_BYTES")
    try:
        receipt = json.loads(raw)
        require(canonical_json(receipt) == raw, "COPY_VERIFY_CANONICAL")
        source_digest = receipt["observation"]["task"]["module_source_digest"]
        file_identity = receipt["observation"]["retained_file"]["identity"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise ValueError("COPY_VERIFY_RECEIPT_FORMAT") from exc
    require(type(source_digest) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", source_digest) is not None,
            "COPY_VERIFY_SOURCE_DIGEST")
    require(type(file_identity) is dict
            and set(file_identity) == {
                "device", "inode", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"
            }
            and all(type(value) is int and value >= 0 for value in file_identity.values())
            and file_identity["inode"] > 0 and file_identity["nlink"] == 1
            and file_identity["size"] == len(_INPUT) and file_identity["mode"] == 0o600
            and file_identity["uid"] == expected["uid"] and file_identity["gid"] == expected["gid"],
            "COPY_VERIFY_FILE_IDENTITY_REQUIRED")
    digest = hashlib.sha256(_INPUT).hexdigest()
    input_digest = "sha256:" + digest
    output = {"bytes": len(_INPUT), "sha256": digest, "readback_equal": True}
    descriptor = {
        "schema": "aragorn/phase3-reference-task/v1",
        "authority": "SOURCE_BOUND_FIXED_LAB_TASK_NOT_MEASUREMENT",
        "template_id": "BENIGN_COPY_READBACK", "entrypoint": "execute_reference_task",
        "module_source_digest": source_digest,
        "input": {"ref": "allowed_copy_text", "encoding": "UTF-8",
                  "bytes": len(_INPUT), "digest": input_digest},
        "output": {"expected": output, "encoding": "CANONICAL_JSON_ASCII_NO_LF",
                   "copy_target": "allowed-copy.txt"},
        "paired_measurement_eligible": False, "phase3_exit_eligible": False,
    }
    expected_receipt = {
        "schema": "aragorn/phase3-local-measurement-receipt/v1",
        "request_digest": canonical_digest(request),
        "deployment_digest": request["deployment_digest"], "boundaries": boundaries,
        "observation": {
            "task": descriptor,
            "result": {
                "schema": "aragorn/phase3-reference-task-result/v1",
                "authority": "FIXED_LAB_TASK_OUTPUT_NOT_MEASUREMENT",
                "template_id": "BENIGN_COPY_READBACK", "input_digest": input_digest,
                "output": output, "output_digest": canonical_digest(output),
                "paired_measurement_eligible": False, "phase3_exit_eligible": False,
            },
            "retained_file": {
                "basename": "allowed-copy.txt", "directory_identity": expected,
                "fixture_digest": canonical_digest(fixture), "identity": file_identity,
            },
        },
    }
    require(request["task_digest"] == canonical_digest(descriptor)
            and request["input_digest"] == input_digest
            and raw == canonical_json(expected_receipt), "COPY_VERIFY_RECEIPT_BINDING_OR_OUTPUT")
    return {"schema": "aragorn/phase3-copy-readback-observation/v1",
            "receipt_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "request_digest": expected_receipt["request_digest"], "deployment_digest": request["deployment_digest"],
            "collection_digest": request["collection_digest"], "pair_id": request["pair_id"], "mode": request["mode"],
            "boundaries": boundaries, "fixture": fixture, "directory_identity": expected,
            "file_identity": file_identity, "content_digest": input_digest}


def observe_copy(raw, request, boundaries, *, copy_directory_fd, expected_copy_directory_identity, expected_fixture):
    """Return independently read bytes and observation only after every final custody/close check."""
    require(type(copy_directory_fd) is int and copy_directory_fd >= 0,
            "COPY_VERIFY_DIRECTORY_FD_REQUIRED")
    observation = expected_copy_observation(raw, request, boundaries,
                                            expected_copy_directory_identity=expected_copy_directory_identity,
                                            expected_fixture=expected_fixture)
    fixture, expected, file_identity = (observation[k] for k in ("fixture", "directory_identity", "file_identity"))
    descriptors = []
    with owned_http_fixture(fixture) as held:
        try:
            held.guard()
            _directory(copy_directory_fd, expected)
            directory_fd = os.dup(copy_directory_fd)
            descriptors.append(directory_fd)
            _directory(directory_fd, expected)
            fd = os.open("allowed-copy.txt", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory_fd)
            descriptors.append(fd)
            _file(fd, directory_fd, file_identity)
            copied = os.read(fd, len(_INPUT) + 1)
            content_digest = "sha256:" + hashlib.sha256(copied).hexdigest()
            require(copied == _INPUT and content_digest == observation["content_digest"],
                    "COPY_VERIFY_CONTENT_CHANGED")
            _file(fd, directory_fd, file_identity)
        finally:
            primary, failed = sys.exception(), False
            try:
                _directory(copy_directory_fd, expected)
                if descriptors:
                    observation["directory_identity"] = _directory(descriptors[0], expected)
                if len(descriptors) == 2:
                    observation["file_identity"] = _file(descriptors[1], descriptors[0], file_identity)
                held.guard()
            except BaseException:
                failed = True
            for descriptor_fd in reversed(descriptors):
                try:
                    os.close(descriptor_fd)
                except BaseException:
                    failed = True
            if failed:
                if primary is not None:
                    primary.add_note("COPY_VERIFY_FINAL_CUSTODY_OR_CLOSE_FAILED")
                else:
                    raise ValueError("COPY_VERIFY_FINAL_CUSTODY_OR_CLOSE_FAILED")
    observation["content_digest"] = content_digest
    return copied, observation


def verify(raw, request, boundaries, *, copy_directory_fd, expected_copy_directory_identity, expected_fixture):
    """Existing collector callback: no completion from a receipt alone."""
    _, observation = observe_copy(raw, request, boundaries, copy_directory_fd=copy_directory_fd,
                                  expected_copy_directory_identity=expected_copy_directory_identity,
                                  expected_fixture=expected_fixture)
    return {**{key: observation[key] for key in ("receipt_digest", "request_digest", "deployment_digest")},
            "semantics": {"completed": True}}
