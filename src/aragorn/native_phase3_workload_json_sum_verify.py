"""Offline JSON-sum receipt consumer, independent of the task implementation.

Completion verifies exact fixed input/output and collector interval bindings.
It cannot prove instrumentation, live host identity, source custody or native
effect attribution from self-reported receipt bytes. Those remain external gates.
"""

import hashlib
import json
import re

from .native_phase3_workload_json_sum_contract import (
    validate_boundaries, validate_request,
)
from .oci_worker_protocol import canonical_digest, canonical_json


def verify(receipt_bytes, request, boundaries):
    validate_request(request)
    validate_boundaries(boundaries)
    if type(receipt_bytes) is not bytes or not 0 < len(receipt_bytes) <= 65536:
        raise ValueError("JSON_SUM_RECEIPT_BYTES")
    try:
        receipt = json.loads(receipt_bytes)
        if canonical_json(receipt) != receipt_bytes:
            raise ValueError("JSON_SUM_RECEIPT_CANONICAL")
        source_digest = receipt["observation"]["task"]["module_source_digest"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise ValueError("JSON_SUM_RECEIPT_FORMAT") from exc
    if type(source_digest) is not str or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", source_digest
    ):
        raise ValueError("JSON_SUM_SOURCE_DIGEST")
    # Deliberately independent fixed expectations; never call the producer.
    input_raw = b'{"values":[1,2,3,4,5,6,7]}\n'
    input_digest = "sha256:" + hashlib.sha256(input_raw).hexdigest()
    output = {"sum": 28}
    descriptor = {
        "schema": "aragorn/phase3-reference-task/v1",
        "authority": "SOURCE_BOUND_FIXED_LAB_TASK_NOT_MEASUREMENT",
        "template_id": "BENIGN_JSON_SUM",
        "entrypoint": "execute_reference_task",
        "module_source_digest": source_digest,
        "input": {
            "ref": "numbers_json", "encoding": "UTF-8",
            "bytes": len(input_raw), "digest": input_digest,
        },
        "output": {
            "expected": output, "encoding": "CANONICAL_JSON_ASCII_NO_LF",
            "copy_target": None,
        },
        "paired_measurement_eligible": False,
        "phase3_exit_eligible": False,
    }
    expected = {
        "schema": "aragorn/phase3-local-measurement-receipt/v1",
        "request_digest": canonical_digest(request),
        "deployment_digest": request["deployment_digest"],
        "boundaries": boundaries,
        "observation": {
            "task": descriptor,
            "result": {
                "schema": "aragorn/phase3-reference-task-result/v1",
                "authority": "FIXED_LAB_TASK_OUTPUT_NOT_MEASUREMENT",
                "template_id": "BENIGN_JSON_SUM",
                "input_digest": input_digest,
                "output": output,
                "output_digest": canonical_digest(output),
                "paired_measurement_eligible": False,
                "phase3_exit_eligible": False,
            },
        },
    }
    if (
        request["task_digest"] != canonical_digest(descriptor)
        or request["input_digest"] != input_digest
        or receipt_bytes != canonical_json(expected)
    ):
        raise ValueError("JSON_SUM_RECEIPT_BINDING_OR_OUTPUT")
    return {
        "receipt_digest": "sha256:" + hashlib.sha256(receipt_bytes).hexdigest(),
        "request_digest": canonical_digest(request),
        "deployment_digest": request["deployment_digest"],
        "semantics": {"completed": True},
    }
