"""In-process fixed line-count task callback for the existing local collector.

The collector supplies Linux CLOCK_BOOTTIME marks in this process. This leaf
does not switch instrumentation, attest a host, or dispatch native effects.
Source/dependency custody and baseline/instrumented setup belong to the caller.
"""

import sys
import time

from . import phase3_reference_tasks as tasks
from .native_phase3_workload_json_sum_contract import (
    validate_boundaries, validate_request,
)
from .oci_worker_protocol import canonical_digest, canonical_json


def execute(request, mark):
    """Validate before acceptance, execute once, mark completion after output.

    No clock conversion, retry, subprocess or file mutation. An exception leaves
    the collector's partial marks intact and never emits a successful receipt.
    """
    validate_request(request)
    request = dict(request)
    if sys.platform != "linux" or not hasattr(time, "CLOCK_BOOTTIME"):
        raise ValueError("LINE_COUNT_LINUX_BOOTTIME_REQUIRED")
    with open(tasks.__file__, "rb") as source:
        source_raw = source.read(1024 * 1024 + 1)
    descriptor = tasks.describe_tasks(source_raw)["BENIGN_LINE_COUNT"]
    if (
        request["task_digest"] != canonical_digest(descriptor)
        or request["input_digest"] != descriptor["input"]["digest"]
    ):
        raise ValueError("LINE_COUNT_TASK_INPUT_BINDING")
    raw = tasks.reference_inputs()["lines_text"]
    start = mark("TASK_ACCEPTED")
    result = tasks.execute_reference_task("BENIGN_LINE_COUNT", raw)
    end = mark("TASK_COMPLETED")
    boundaries = {"TASK_ACCEPTED": start, "TASK_COMPLETED": end}
    validate_boundaries(boundaries)
    return canonical_json({
        "schema": "aragorn/phase3-local-measurement-receipt/v1",
        "request_digest": canonical_digest(request),
        "deployment_digest": request["deployment_digest"],
        "boundaries": boundaries,
        "observation": {"task": descriptor, "result": result},
    })
