"""Finite collector request contract; no execution or qualification authority."""

import re


def validate_request(request):
    keys = {
        "kind", "mode", "pair_id", "task_digest", "input_digest",
        "host_profile_digest", "collection_digest", "deployment_digest",
    }
    if type(request) is not dict or set(request) != keys:
        raise ValueError("JSON_SUM_REQUEST_FIELDS")
    if request["kind"] != "task" or request["mode"] not in (
        "baseline", "instrumented"
    ):
        raise ValueError("JSON_SUM_TASK_MODE")
    if type(request["pair_id"]) is not str or not re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{0,127}", request["pair_id"]
    ):
        raise ValueError("JSON_SUM_PAIR_ID")
    for key in keys - {"kind", "mode", "pair_id"}:
        if type(request[key]) is not str or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", request[key]
        ):
            raise ValueError("JSON_SUM_BINDING_DIGEST")


def validate_boundaries(boundaries):
    if type(boundaries) is not dict or set(boundaries) != {
        "TASK_ACCEPTED", "TASK_COMPLETED"
    }:
        raise ValueError("JSON_SUM_BOUNDARY_FIELDS")
    start, end = boundaries["TASK_ACCEPTED"], boundaries["TASK_COMPLETED"]
    if not (
        type(start) is int and type(end) is int and 0 <= start < end < 2**63
    ):
        raise ValueError("JSON_SUM_BOUNDARY_CHRONOLOGY")
