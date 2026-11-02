"""Render finite HTTP branches over the exact common74 capability sources.

No predecessor is edited and no service is launched. The common successor
stager owns publication, custody, inventory and deployment-source pins.
"""

from __future__ import annotations

import hashlib

_PREFIX = "src/aragorn/"
_GRANT = _PREFIX + "runtime_capability_grant.py"
_V2 = _PREFIX + "runtime_action_broker_v2.py"
_V3 = _PREFIX + "runtime_action_broker_v3.py"
_V4 = _PREFIX + "runtime_action_broker_v4.py"
_V5 = _PREFIX + "runtime_action_broker_v5.py"
_JOURNAL = _PREFIX + "runtime_endpoint_journal.py"
INPUTS = {
    _GRANT: (9741, "058aa743c6bdebffe1660120d88886d465aaaa5192171979e466ba6ce20f5681"),
    _V2: (18164, "a77d7c5cc2b607b9234f6758283bdff74c73586651e6aa7d5a9e3c3ab48b14e3"),
    _V3: (30803, "408f0b5373139c93b13e61fcf4ea6791865841806f0a9aa8a269e095cd0d9f8d"),
    _V4: (51170, "a452fe26c0861b102a61c3763192a729cc6184a37c26aebc1086d42b5400f565"),
    _V5: (14578, "cd7b85e520de7e580d74ffb66c13e67e6984c9f9513c7a7b03c5ebe5416fba6a"),
    _JOURNAL: (
        17052,
        "c6decbe2de6c0ba48af7b2ccda10a38cd98769f43b186fe2f7ef125f01a977f2",
    ),
}


class HttpCapabilityRenderError(ValueError):
    """A common74 source or the reviewed finite boundary changed."""


def _change(raw, before, after, changes):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != 1:
        raise HttpCapabilityRenderError("HTTP capability anchor changed")
    result = raw.replace(before, after)
    if result.count(after) != 1 or result.replace(after, before) != raw:
        raise HttpCapabilityRenderError("HTTP capability change is not reversible")
    changes.append((before, after))
    return result


def _function_change(raw, function, before, after, changes):
    anchor = ("def " + function + "(").encode("ascii")
    if raw.count(anchor) != 1:
        raise HttpCapabilityRenderError("HTTP capability function changed")
    start = raw.index(anchor)
    end = raw.find(b"\n\ndef ", start + len(anchor))
    end = len(raw) if end == -1 else end
    section = raw[start:end].decode("ascii")
    if section.count(before) != 1:
        raise HttpCapabilityRenderError("HTTP capability function anchor changed")
    return _change(raw, section, section.replace(before, after), changes)


def _render(name, original):
    if (
        type(original) is not bytes
        or (len(original), hashlib.sha256(original).hexdigest()) != INPUTS[name]
    ):
        raise HttpCapabilityRenderError("HTTP capability predecessor pin changed")
    changes = []
    if name == _JOURNAL:
        raw = _change(
            original,
            '_SCHEMA = "aragorn/runtime-endpoint-journal-event/v2"',
            '_SCHEMA = "aragorn/runtime-endpoint-journal-event/v3"',
            changes,
        )
        raw = _function_change(
            raw,
            "_valid_event",
            'not in {("ALLOW", "CREATED"), ("BLOCK", "NOT_PERFORMED")}',
            'not in {("ALLOW", "CREATED"), ("ALLOW", "SENT"), ("BLOCK", "NOT_PERFORMED")}',
            changes,
        )
        before = """                and (value.get("verdict"), value.get("effect_status"))
                in {("ALLOW", "CREATED"), ("BLOCK", "NOT_PERFORMED")}
"""
        after = """                and (
                    (value.get("schema") == "aragorn/runtime-action-broker-result/v1"
                     and value.get("authority") == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
                     and (value.get("verdict"), value.get("effect_status"))
                     in {("ALLOW", "CREATED"), ("BLOCK", "NOT_PERFORMED")})
                    or (value.get("schema") == "aragorn/runtime-http-broker-result/v1"
                        and value.get("authority") == "BROKER_HTTP_DECISION_ONLY_NOT_SINK_OR_RUN_QUALIFICATION"
                        and (value.get("verdict"), value.get("effect_status"))
                        in {("ALLOW", "SENT"), ("BLOCK", "NOT_PERFORMED")})
                )
"""
        raw = _function_change(raw, "note", before, after, changes)
    else:
        raw = _change(
            original,
            "from __future__ import annotations\n",
            "from __future__ import annotations\n\nfrom . import runtime_http_capability as _http_capability\n",
            changes,
        )
    if name in {_GRANT, _V2}:
        variable = "document" if name == _GRANT else "submission"
        raw = _change(
            raw,
            f'    if {variable}["schema"] != "aragorn/runtime-observed-create-submission/v2":\n',
            f'    if {variable}["schema"] not in {{"aragorn/runtime-observed-create-submission/v2", _http_capability.PROFILED_SCHEMA}}:\n',
            changes,
        )
        variable = "profiled" if name == _GRANT else "submission"
        old = f'    legacy = {{**{variable}, "schema": "aragorn/runtime-observed-create-submission/v1"}}\n    legacy.pop("runtime_attribution")\n'
        old += (
            "    observed = _observed_submission(legacy)\n"
            if name == _GRANT
            else "    legacy = _observed_submission(legacy)\n"
        )
        target = "observed" if name == _GRANT else "legacy"
        new = f"    if _http_capability.is_http_profiled({variable}):\n        {target} = _http_capability.observed_from_profile({variable})\n    else:\n"
        new += "".join("    " + line for line in old.splitlines(keepends=True))
        raw = _change(raw, old, new, changes)
    if name == _V2:
        raw = _function_change(
            raw,
            "mediate_profiled_runtime_create",
            "    try:\n        result = mediate_observed_runtime_create(\n",
            "    mediator = (_http_capability.mediation.mediate_observed_http\n                if _http_capability.is_http_profiled(submission)\n                else mediate_observed_runtime_create)\n    try:\n        result = mediator(\n",
            changes,
        )
    if name in {_V3, _V4}:
        function = "_result_record" if name == _V3 else "_profile_result_record"
        raw = _function_change(
            raw,
            function,
            '    document = _exact(receipt, _PROFILE_RECEIPT_FIELDS, "runtime profile receipt")\n',
            '    if _http_capability.is_http_claim(claim):\n        return _http_capability.profile_result_record(claim, receipt)\n    document = _exact(receipt, _PROFILE_RECEIPT_FIELDS, "runtime profile receipt")\n',
            changes,
        )
    if name == _V3:
        raw = _function_change(
            raw,
            "_claim",
            '    document = _exact(value, _CLAIM_FIELDS, "runtime capability lease claim")\n',
            '    if _http_capability.is_http_claim(value):\n        return _http_capability.validate_claim(value, expected_lease_digest)\n    document = _exact(value, _CLAIM_FIELDS, "runtime capability lease claim")\n',
            changes,
        )
        raw = _function_change(
            raw,
            "_lease_result",
            '    document = _exact(value, _RESULT_FIELDS, "runtime capability lease result")\n',
            '    if _http_capability.is_http_claim(claim):\n        return _http_capability.validate_lease_result(value, claim)\n    document = _exact(value, _RESULT_FIELDS, "runtime capability lease result")\n',
            changes,
        )
    if name == _V4:
        raw = _function_change(
            raw,
            "_build_claim",
            '    request = legacy["envelope"]["request"]\n',
            '    if legacy.get("schema") == _http_capability.mediation.SUBMISSION_SCHEMA:\n        return _http_capability.build_grant_claim(\n            grant, lease, legacy, attribution, submission_digest, now_unix\n        )\n    request = legacy["envelope"]["request"]\n',
            changes,
        )
    # Post-effect receipt, response and held-lineage cleanup failures must never
    # turn a completed send into a known no-effect outcome or reset its grant.
    functions = {
        _V2: ("mediate_profiled_runtime_create", "_handle_connection"),
        _V3: ("_consume_lease", "_handle_connection"),
        _V4: ("_consume_grant", "_handle_connection"),
        _V5: ("mediate_lineage_granted_profiled_runtime_create", "_handle_connection"),
    }.get(name, ())
    for function in functions:
        access = (
            'result.get("effect_status")'
            if function == "mediate_lineage_granted_profiled_runtime_create"
            else 'result["effect_status"]'
        )
        raw = _function_change(
            raw,
            function,
            access + ' == "CREATED":',
            access + ' in {"CREATED", "SENT"}:',
            changes,
        )
    restored = raw
    for before, after in reversed(changes):
        if restored.count(after) != 1:
            raise HttpCapabilityRenderError("HTTP capability reverse anchor changed")
        restored = restored.replace(after, before)
    if restored != original:
        raise HttpCapabilityRenderError("HTTP capability unrelated bytes changed")
    return raw


def render(original: dict[str, bytes]) -> dict[str, bytes]:
    """Return six reviewed replacements keyed by repository source name."""
    if type(original) is not dict or not set(INPUTS) <= set(original):
        raise HttpCapabilityRenderError("HTTP capability source inventory changed")
    return {name: _render(name, original[name]) for name in INPUTS}
