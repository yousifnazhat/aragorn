"""Finite HTTP extensions to frozen measurement planning/replay sources.

Returns source bytes only. Does not install, import rendered code, launch a
runtime or manufacture a measurement. The predecessor files remain unchanged.
"""

from __future__ import annotations

import hashlib

PLAN = "src/aragorn/runtime_broker_measurement_plan.py"
PRIOR = "src/aragorn/runtime_broker_decision_measurement_verify.py"
EFFECTIVE = "src/aragorn/runtime_broker_effective_receipt_verify.py"
INPUTS = {
    PLAN: (13206, "5789d265c779ad4d5674d7dabe0cd65a289274da6663369d5d17a8557fa78c30"),
    PRIOR: (21956, "0354718223c4f65d2d92908817a0ac29dc3f6e5fcc873933eee8afa65672860f"),
    EFFECTIVE: (
        16027,
        "a8441ec4098d119677b29b3644f5040d6301b29e2c600ca090f90417c1399cfa",
    ),
}
HTTP_MEASUREMENT_SOURCES = (
    "native_phase3_http_canary_contract.py",
    "runtime_http_action.py",
    "runtime_http_broker.py",
    "runtime_http_ingress.py",
    "runtime_http_capability.py",
    "runtime_action_worker.py",
    "runtime_action_observation_publisher.py",
    "runtime_action_observation_publisher_v2.py",
    "runtime_capability_grant.py",
    "runtime_action_broker_v2.py",
    "runtime_action_broker_v3.py",
    "runtime_native_tool_receipts.py",
    "runtime_worker_ingress_measurement.py",
    "runtime_action_service.py",
)


class HttpCollectionRenderError(ValueError):
    """Pinned input or finite reversible anchor changed."""


def _change(raw, before, after):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != 1 or after in raw:
        raise HttpCollectionRenderError("HTTP collection anchor changed")
    changed = raw.replace(before, after)
    if changed.replace(after, before) != raw:
        raise HttpCollectionRenderError("HTTP collection replacement is not reversible")
    return changed


def render(original):
    """Three finite replacements, using the exact common HTTP source inventory."""
    if type(original) is not dict or not set(INPUTS) <= set(original):
        raise HttpCollectionRenderError("HTTP collection source inventory changed")
    outputs = {}
    for name, (size, pin) in INPUTS.items():
        raw = original[name]
        if (
            type(raw) is not bytes
            or len(raw) != size
            or hashlib.sha256(raw).hexdigest() != pin
        ):
            raise HttpCollectionRenderError("HTTP collection predecessor pin changed")
        raw = _change(
            raw,
            "from __future__ import annotations\n",
            "from __future__ import annotations\n\nfrom . import native_phase3_http_collection_verify as _http_collection\n",
        )
        if name in (PLAN, PRIOR):
            raw = _change(
                raw,
                "_SOURCES = {\n",
                "_SOURCES = {\n"
                + "".join(
                    '    "' + source + '",\n' for source in HTTP_MEASUREMENT_SOURCES
                ),
            )
        if name == PLAN:
            raw = _change(
                raw,
                '_require(len(binding_raw) <= 4096, "binding exceeds credential boundary")',
                '_require(len(binding_raw) <= 8192, "binding exceeds credential boundary")',
            )
            start = '    _require(\n        set(descriptor) == {"schema", "root_device", "root_inode", "target_name"}\n'
            end = '        "unsupported protected action descriptor",\n    )\n'
            if raw.count(start.encode()) != 1 or raw.count(end.encode()) != 1:
                raise HttpCollectionRenderError("HTTP plan descriptor boundary changed")
            section = raw[
                raw.index(start.encode()) : raw.index(end.encode()) + len(end)
            ].decode("ascii")
            replacement = (
                '    if descriptor.get("schema") == "aragorn/runtime-http-endpoint/v1":\n'
                "        _http_collection.validate_plan_descriptor(\n"
                "            descriptor, grant, pins, attempt_id, expected_boot_id\n"
                "        )\n"
                "    else:\n"
                + "".join("    " + line for line in section.splitlines(keepends=True))
            )
            raw = _change(raw, section, replacement)
        elif name == PRIOR:
            raw = _change(
                raw,
                "plan = _exact(_parse(raw, 4096), _BINDING_KEYS)",
                "plan = _exact(_parse(raw, 8192), _BINDING_KEYS)",
            )
            raw = _change(
                raw,
                '    claim, lease = state["claim"], state["claim"]["lease"]\n',
                '    if profiled.get("schema") == _http_collection.PROFILED:\n'
                "        return _http_collection.native_join(plan, pending, state, profiled, grant_raw, path)\n"
                '    claim, lease = state["claim"], state["claim"]["lease"]\n',
            )
        else:
            raw = _change(
                raw,
                '    profile = claim["profile_claim"]\n',
                '    if claim["profile_claim"].get("schema") == "aragorn/runtime-http-capability-lease-claim/v1":\n'
                "        return _http_collection.result_record(claim, receipt, result, request)\n"
                '    profile = claim["profile_claim"]\n',
            )
        outputs[name] = raw
    return outputs
