"""Finite HTTP94 original-plan and permanent-handoff source bridge.

Only exact frozen source bytes are rendered. This is not a host/guest capture
launcher and does not activate, collect, adapt controller marks, or retry. The
caller must compose the matching nine-writer preparation, 22-source measurement
planner/validator/provisioner, and 43-path identity reader before installation.
"""

from __future__ import annotations

import hashlib

PLAN = "scripts/runtime_native_common_attempt_plan.py"
HANDOFF = "scripts/runtime_native_common_measurement_handoff.py"
INPUTS = {
    PLAN: (28754, "d4c0e36fa6920448818401caecf07286a79f14877668cebc5ea3b04a7992c433"),
    HANDOFF: (
        20956,
        "b1adf288edfda538ee43d04eb5aeda8a853c9f6879d77965c350c884164b3551",
    ),
}


class NativeHttpAttemptPlanRenderError(ValueError):
    """The finite predecessor or reversible bridge boundary changed."""


def _change(raw, before, after, changes):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != 1 or after in raw:
        raise NativeHttpAttemptPlanRenderError("HTTP attempt-plan anchor changed")
    result = raw.replace(before, after)
    if result.replace(after, before) != raw:
        raise NativeHttpAttemptPlanRenderError("HTTP attempt-plan reversal changed")
    changes.append((before, after))
    return result


_ACTION = '''def _http_action(arguments, inputs, selected, boot, descriptor_raw, payload_raw):
    """Bind exact writer bytes and selected action; no observation or side effect."""
    _require(common.PREPARATION_SCHEMA == "aragorn/native-common-deployment-preparation/v4"
             and len(common.PROVISIONING_PATHS) == 9
             and set(inputs) == set(common.PROVISIONING_PATHS),
             "HTTP_READY_NINE_WRITER_PREPARATION_REQUIRED")
    binding = _http.fixture_binding(common.old._parse(inputs[common.HTTP_FIXTURE], 4096))
    fixture = binding["fixture"]
    descriptor = common.old._parse(descriptor_raw, 4096)
    readiness = common.old._parse(inputs[common.HTTP_READINESS], 4096)
    _require(fixture["container_id"] == arguments["container_id"]
             and fixture["boot_id"] == boot
             and descriptor == _http.endpoint_descriptor(binding)
             and descriptor_raw == canonical_json(descriptor)
             and payload_raw == _canary.canary_request(selected),
             "FIXED_NATIVE_HTTP_ACTION_CHANGED")
    _require(set(readiness) == {"schema", "readiness_nonce", "fixture_binding_digest", "timeout_ms"}
             and readiness["schema"] == "aragorn/runtime-http-readiness-input/v1"
             and readiness["fixture_binding_digest"] == common.old._digest(inputs[common.HTTP_FIXTURE])
             and readiness["readiness_nonce"] == arguments["readiness_nonce"]
             and type(readiness["timeout_ms"]) is int and readiness["timeout_ms"] == 500,
             "HTTP_READINESS_WRITER_JOIN_CHANGED")
    _canary.readiness_request(readiness["readiness_nonce"])
    _require(inputs[common.HTTP_FIXTURE] == canonical_json(binding)
             and inputs[common.HTTP_READINESS] == canonical_json(readiness),
             "HTTP_WRITER_CANONICAL_BYTES_CHANGED")
    policy = common.old._parse(inputs[common.old.live._POLICY])
    expected = _http.action_digests(selected, binding)
    _require(type(policy.get("allow")) is list and len(policy["allow"]) == 1
             and all(policy["allow"][0].get(key) == pin for key, pin in expected.items()),
             "ACTUAL_HTTP_WRITER_ACTION_DIFFERS")
    return {"fixture_binding_digest": common.old._digest(inputs[common.HTTP_FIXTURE]),
            "readiness_input_digest": common.old._digest(inputs[common.HTTP_READINESS]),
            "readiness_nonce": readiness["readiness_nonce"]}


'''


def _plan(raw, changes):
    raw = _change(
        raw,
        "from aragorn import native_phase3_common_preparation as common\n",
        "from aragorn import native_phase3_common_preparation as common\n"
        "from aragorn import native_phase3_http_collection_verify as _http\n"
        "from aragorn import native_phase3_http_canary_contract as _canary\n",
        changes,
    )
    raw = _change(
        raw,
        '    "baseline_capture_raw",\n}\nFALSE_FLAGS',
        '    "baseline_capture_raw",\n    "http_attempt_id",\n    "readiness_nonce",\n}\nFALSE_FLAGS',
        changes,
    )
    raw = _change(
        raw,
        "        arguments = dict(common_arguments)\n",
        "        arguments = dict(common_arguments)\n"
        '        _require(arguments.pop("http_attempt_id") == selected_attempt_id,\n'
        '                 "HTTP_SELECTED_ATTEMPT_DIFFERS_FROM_WRITER")\n',
        changes,
    )
    raw = _change(
        raw,
        'SCHEMA = "aragorn/native-common-attempt-plan/v1"',
        'SCHEMA = "aragorn/native-http-attempt-plan/v1"',
        changes,
    )
    raw = _change(
        raw,
        "def prepare_native_common_attempt_plan(\n",
        _ACTION + "def prepare_native_common_attempt_plan(\n",
        changes,
    )
    raw = _change(
        raw,
        "        private_pins = {common.old._digest(raw) for raw in inputs.values()}\n",
        "        http_binding = _http_action(arguments, inputs, selected_attempt_id,\n"
        "            expected_boot_id, protected_descriptor_raw, payload_raw)\n"
        '        _require(expected_attempt_families.get(selected_attempt_id) == "EXFILTRATION"\n'
        "                 and selected_attempt_id != expected_unattributed_attempt_id,\n"
        '                 "HTTP_SELECTED_FAMILY_OR_ATTRIBUTION_CHANGED")\n'
        "        private_pins = {common.old._digest(raw) for raw in inputs.values()}\n",
        changes,
    )
    start = "                descriptor = common.old._parse(protected_descriptor_raw, 4096)\n"
    end = '                    "FIXED_NATIVE_ACTION_CHANGED",\n                )\n'
    if raw.count(start.encode()) != 1 or raw.count(end.encode()) != 1:
        raise NativeHttpAttemptPlanRenderError("HTTP action boundary changed")
    before = raw[raw.index(start.encode()) : raw.index(end.encode()) + len(end)].decode(
        "ascii"
    )
    raw = _change(
        raw,
        before,
        "                _require(_http_action(arguments, inputs, selected_attempt_id,\n"
        "                    expected_boot_id, protected_descriptor_raw, payload_raw) == http_binding,\n"
        '                    "HTTP_ACTION_WRITER_READBACK_CHANGED")\n',
        changes,
    )
    raw = _change(
        raw,
        "                    source_records=sources,\n",
        "                    source_records=sources,\n"
        "                    http_binding=http_binding,\n",
        changes,
    )
    raw = _change(
        raw,
        '    "NO_AUTOMATIC_RETRY_RESET_ACTIVATION_OR_OVERALL_SOURCE_ATTESTATION",\n',
        '    "NO_AUTOMATIC_RETRY_RESET_ACTIVATION_OR_OVERALL_SOURCE_ATTESTATION",\n'
        '    "HTTP_SOURCE_FUNCTIONS_ARE_INSPECTED_NOT_GENERIC_MARK_CALLBACKS",\n'
        '    "BROKER_STARTUP_READINESS_AND_SAME_PROCESS_LISTENER_WITNESS_REMAIN_REQUIRED",\n',
        changes,
    )
    return raw


def _handoff(raw, changes):
    raw = _change(
        raw,
        "if __package__:\n"
        "    from scripts import runtime_native_blocked_create_workload as workload\n"
        "else:\n"
        '    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]\n'
        "    import runtime_native_blocked_create_workload as workload\n\n"
        "from aragorn import native_phase3_blocked_create_verify as blockedverify\n",
        "if not __package__:\n"
        '    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]\n\n'
        "from aragorn import native_phase3_http_collection as workload\n"
        "from aragorn import native_phase3_http_collection_verify as httpverify\n"
        "from aragorn import native_phase3_http_canary_contract as canary\n",
        changes,
    )
    raw = _change(
        raw,
        'SCHEMA = "aragorn/native-common-measurement-handoff/v1"',
        'SCHEMA = "aragorn/native-http-measurement-handoff/v1"',
        changes,
    )
    raw = _change(
        raw,
        '        "execute": workload.run_native_blocked_create_workload,\n'
        '        "verify": blockedverify.verify_native_blocked_create,\n',
        '        "execute": workload.collect_native_http_attempt,\n'
        '        "verify": httpverify.verify_native_http_collection,\n',
        changes,
    )
    raw = _change(
        raw,
        '            "payload_bytes_verified",\n            "activation_performed",\n',
        '            "payload_bytes_verified",\n'
        '            "http_endpoint_bound",\n            "http_fixture_binding_digest",\n'
        '            "activation_performed",\n',
        changes,
    )
    raw = _change(
        raw,
        "def _provisioned(value: dict, measured: dict, binding_pin: str) -> bytes:\n",
        "def _provisioned(value: dict, measured: dict, binding_pin: str, fixture_binding_pin: str) -> bytes:\n",
        changes,
    )
    raw = _change(
        raw,
        '        and detached["schema"] == "aragorn/native-measurement-provisioning/v1"\n',
        '        and detached["schema"] == "aragorn/native-http-measurement-provisioning/v1"\n'
        '        and detached["http_endpoint_bound"] is True\n'
        '        and detached["http_fixture_binding_digest"]\n'
        "        == fixture_binding_pin\n",
        changes,
    )
    raw = _change(
        raw,
        "                        provisioned, measured, expected_binding_digest\n",
        "                        provisioned, measured, expected_binding_digest,\n"
        "                        common.old._digest(inputs[common.HTTP_FIXTURE])\n",
        changes,
    )
    raw = _change(
        raw,
        '            selected = scheduled_request.get("attempt_id")\n',
        '            selected = scheduled_request.get("attempt_id")\n'
        "            canary.canary_bytes(selected)\n"
        '            _require(common.PREPARATION_SCHEMA == "aragorn/native-common-deployment-preparation/v4"\n'
        "                     and len(common.PROVISIONING_PATHS) == 9\n"
        "                     and set(inputs) == set(common.PROVISIONING_PATHS)\n"
        '                     and scheduled_request.get("family") == "EXFILTRATION"\n'
        '                     and scheduled_request.get("negative_control") is False,\n'
        '                     "HTTP_READY_ATTRIBUTED_HANDOFF_REQUIRED")\n',
        changes,
    )
    raw = _change(
        raw,
        '    "NO_ACTIVATION_SERVICE_CLEANUP_TIMEOUT_RESET_OR_AUTOMATIC_RETRY",\n',
        '    "NO_ACTIVATION_SERVICE_CLEANUP_TIMEOUT_RESET_OR_AUTOMATIC_RETRY",\n'
        '    "HTTP_FUNCTION_SOURCE_PINS_DO_NOT_ADAPT_GENERIC_COLLECTOR_MARKS",\n'
        '    "BROKER_READINESS_INPUT_IS_NOT_REACHABILITY_OR_LISTENER_EVIDENCE",\n',
        changes,
    )
    return raw


def render(original):
    """Return exactly two source-keyed outputs; no generated imports or effects."""
    if type(original) is not dict:
        raise NativeHttpAttemptPlanRenderError("HTTP attempt-plan sources required")
    result = {}
    for name, transform in ((PLAN, _plan), (HANDOFF, _handoff)):
        raw = original.get(name)
        if (
            type(raw) is not bytes
            or (len(raw), hashlib.sha256(raw).hexdigest()) != INPUTS[name]
        ):
            raise NativeHttpAttemptPlanRenderError(
                "HTTP attempt-plan predecessor pin changed"
            )
        changes = []
        rendered = transform(raw, changes)
        restored = rendered
        for before, after in reversed(changes):
            restored = restored.replace(after, before)
        if restored != raw:
            raise NativeHttpAttemptPlanRenderError(
                "HTTP attempt-plan changed unrelated bytes"
            )
        result[name] = rendered
    return result
