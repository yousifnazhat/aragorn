"""Stage bounded effective-BLOCK receipts without changing frozen predecessors."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import stage_runtime_broker_measurement_receipt_profile as predecessor

renderer = predecessor.renderer
base = predecessor.base
_PARENT = "scripts/stage_runtime_broker_measurement_receipt_profile.py"
_PARENT_PIN = (
    8415,
    "sha256:102da43f55c478c68adb49a72f90c6d326baeaea01209facc0ddb4430f4662e4",
)
_PROFILE = "src/aragorn/runtime_action_broker_v3.py"
_PROFILE_PIN = (
    30803,
    "sha256:408f0b5373139c93b13e61fcf4ea6791865841806f0a9aa8a269e095cd0d9f8d",
)
_GRANT = renderer._GRANT
_HELPER = predecessor._HELPER
_ACTIVATOR = predecessor._ACTIVATOR
_SCHEMA = "aragorn/runtime-broker-effective-receipt-staged-profile/v1"
EVIDENCE_SCHEMA = "aragorn/runtime-broker-decision-measurement/v2"
COMPLETION_SCHEMA = "aragorn/runtime-broker-decision-measurement-complete/v2"
EFFECTIVE_LIMIT = (
    "RECORDED_EFFECTIVE_BLOCK_DOES_NOT_PROVE_BROKER_REASON_OR_POLICY_CAUSALITY"
)
_OLD_LIMIT = "EXISTING_CONSUMPTION_CHECKS_CAN_REFUSE_REPLAY_OR_MIXED_VERDICT_BLOCKS"
_OUTPUTS = {
    _GRANT: (
        51170,
        "sha256:a452fe26c0861b102a61c3763192a729cc6184a37c26aebc1086d42b5400f565",
    ),
    _HELPER: (
        20008,
        "sha256:aa846fc932e78dbad8f255e5b459e18974840dbc2eadd888be347e8b58a799d4",
    ),
    _ACTIVATOR: (
        41455,
        "sha256:d75027b08cba460cc87e6abb5e834ab54c530c4ddce045e39108abea11428d46",
    ),
}

_IMPORTED_VALIDATOR = """from .runtime_action_broker_v3 import (
    _result_record as _profile_result_record,
)
"""
_LOCAL_MARKER = (
    "# Effective receipt validation is local; the V3 predecessor stays frozen.\n"
)
_OLD_DECISION = """    valid_decision = (
        isinstance(decision, dict)
        and decision.get("schema") == "aragorn/runtime-action-decision/v1"
        and decision.get("authority")
        == "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        and decision.get("request_digest") == claim["request_digest"]
        and decision.get("verdict") == result["verdict"]
        and decision.get("reason_codes") == result["reason_codes"]
    )
"""
_EFFECTIVE_DECISION = '''def _effective_recorded_decision(decision: object, result: dict, request_digest: str) -> bool:
    """Validate recorded policy/effective roles, never re-evaluate policy or retry."""
    reasons = result["reason_codes"]
    if type(reasons) is not list or any(type(code) is not str for code in reasons):
        return False
    if decision is None:
        return (
            result["verdict"] == "BLOCK"
            and result["effect_status"] == "NOT_PERFORMED"
            and reasons == ["BROKER_REPLAY_BLOCKED"]
        )
    if (
        type(decision) is not dict
        or decision.get("schema") != "aragorn/runtime-action-decision/v1"
        or decision.get("authority")
        != "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        or decision.get("request_digest") != request_digest
        or type(decision.get("reason_codes")) is not list
        or any(type(code) is not str for code in decision["reason_codes"])
        or any(re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code) is None or code.startswith("BROKER_") for code in decision["reason_codes"])
        or decision["reason_codes"] != sorted(set(decision["reason_codes"]))
        or decision.get("verdict") not in {"ALLOW", "BLOCK"}
        or (decision["verdict"] == "ALLOW") != (decision["reason_codes"] == [])
        or reasons == ["BROKER_REPLAY_BLOCKED"]
    ):
        return False
    if result["verdict"] == "ALLOW":
        return decision["verdict"] == "ALLOW" and reasons == []
    if result["verdict"] != "BLOCK" or not reasons:
        return False
    if decision["verdict"] == "BLOCK" and reasons == decision["reason_codes"]:
        return True
    snapshot_reasons = {
        "BROKER_RUNTIME_PIN_MISMATCH", "BROKER_SENSOR_PIN_MISMATCH",
        "BROKER_EFFECT_MEASUREMENT_MISMATCH", "BROKER_EFFECT_BINDING_MISMATCH",
    }
    final_reasons = {
        "BROKER_CLOCK_ROLLBACK", "BROKER_CLOCK_UNSTABLE",
        "BROKER_CLAIM_STATE_CHANGED", "BROKER_DEADLINE_EXPIRED",
    }
    return (
        (reasons == sorted(set(reasons)) and set(reasons) <= snapshot_reasons)
        or (len(reasons) == 1 and reasons[0] in final_reasons)
    )


'''


class BrokerEffectiveReceiptStageError(ValueError):
    """The fixed successor cannot preserve its reviewed predecessor bytes."""


def _render_grant(raw: bytes, profile_raw: bytes) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != renderer._OUTPUTS[_GRANT] or (
        len(profile_raw),
        base.overlay._digest(profile_raw),
    ) != _PROFILE_PIN:
        raise BrokerEffectiveReceiptStageError("effective receipt predecessor changed")
    source = profile_raw.decode("ascii")
    fields = source[
        source.index("_PROFILE_RECEIPT_FIELDS = {") : source.index("\n\n@dataclass")
    ]
    method = source[
        source.index("def _result_record(\n") : source.index("\n\ndef _lease(")
    ]
    method = renderer._replace(
        method.encode("ascii"), "def _result_record(\n", "def _profile_result_record(\n"
    )
    method = renderer._replace(
        method,
        _OLD_DECISION,
        '    valid_decision = _effective_recorded_decision(decision, result, claim["request_digest"])\n',
    )
    # The receipt/hash/attribution/result-state checks are copied verbatim from
    # the pinned V3 function. Only the role-specific decision relation changes.
    inserted = fields + "\n\n" + _EFFECTIVE_DECISION + method.decode("ascii") + "\n\n"
    original = raw
    raw = renderer._replace(raw, _IMPORTED_VALIDATOR, _LOCAL_MARKER)
    raw = renderer._replace(
        raw, "def _result_record(\n", inserted + "def _result_record(\n"
    )
    restored = renderer._replace(
        raw, inserted + "def _result_record(\n", "def _result_record(\n"
    )
    restored = renderer._replace(restored, _LOCAL_MARKER, _IMPORTED_VALIDATOR)
    if restored != original:
        raise BrokerEffectiveReceiptStageError("grant transformation is not reversible")
    return raw


def _render_helper(raw: bytes) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != predecessor._OUTPUTS[_HELPER]:
        raise BrokerEffectiveReceiptStageError("receipt-retaining helper changed")
    changes = (
        ("aragorn/runtime-broker-decision-measurement/v1", EVIDENCE_SCHEMA),
        ("aragorn/runtime-broker-decision-measurement-complete/v1", COMPLETION_SCHEMA),
        (_OLD_LIMIT, EFFECTIVE_LIMIT),
    )
    original = raw
    for before, after in changes:
        raw = renderer._replace(raw, before, after)
    restored = raw
    for before, after in reversed(changes):
        restored = renderer._replace(restored, after, before)
    if restored != original:
        raise BrokerEffectiveReceiptStageError(
            "helper transformation is not reversible"
        )
    return raw


def _render_activator(raw: bytes, grant_raw: bytes, helper_raw: bytes) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != predecessor._OUTPUTS[_ACTIVATOR]:
        raise BrokerEffectiveReceiptStageError("receipt-retaining activator changed")
    for old, new in (
        (renderer._OUTPUTS[_GRANT][1], base.overlay._digest(grant_raw)),
        (predecessor._OUTPUTS[_HELPER][1], base.overlay._digest(helper_raw)),
    ):
        raw = renderer._replace(raw, old[7:], new[7:])
    return raw


def _verified_payloads():
    base.overlay._read_pinned(_PARENT, *_PARENT_PIN, root=_ROOT)
    inherited, previous_replacements = predecessor._verified_payloads()
    original = inherited | previous_replacements
    profile_raw = base.overlay._read_pinned(_PROFILE, *_PROFILE_PIN, root=_ROOT)
    grant_destination, grant_mode = renderer.predecessor._destination(_GRANT)
    helper_destination, helper_mode = renderer.predecessor._destination(_HELPER)
    activator_destination, activator_mode = renderer.predecessor._destination(
        _ACTIVATOR
    )
    grant = _render_grant(original[grant_destination][2], profile_raw)
    helper = _render_helper(original[helper_destination][2])
    replacements = {
        grant_destination: (_GRANT, grant_mode, grant),
        helper_destination: (_HELPER, helper_mode, helper),
        activator_destination: (
            _ACTIVATOR,
            activator_mode,
            _render_activator(original[activator_destination][2], grant, helper),
        ),
    }
    actual = {
        name: (len(raw), base.overlay._digest(raw))
        for name, _, raw in replacements.values()
    }
    if actual != _OUTPUTS or len(original) != 73 or len(original | replacements) != 73:
        raise BrokerEffectiveReceiptStageError("effective receipt output pins changed")
    return original, replacements


def stage_runtime_broker_effective_receipt_profile(output: Path) -> dict:
    """Stage three exact replacements; neither activate nor measure anything."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise BrokerEffectiveReceiptStageError(
                "DESTDIR must be absolute and absent"
            )
        custody = base._parent_custody(output.parent)
        original, replacements = _verified_payloads()
        report = predecessor.stage_runtime_broker_measurement_receipt_profile(output)
        base._audit_tree(output, original)
        base._apply_overrides(output, replacements)
        final = original | replacements
        base._audit_tree(output, final)
        if (
            _verified_payloads() != (original, replacements)
            or base._parent_custody(output.parent) != custody
        ):
            raise BrokerEffectiveReceiptStageError("effective receipt custody changed")
        return {
            **report,
            "schema": _SCHEMA,
            "effective_block_receipt_staged": True,
            "evidence_schema": EVIDENCE_SCHEMA,
            "completion_schema": COMPLETION_SCHEMA,
            "binding_source_pins": {
                **report["binding_source_pins"],
                Path(_GRANT).name: _OUTPUTS[_GRANT][1],
                Path(_HELPER).name: _OUTPUTS[_HELPER][1],
            },
            "files": [
                {
                    "path": "/" + name,
                    "source_name": source,
                    "bytes": len(raw),
                    "digest": base.overlay._digest(raw),
                    "mode": f"{mode:04o}",
                }
                for name, (source, mode, raw) in sorted(final.items())
            ],
            "source_inputs": report["source_inputs"]
            + [{"name": _PARENT, "bytes": _PARENT_PIN[0], "digest": _PARENT_PIN[1]}],
            "new_dependencies": [
                {
                    **row,
                    "bytes": _OUTPUTS[row["name"]][0],
                    "digest": _OUTPUTS[row["name"]][1],
                }
                if row["name"] in _OUTPUTS
                else row
                for row in report["new_dependencies"]
            ],
            "missing_inputs": [
                value
                for value in report["missing_inputs"]
                if value
                != "replay and broker-only BLOCK verdicts rejected by inherited consumption checks remain pending and are not completed samples"
            ]
            + [
                "successor effective-receipt verification and real workload/attribution/residue evidence remain required; recorded BLOCK is not independent policy or effect proof",
                "one exact new owned-fixture validation remains necessary before any deployment claim; old pending or indeterminate attempts must not be replayed or relabeled",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise BrokerEffectiveReceiptStageError(
            "cannot stage effective receipt successor"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    try:
        report = stage_runtime_broker_effective_receipt_profile(
            parser.parse_args().output
        )
    except BrokerEffectiveReceiptStageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, allow_nan=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
