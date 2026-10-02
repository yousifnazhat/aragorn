"""Stage a 73-file receipt-complete timing successor; never activate or execute."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import stage_runtime_broker_decision_measurement_profile as predecessor

renderer = predecessor.renderer
base = renderer.base
_PARENT = "scripts/stage_runtime_broker_decision_measurement_profile.py"
_PARENT_PIN = (
    6078,
    "sha256:695ff25e6cf6b0639e5717f3977b904bd673f15b1594f9a1da2d2d7a051a39bf",
)
_HELPER = renderer._HELPER
_ACTIVATOR = renderer._ACTIVATOR
_SCHEMA = "aragorn/runtime-broker-measurement-receipt-staged-profile/v1"
_OUTPUTS = {
    _HELPER: (
        20004,
        "sha256:203f2bac79c46ca100f7a7fee5990bcd50826352f87137701d46c3970e2a31b2",
    ),
    _ACTIVATOR: (
        41455,
        "sha256:c511958024901f6b8b15ba7539365324e3e5d842a6a4702a8092705fef7e39c3",
    ),
}


class BrokerMeasurementReceiptStageError(ValueError):
    """The receipt-retaining successor cannot preserve its exact predecessor."""


def _render_helper(raw: bytes) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != renderer._ADDED[_HELPER]:
        raise BrokerMeasurementReceiptStageError("frozen measurement helper changed")
    replacements = (
        (
            "class Trace:\n    pending: dict\n",
            "class Trace:\n    pending: dict\n    profiled_submission_raw: bytes\n",
        ),
        (
            "        trace = Trace(\n",
            (
                '        profiled = {**legacy, "schema": "aragorn/runtime-observed-create-submission/v2", "runtime_attribution": attribution}\n'
                "        profiled_raw = canonical_json(profiled)\n"
                "        _require(0 < len(profiled_raw) <= _LIMIT and canonical_digest(profiled) == submission_digest)\n"
                "        trace = Trace(\n"
            ),
        ),
        (
            '                "runtime_attribution_digest": canonical_digest(attribution),\n            }\n        )\n',
            '                "runtime_attribution_digest": canonical_digest(attribution),\n            },\n            profiled_submission_raw=profiled_raw,\n        )\n',
        ),
        (
            "            evidence = {\n",
            (
                "            _require(type(trace.profiled_submission_raw) is bytes and 0 < len(trace.profiled_submission_raw) <= _LIMIT)\n"
                '            profiled = broker._parse_canonical_document(trace.profiled_submission_raw, "retained profiled submission")\n'
                '            _require(canonical_digest(profiled) == trace.pending["submission_digest"])\n'
                "            profiled_digest = put(profiled)\n"
                '            _require(profiled_digest == trace.pending["submission_digest"])\n'
                "            evidence = {\n"
            ),
        ),
        (
            "            for pin in (\n",
            "            for pin in (\n                profiled_digest,\n",
        ),
    )
    original = raw
    for before, after in replacements:
        raw = renderer._replace(raw, before, after)
    restored = raw
    for before, after in reversed(replacements):
        restored = renderer._replace(restored, after, before)
    if restored != original:
        raise BrokerMeasurementReceiptStageError(
            "helper transformation is not reversible"
        )
    return raw


def _render_activator(raw: bytes, helper_raw: bytes) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != renderer._OUTPUTS[_ACTIVATOR]:
        raise BrokerMeasurementReceiptStageError("frozen measurement activator changed")
    return renderer._replace(
        raw, renderer._ADDED[_HELPER][1][7:], base.overlay._digest(helper_raw)[7:]
    )


def _verified_payloads():
    base.overlay._read_pinned(_PARENT, *_PARENT_PIN, root=_ROOT)
    base.overlay._read_pinned(
        predecessor._RENDERER, *predecessor._RENDERER_PIN, root=_ROOT
    )
    inherited, overrides = renderer._verified_payloads()
    original = inherited | overrides
    helper_destination, helper_mode = renderer.predecessor._destination(_HELPER)
    activator_destination, activator_mode = renderer.predecessor._destination(
        _ACTIVATOR
    )
    helper = _render_helper(original[helper_destination][2])
    replacements = {
        helper_destination: (_HELPER, helper_mode, helper),
        activator_destination: (
            _ACTIVATOR,
            activator_mode,
            _render_activator(original[activator_destination][2], helper),
        ),
    }
    actual = {
        name: (len(raw), base.overlay._digest(raw))
        for name, _, raw in replacements.values()
    }
    if actual != _OUTPUTS or len(original) != 73 or len(original | replacements) != 73:
        raise BrokerMeasurementReceiptStageError(
            "receipt successor output pins changed"
        )
    return original, replacements


def stage_runtime_broker_measurement_receipt_profile(output: Path) -> dict:
    """Stage two payload replacements, without changing source predecessors."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise BrokerMeasurementReceiptStageError(
                "DESTDIR must be absolute and absent"
            )
        custody = base._parent_custody(output.parent)
        original, replacements = _verified_payloads()
        report = predecessor.stage_runtime_broker_decision_measurement_profile(output)
        base._audit_tree(output, original)
        base._apply_overrides(output, replacements)
        final = original | replacements
        base._audit_tree(output, final)
        if (
            _verified_payloads() != (original, replacements)
            or base._parent_custody(output.parent) != custody
        ):
            raise BrokerMeasurementReceiptStageError(
                "receipt successor staging custody changed"
            )
        return {
            **report,
            "schema": _SCHEMA,
            "authority": "OPT_IN_DESTDIR_ONLY_NOT_ACTIVATION_MEASUREMENT_OR_PHASE3_QUALIFICATION",
            "profiled_submission_retention_staged": True,
            "binding_source_pins": {
                **report["binding_source_pins"],
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
                {**row, "bytes": _OUTPUTS[_HELPER][0], "digest": _OUTPUTS[_HELPER][1]}
                if row["name"] == _HELPER
                else row
                for row in report["new_dependencies"]
            ],
            "missing_inputs": report["missing_inputs"]
            + [
                "independently retained completion/binding/process custody pins and raw grant/protected-path descriptor for read-only receipt verification",
                "profiled submission retention does not establish independent attribution, protected-sink residue absence, full request latency, or a cross-process clock domain",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise BrokerMeasurementReceiptStageError(
            "cannot stage broker measurement receipt successor"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    try:
        report = stage_runtime_broker_measurement_receipt_profile(
            parser.parse_args().output
        )
    except BrokerMeasurementReceiptStageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, allow_nan=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
