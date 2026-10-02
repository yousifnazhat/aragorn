"""Stage the opt-in 73-file measured native broker; never activate or collect."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_runtime_broker_decision_measurement as renderer

base = renderer.base
_SCHEMA = "aragorn/runtime-broker-decision-measurement-staged-profile/v1"
_RENDERER = "scripts/materialize_runtime_broker_decision_measurement.py"
_RENDERER_PIN = (
    13324,
    "sha256:801314f15993a13d05190e7e01a7ccbdf7b82aaa399634f94b8274855b0e9c33",
)


class BrokerDecisionMeasurementStageError(ValueError):
    """The opt-in measured profile could not preserve its fixed predecessor."""


def stage_runtime_broker_decision_measurement_profile(output: Path) -> dict:
    """Materialize a distinct profile; the original native startup profile stays exact."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise BrokerDecisionMeasurementStageError(
                "DESTDIR must be absolute and absent"
            )
        base.overlay._read_pinned(_RENDERER, *_RENDERER_PIN, root=_ROOT)
        parent = base._parent_custody(output.parent)
        original, replacements = renderer._verified_payloads()
        report = renderer.predecessor.stage_runtime_native_startup_profile(output)
        base._audit_tree(output, original)
        base._apply_overrides(output, replacements)
        final = original | replacements
        base._audit_tree(output, final)
        if (
            renderer._verified_payloads() != (original, replacements)
            or base._parent_custody(output.parent) != parent
        ):
            raise BrokerDecisionMeasurementStageError(
                "measurement staging custody changed"
            )
        sources = {
            **renderer.predecessor._SOURCE_PINS,
            renderer._PARENT: renderer._PARENT_PIN,
            _RENDERER: _RENDERER_PIN,
            **renderer._ADDED,
        }
        dependencies = {row["name"] for row in report["new_dependencies"]} | set(
            renderer._ADDED
        )
        binding_sources = {
            "runtime_action_broker.py",
            "runtime_action_broker_v4.py",
            "runtime_action_broker_v5.py",
            "runtime_action_service_v5.py",
            "runtime_broker_decision_measurement.py",
            "phase3_deployment.py",
            "phase3_quantitative_metrics.py",
        }
        return {
            **report,
            "schema": _SCHEMA,
            "authority": "OPT_IN_DESTDIR_ONLY_NOT_ACTIVATION_MEASUREMENT_OR_PHASE3_QUALIFICATION",
            "decision_measurement_deployed": False,
            "measurement_binding_provisioned": False,
            "measurement_collected": False,
            "phase3_qualification": False,
            "run_qualification": False,
            "measurement_scope": "VALIDATED_V4_GRANT_REDEMPTION_TO_EFFECTIVE_PRE_LINK_DECISION",
            "binding_source_pins": {
                Path(source).name: base.overlay._digest(raw)
                for source, _, raw in final.values()
                if Path(source).name in binding_sources
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
            "source_inputs": [
                {"name": name, "bytes": pin[0], "digest": pin[1]}
                for name, pin in sorted(sources.items())
            ],
            "new_dependencies": [
                {
                    "name": name,
                    "bytes": len(final[renderer.predecessor._destination(name)[0]][2]),
                    "digest": base.overlay._digest(
                        final[renderer.predecessor._destination(name)[0]][2]
                    ),
                }
                for name in sorted(dependencies)
            ],
            "missing_inputs": report["missing_inputs"]
            + [
                "operator root-owned 0400 /etc/aragorn/runtime-broker-decision-measurement.json for one exact grant and permitted action",
                "broker-owned private fixed decision-measurement-inputs CAS containing frozen commitment, schedule and seven deployment artifacts",
                "fresh accepted BOOT_ID and independent deployment identity verification; credential digests are not external attestation",
                "clean one-shot measurement state; pending or complete latches require explicit operator investigation, never automatic reset",
                "live successor activation and retained-decision fixture acceptance have not been performed",
                "not full request acceptance latency, unrelated/unattributed rejection coverage, protected-sink residue, or paired-task overhead evidence",
                "replay and broker-only BLOCK verdicts rejected by inherited consumption checks remain pending and are not completed samples",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise BrokerDecisionMeasurementStageError(
            "cannot stage measured broker successor"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    try:
        report = stage_runtime_broker_decision_measurement_profile(
            parser.parse_args().output
        )
    except BrokerDecisionMeasurementStageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, allow_nan=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
