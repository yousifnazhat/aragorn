"""Stage pinned best-effort endpoint journal sources; never activate services."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_runtime_endpoint_journal as journal
from scripts import stage_runtime_quarantine_profile as base

_SCHEMA = "aragorn/runtime-endpoint-journal-staged-profile/v1"
_AUTHORITY = (
    "CALLER_OWNED_DESTDIR_BYTES_ONLY_NOT_DEPLOYMENT_DURABLE_RETENTION_OR_RUN_AUTHORITY"
)
_SUPPORT_PINS = {
    **journal._SUPPORT_PINS,
    "scripts/stage_runtime_quarantine_profile.py": (
        22_903,
        "sha256:68f6eff891df9d1852b6221c6e3c1e600b90c8c2797e62d6ecf8e11b2f29bb4f",
    ),
    "scripts/materialize_runtime_quarantine_activation.py": (
        10_674,
        "sha256:520ab0ec32f9fdc082420ee4dca4add94410432a6af6160c2c967a5e2c67c314",
    ),
    "scripts/materialize_runtime_endpoint_journal.py": (
        13_578,
        "sha256:a8adf022becb64b8171da9cbd203ace93a373619795985bca1ee601d79aaa0ec",
    ),
}
_ACTIVATOR_INPUT_PIN = (
    34_705,
    "sha256:c01ae51517f7d51428dbbf336eee1cb5213d2e5991ea7b3e7ac9cbc2dec8af8d",
)
_ACTIVATOR_OUTPUT_PIN = (
    34_827,
    "sha256:a98787da263dd3d01cb14ab31216cae0a67a0b9e56a616e7cf6a0bbb977e8392",
)
_SOURCE_PINS = {
    **_SUPPORT_PINS,
    **base._BASE_INPUTS,
    **base.activation._DEPENDENCIES,
    journal._HELPER: journal._HELPER_PIN,
}


class RuntimeEndpointJournalStageError(ValueError):
    """A fixed source, output identity, custody check, or staging step failed."""


def _pin_line(name: str, digest: str) -> str:
    destination, mode = base._destination(name)
    return f"{mode:o} {digest[7:]} /{destination}\n"


def _render_activator(raw: bytes) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != _ACTIVATOR_INPUT_PIN:
        raise RuntimeEndpointJournalStageError("quarantine activator identity changed")
    original = raw
    replacements = []
    for name in (journal._WORKER, journal._SENSOR, journal._BROKER):
        old_digest = (
            journal._WORKER_PIN[1]
            if name == journal._WORKER
            else base.services._SERVICES[name][3]
        )
        before = _pin_line(name, old_digest)
        after = _pin_line(name, journal._OUTPUTS[name][1])
        raw = base.activation._replace(raw, before, after)
        replacements.append((before, after))
    helper_line = _pin_line(journal._HELPER, journal._HELPER_PIN[1])
    raw = base.activation._replace(raw, "\nEOF\n", "\n" + helper_line + "EOF\n")
    if (len(raw), base.overlay._digest(raw)) != _ACTIVATOR_OUTPUT_PIN:
        raise RuntimeEndpointJournalStageError("journal activator identity changed")
    restored = base.activation._replace(raw, helper_line, "")
    for before, after in reversed(replacements):
        restored = base.activation._replace(restored, after, before)
    if restored != original:
        raise RuntimeEndpointJournalStageError("journal activator changed other logic")
    return raw


def _verified_payloads() -> tuple[dict[str, base._Payload], dict[str, base._Payload]]:
    if base._ROOT != _ROOT or journal._ROOT != _ROOT:
        raise RuntimeEndpointJournalStageError("staging source roots disagree")
    for name, pin in _SOURCE_PINS.items():
        base.overlay._read_pinned(name, *pin, root=_ROOT)
    _, original, quarantined = base._verified_payloads()
    payloads = original | quarantined
    rendered, _ = journal._verified_inputs()
    if set(rendered) != {
        journal._WORKER,
        journal._SENSOR,
        journal._BROKER,
        journal._HELPER,
    }:
        raise RuntimeEndpointJournalStageError("journal source inventory changed")
    replacements = {
        base._destination(name)[0]: (name, base._destination(name)[1], raw)
        for name, raw in rendered.items()
    }
    activator = base.activation._ACTIVATOR
    destination, mode = base._destination(activator)
    replacements[destination] = (
        activator,
        mode,
        _render_activator(payloads[destination][2]),
    )
    if (
        len(payloads) != 54
        or len(replacements) != 5
        or len(payloads | replacements) != 55
    ):
        raise RuntimeEndpointJournalStageError("staged profile inventory changed")
    return payloads, replacements


def stage_runtime_endpoint_journal_profile(output: Path) -> dict[str, Any]:
    """Assemble one absent absolute DESTDIR; incomplete output may remain on failure.

    The inherited installer runs only against its private verified snapshot.
    No activator, service, credentials, or endpoint producer is executed here.
    Best-effort journal emission is not durable retention or RUN qualification.
    """
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise RuntimeEndpointJournalStageError(
                "DESTDIR must be an absolute absent Path"
            )
        parent = base._parent_custody(output.parent)
        payloads, replacements = _verified_payloads()
        report = base.stage_runtime_quarantine_profile(output)
        if base._parent_custody(output.parent) != parent:
            raise RuntimeEndpointJournalStageError("DESTDIR parent changed")
        base._audit_tree(output, payloads)
        base._apply_overrides(output, replacements)
        final = payloads | replacements
        base._audit_tree(output, final)
        if _verified_payloads() != (payloads, replacements):
            raise RuntimeEndpointJournalStageError("staging sources changed")
        if base._parent_custody(output.parent) != parent:
            raise RuntimeEndpointJournalStageError("DESTDIR parent changed")
        return {
            **report,
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
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
            "new_dependencies": sorted(
                report["new_dependencies"]
                + [
                    {
                        "name": journal._HELPER,
                        "bytes": journal._HELPER_PIN[0],
                        "digest": journal._HELPER_PIN[1],
                    }
                ],
                key=lambda item: item["name"],
            ),
            "source_inputs": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in sorted(_SOURCE_PINS.items())
            ],
            "runtime_journal_deployed": False,
            "durable_event_retention": False,
            "run_qualification": False,
            "missing_inputs": report["missing_inputs"]
            + [
                "root-authorized deployment and current profile identity for endpoint journal producers",
                "event-loss health enforcement, durable retention and complete RUN event coverage",
                "independent timing and qualification; endpoint observations do not establish causation",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeEndpointJournalStageError(
            f"cannot stage endpoint journal profile: {exc}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    output = parser.parse_args().output
    try:
        manifest = stage_runtime_endpoint_journal_profile(output)
    except RuntimeEndpointJournalStageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
