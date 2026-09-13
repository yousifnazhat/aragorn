"""Stage a pinned, expiry-bounded broker response lifetime; never activate it."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import stage_runtime_endpoint_journal_profile as journal

base = journal.base
_BROKER = journal.journal._BROKER
_ACTIVATOR = base.activation._ACTIVATOR
_SCHEMA = "aragorn/runtime-broker-response-drain-staged-profile/v1"
_AUTHORITY = (
    "CALLER_OWNED_DESTDIR_BYTES_ONLY_NOT_DEPLOYMENT_COMPLETION_OR_RUN_AUTHORITY"
)
_SOURCE_PINS = {
    **journal._SOURCE_PINS,
    "scripts/stage_runtime_endpoint_journal_profile.py": (
        8_129,
        "sha256:a3caab42c6f11fee617e1f8a0294bc9dfb9d773e9222b4ceae6c9ed1e637c658",
    ),
}
_INPUTS = {
    _BROKER: journal.journal._OUTPUTS[_BROKER],
    _ACTIVATOR: journal._ACTIVATOR_OUTPUT_PIN,
}
# Exact deterministic render identities are checked before any staging write.
_OUTPUTS = {
    _BROKER: (
        14_578,
        "sha256:cd7b85e520de7e580d74ffb66c13e67e6984c9f9513c7a7b03c5ebe5416fba6a",
    ),
    _ACTIVATOR: (
        34_827,
        "sha256:5cd0c6e3729e1d6b2e35eae3cd959bb0b9d63a682606c797ddb340dcbfb1a834",
    ),
}


class RuntimeBrokerResponseDrainStageError(ValueError):
    """A fixed source, custody check, transformation, or staging step failed."""


_OLD_LOOP = """        while True:
            state = initialize_runtime_capability_grant(
                config.broker,
                deadline_monotonic=time.monotonic() + request_timeout_seconds,
            )
            if state["status"] != "AVAILABLE":
                return
            remaining = grant["expires_at_unix"] - time.time()
            if remaining <= 0:
                continue
            listener.settimeout(remaining)
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            with connection:
                try:
                    _handle_connection(
                        connection,
                        config,
                        timeout_seconds=request_timeout_seconds,
                    )
                except RuntimeActionEffectIndeterminate as exc:
                    _LOG.error("runtime action effect is indeterminate: %s", exc)
                except RuntimeActionBrokerError as exc:
                    _LOG.warning("runtime action failed before effect: %s", exc)
"""
_NEW_LOOP = """        while True:
            if completed_result_digest is not None:
                consumed_state = _verify_completed_consumption(
                    config, consumed_state, completed_result_digest,
                    deadline=time.monotonic() + request_timeout_seconds,
                )
            else:
                state = initialize_runtime_capability_grant(
                    config.broker,
                    deadline_monotonic=time.monotonic() + request_timeout_seconds,
                )
                if state["status"] != "AVAILABLE":
                    return
            remaining = min(
                grant["expires_at_unix"] - time.time(),
                lifetime_deadline - time.monotonic(),
            )
            if remaining <= 0:
                return
            listener.settimeout(remaining)
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            result = None
            with connection:
                try:
                    result = _handle_connection(
                        connection,
                        config,
                        timeout_seconds=request_timeout_seconds,
                    )
                except RuntimeActionEffectIndeterminate as exc:
                    _LOG.error("runtime action effect is indeterminate: %s", exc)
                    raise
                except RuntimeActionBrokerError as exc:
                    _LOG.warning("runtime action failed before effect: %s", exc)
            # A successful send alone is insufficient: context cleanup above
            # must also return. Spent grants still use the unchanged v4 claim gate.
            if result is not None:
                if consumed_state is not None:
                    raise RuntimeActionBrokerError("spent grant returned a new result")
                completed_result_digest = canonical_digest(result)
"""
_CLOCK_ANCHOR = """    control_fd = _open_protected_directory(
"""
_CLOCK_REPLACEMENT = """    # One deadline for this process lifetime, never renewed by consumption or
    # another request. Wall rollback cannot extend it beyond the initial budget.
    started_monotonic = time.monotonic()
    lifetime_seconds = min(
        max(0.0, grant["expires_at_unix"] - time.time()),
        grant["expires_at_unix"] - grant["issued_at_unix"],
    )
    lifetime_deadline = started_monotonic + lifetime_seconds
    completed_result_digest: str | None = None
    consumed_state: bytes | None = None
    control_fd = _open_protected_directory(
"""
_VERIFY_CONSUMPTION = '''def _verify_completed_consumption(
    config: RuntimeActionBrokerV5Config,
    expected: bytes | None,
    result_digest: str,
    *,
    deadline: float,
) -> bytes:
    """Read-only, locked join; never recover, publish, or discard state."""
    grant_digest = canonical_digest(_validate_config(config))
    verified: bytes | None = None

    def verify(control_fd: int) -> None:
        nonlocal verified
        current = _load_state(control_fd, config.broker, grant_digest)
        raw = canonical_json(current)
        if current["status"] != "CONSUMED" or (expected is not None and raw != expected):
            raise RuntimeActionBrokerError("completed response state changed")
        _require_no_pending_at(control_fd, config.broker)
        receipt = _load_profile_receipt(control_fd, config.broker)
        result = _result_record(current["claim"], receipt)
        if (
            canonical_json(result) != canonical_json(current["result"])
            or result["profile_result"]["broker_result_digest"] != result_digest
        ):
            raise RuntimeActionBrokerError("completed response is unbound")
        verified = raw

    _with_profile_lock(config.broker.broker, deadline, verify)
    if verified is None:
        raise RuntimeActionBrokerError("completed response was not verified")
    return verified


'''


def _render_broker(raw: bytes) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != _INPUTS[_BROKER]:
        raise RuntimeBrokerResponseDrainStageError("journal broker identity changed")
    replacements = (
        (
            "from .oci_worker_protocol import WorkerProtocolError, canonical_json\n",
            "from .oci_worker_protocol import WorkerProtocolError, canonical_digest, canonical_json\n",
        ),
        (
            "    RuntimeActionBrokerV4Config,\n    _issued_submission,\n",
            (
                "    RuntimeActionBrokerV4Config,\n    _issued_submission,\n"
                "    _load_state,\n    _load_profile_receipt,\n    _require_no_pending_at,\n"
                "    _result_record,\n    _with_profile_lock,\n"
            ),
        ),
        (_CLOCK_ANCHOR, _CLOCK_REPLACEMENT),
        (_OLD_LOOP, _NEW_LOOP),
        (
            "    timeout_seconds: float,\n) -> None:\n    broker = config.broker.broker.broker\n",
            "    timeout_seconds: float,\n) -> dict[str, Any]:\n    broker = config.broker.broker.broker\n",
        ),
        (
            "        raise\n\n\ndef _validate_config(config: RuntimeActionBrokerV5Config)",
            "        raise\n    return result\n\n\ndef _validate_config(config: RuntimeActionBrokerV5Config)",
        ),
        (
            "def _validate_config(config: RuntimeActionBrokerV5Config)",
            _VERIFY_CONSUMPTION
            + "def _validate_config(config: RuntimeActionBrokerV5Config)",
        ),
    )
    original = raw
    for before, after in replacements:
        raw = base.activation._replace(raw, before, after)
    restored = raw
    for before, after in reversed(replacements):
        restored = base.activation._replace(restored, after, before)
    if restored != original:
        raise RuntimeBrokerResponseDrainStageError("broker changed other behavior")
    return raw


def _render_activator(raw: bytes) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != _INPUTS[_ACTIVATOR]:
        raise RuntimeBrokerResponseDrainStageError("journal activator identity changed")
    before = journal._pin_line(_BROKER, _INPUTS[_BROKER][1])
    after = journal._pin_line(_BROKER, _OUTPUTS[_BROKER][1])
    rendered = base.activation._replace(raw, before, after)
    if base.activation._replace(rendered, after, before) != raw:
        raise RuntimeBrokerResponseDrainStageError("activator changed other logic")
    return rendered


def _verified_payloads() -> tuple[dict[str, base._Payload], dict[str, base._Payload]]:
    if journal._ROOT != _ROOT:
        raise RuntimeBrokerResponseDrainStageError("staging source roots disagree")
    for name, pin in _SOURCE_PINS.items():
        base.overlay._read_pinned(name, *pin, root=_ROOT)
    original, overrides = journal._verified_payloads()
    payloads = original | overrides
    replacements = {}
    for name, render in ((_BROKER, _render_broker), (_ACTIVATOR, _render_activator)):
        destination, mode = base._destination(name)
        raw = render(payloads[destination][2])
        if (len(raw), base.overlay._digest(raw)) != _OUTPUTS[name]:
            raise RuntimeBrokerResponseDrainStageError("response drain output changed")
        replacements[destination] = (name, mode, raw)
    if (
        len(payloads) != 55
        or len(replacements) != 2
        or len(payloads | replacements) != 55
    ):
        raise RuntimeBrokerResponseDrainStageError("staged profile inventory changed")
    return payloads, replacements


def stage_runtime_broker_response_drain_profile(output: Path) -> dict[str, Any]:
    """Stage two overrides over the exact 55-file profile; partial output may remain.

    This preserves all fail-stop unit dependencies and one-shot effect authority.
    The spent broker may stay alive only through the original bounded lifetime,
    not until an application ACK. It does not guarantee native turn completion.
    No credentials, grants, state, service, or activator are provisioned or run.
    """
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise RuntimeBrokerResponseDrainStageError(
                "DESTDIR must be an absolute absent Path"
            )
        parent = base._parent_custody(output.parent)
        payloads, replacements = _verified_payloads()
        report = journal.stage_runtime_endpoint_journal_profile(output)
        if base._parent_custody(output.parent) != parent:
            raise RuntimeBrokerResponseDrainStageError("DESTDIR parent changed")
        base._audit_tree(output, payloads)
        base._apply_overrides(output, replacements)
        final = payloads | replacements
        base._audit_tree(output, final)
        if _verified_payloads() != (payloads, replacements):
            raise RuntimeBrokerResponseDrainStageError("staging sources changed")
        if base._parent_custody(output.parent) != parent:
            raise RuntimeBrokerResponseDrainStageError("DESTDIR parent changed")
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
            "source_inputs": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in sorted(_SOURCE_PINS.items())
            ],
            "broker_response_drain_deployed": False,
            "native_terminal_retention": False,
            "native_turn_completion": False,
            "missing_inputs": report["missing_inputs"]
            + [
                "root-authorized deployment and expiry/lifecycle validation of this successor",
                "mandatory native attempt/terminal hooks and independently bound durable receipt path",
                "response lifetime is not application ACK, completion, latency or RUN qualification",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeBrokerResponseDrainStageError(
            "cannot stage broker response drain profile"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    try:
        report = stage_runtime_broker_response_drain_profile(parser.parse_args().output)
    except RuntimeBrokerResponseDrainStageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
