"""Render one fixed worker ingress successor; never stage or activate it.

The source overlay still needs reviewed unit/state-directory changes,
activator pins and installed-source inventories before it can be deployed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_runtime_native_create_gate as base

overlay = base.overlay
_WORKER = base._WORKER
_HELPER = "src/aragorn/runtime_worker_ingress_measurement.py"
_INPUT = (
    46629,
    "sha256:df55f788ed29d188c71ca201d5778e7bff734b9a2f09445d8247c4ab6f40cd32",
)
_DEPENDENCIES = {
    "scripts/materialize_runtime_native_create_gate.py": (
        8686,
        "sha256:91b377340c5bffaf4cca0af676501c3d674663d4ede21afa43d215385269243b",
    ),
    _HELPER: (
        20731,
        "sha256:aba3d6b705f9b147fdf89f083ec6edcde7d3165ba1a8008cf4bcdcaee88fe17e",
    ),
}
_OUTPUT = (
    49327,
    "sha256:1ba2bc446b0561d992ef800d324269ab6a428b2cb3449109fe771029317f850a",
)


class WorkerIngressOverlayError(ValueError):
    """An exact predecessor, source anchor or reviewed output pin changed."""


_GATE = '''def _relay_native_attempt_once(
    request: dict[str, Any],
    config: RuntimeActionWorkerConfig,
    *,
    deadline: float,
    native_receipts: _receipts.NativeToolReceiptStore,
    relayed_native_attempts: set[str],
    ingress: _ingress.NativeWorkerIngress,
    ingress_trace: object,
) -> dict[str, Any]:
    """Keep the original once-only lock and bind actual retained attempt bytes."""
    validated, _payload = _worker_request(request)
    request_digest = canonical_digest(validated)
    ingress_failure: _receipts.NativeToolReceiptFatal | None = None
    try:
        with native_receipts._locked() as fd:
            state, receipts = native_receipts._load(fd)
            _receipts._trust(
                type(relayed_native_attempts) is set
                and len(relayed_native_attempts) <= _receipts._MAX_CALLS
                and not native_receipts._halted
            )
            _receipts._require(len(receipts) % 2 == 1)
            attempt = receipts[-1]
            event = attempt["event"]
            attempt_digest = canonical_digest(attempt)
            _receipts._require(
                event["tool_name"] == "aragorn_runtime_create"
                and event["worker_request_digest"] == request_digest
                and all(
                    event[name] == validated[name]
                    for name in ("run_id", "session_id", "tool_call_digest")
                )
                and attempt_digest not in relayed_native_attempts
                and len(relayed_native_attempts) < _receipts._MAX_CALLS
            )
            before = canonical_digest(state)
            # Consumption still precedes measurement retention and every sensor
            # connection. Failure never clears either once-only boundary.
            relayed_native_attempts.add(attempt_digest)
            try:
                ingress.bind_attempt(
                    ingress_trace, attempt, state, native_receipts.genesis_digest
                )
                return _relay_request(
                    validated, config, deadline=deadline,
                    ingress=ingress, ingress_trace=ingress_trace,
                )
            except _receipts.NativeToolReceiptFatal as exc:
                ingress_failure = exc
                raise
            finally:
                native_receipts._load(fd, expected_state_digest=before)
                _receipts._trust(not native_receipts._halted)
    except BaseException as exc:
        # Neither the final chain read nor lock/descriptor cleanup may turn a
        # retained-ingress failure into ordinary per-connection cancellation.
        if ingress_failure is not None and exc is not ingress_failure:
            raise ingress_failure from exc
        raise


'''

_CLEANUP = """    finally:
        cleanup_error: BaseException | None = None
        if listener is not None:
            try:
                listener.close()
            except BaseException as exc:
                if receipt_failure is None and not isinstance(exc, OSError):
                    raise
                cleanup_error = exc
        if bound:
            try:
                current = os.stat(
                    config.socket_path.name,
                    dir_fd=runtime_fd,
                    follow_symlinks=False,
                )
                if socket_identity == (current.st_dev, current.st_ino):
                    os.unlink(config.socket_path.name, dir_fd=runtime_fd)
                    os.fsync(runtime_fd)
            except FileNotFoundError:
                pass
            except BaseException as exc:
                if receipt_failure is None and not isinstance(exc, OSError):
                    raise
                cleanup_error = cleanup_error or exc
        try:
            os.close(runtime_fd)
        except BaseException as exc:
            if receipt_failure is None and not isinstance(exc, OSError):
                raise
            cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            if receipt_failure is not None:
                raise receipt_failure from cleanup_error
            raise RuntimeActionWorkerError("worker transport cleanup failed") from (
                cleanup_error
            )
"""
_INGRESS_CLEANUP = (
    "    finally:\n        try:\n"
    + "".join("    " + line for line in _CLEANUP.splitlines(keepends=True)[1:])
    + "        finally:\n"
    "            if ingress is not None:\n"
    "                try:\n"
    "                    ingress.close()\n"
    "                except BaseException as exc:\n"
    "                    if receipt_failure is not None:\n"
    "                        raise receipt_failure from exc\n"
    "                    if isinstance(exc, _receipts.NativeToolReceiptFatal):\n"
    "                        raise\n"
    '                    raise _receipts.NativeToolReceiptFatal("worker ingress cleanup failed") from exc\n'
)

_REPLACEMENTS = (
    (
        "from . import runtime_native_tool_receipts as _receipts\n",
        "from . import runtime_native_tool_receipts as _receipts\n"
        "from . import runtime_worker_ingress_measurement as _ingress\n",
    ),
    (
        "    relayed_native_attempts: set[str] = set()\n",
        "    relayed_native_attempts: set[str] = set()\n"
        "    ingress: _ingress.NativeWorkerIngress | None = None\n",
    ),
    (
        "    try:\n        _prepare_socket_path(runtime_fd, config)\n",
        "    try:\n"
        "        ingress = _ingress.NativeWorkerIngress(\n"
        "            expected_worker_uid=config.expected_worker_uid,\n"
        "            expected_worker_gid=config.expected_worker_gid,\n"
        "            binding={\n"
        '                "schema": _BINDING_SCHEMA,\n'
        '                "runtime_digest": config.binding.runtime_digest,\n'
        '                "active_skill_digest": config.binding.active_skill_digest,\n'
        '                "policy_digest": config.binding.policy_digest,\n'
        '                "policy_version": config.binding.policy_version,\n'
        "            },\n"
        "        )\n"
        "        _prepare_socket_path(runtime_fd, config)\n",
    ),
    (
        "                        relayed_native_attempts=relayed_native_attempts,\n",
        "                        relayed_native_attempts=relayed_native_attempts,\n"
        "                        ingress=ingress,\n",
    ),
    (_CLEANUP, _INGRESS_CLEANUP),
    (
        "    relayed_native_attempts: set[str],\n) -> None:\n",
        "    relayed_native_attempts: set[str],\n"
        "    ingress: _ingress.NativeWorkerIngress,\n) -> None:\n",
    ),
    (
        "        # Receipt-only requests return before the held open-attempt gate.\n",
        "        # Receipt-only requests return before the held open-attempt gate.\n"
        "        ingress_trace = ingress.begin(request, (pid, uid, gid))\n",
    ),
    (
        "                relayed_native_attempts=relayed_native_attempts,\n            )\n",
        "                relayed_native_attempts=relayed_native_attempts,\n"
        "                ingress=ingress, ingress_trace=ingress_trace,\n            )\n",
    ),
    (base._GATE, _GATE),
    (
        "    deadline: float,\n    clock: Callable[[], int] | None = None,\n",
        "    deadline: float,\n"
        "    ingress: _ingress.NativeWorkerIngress,\n    ingress_trace: object,\n"
        "    clock: Callable[[], int] | None = None,\n",
    ),
    (
        "    failure: Exception | None = None\n    try:\n",
        "    failure: Exception | None = None\n"
        "    ingress_failure: _receipts.NativeToolReceiptFatal | None = None\n"
        "    try:\n",
    ),
    (
        '        _journal.note("action_document", envelope)\n',
        '        ingress.bind_action(ingress_trace, envelope["request"])\n'
        '        _journal.note("action_document", envelope)\n',
    ),
    (
        "    except (\n        OSError,\n        RuntimeActionBrokerError,\n        RuntimeActionWorkerError,\n",
        "    except _receipts.NativeToolReceiptFatal as exc:\n"
        "        ingress_failure = exc\n        raise\n"
        "    except (\n        OSError,\n        RuntimeActionBrokerError,\n        RuntimeActionWorkerError,\n",
    ),
    (
        "            except OSError as exc:\n                failure = failure or exc\n",
        "            except BaseException as exc:\n"
        "                if ingress_failure is None and not isinstance(exc, OSError):\n"
        "                    raise\n"
        "                failure = failure or exc\n",
    ),
)


def _replace(raw: bytes, before: str, after: str, *, count: int = 1) -> bytes:
    old, new = before.encode("ascii"), after.encode("ascii")
    if raw.count(old) != count or old == new or new in raw:
        raise WorkerIngressOverlayError("worker ingress source anchor changed")
    rendered = raw.replace(old, new)
    if rendered.count(new) != count or rendered.replace(new, old) != raw:
        raise WorkerIngressOverlayError("worker ingress transform is not reversible")
    return rendered


def _transform(raw: bytes) -> bytes:
    if type(raw) is not bytes or len(raw) != _INPUT[0]:
        raise WorkerIngressOverlayError("worker ingress input size changed")
    if overlay._digest(raw) != _INPUT[1]:
        raise WorkerIngressOverlayError("worker ingress predecessor changed")
    original = raw
    for index, (before, after) in enumerate(_REPLACEMENTS):
        # The last exact anchor is the matching sensor and protected-FD cleanup.
        raw = _replace(
            raw, before, after, count=2 if index == len(_REPLACEMENTS) - 1 else 1
        )
    restored = raw
    for before, after in reversed(_REPLACEMENTS):
        restored = restored.replace(after.encode("ascii"), before.encode("ascii"))
    if restored != original:
        raise WorkerIngressOverlayError("worker ingress changed unrelated source")
    return raw


def _verified_inputs() -> bytes:
    if base._ROOT != _ROOT:
        raise WorkerIngressOverlayError("worker ingress source roots disagree")
    for name, pin in _DEPENDENCIES.items():
        overlay._read_pinned(name, *pin, root=_ROOT)
    raw = _transform(base._verified_inputs())
    if (len(raw), overlay._digest(raw)) != _OUTPUT:
        raise WorkerIngressOverlayError("worker ingress output identity changed")
    return raw


def materialize_runtime_worker_ingress_measurement(output: Path) -> dict:
    """Publish one source file only; never provision, activate or collect."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise WorkerIngressOverlayError("output must be an absent absolute Path")
        raw = _verified_inputs()
        overlay._write_overlay(output, {Path(_WORKER).name: raw}, ())
        if _verified_inputs() != raw:
            raise WorkerIngressOverlayError("worker ingress sources changed")
        return {
            "schema": "aragorn/runtime-worker-ingress-source-overlay/v1",
            "authority": "PINNED_WORKER_SOURCE_ONLY_NOT_DEPLOYMENT_TIMING_OR_PHASE3_AUTHORITY",
            "files": [
                {"name": Path(_WORKER).name, "bytes": len(raw), "digest": _OUTPUT[1]}
            ],
            "predecessor_worker": {
                "name": _WORKER,
                "bytes": _INPUT[0],
                "digest": _INPUT[1],
            },
            "required_checkout_dependencies_not_included": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in sorted(_DEPENDENCIES.items())
            ],
            "standalone_executable": False,
            "production_activation_eligible": False,
            "native_hook_reachability": False,
            "measurement_collected": False,
            "run_eligible": False,
            "metrics_eligible": False,
            "phase3_eligible": False,
            "limitations": [
                "REQUIRES_REVIEWED_STATE_DIRECTORY_AND_UNIT_ACTIVATOR_PINS",
                "REQUIRES_COMMON_STAGE_STATIC_SOURCE_AND_DEPLOYMENT_MIGRATION",
                "AUTHENTICATED_FRAME_BOUNDARY_NOT_SOCKET_ACCEPT_OR_GATEWAY_DISPATCH_TIME",
                "NATIVE_RECEIPT_CORRELATION_NOT_INDEPENDENT_APPLICATION_CAUSATION",
                "NO_EFFECTIVE_FINAL_DECISION_COMMON_CLOCK_OR_SINK_RESIDUE_JOIN",
                "NO_RUNTIME_ACTIVATION_PERFORMANCE_OR_PHASE3_QUALIFICATION",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise WorkerIngressOverlayError(
            "cannot materialize worker ingress source"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    report = materialize_runtime_worker_ingress_measurement(parser.parse_args().output)
    print(json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
