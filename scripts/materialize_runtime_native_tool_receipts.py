"""Render fixed native receipt transport sources; never stage or activate them.

This overlay is not mandatory native tool capture. Existing create requests are
not yet gated by the open-attempt worker_request_digest. Root provisioning,
updated activation pins, native hooks and qualified performance remain separate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import stage_runtime_endpoint_journal_profile as base

_WORKER = base.journal._WORKER
_JOURNAL = base.journal._HELPER
_STARTUP = "src/aragorn/runtime_skill_startup_service.py"
_UNIT = base.base.activation._UNIT
_CORE = "src/aragorn/runtime_native_tool_receipts.py"
_DEPENDENCIES = {
    "scripts/stage_runtime_endpoint_journal_profile.py": (
        8129,
        "sha256:a3caab42c6f11fee617e1f8a0294bc9dfb9d773e9222b4ceae6c9ed1e637c658",
    ),
    _CORE: (
        22210,
        "sha256:b1d3c1d1fcdc3745a166ea39a8123260574a98a0d5e3a0361bf92a43d7581459",
    ),
}
_INPUTS = {
    _WORKER: base.journal._OUTPUTS[_WORKER],
    _JOURNAL: base.journal._HELPER_PIN,
    _STARTUP: base.base.activation._DEPENDENCIES[_STARTUP],
    _UNIT: base.base.activation._OUTPUTS[_UNIT],
}
_OUTPUTS = {
    _WORKER: (
        44163,
        "sha256:0ccf4c808e006ff9464582014dda22497b2607512543392d4a83c9878e57b50c",
    ),
    _JOURNAL: (
        17052,
        "sha256:c6decbe2de6c0ba48af7b2ccda10a38cd98769f43b186fe2f7ef125f01a977f2",
    ),
    _STARTUP: (
        8408,
        "sha256:e88c882f8bf41decc7378651e791fcedbdffa768cce32fe69775ae489fe5cecc",
    ),
    _UNIT: (
        2946,
        "sha256:dd8b741f13be3e1bd4c646bbabb5995c4cc843792a5d29efde862c43da283665",
    ),
}


class NativeToolReceiptOverlayError(ValueError):
    """The fixed predecessor, a source anchor or an output identity changed."""


def _replace(raw: bytes, before: str, after: str) -> bytes:
    return base.base.activation._replace(raw, before, after)


_OPEN_STORE = '''def _open_native_receipts(
    binding: RuntimeActionWorkerBinding, worker_uid: int, worker_gid: int
) -> _receipts.NativeToolReceiptStore:
    """Bind preprovisioned state to held, fixed, read-only systemd credentials."""
    from . import runtime_skill_startup_service as _receipt_credentials

    entries: list[_receipt_credentials._Held] = []
    try:
        directory_fd = _receipt_credentials._open_directory(worker_uid, entries)
        raw_binding = _receipt_credentials._read_credential(
            directory_fd, "worker-binding", worker_uid, entries, 4096
        )
        expected_binding = {
            "schema": _BINDING_SCHEMA,
            "runtime_digest": binding.runtime_digest,
            "active_skill_digest": binding.active_skill_digest,
            "policy_digest": binding.policy_digest,
            "policy_version": binding.policy_version,
        }
        if raw_binding != canonical_json(expected_binding):
            raise _receipts.NativeToolReceiptFatal("worker credential binding changed")
        genesis = _receipts.broker._parse_canonical_document(
            _receipt_credentials._read_credential(
                directory_fd, "native-tool-genesis", worker_uid, entries, 4096
            ), "native tool genesis credential"
        )
        for name, expected in (
            ("runtime_digest", binding.runtime_digest),
            ("policy_digest", binding.policy_digest),
            ("policy_version", binding.policy_version),
            ("worker_uid", worker_uid),
            ("worker_gid", worker_gid),
        ):
            if type(genesis.get(name)) is not type(expected) or genesis[name] != expected:
                raise _receipts.NativeToolReceiptFatal("native tool genesis binding changed")
        # The core validates the complete genesis schema, private namespace and
        # chain. It never initializes or repairs missing or unresolved state.
        store = _receipts.NativeToolReceiptStore(
            _NATIVE_RECEIPT_ROOT, canonical_digest(genesis)
        )
        _receipt_credentials._recheck(entries, directory_fd)
        return store
    except BaseException as exc:
        raise _receipts.NativeToolReceiptFatal("native tool receipt startup failed") from exc
    finally:
        failure = None
        for entry in reversed(entries):
            try:
                os.close(entry.fd)
            except BaseException as exc:
                failure = failure or exc
        if failure is not None:
            raise _receipts.NativeToolReceiptFatal("native tool credential cleanup failed") from failure


'''

_DISPATCH = """        schema = request.get("schema")
        if schema in ("aragorn/native-tool-attempt/v1", "aragorn/native-tool-terminal/v1"):
            operation = "ATTEMPT" if schema == "aragorn/native-tool-attempt/v1" else "TERMINAL"
            _journal.note("receipt_entered", operation)
            try:
                result = (
                    native_receipts.retain_attempt(request)
                    if operation == "ATTEMPT"
                    else native_receipts.retain_terminal(request)
                )
            except _receipts.NativeToolReceiptRejected as exc:
                _journal.note("receipt_refused")
                raise RuntimeActionWorkerError("native tool receipt request refused") from exc
            except BaseException as exc:
                _journal.note("receipt_indeterminate")
                raise _receipts.NativeToolReceiptFatal("native tool receipt retention failed") from exc
            _journal.note("receipt_result", result)
            _journal.note("delivery_attempt")
            _send_frame(connection, canonical_json(result), deadline)
            _journal.note("delivery_sent")
            return
        # Receipt-only requests never enter this existing effect relay. This
        # transport slice does not yet require a matching attempt for creates.
"""


def _render_worker(raw: bytes) -> bytes:
    replacements = (
        (
            "from . import runtime_endpoint_journal as _journal\n",
            (
                "from . import runtime_endpoint_journal as _journal\n"
                "from . import runtime_native_tool_receipts as _receipts\n"
            ),
        ),
        (
            "class RuntimeActionWorkerError(RuntimeError):\n",
            (
                '_NATIVE_RECEIPT_ROOT = Path("/var/lib/aragorn-runtime-tool-receipts")\n\n\n'
                "class RuntimeActionWorkerError(RuntimeError):\n"
            ),
        ),
        (
            "def serve_runtime_action_worker(\n    config: RuntimeActionWorkerConfig,\n    *,\n",
            (
                "def serve_runtime_action_worker(\n    config: RuntimeActionWorkerConfig,\n    *,\n"
                "    native_receipts: _receipts.NativeToolReceiptStore,\n"
            ),
        ),
        (
            "    _validate_config(config)\n",
            (
                "    _validate_config(config)\n"
                "    if not isinstance(native_receipts, _receipts.NativeToolReceiptStore):\n"
                '        raise _receipts.NativeToolReceiptFatal("native tool receipt store is required")\n'
            ),
        ),
        (
            "    socket_identity: tuple[int, int] | None = None\n",
            (
                "    socket_identity: tuple[int, int] | None = None\n"
                "    receipt_failure: _receipts.NativeToolReceiptFatal | None = None\n"
            ),
        ),
        (
            "                        timeout_seconds=request_timeout_seconds,\n",
            (
                "                        timeout_seconds=request_timeout_seconds,\n"
                "                        native_receipts=native_receipts,\n"
            ),
        ),
        (
            "                except RuntimeActionWorkerError:\n                    continue\n",
            (
                "                except _receipts.NativeToolReceiptFatal as exc:\n"
                "                    receipt_failure = exc\n                    raise\n"
                "                except RuntimeActionWorkerError:\n                    continue\n"
            ),
        ),
        (
            "    except RuntimeActionWorkerError:\n        raise\n    except OSError as exc:\n",
            (
                "    except _receipts.NativeToolReceiptFatal as exc:\n"
                "        receipt_failure = exc\n        raise\n"
                "    except RuntimeActionWorkerError:\n        raise\n    except OSError as exc:\n"
            ),
        ),
        (
            '    except OSError as exc:\n        raise RuntimeActionWorkerError(f"worker transport failed: {exc}") from exc\n',
            (
                "    except OSError as exc:\n"
                "        if receipt_failure is not None:\n"
                "            raise receipt_failure from exc\n"
                '        raise RuntimeActionWorkerError(f"worker transport failed: {exc}") from exc\n'
                "    except BaseException as exc:\n"
                "        if receipt_failure is not None:\n"
                "            raise receipt_failure from exc\n"
                "        raise\n"
            ),
        ),
        (
            "        cleanup_error: OSError | None = None\n",
            "        cleanup_error: BaseException | None = None\n",
        ),
        (
            "        if cleanup_error is not None:\n",
            (
                "        if cleanup_error is not None:\n"
                "            if receipt_failure is not None:\n"
                "                raise receipt_failure from cleanup_error\n"
            ),
        ),
        (
            "    except KeyboardInterrupt:\n        return 0\n",
            (
                "    except _receipts.NativeToolReceiptFatal:\n"
                "        # No raw error or credential data; do not let output failure mask fail-stop.\n"
                "        return 126\n    except KeyboardInterrupt:\n        return 0\n"
            ),
        ),
        (
            "def _run(credential_path: Path) -> None:\n",
            _OPEN_STORE + "def _run(credential_path: Path) -> None:\n",
        ),
        (
            "    binding = _read_worker_binding(credential_path, identities[0])\n",
            (
                "    binding = _read_worker_binding(credential_path, identities[0])\n"
                "    native_receipts = _open_native_receipts(binding, identities[0], identities[1])\n"
            ),
        ),
        (
            "            binding=binding,\n        )\n    )\n",
            "            binding=binding,\n        ),\n        native_receipts=native_receipts,\n    )\n",
        ),
        (
            "    timeout_seconds: float,\n) -> None:\n",
            (
                "    timeout_seconds: float,\n"
                "    native_receipts: _receipts.NativeToolReceiptStore,\n) -> None:\n"
            ),
        ),
        (
            "        result = _relay_request(request, config, deadline=deadline)\n",
            _DISPATCH
            + "        result = _relay_request(request, config, deadline=deadline)\n",
        ),
    )
    for before, after in replacements:
        raw = _replace(raw, before, after)
    # Only an already-fatal receipt changes cleanup exception precedence. Normal
    # worker cancellation/cleanup behavior remains that of the pinned predecessor.
    for indentation, assignment in (
        (12, "cleanup_error = exc"),
        (12, "cleanup_error = cleanup_error or exc"),
        (8, "cleanup_error = cleanup_error or exc"),
    ):
        indent = " " * indentation
        before = f"{indent}except OSError as exc:\n{indent}    {assignment}\n"
        after = (
            f"{indent}except BaseException as exc:\n"
            f"{indent}    if receipt_failure is None and not isinstance(exc, OSError):\n"
            f"{indent}        raise\n{indent}    {assignment}\n"
        )
        raw = _replace(raw, before, after)
    return raw


_RECEIPT_VALIDATION = """    operation = document["receipt_operation"]
    receipt = document["receipt_state"]
    if operation is None:
        if receipt is not None or document["result_kind"] == "LOCAL_RECEIPT_ACK":
            return False
    else:
        statuses = (
            {"ATTEMPT_RECORDED_EXECUTE_ONCE", "ALREADY_RECORDED_DO_NOT_EXECUTE"}
            if operation == "ATTEMPT"
            else {"TERMINAL_RECORDED", "TERMINAL_ALREADY_RECORDED"}
        )
        if (
            document["role"] != "worker"
            or document["submission"] != "NOT_STARTED"
            or action is not None
            or document["profile_attribution_digest"] is not None
            or document["worker_status"] is not None
            or receipt not in statuses | {"ENTERED", "REFUSED", "INDETERMINATE"}
            or ((receipt in statuses) != (document["result_kind"] == "LOCAL_RECEIPT_ACK"))
        ):
            return False
        if receipt not in statuses and (worker is not None or document["result_digest"] is not None):
            return False
"""

_RECEIPT_NOTE = """        elif kind == "receipt_entered" and value in {"ATTEMPT", "TERMINAL"}:
            document["receipt_operation"] = value
            document["receipt_state"] = "ENTERED"
        elif kind in {"receipt_refused", "receipt_indeterminate"}:
            if document["receipt_operation"] is not None:
                document["receipt_state"] = "REFUSED" if kind == "receipt_refused" else "INDETERMINATE"
        elif kind == "receipt_result":
            statuses = (
                {"ATTEMPT_RECORDED_EXECUTE_ONCE", "ALREADY_RECORDED_DO_NOT_EXECUTE"}
                if document["receipt_operation"] == "ATTEMPT"
                else {"TERMINAL_RECORDED", "TERMINAL_ALREADY_RECORDED"}
            )
            if (
                type(value) is dict
                and set(value) == {"schema", "authority", "genesis_digest", "receipt_digest", "event_digest", "sequence", "status", "effect_authorized", "run_qualified"}
                and value["schema"] == "aragorn/native-tool-receipt-ack/v1"
                and value["authority"] == "WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY"
                and document["receipt_operation"] is not None
                and value["status"] in statuses
                and type(value["sequence"]) is int and 1 <= value["sequence"] <= 1024
                and value["effect_authorized"] is False and value["run_qualified"] is False
                and all(type(value[name]) is str and _DIGEST.fullmatch(value[name]) for name in ("genesis_digest", "receipt_digest", "event_digest"))
            ):
                document["receipt_state"] = value["status"]
                document["worker_request_digest"] = value["event_digest"]
                document["request_state"] = "VALIDATED"
                document["result_kind"] = "LOCAL_RECEIPT_ACK"
                document["result_digest"] = canonical_digest(value)
"""


def _render_journal(raw: bytes) -> bytes:
    replacements = (
        (
            '_SCHEMA = "aragorn/runtime-endpoint-journal-event/v1"',
            '_SCHEMA = "aragorn/runtime-endpoint-journal-event/v2"',
        ),
        (
            '    "role": _ROLES,\n',
            (
                '    "role": _ROLES,\n'
                '    "receipt_operation": {None, "ATTEMPT", "TERMINAL"},\n'
                '    "receipt_state": {None, "ENTERED", "REFUSED", "INDETERMINATE", "ATTEMPT_RECORDED_EXECUTE_ONCE", "ALREADY_RECORDED_DO_NOT_EXECUTE", "TERMINAL_RECORDED", "TERMINAL_ALREADY_RECORDED"},\n'
            ),
        ),
        (
            '    "result_kind": {"NONE", "CANONICAL_REPLY_ONLY", "VALIDATED_BROKER_RESULT"},\n',
            '    "result_kind": {"NONE", "CANONICAL_REPLY_ONLY", "VALIDATED_BROKER_RESULT", "LOCAL_RECEIPT_ACK"},\n',
        ),
        (
            '        "CONNECTION_OBSERVED",\n',
            (
                '        "CONNECTION_OBSERVED",\n'
                '        "LOCAL_RECEIPT_ACK_OBSERVED",\n'
                '        "RECEIPT_REQUEST_REFUSED",\n'
                '        "RECEIPT_RETENTION_INDETERMINATE",\n'
            ),
        ),
        (
            '\n    if document["result_kind"] == "VALIDATED_BROKER_RESULT":\n',
            "\n"
            + _RECEIPT_VALIDATION
            + '    if document["result_kind"] == "VALIDATED_BROKER_RESULT":\n',
        ),
        (
            '    elif document["result_kind"] == "CANONICAL_REPLY_ONLY":\n',
            (
                '    elif document["result_kind"] == "LOCAL_RECEIPT_ACK":\n'
                '        if operation is None or worker is None or document["result_digest"] is None:\n'
                "            return False\n"
                '    elif document["result_kind"] == "CANONICAL_REPLY_ONLY":\n'
            ),
        ),
        (
            '        "role": role,\n',
            '        "role": role,\n        "receipt_operation": None,\n        "receipt_state": None,\n',
        ),
        (
            '                    if document["result_kind"] == "VALIDATED_BROKER_RESULT":\n',
            (
                '                    if document["receipt_operation"] is not None:\n'
                "                        outcome = (\n"
                '                            "LOCAL_RECEIPT_ACK_OBSERVED" if document["result_kind"] == "LOCAL_RECEIPT_ACK"\n'
                '                            else "RECEIPT_REQUEST_REFUSED" if document["receipt_state"] == "REFUSED"\n'
                '                            else "RECEIPT_RETENTION_INDETERMINATE"\n'
                "                        )\n"
                '                    elif document["result_kind"] == "VALIDATED_BROKER_RESULT":\n'
            ),
        ),
        (
            '        elif kind == "worker_result":\n',
            _RECEIPT_NOTE + '        elif kind == "worker_result":\n',
        ),
    )
    for before, after in replacements:
        raw = _replace(raw, before, after)
    return raw


def _render(name: str, raw: bytes) -> bytes:
    if (len(raw), base.base.overlay._digest(raw)) != _INPUTS.get(name):
        raise NativeToolReceiptOverlayError("native receipt input changed")
    if name == _WORKER:
        return _render_worker(raw)
    if name == _JOURNAL:
        return _render_journal(raw)
    if name == _STARTUP:
        return _replace(
            raw,
            '_CREDENTIAL_NAMES = frozenset({"worker-binding", "openclaw-config"})',
            '_CREDENTIAL_NAMES = frozenset({"worker-binding", "openclaw-config", "native-tool-genesis"})',
        )
    if name == _UNIT:
        raw = _replace(
            raw,
            "RuntimeDirectoryMode=0711\n",
            "RuntimeDirectoryMode=0711\nStateDirectory=aragorn-runtime-tool-receipts\nStateDirectoryMode=0700\n",
        )
        raw = _replace(
            raw,
            "LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json\n",
            "LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json\nLoadCredential=native-tool-genesis:/etc/aragorn/runtime-native-tool-genesis.json\n",
        )
        return _replace(
            raw,
            "InaccessiblePaths=/etc/aragorn/runtime-action-worker.json ",
            "InaccessiblePaths=/etc/aragorn/runtime-native-tool-genesis.json /etc/aragorn/runtime-action-worker.json ",
        )
    raise NativeToolReceiptOverlayError("unsupported native receipt source")


def _verified_inputs() -> dict[str, bytes]:
    if base._ROOT != _ROOT:
        raise NativeToolReceiptOverlayError("source roots disagree")
    for name, pin in _DEPENDENCIES.items():
        base.base.overlay._read_pinned(name, *pin, root=_ROOT)
    original, overrides = base._verified_payloads()
    payloads = original | overrides
    if len(payloads) != 55:
        raise NativeToolReceiptOverlayError("predecessor inventory changed")
    rendered = {}
    for name in _INPUTS:
        raw = payloads[base.base._destination(name)[0]][2]
        result = _render(name, raw)
        if (len(result), base.base.overlay._digest(result)) != _OUTPUTS[name]:
            raise NativeToolReceiptOverlayError("native receipt output changed")
        rendered[name] = result
    return rendered


def materialize_runtime_native_tool_receipts(output: Path) -> dict[str, Any]:
    """Publish four flat read-only sources, not a deployable profile or credentials."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise NativeToolReceiptOverlayError(
                "output must be an absent absolute Path"
            )
        rendered = _verified_inputs()
        base.base.overlay._write_overlay(
            output, {Path(name).name: raw for name, raw in rendered.items()}, ()
        )
        if _verified_inputs() != rendered:
            raise NativeToolReceiptOverlayError("source inputs changed")
        return {
            "schema": "aragorn/runtime-native-tool-receipt-source-overlay/v1",
            "authority": "PINNED_RECEIPT_TRANSPORT_SOURCE_ONLY_NOT_DEPLOYMENT_OR_RUN_AUTHORITY",
            "files": [
                {
                    "name": Path(name).name,
                    "source_name": name,
                    "bytes": len(raw),
                    "digest": base.base.overlay._digest(raw),
                }
                for name, raw in rendered.items()
            ],
            "required_checkout_dependencies_not_included": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in _DEPENDENCIES.items()
            ],
            "standalone_executable": False,
            "production_activation_eligible": False,
            "mandatory_native_capture": False,
            "create_to_attempt_binding": False,
            "run_eligible": False,
            "limitations": [
                "REQUIRES_COMPLETE_PINNED_JOURNAL_QUARANTINE_PROFILE_AND_ISSUER_OVERRIDE",
                "REQUIRES_ROOT_PROVISIONED_PERSISTENT_STATE_AND_GENESIS_CREDENTIAL",
                "REQUIRES_SUCCESSOR_ACTIVATOR_PINS_AND_EXACT_THREE_CREDENTIAL_STATE_DIRECTORY_CHECKS",
                "NO_NATIVE_HOOKS_OR_CREATE_TO_OPEN_ATTEMPT_GATE",
                "JOURNAL_V2_IS_BEST_EFFORT_AND_NOT_A_DURABLE_RECEIPT_ACK",
                "NO_CROSS_RESTART_OWNER_ROLLBACK_RESISTANCE_OR_PERFORMANCE_QUALIFICATION",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise NativeToolReceiptOverlayError(
            "cannot materialize native receipt transport"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    report = materialize_runtime_native_tool_receipts(parser.parse_args().output)
    print(json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
