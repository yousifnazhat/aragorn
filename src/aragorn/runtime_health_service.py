"""Publish one fixed-path, root-provisioned runtime health credential."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import (
    RuntimeActionBrokerConfig,
    RuntimeActionBrokerError,
    _parse_canonical_document,
    publish_runtime_control_document,
)
from .runtime_action_service import (
    _CONTROL_ROOT,
    _PROTECTED_ROOT,
    _STAGING_ROOT,
    RuntimeActionServiceError,
    _credential_path,
    _read_credential_bytes,
    _service_identities,
)
from .runtime_action_service_v2 import _read_runtime_binding


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        print(
            "usage: aragorn-runtime-health-service RUNTIME_BINDING_CREDENTIAL HEALTH_CREDENTIAL",
            file=sys.stderr,
        )
        return 64
    try:
        result = _run(Path(arguments[0]), Path(arguments[1]))
        print(canonical_json(result).decode("ascii"))
        return 0
    except KeyboardInterrupt:
        return 130
    except (KeyError, OSError, RuntimeActionBrokerError, TypeError, ValueError) as exc:
        print(f"aragorn runtime health service: {exc}", file=sys.stderr)
        return 126


def _run(runtime_binding_path: Path, health_path: Path) -> dict[str, object]:
    if sys.platform != "linux":
        raise RuntimeActionServiceError("Linux execution is required")
    broker_uid, runtime_uid, runtime_gid, sensor_uid, sensor_gid = _service_identities()
    runtime_binding_path = _credential_path(runtime_binding_path, broker_uid)
    health_path = _credential_path(health_path, broker_uid, credential_name="health")
    runtime_digest, _runtime_profile_digest = _read_runtime_binding(
        runtime_binding_path, broker_uid
    )
    document = _parse_canonical_document(
        _read_credential_bytes(health_path, broker_uid, label="runtime health"),
        "runtime health credential",
    )
    config = RuntimeActionBrokerConfig(
        socket_path=_CONTROL_ROOT / "broker.sock",
        instance_lock_path=_CONTROL_ROOT / "broker.instance.lock",
        lock_path=_CONTROL_ROOT / "broker.lock",
        control_root=_CONTROL_ROOT,
        protected_root=_PROTECTED_ROOT,
        staging_root=_STAGING_ROOT,
        policy_path=_CONTROL_ROOT / "policy.json",
        revocations_path=_CONTROL_ROOT / "revocations.json",
        health_path=_CONTROL_ROOT / "health.json",
        observation_path=_CONTROL_ROOT / "observation.json",
        state_path=_CONTROL_ROOT / "state.json",
        expected_broker_uid=broker_uid,
        expected_peer_uid=sensor_uid,
        expected_peer_gid=sensor_gid,
        expected_runtime_digest=runtime_digest,
        expected_runtime_uid=runtime_uid,
        expected_runtime_gid=runtime_gid,
    )
    publish_runtime_control_document(config.health_path, document, config)
    return {
        "schema": "aragorn/runtime-health-publication-result/v1",
        "authority": "LOCAL_PROCESS_RESULT_ONLY_NOT_DURABLE_PROVENANCE_OR_RESPONSE_AUTHORITY",
        "health_digest": canonical_digest(document),
        "epoch": document["epoch"],
        "health_status": document["status"],
    }


if __name__ == "__main__":
    raise SystemExit(main())
