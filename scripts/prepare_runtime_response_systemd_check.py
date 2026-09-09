"""Prepare only the disposable Docker/systemd response fixture, then check it."""

from __future__ import annotations

import os
import re
import runpy
import sys
import time
from pathlib import Path
from unittest.mock import patch

sys.path[:0] = ["/usr/lib/aragorn", "/src/scripts"]

from aragorn import runtime_response_service as response
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


def _require_fixture() -> None:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or re.fullmatch(
            r"/docker/[0-9a-f]{64}/init\.scope", response._process_cgroup(1)
        )
        is None
    ):
        raise RuntimeError(
            "preparation requires the disposable root Docker/systemd fixture"
        )


def _run() -> dict:
    _require_fixture()
    import runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe as v3

    combined, p37c = v3.combined, v3.p37c
    p37b, openclaw = p37c.p37b, p37c.openclaw
    identities = response._identities()
    broker_uid, worker_uid, worker_gid, gateway_uid, gateway_gid, _, _ = identities
    combined._reset_transient_request_directory()
    p37b.prior.lineage._reset()
    producer = p37b.prior._prepare_producer(worker_gid)
    p37b.prior._producer = producer
    skill_path = producer["paths"]["skill"]
    skill_raw = skill_path.read_bytes()
    skill_digest = p37c._digest(skill_raw)
    if skill_digest != v3._SKILL_DIGEST:
        raise RuntimeError("producer skill differs from the frozen singleton")
    p37b._reset_action_plane()
    with patch.object(combined, "_CONFIG", v3._CONFIG):
        config, _, _, _ = combined._prepare_gateway(
            gateway_uid, gateway_gid, worker_uid, producer["skill_name"], skill_raw
        )
    descriptor = os.open(p37c.lineage._PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    try:
        action = p37c._action_digests(descriptor, p37b._TARGET, p37b._PAYLOAD)
    finally:
        os.close(descriptor)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "phase3-runtime-response-systemd-check",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": openclaw._SENSOR_DIGEST,
        "revocation_source_digest": openclaw._REVOCATION_SOURCE,
        "allow": [
            {
                "runtime_digest": v3._RUNTIME_DIGEST,
                "active_skill_digest": skill_digest,
                **action,
            }
        ],
    }
    binding = {
        "schema": "aragorn/runtime-action-worker-binding/v1",
        "runtime_digest": v3._RUNTIME_DIGEST,
        "active_skill_digest": skill_digest,
        "policy_digest": canonical_digest(policy),
        "policy_version": 1,
    }
    profile_document, profile = p37b._profile(
        runtime_digest=v3._RUNTIME_DIGEST,
        executable_digest=p37c._file(p37b._PYTHON.resolve(strict=True))["digest"],
        cgroup=p37b._predicted_service_cgroup(p37b._WORKER_UNIT),
        skill_path=skill_path,
    )
    now = int(time.time())
    with patch.object(openclaw, "_RUNTIME_DIGEST", v3._RUNTIME_DIGEST):
        grant = p37c._grant(
            profile_digest=profile.digest,
            policy=policy,
            action=action,
            producer=producer,
            skill_digest=skill_digest,
            issued_at=now - 1,
            expires_at=now + 240,
        )
        controls = p37b._controls(policy, action, skill_digest, now, 1)
        p37b._write_stack_inputs(
            profile_document=profile_document,
            profile_digest=profile.digest,
            worker_binding=binding,
            grant=grant,
            controls=controls,
            broker_uid=broker_uid,
            worker_gid=worker_gid,
        )
    activation = p37c._command([str(p37c._ACTIVATOR)], timeout=60)
    if activation["exit_code"] != 0:
        raise RuntimeError(
            "fixture activation failed: "
            + p37c._raw_bytes(activation["stderr"]).decode()[-3000:]
        )
    units = {unit: p37b._unit(unit) for unit in p37c._UNITS}
    if not all(
        item["ActiveState"] == "active" and int(item["MainPID"]) > 0
        for item in units.values()
    ):
        raise RuntimeError("response fixture stack is not active")
    listener = p37c._gateway_listener(int(units[p37b._GATEWAY_UNIT]["MainPID"]))
    now = int(time.time())
    revocations = {
        **controls["revocations"],
        "generation": 2,
        "observed_at_unix": now,
        "expires_at_unix": now + 15,
        "skill_digests": [skill_digest],
    }
    p37b._write_document(
        Path("/etc/aragorn/runtime-action-revocation-publication.json"), revocations
    )
    publication = p37c._command(
        ["/usr/bin/systemctl", "start", "aragorn-runtime-revocation-publisher.service"],
        timeout=10,
    )
    if publication["exit_code"] != 0:
        raise RuntimeError("fixture revocation publication failed")
    checker = runpy.run_path("/opt/aragorn/runtime-response-systemd-check.py")
    result = checker["_run"](skill_digest, canonical_digest(revocations))
    return {
        "schema": "aragorn/runtime-response-systemd-fixture/v1",
        "setup": {
            "runtime_digest": v3._RUNTIME_DIGEST,
            "configuration_digest": canonical_digest(config),
            "skill_digest": skill_digest,
            "installed_activator": p37c._file(p37c._ACTIVATOR),
            "installed_worker": p37c._file(v3._PREFLIGHT),
            "activation": activation,
            "units_before": units,
            "gateway_listener": listener,
            "revocations": revocations,
            "publication": publication,
        },
        "check": result,
    }


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("fixture preparation accepts no arguments")
    print(canonical_json(_run()).decode("ascii"))
