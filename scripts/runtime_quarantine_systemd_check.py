"""One owned-fixture startup/denial response check, never production recovery."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path[:0] = [
    "/usr/lib/aragorn",
    str(Path(__file__).resolve().parent),
    "/src/scripts",
]

import runtime_response_systemd_check as prior

from aragorn import runtime_quarantine_response as quarantine
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.protected_skill_quarantine import read_quarantine_at

response = quarantine.response
_WORKER = "aragorn-runtime-action-worker.service"
_GATEWAY = "aragorn-agent-gateway.service"
_SENSOR = "aragorn-runtime-lineage-capability-observation-publisher.service"
_BROKER = "aragorn-runtime-lineage-capability-action-broker.service"
_ALL_UNITS = (_GATEWAY, _WORKER, _SENSOR, _BROKER)
_SHIM = "/usr/libexec/aragorn/aragorn-runtime-quarantine-service.py"
_STARTUP = "/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-skill-startup-service.py"
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _require_fixture(container: str) -> None:
    _expect(
        type(container) is str
        and re.fullmatch(r"[0-9a-f]{64}", container) is not None
        and sys.platform == "linux"
        and os.geteuid() == 0
        and response._process_cgroup(1) == "/docker/" + container + "/init.scope",
        "check requires the exact owned root Docker/systemd fixture",
    )


def _startup_state(status: int) -> dict[str, Any]:
    properties = (
        "Id",
        "InvocationID",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlPID",
        "ExecStartPre",
        "User",
        "Group",
        "NoNewPrivileges",
        "AmbientCapabilities",
        "CapabilityBoundingSet",
        "LimitNOFILE",
        "LimitNOFILESoft",
        "BindsTo",
    )
    state = response._show_unit(_WORKER, properties)
    command = state["ExecStartPre"]
    prefix = (
        "{ path=/usr/bin/python3.12 ; argv[]=" + _STARTUP + " ; ignore_errors=no ; "
    )
    _expect(
        command.startswith(prefix)
        and command.count("argv[]=") == 1
        and command.count("ignore_errors=") == 1
        and re.search(
            r"; pid=[1-9][0-9]* ; code=exited ; status="
            + str(status)
            + r"(?:/[A-Z0-9]+)? }$",
            command,
        )
        is not None
        and re.fullmatch(r"[0-9a-f]{32}", state["InvocationID"]) is not None
        and state["User"] == "aragorn-runtime"
        and state["Group"] == "aragorn-runtime"
        and state["NoNewPrivileges"] == "yes"
        and state["AmbientCapabilities"] == ""
        and state["CapabilityBoundingSet"] == ""
        and state["LimitNOFILE"] == "128"
        and state["LimitNOFILESoft"] == "128"
        and state["BindsTo"] == _SENSOR,
        "worker did not execute the exact unprivileged mandatory startup check",
    )
    credentials = (
        response._command(
            [
                "/usr/bin/busctl",
                "get-property",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1/unit/aragorn_2druntime_2daction_2dworker_2eservice",
                "org.freedesktop.systemd1.Service",
                "LoadCredential",
            ],
            timeout=3,
        )
        .decode("ascii")
        .strip()
    )
    binding = '"worker-binding" "/etc/aragorn/runtime-action-worker.json"'
    config = '"openclaw-config" "/etc/aragorn/agent-gateway/openclaw.json"'
    _expect(
        credentials
        in {"a(ss) 2 " + binding + " " + config, "a(ss) 2 " + config + " " + binding},
        "worker credential delivery changed",
    )
    if status == 0:
        _expect(
            state["ActiveState"] == "active" and int(state["MainPID"]) > 0,
            "clean worker did not start",
        )
    else:
        _expect(
            state["ActiveState"] == "failed"
            and state["MainPID"] == "0"
            and state["ControlPID"] == "0"
            and not os.path.lexists("/run/aragorn-runtime-action-worker/worker.sock"),
            "denied worker has a process or socket",
        )
    return {"unit": state, "load_credentials": credentials}


def _installed(skill: str) -> dict[str, Any]:
    with quarantine._installed_guard() as (root_fd, entries):
        record, tree, measured, active = quarantine.startup._installed_snapshot(
            root_fd, entries
        )
        _expect(measured == skill, "fixture installed skill changed")
        denial = read_quarantine_at(root_fd, skill, expected_uid=0)
        marker = None
        if denial is not None:
            name = ".aragorn-quarantined-skill-" + skill[7:] + ".json"
            marker = {
                "name": name,
                "identity": list(
                    response.broker._file_identity(
                        os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                    )
                ),
                "digest": canonical_digest(denial),
                "document": denial,
            }
        quarantine._recheck_installed(root_fd, entries, record, active)
        return {
            "active_record_digest": canonical_digest(record),
            "tree_digest": tree,
            "skill_digest": measured,
            "denial": marker,
        }


def _invoke(skill: str, snapshot: str) -> dict[str, Any]:
    argv = ["/usr/bin/python3.12", "-I", "-S", "-B", _SHIM, skill, snapshot]
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=_ENV,
        timeout=45,
        check=False,
    )
    _expect(
        len(result.stdout) <= 131072 and len(result.stderr) <= 4096,
        "quarantine command output exceeds fixture bound",
    )
    return {
        "argv": argv,
        "exit_code": result.returncode,
        "stdout": result.stdout.decode("ascii"),
        "stderr": result.stderr.decode("ascii"),
    }


def _startup_inputs() -> dict[str, str]:
    return {
        str(path): "sha256:"
        + hashlib.sha256(response._read_regular(path, 0, {mode})).hexdigest()
        for path, mode in (
            (response._WORKER_BINDING, 0o400),
            (Path("/etc/aragorn/agent-gateway/openclaw.json"), 0o400),
            (quarantine.startup._EXTERNAL_SOURCE, 0o444),
        )
    }


def _counterfactual_start(
    container: str, barrier: dict, installed: dict, initial: dict, inputs: dict
) -> dict:
    """Remove only this response's two masks in this doomed fixture; never its denial."""
    _require_fixture(container)
    expected_paths = [str(response._MASK_ROOT / unit) for unit in response._UNITS]
    _expect(
        barrier["status"] == "PERSISTENT_FIXED_PROFILE_STARTS_MASKED"
        and barrier["directory_fsynced"] is True
        and barrier["automatic_unmask_supported"] is False
        and [item["path"] for item in barrier["masks"]] == expected_paths
        and all(
            item["target"] == "/dev/null" and item["unit"]["Id"] == unit
            for item, unit in zip(barrier["masks"], response._UNITS, strict=True)
        ),
        "counterfactual masks are not the exact response-created pair",
    )
    with response._activation_guard():
        _expect(
            _startup_inputs() == inputs,
            "startup inputs changed before counterfactual start",
        )
        _expect(
            _installed(installed["skill_digest"]) == installed,
            "denial changed before counterfactual start",
        )
        response.broker._require_protected_ancestry(response._MASK_ROOT, 0)
        fd = os.open(
            response._MASK_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            identities = {}
            for unit in response._UNITS:
                metadata = os.stat(unit, dir_fd=fd, follow_symlinks=False)
                _expect(
                    stat.S_ISLNK(metadata.st_mode)
                    and metadata.st_uid == 0
                    and metadata.st_gid == 0
                    and metadata.st_nlink == 1
                    and os.readlink(unit, dir_fd=fd) == "/dev/null",
                    "counterfactual mask custody changed",
                )
                identities[unit] = response.broker._file_identity(metadata)
            for unit in response._UNITS:
                _expect(
                    response.broker._file_identity(
                        os.stat(unit, dir_fd=fd, follow_symlinks=False)
                    )
                    == identities[unit]
                    and os.readlink(unit, dir_fd=fd) == "/dev/null",
                    "counterfactual mask was rebound",
                )
                os.unlink(unit, dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(fd)
        response._command(["/usr/bin/systemctl", "daemon-reload"], timeout=5)
        argv = [
            "/usr/bin/systemctl",
            "--system",
            "--no-pager",
            "--no-ask-password",
            "start",
            _WORKER,
        ]
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=_ENV,
            timeout=10,
            check=False,
        )
        _expect(
            result.returncode != 0 and not result.stdout and len(result.stderr) <= 4096,
            "denied worker start was not refused",
        )
        denied = _startup_state(126)
        _expect(
            denied["unit"]["InvocationID"] != initial["unit"]["InvocationID"],
            "denied start reused the clean invocation",
        )
        _expect(
            _installed(installed["skill_digest"]) == installed,
            "counterfactual start changed installed denial",
        )
        _expect(_startup_inputs() == inputs, "counterfactual startup inputs changed")
        return {
            "authority": "OWNED_DISPOSABLE_FIXTURE_COUNTERFACTUAL_NOT_PRODUCTION_UNMASK_OR_RECOVERY",
            "removed_mask_paths": expected_paths,
            "start": {
                "argv": argv,
                "exit_code": result.returncode,
                "stdout": "",
                "stderr": result.stderr.decode("ascii"),
            },
            "worker": denied,
            "gateway_after": response._unit_state(_GATEWAY),
            "denial_unchanged": True,
            "gateway_containment_claim": False,
        }


def _prepare() -> dict[str, Any]:
    # Existing producer/setup primitives operate only after the exact fixture guard.
    import runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe as v3

    combined, p37c = v3.combined, v3.p37c
    p37b, openclaw = p37c.p37b, p37c.openclaw
    identities = response._identities()
    broker_uid, worker_uid, worker_gid, gateway_uid, gateway_gid, _, _ = identities
    response._EVIDENCE_ROOT.mkdir(mode=0o700)
    combined._reset_transient_request_directory()
    p37b.prior.lineage._reset()
    producer = p37b.prior._prepare_producer(worker_gid)
    p37b.prior._producer = producer
    skill_path = producer["paths"]["skill"]
    skill_raw = skill_path.read_bytes()
    skill = p37c._digest(skill_raw)
    _expect(
        skill == v3._SKILL_DIGEST,
        "producer skill differs from fixed external singleton",
    )
    p37b._reset_action_plane()
    with patch.object(combined, "_CONFIG", v3._CONFIG):
        config, _, _, _ = combined._prepare_gateway(
            gateway_uid, gateway_gid, worker_uid, producer["skill_name"], skill_raw
        )
    fd = os.open(p37c.lineage._PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    try:
        action = p37c._action_digests(fd, p37b._TARGET, p37b._PAYLOAD)
    finally:
        os.close(fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "phase3-runtime-quarantine-systemd-check",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": openclaw._SENSOR_DIGEST,
        "revocation_source_digest": openclaw._REVOCATION_SOURCE,
        "allow": [
            {
                "runtime_digest": v3._RUNTIME_DIGEST,
                "active_skill_digest": skill,
                **action,
            }
        ],
    }
    binding = {
        "schema": "aragorn/runtime-action-worker-binding/v1",
        "runtime_digest": v3._RUNTIME_DIGEST,
        "active_skill_digest": skill,
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
            skill_digest=skill,
            issued_at=now - 1,
            expires_at=now + 240,
        )
        controls = p37b._controls(policy, action, skill, now, 1)
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
    _expect(activation["exit_code"] == 0, "successor fixture activation failed")
    startup = _startup_state(0)
    now = int(time.time())
    revocations = {
        **controls["revocations"],
        "generation": 2,
        "observed_at_unix": now,
        "expires_at_unix": now + 15,
        "skill_digests": [skill],
    }
    p37b._write_document(
        Path("/etc/aragorn/runtime-action-revocation-publication.json"), revocations
    )
    publication = p37c._command(
        ["/usr/bin/systemctl", "start", "aragorn-runtime-revocation-publisher.service"],
        timeout=10,
    )
    _expect(publication["exit_code"] == 0, "fixture revocation publication failed")
    return {
        "runtime_digest": v3._RUNTIME_DIGEST,
        "configuration_digest": canonical_digest(config),
        "skill_digest": skill,
        "producer_transaction": producer["transaction"],
        "activation": activation,
        "startup": startup,
        "revocations": revocations,
        "publication": publication,
        "producer_authority": "LEGACY_INITIAL_FIXTURE_INSTALL_NOT_SUCCESSOR_PRODUCER_DEPLOYMENT",
    }


def _stop_fixture() -> dict[str, Any]:
    response._command(["/usr/bin/systemctl", "stop", *_ALL_UNITS], timeout=15)
    # The expected pre-start denial leaves a failed flag after stop. Its evidence
    # is already recorded above; reset only this doomed fixture's worker state.
    response._command(["/usr/bin/systemctl", "reset-failed", _WORKER], timeout=3)
    states = {}
    properties = ("Id", "ActiveState", "MainPID", "ControlPID")
    for unit in _ALL_UNITS:
        # The production response reader intentionally accepts only its two units.
        # This fixture cleanup additionally owns the fixed sensor and broker.
        raw = response._command(
            ["/usr/bin/systemctl", "show", "--property=" + ",".join(properties), unit],
            timeout=3,
        )
        pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
        _expect(
            all(len(pair) == 2 for pair in pairs), "malformed fixture cleanup state"
        )
        state = dict(pairs)
        _expect(
            len(pairs) == len(properties)
            and set(state) == set(properties)
            and state["Id"] == unit,
            "unbound fixture cleanup state",
        )
        states[unit] = state
    _expect(
        all(
            item["ActiveState"] == "inactive"
            and item["MainPID"] == "0"
            and item["ControlPID"] == "0"
            for item in states.values()
        ),
        "fixture stack cleanup was not confirmed: "
        + canonical_json(states).decode("ascii"),
    )
    return states


def _run(container: str) -> dict[str, Any]:
    _require_fixture(container)
    try:
        setup = _prepare()
        skill = setup["skill_digest"]
        snapshot = canonical_digest(setup["revocations"])
        identities = response._identities()
        before = prior._running(identities)
        inputs = _startup_inputs()
        installed_before = _installed(skill)
        _expect(installed_before["denial"] is None, "fixture skill was already denied")
        wrong = "sha256:" + ("0" if skill[7] != "0" else "1") + skill[8:]
        negative = _invoke(wrong, snapshot)
        _expect(
            negative["exit_code"] == 126
            and negative["stdout"] == ""
            and negative["stderr"] == "aragorn runtime quarantine: REFUSED\n",
            "wrong skill was not refused",
        )
        _expect(
            prior._running(identities) == before
            and _installed(skill) == installed_before
            and _startup_inputs() == inputs,
            "wrong skill changed the fixture",
        )
        positive = _invoke(skill, snapshot)
        _expect(
            positive["exit_code"] == 0
            and not positive["stderr"]
            and positive["stdout"].endswith("\n"),
            "quarantine response was not confirmed",
        )
        envelope = response.broker._parse_canonical_document(
            positive["stdout"][:-1].encode("ascii"), "quarantine result"
        )
        result, retention = prior._retained_response(envelope)
        installed_after = _installed(skill)
        _expect(_startup_inputs() == inputs, "response changed startup inputs")
        marker = installed_after["denial"]
        _expect(
            result["status"]
            == "DIGEST_DENIAL_RECORDED_AND_FIXED_PROFILE_STOPPED_MASKED"
            and result["expected_skill_digest"] == skill
            and result["revocation_snapshot_digest"] == snapshot
            and result["accepted_revocation"]["generation"] == 2
            and result["before"] == before
            and {**installed_after, "denial": None} == installed_before
            and marker is not None
            and marker["document"] == result["denial_record"]
            and marker["digest"] == result["denial_record_digest"]
            and marker["document"]["skill_digest"] == skill
            and marker["document"]["revocation_snapshot_digest"] == snapshot
            and result["active_record_digest"]
            == installed_after["active_record_digest"]
            and result["tree_digest"] == installed_after["tree_digest"],
            "response, installed bytes, accepted revocation or denial are unbound",
        )
        masks = prior._start_refused()
        cgroups = [
            response._cgroup_empty(unit, item["unit"])
            for unit, item in zip(response._UNITS, before, strict=True)
        ]
        _expect(
            all(item["status"] in {"EMPTY", "ABSENT"} for item in cgroups),
            "response cgroups remain populated",
        )
        counterfactual = _counterfactual_start(
            container,
            result["future_start_barrier"],
            installed_after,
            setup["startup"],
            inputs,
        )
        observation = {
            "schema": "aragorn/runtime-quarantine-systemd-integration-observation/v1",
            "authority": "LOCAL_SUCCESSOR_STARTUP_AND_MANUAL_RESPONSE_NOT_RUN_OR_PHASE3_QUALIFICATION",
            "status": "OBSERVED",
            "fixture_container": container,
            "setup": setup,
            "before": before,
            "installed_before": installed_before,
            "startup_inputs": inputs,
            "wrong_skill_refusal": negative,
            "response_invocation": positive,
            "evidence_retention": retention,
            "installed_after": installed_after,
            "masked_start_refusal": masks,
            "cgroups_after_response": cgroups,
            "counterfactual_startup_denial": counterfactual,
            "run_conformance_eligible": False,
            "phase3_eligible": False,
            "limitations": [
                "ONE_OWNED_DISPOSABLE_FIXTURE_NOT_PRODUCTION_DEPLOYMENT",
                "COUNTERFACTUAL_REMOVES_ONLY_THIS_RESPONSE_MASKS_NEVER_THE_DENIAL",
                "WORKER_PRESTART_REFUSAL_NOT_GATEWAY_CONTAINMENT_OR_PROCESS_BYTE_CONSUMPTION",
                "LEGACY_INITIAL_INSTALL_NOT_SUCCESSOR_PRODUCER_REINSTALL_ENFORCEMENT",
                "MANUAL_RESPONSE_NOT_AUTOMATIC_DETECTION_DISPATCH_OR_RUN_METRICS",
                "LOCAL_RETENTION_NOT_INDEPENDENT_QUALIFICATION",
            ],
        }
    finally:
        pending = sys.exception()
        try:
            cleanup = _stop_fixture()
        except (RuntimeError, OSError, ValueError) as exc:
            if pending is not None:
                raise RuntimeError(
                    f"fixture operation failed: {pending}; cleanup failed: {exc}"
                ) from exc
            raise
    observation["fixture_stack_cleanup"] = cleanup
    return observation


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            "usage: runtime_quarantine_systemd_check OWNED_CONTAINER_ID",
            file=sys.stderr,
        )
        return 64
    try:
        print(canonical_json(_run(arguments[0])).decode("ascii"))
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"quarantine fixture not confirmed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
