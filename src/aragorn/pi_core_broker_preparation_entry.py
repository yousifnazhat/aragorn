"""Explicit admitted broker-base installation or separate grant preparation."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import time

from . import pi_core_coordinator_entry as coordinator
from . import pi_core_service_lifecycle as lifecycle
from .pi_core_bundle_launch import hold_prepared_pi_bundle
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-broker-preparation-result/v1"
AUTHORITY = "PROTECTED_GRANT_PREPARATION_ONLY_NOT_ACTIVATION_OR_PHASE3"
_SOURCE = "opt/aragorn/src/aragorn/pi_core_broker_preparation_entry.py"
BASE_SCHEMA = "aragorn/pi-core-broker-base-result/v1"
BASE_AUTHORITY = "PROTECTED_BASE_INSTALLATION_ONLY_NOT_ACTIVATION_OR_PHASE3"
_BASE_SOURCE = "opt/aragorn/src/aragorn/pi_core_broker_base_provision.py"


class PiBrokerPreparationEntryError(RuntimeError):
    """Preparation refused or uncertain; retained state must not be retried."""


def _custody(source_loader, host_custody, deadline, *, installer=False):
    pin, sources, host = coordinator._custody(source_loader, host_custody, deadline)
    expected = coordinator._pin(source_loader.source_digests.get(_SOURCE))
    coordinator._require(sum(type(row) is dict and row.get("module") == __name__ and
        row.get("path") == _SOURCE and row.get("digest") == expected for row in sources) == 1,
        "BROKER_PREPARATION_SOURCE_NOT_CONSUMED")
    if installer:
        expected = coordinator._pin(source_loader.source_digests.get(_BASE_SOURCE))
        coordinator._require(sum(type(row) is dict and
            row.get("module") == "aragorn.pi_core_broker_base_provision" and
            row.get("path") == _BASE_SOURCE and row.get("digest") == expected for row in sources) == 1,
            "BROKER_BASE_INSTALLER_SOURCE_NOT_CONSUMED")
    return pin, sources, host


def _record(value):
    coordinator._require(type(value) is dict and value.get("schema") == "aragorn/pi-core-service-lifecycle/v1"
        and value.get("phase3_exit_eligible") is False and value.get("loaded_code_verified") is False,
        "BROKER_PREPARATION_INVALID_LIFECYCLE")
    raw = canonical_json(value)
    coordinator._require(len(raw) <= 4 * 1024 * 1024, "BROKER_PREPARATION_EVIDENCE_BOUND")
    return json.loads(raw)


def _completed(value):
    prepared = value.get("broker_preparation")
    return (value.get("status") == "CLOSED" and type(value.get("cleanup")) is dict and
        value["cleanup"].get("status") == "VERIFIED_OWNED_CLEANUP" and type(prepared) is dict and
        prepared.get("schema") == "aragorn/pi-core-broker-preparation/v1" and
        prepared.get("authority") == "EXPLICIT_GRANT_PREPARATION_NOT_ACTIVATION_OR_PHASE3" and
        prepared.get("status") == "PREPARED" and prepared.get("phase") == "COMPLETE" and
        prepared.get("command_attempted") is True and prepared.get("ack_attempted") is True and
        prepared.get("ack_sent") is True and prepared.get("phase3_exit_eligible") is False and
        all(type(prepared.get(key)) is dict for key in ("command", "result_packet", "readback")))


def _base_record(value):
    coordinator._require(type(value) is dict and
        value.get("schema") == "aragorn/pi-core-broker-base-installation/v1" and
        value.get("authority") == "FRESH_BASE_CONTROLS_ONLY_NOT_POLICY_HEALTH_GRANT_OR_PHASE3" and
        value.get("status") in {"INSTALLED", "REFUSED", "PARTIAL_OR_INDETERMINATE", "CLEANUP_HOLD"} and
        type(value.get("mutation_attempted")) is bool and type(value.get("owned_handles_closed")) is bool and
        all(value.get(key) is False for key in
            ("activation_performed", "service_ready", "current_grant_authority", "phase3_exit_eligible")),
        "BROKER_BASE_INVALID_INSTALLATION")
    raw = canonical_json(value)
    coordinator._require(len(raw) <= 4 * 1024 * 1024, "BROKER_BASE_EVIDENCE_BOUND")
    return json.loads(raw)


def run(plan_path, expected_plan_digest, *, deadline_ns, source_loader, host_custody, install_base=False):
    """The literal local selector installs fresh controls; default prepares a grant."""
    installing = install_base is True
    observation = {"schema": BASE_SCHEMA if installing else SCHEMA,
        "authority": BASE_AUTHORITY if installing else AUTHORITY, "status": "REFUSED",
        "managed_call_attempted": False, "managed_result": None,
        "preparation_attempted": False, "preparation_result": None,
        "host_before": None, "host_after": None, "source_before": None, "source_after": None,
        "plan_digest": None, "deployment_digest": None, "context_digest": None,
        "owned_inputs_closed": False, "owned_holders_closed": False,
        "input_cleanup_uncertainty": [], "preparation_failure_evidence": None,
        "phase3_exit_eligible": False}
    if installing:
        observation.update(base_installation_attempted=False, base_installation_result=None,
                           base_installation_failure_evidence=None)
    inputs = failure = body_failure = None
    phase = "PREFLIGHT"
    try:
        coordinator._require(type(install_base) is bool, "BROKER_BASE_LOCAL_BOOLEAN_REQUIRED")
        coordinator._require(os.geteuid() == os.getegid() == 0, "BROKER_PREPARATION_ROOT_REQUIRED")
        deadline = coordinator._deadline(deadline_ns)
        host_pin, observation["source_before"], observation["host_before"] = _custody(
            source_loader, host_custody, deadline)
        path, pin = coordinator._path(str(plan_path)), coordinator._pin(expected_plan_digest)
        inputs = coordinator._Inputs(deadline)
        candidate = inputs.read(path, pin, coordinator._PLAN_LIMIT)
        base_reference = None
        if installing:
            coordinator._require(type(candidate) is dict and "broker_base_state" in candidate,
                                 "BROKER_BASE_STATE_REFERENCE_REQUIRED")
            base_reference = coordinator._reference(candidate["broker_base_state"])
            candidate = {key: value for key, value in candidate.items() if key != "broker_base_state"}
        plan = coordinator._plan(candidate, host_pin, path)
        coordinator._require(plan["mode"] == "UNAVAILABLE" and plan["provider"] is None,
                             "BROKER_PREPARATION_CANNOT_CARRY_PROVIDER_AUTHORITY")
        observation["plan_digest"] = pin
        phase = "PREPARED_INPUTS"
        base_state = inputs.ref(base_reference) if installing else None
        context, deployment = inputs.ref(plan["context"]), inputs.ref(plan["deployment"])
        observation["deployment_digest"] = plan["deployment"]["digest"]
        observation["context_digest"] = plan["context"]["digest"]
        coordinator._launch(inputs.ref(plan["launch"]), plan["mode"])
        r, c, p = (plan[name] for name in ("service_runtime", "service_configuration", "provider_inputs"))
        runtime_args = dict(deployment_path=coordinator._path(r["deployment_path"]), receipt_digest=r["receipt_digest"],
            manifest=inputs.ref(r["manifest"]), manifest_digest=r["manifest"]["digest"],
            runtime_binding=inputs.ref(r["runtime_binding"]), runtime_binding_digest=r["runtime_binding"]["digest"], deadline=deadline)
        config_args = dict(deployment_path=coordinator._path(c["deployment_path"]), receipt_digest=c["receipt_digest"],
            manifest=inputs.ref(c["manifest"]), manifest_digest=c["manifest"]["digest"],
            configurations=inputs.ref(c["configurations"]), configurations_digest=c["configurations"]["digest"], deadline=deadline)
        public_args = dict(deployment_path=coordinator._path(p["deployment_path"]), receipt_digest=p["receipt_digest"],
            manifest=inputs.ref(p["manifest"]), manifest_digest=p["manifest"]["digest"], deadline=deadline)
        inputs.guard()
        _custody(source_loader, host_custody, deadline)
        cas_root = coordinator._path(plan["cas_root"])
        inputs.hold_directory(cas_root)
        cas = coordinator.CAS(cas_root, read_only=True)
        phase = "HELD_INPUTS"
        with ExitStack() as stack:
            try:
                runtime = stack.enter_context(coordinator.runtime.hold_pi_service_runtime(**runtime_args))
                config = stack.enter_context(coordinator.configuration.hold_pi_service_configuration(**config_args))
                public = stack.enter_context(coordinator.configuration.hold_pi_provider_inputs(**public_args))
                configs = config.configurations
                grant = configs["action"]["capability_grant"]
                coordinator._require(grant == configs["sensor"]["capability_grant"], "BROKER_PREPARATION_GRANTS_DIFFER")
                profile = coordinator.process.runtime_process_profile(configs["sensor"]["observation_binding"]["runtime_profile"])
                binding = coordinator.RuntimeActionWorkerBinding(*(grant[key] for key in
                    ("runtime_digest", "active_skill_digest", "policy_digest", "policy_version")))
                stack.enter_context(hold_prepared_pi_bundle(cas, context, profile=profile, grant=grant,
                    protected_root=Path("/var/lib/aragorn/admitted"),
                    runtime_conformance_digest=plan["runtime_conformance_digest"], deployment=deployment,
                    revoked_context_ids=tuple(plan["revoked_context_ids"]), now_unix=int(time.time()), deadline=deadline))
                inputs.guard()
                if installing:
                    # Import only this fixed handler through the already-installed
                    # source loader, then verify its actual consumed source row.
                    from . import pi_core_broker_base_provision as base
                    call_pin, observation["source_before"], observation["host_before"] = _custody(
                        source_loader, host_custody, deadline, installer=True)
                    coordinator._require(call_pin == host_pin, "BROKER_BASE_HOST_CHANGED")
                    phase = "BASE_INSTALLATION"
                    observation["base_installation_attempted"] = True
                    try:
                        observation["base_installation_result"] = _base_record(base.provision_pi_broker_base(
                            configuration=config, base_state=base_state, base_state_digest=base_reference["digest"],
                            deadline=deadline))
                    except BaseException as exc:
                        observation["base_installation_failure_evidence"] = "UNAVAILABLE_OR_INVALID"
                        try:
                            observation["base_installation_result"] = _base_record(getattr(exc, "pi_broker_base_observation", None))
                            observation["base_installation_failure_evidence"] = "RETAINED"
                        except BaseException:
                            pass  # Never replace an original installation or cleanup failure.
                        raise
                    installed = observation["base_installation_result"]
                    coordinator._require(installed["status"] == "INSTALLED" and
                        installed["mutation_attempted"] is installed["owned_handles_closed"] is True and
                        type(installed.get("readback")) is dict and installed.get("cleanup_uncertainty") == [] and
                        installed.get("destination") == "/var/lib/aragorn-runtime-action" and
                        installed.get("configuration_digest") == canonical_digest(configs) and
                        installed.get("base_state_digest") == base_reference["digest"], "BROKER_BASE_NOT_COMPLETE")
                else:
                    _custody(source_loader, host_custody, deadline)
                    phase = "PREPARATION_CALL"
                    observation["preparation_attempted"] = True
                    try:
                        observation["preparation_result"] = _record(lifecycle.prepare_native_pi_broker_control(
                            deployment=runtime, configuration=config, provider_inputs=public, binding=binding,
                            deadline=deadline, cleanup_timeout_seconds=5.0))
                    except BaseException as exc:
                        observation["preparation_failure_evidence"] = "UNAVAILABLE_OR_INVALID"
                        try:
                            observation["preparation_result"] = _record(getattr(exc, "pi_service_lifecycle_observation", None))
                            observation["preparation_failure_evidence"] = "RETAINED"
                        except BaseException:
                            pass  # The direct owner's evidence must not replace its original failure.
                        raise
                    coordinator._require(_completed(observation["preparation_result"]), "BROKER_PREPARATION_NOT_COMPLETE")
                phase = "POST_CALL_CUSTODY"
                inputs.guard()
                after_pin, observation["source_after"], observation["host_after"] = _custody(
                    source_loader, host_custody, deadline, installer=installing)
                coordinator._require(after_pin == host_pin, "BROKER_PREPARATION_HOST_CHANGED")
                phase = "HOLDER_CLEANUP"
            except BaseException as exc:
                body_failure = exc
                raise
        observation["owned_holders_closed"] = True
        observation["status"] = ("BASE_CONTROLS_INSTALLED_NOT_READY_OR_QUALIFIED" if installing else
                                 "BROKER_PREPARED_NOT_ACTIVATED_OR_QUALIFIED")
    except BaseException as exc:
        failure = body_failure or exc
        if body_failure is not None and exc is not body_failure:
            phase = "HOLDER_CLEANUP"
    finally:
        if inputs is not None:
            try:
                inputs.close()
                observation["owned_inputs_closed"] = True
            except BaseException as exc:
                failure = failure or exc
                phase = "INPUT_CLEANUP"
            observation["input_cleanup_uncertainty"] = json.loads(canonical_json(inputs.cleanup_uncertainty))
    if failure is not None:
        result = observation["base_installation_result"] if installing else observation["preparation_result"]
        hold = type(result) is dict and result.get("status") == "CLEANUP_HOLD"
        if installing and type(result) is dict:
            hold = hold or result.get("owned_handles_closed") is False or bool(result.get("cleanup_uncertainty"))
        observation["status"] = "CLEANUP_HOLD" if hold or phase in {"HOLDER_CLEANUP", "INPUT_CLEANUP"} else "REFUSED_OR_INDETERMINATE"
        observation["failure_stage"] = phase
        error = PiBrokerPreparationEntryError("BROKER_BASE_REFUSED_OR_CLEANUP_HOLD" if installing else
                                              "BROKER_PREPARATION_REFUSED_OR_CLEANUP_HOLD")
        error.observation = observation
        raise error from failure
    return observation
