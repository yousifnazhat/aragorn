"""Compose held services with an unavailable or explicitly approved Pi path.

No provisioning, credential setup, provider dispatch or activation occurs on
import. This explicit operational entrypoint retains each owner's cleanup result;
neither a service connection nor a NO_REQUEST bootstrap is a useful-task result.
"""

import json

from . import pi_core_native_supervisor as native
from . import pi_core_service_lifecycle as lifecycle
from . import pi_core_service_configuration as configuration
from . import pi_core_service_provision as runtime
from . import pi_core_service_entry as entry
from . import pi_core_provider_credential as credentials
from . import pi_core_provider_approval as approvals
from .pi_core_native_provider import PiNativeProviderChannels
from . import runtime_process_profile as process
from .pi_core_confined_launch import PiConfinedLaunchConfig
from .oci_worker_protocol import canonical_json
from .runtime_action_worker import RuntimeActionWorkerBinding
from .runtime_capability_grant import parse_runtime_capability_grant


class PiManagedBootstrapError(RuntimeError):
    """Input/custody refusal; no retries or implicit effect authority."""


def _require(value, reason):
    if not value:
        raise PiManagedBootstrapError(reason)


def _uncertain(uncertainty, owner, reason):
    # Only fixed owner/reason pairs from this module enter the public metadata.
    row = {"owner": owner, "reason": reason}
    if row not in uncertainty:
        uncertainty.append(row)


def _copy_observation(value):
    _require(type(value) is dict, "owner observation is not an object")
    raw = canonical_json(value)
    _require(len(raw) <= 4 * 1024 * 1024, "owner observation exceeds the managed report bound")
    return json.loads(raw)


def _snapshot(value, owner, uncertainty):
    try:
        return _copy_observation(value)
    except BaseException:
        _uncertain(uncertainty, owner, "SNAPSHOT_UNAVAILABLE")
        return None


def _service_failure_observation(services, failure, uncertainty):
    if services is not None:
        try:
            value = services.observation
        except BaseException:
            _uncertain(uncertainty, "services", "SNAPSHOT_UNAVAILABLE")
        else:
            retained = _snapshot(value, "services", uncertainty)
            if retained is not None:
                return retained
    # The existing factory attaches this record even to an OSError before
    # yielding. Its call boundary, not the exception's class, owns that record.
    try:
        value = getattr(failure, "pi_service_lifecycle_observation", None)
        if value is None:
            _uncertain(uncertainty, "services", "NO_OWNED_OBSERVATION")
            return None
        if (type(value) is not dict or
                value.get("schema") != "aragorn/pi-core-service-lifecycle/v1" or
                value.get("status") not in ("PREPARING", "CLOSED", "CLEANUP_HOLD",
                    "AUTHENTICATED_SERVICES_PROVIDER_PREPARED",
                    "AUTHENTICATED_SERVICES_PROVIDER_UNAVAILABLE") or
                value.get("loaded_code_verified") is not False or
                value.get("phase3_exit_eligible") is not False or
                type(value.get("cleanup")) is not dict):
            _uncertain(uncertainty, "services", "INVALID_EXCEPTION_OBSERVATION")
            return None
        return _snapshot(value, "services", uncertainty)
    except BaseException:
        _uncertain(uncertainty, "services", "SNAPSHOT_UNAVAILABLE")
        return None


def _native_failure_observation(failure, uncertainty):
    try:
        value = getattr(failure, "pi_native_supervisor_observation", None)
        if value is None:
            return None
        _require(type(value) is dict and
                 value.get("schema") == "aragorn/pi-core-native-supervisor-result/v1" and
                 value.get("authority") == "BOOTSTRAP_AND_OWNED_CLEANUP_ONLY_NOT_EFFECT_RUN_OR_PHASE3_QUALIFICATION" and
                 value.get("status") == "CLEANUP_HOLD" and
                 all(key in value and (value[key] is None or type(value[key]) is dict) for key in
                     ("bootstrap", "identity_registration", "request_channel", "provider_channel",
                      "source_observation", "cleanup")), "native failure observation is invalid")
        return _copy_observation(value)
    except BaseException:
        _uncertain(uncertainty, "worker", "INVALID_NATIVE_FAILURE_OBSERVATION")
        return None


def _cleanup_verified(value):
    return (type(value) is dict and value.get("status") != "CLEANUP_HOLD" and
            type(value.get("cleanup")) is dict and
            value["cleanup"].get("status") == "VERIFIED_OWNED_CLEANUP")


def _result(worker, services, enabled, status):
    return {"schema": "aragorn/pi-core-managed-bootstrap-result/v1",
        "authority": "SERVICE_AND_WORKER_BOOTSTRAP_ONLY_NOT_USEFUL_TASK_OR_PHASE3",
        "status": status, "worker": worker, "services": services,
        "provider_available": False, "provider_configured": enabled,
        "useful_task_verified": False, "loaded_code_verified": False,
        "phase3_exit_eligible": False}


def run_native_pi_service_bootstrap(cas, context, *, profile, grant, protected_root,
        runtime_conformance_digest, deployment, revoked_context_ids, now_unix,
        deadline, config, service_runtime, service_configuration, provider_inputs,
        binding, cleanup_timeout_seconds=5.0, provider_credential=None, provider_approval=None):
    """Run one explicit managed lifetime; unavailable remains the default.

    Borrowed runtime/config/public-input holders remain caller-owned. The service
    owner reserves its cleanup budget first; the existing worker owner reserves
    its own budget inside that deadline. Neither can extend the original limit.
    """
    _require(type(config) is PiConfinedLaunchConfig and config.native_request is True,
             "managed service bootstrap requires the protected native request mode")
    enabled = config.provider_route_digest is not None
    if enabled:
        _require(type(provider_credential) is credentials.PiProviderCredential and
                 type(provider_approval) is approvals.PiProviderApproval,
                 "provider-enabled lifecycle requires separately prepared credential, egress and approval custody")
        _require(provider_credential.provider_inputs is provider_inputs and
                 provider_approval.route_digest == config.provider_route_digest,
                 "provider credential, profile and approved route differ")
        provider_credential.guard(deadline=deadline)
        provider_approval.guard(deadline=deadline)
    else:
        _require(provider_credential is None and provider_approval is None,
                 "unavailable bootstrap cannot receive provider authority")
    _require(type(profile) is process.RuntimeProcessProfile and
             type(binding) is RuntimeActionWorkerBinding,
             "exact worker profile and binding required")
    _require(type(service_runtime) is runtime.PiServiceRuntime and
             type(service_configuration) is configuration.PiServiceConfiguration and
             type(provider_inputs) is configuration.PiProviderInputs,
             "held runtime, service configuration and public inputs required")
    for held in (service_runtime, service_configuration, provider_inputs):
        held.guard(deadline=deadline)
    configs = service_configuration.configurations
    approved = parse_runtime_capability_grant(canonical_json(grant), now_unix)
    _require(approved == configs["action"]["capability_grant"] ==
             configs["sensor"]["capability_grant"], "worker and services disagree on the grant")
    _require(service_configuration.identities["worker"] ==
             {"uid": config.worker_uid, "gid": config.worker_gid}, "worker role differs")
    expected_profile = process.runtime_process_profile(configs["sensor"]["observation_binding"]["runtime_profile"])
    _require(profile == expected_profile and profile.digest == approved["runtime_profile_digest"],
             "worker and sensor profiles differ")
    _require(all(getattr(binding, key) == approved[key] for key in
             ("runtime_digest", "active_skill_digest", "policy_digest", "policy_version")),
             "worker binding differs from the prepared grant")
    if enabled:
        root = provider_approval.config
        _require(root.expected_broker_uid == 0 and
                 (root.expected_runtime_uid, root.expected_runtime_gid) == (config.worker_uid, config.worker_gid) and
                 root.expected_runtime_digest == profile.runtime_digest and
                 not root.control_root.is_relative_to(entry.EFFECT_ROOT) and
                 not entry.EFFECT_ROOT.is_relative_to(root.control_root),
                 "root provider approval differs from the worker or aliases action control")
    worker = services = worker_snapshot = service_result = None
    worker_call_attempted = service_read_attempted = False
    uncertainty = []
    try:
        with lifecycle.hold_native_pi_services(deployment=service_runtime,
                configuration=service_configuration, binding=binding,
                provider_inputs=provider_inputs, deadline=deadline,
                cleanup_timeout_seconds=cleanup_timeout_seconds,
                **({"provider_credential": provider_credential} if enabled else {})) as services:
            services.guard(deadline=services.operation_deadline)
            worker_call_attempted = True
            try:
                worker = native.run_native_pi_worker(cas, context, profile=profile, grant=approved,
                    protected_root=protected_root, runtime_conformance_digest=runtime_conformance_digest,
                    deployment=deployment, revoked_context_ids=revoked_context_ids, now_unix=now_unix,
                    deadline=services.operation_deadline, config=config,
                    cleanup_timeout_seconds=cleanup_timeout_seconds,
                    request_channels=services.channels.request_channels,
                    **({"provider_channels": PiNativeProviderChannels(provider_approval.config,
                            services.channels, provider_approval)} if enabled else {}))
            except BaseException as failure:
                worker_snapshot = _native_failure_observation(failure, uncertainty)
                raise
            # Retain the returned bytes before a later service owner can fail.
            try:
                worker_snapshot = _copy_observation(worker)
            except BaseException:
                _uncertain(uncertainty, "worker", "SNAPSHOT_UNAVAILABLE")
                raise
        service_read_attempted = True
        service_result = services.observation
        complete = (worker.get("status") == "BOOTSTRAP_COMPLETE" and
                    worker.get("cleanup", {}).get("status") == "VERIFIED_OWNED_CLEANUP" and
                    service_result.get("cleanup", {}).get("status") == "VERIFIED_OWNED_CLEANUP")
        return _result(worker, service_result, enabled,
            "BOOTSTRAP_COMPLETE" if complete else "CLEANUP_HOLD" if
                worker.get("status") == "CLEANUP_HOLD" or
                worker.get("cleanup", {}).get("status") != "VERIFIED_OWNED_CLEANUP" or
                service_result.get("cleanup", {}).get("status") != "VERIFIED_OWNED_CLEANUP" else "REFUSED")
    except BaseException as failure:
        if worker_call_attempted and worker_snapshot is None:
            # A missing fixed producer record is unknown, not clean shutdown.
            _uncertain(uncertainty, "worker", "NO_RETURNED_OBSERVATION")
        service_snapshot = (_snapshot(service_result, "services", uncertainty) if service_read_attempted
                            else _service_failure_observation(services, failure, uncertainty))
        clean = (not uncertainty and _cleanup_verified(service_snapshot) and
                 (not worker_call_attempted or _cleanup_verified(worker_snapshot)))
        observation = _result(worker_snapshot, service_snapshot, enabled,
                              "REFUSED" if clean else "CLEANUP_HOLD")
        observation["failure_evidence"] = {
            "service_scope_acquired": services is not None,
            "worker_call_attempted": worker_call_attempted,
            "uncertainty": uncertainty}
        try:
            failure.pi_managed_bootstrap_observation = observation
        except BaseException:
            # An exception that forbids attachment must still escape unchanged;
            # its caller will retain unknown evidence rather than false success.
            pass
        raise
