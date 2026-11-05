"""Compose held service lifecycle with the existing unavailable Pi bootstrap.

No provisioning, credential setup, provider dispatch or activation occurs on
import. This explicit operational entrypoint retains each owner's cleanup result;
neither a service connection nor a NO_REQUEST bootstrap is a useful-task result.
"""

from . import pi_core_native_supervisor as native
from . import pi_core_service_lifecycle as lifecycle
from . import pi_core_service_configuration as configuration
from . import pi_core_service_provision as runtime
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


def run_native_pi_service_bootstrap(cas, context, *, profile, grant, protected_root,
        runtime_conformance_digest, deployment, revoked_context_ids, now_unix,
        deadline, config, service_runtime, service_configuration, provider_inputs,
        binding, cleanup_timeout_seconds=5.0):
    """Run one explicit managed bootstrap, never turn on the provider path.

    Borrowed runtime/config/public-input holders remain caller-owned. The service
    owner reserves its cleanup budget first; the existing worker owner reserves
    its own budget inside that deadline. Neither can extend the original limit.
    """
    _require(type(config) is PiConfinedLaunchConfig and config.native_request is True,
             "managed service bootstrap requires the protected native request mode")
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
    worker = None
    with lifecycle.hold_native_pi_services(deployment=service_runtime,
            configuration=service_configuration, binding=binding,
            provider_inputs=provider_inputs, deadline=deadline,
            cleanup_timeout_seconds=cleanup_timeout_seconds) as services:
        services.guard(deadline=services.operation_deadline)
        worker = native.run_native_pi_worker(cas, context, profile=profile, grant=approved,
            protected_root=protected_root, runtime_conformance_digest=runtime_conformance_digest,
            deployment=deployment, revoked_context_ids=revoked_context_ids, now_unix=now_unix,
            deadline=services.operation_deadline, config=config,
            cleanup_timeout_seconds=cleanup_timeout_seconds,
            request_channels=services.channels.request_channels)
    service_result = services.observation
    complete = (worker.get("status") == "BOOTSTRAP_COMPLETE" and
                worker.get("cleanup", {}).get("status") == "VERIFIED_OWNED_CLEANUP" and
                service_result.get("cleanup", {}).get("status") == "VERIFIED_OWNED_CLEANUP")
    return {"schema": "aragorn/pi-core-managed-bootstrap-result/v1",
        "authority": "SERVICE_AND_WORKER_BOOTSTRAP_ONLY_NOT_USEFUL_TASK_OR_PHASE3",
        "status": "BOOTSTRAP_COMPLETE" if complete else "CLEANUP_HOLD" if
            worker.get("status") == "CLEANUP_HOLD" or
            worker.get("cleanup", {}).get("status") != "VERIFIED_OWNED_CLEANUP" or
            service_result.get("cleanup", {}).get("status") != "VERIFIED_OWNED_CLEANUP" else "REFUSED",
        "worker": worker, "services": service_result, "provider_available": False,
        "useful_task_verified": False, "loaded_code_verified": False,
        "phase3_exit_eligible": False}
