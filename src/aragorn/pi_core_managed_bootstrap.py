"""Compose held services with an unavailable or explicitly approved Pi path.

No provisioning, credential setup, provider dispatch or activation occurs on
import. This explicit operational entrypoint retains each owner's cleanup result;
neither a service connection nor a NO_REQUEST bootstrap is a useful-task result.
"""

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
    worker = None
    with lifecycle.hold_native_pi_services(deployment=service_runtime,
            configuration=service_configuration, binding=binding,
            provider_inputs=provider_inputs, deadline=deadline,
            cleanup_timeout_seconds=cleanup_timeout_seconds,
            **({"provider_credential": provider_credential} if enabled else {})) as services:
        services.guard(deadline=services.operation_deadline)
        worker = native.run_native_pi_worker(cas, context, profile=profile, grant=approved,
            protected_root=protected_root, runtime_conformance_digest=runtime_conformance_digest,
            deployment=deployment, revoked_context_ids=revoked_context_ids, now_unix=now_unix,
            deadline=services.operation_deadline, config=config,
            cleanup_timeout_seconds=cleanup_timeout_seconds,
            request_channels=services.channels.request_channels,
            **({"provider_channels": PiNativeProviderChannels(provider_approval.config,
                    services.channels, provider_approval)} if enabled else {}))
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
        "provider_configured": enabled,
        "useful_task_verified": False, "loaded_code_verified": False,
        "phase3_exit_eligible": False}
