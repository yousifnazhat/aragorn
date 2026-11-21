"""Protected owner of one stopped-mask observation, not service bootstrap or admission."""
import os
from pathlib import Path
import re
import time

from . import pi_core_coordinator_entry as entry
from . import pi_core_mask_capture_release as release
from . import pi_core_native_supervisor as native
from . import pi_core_node_source_observer as node
from . import pi_core_restricted_profile as restricted
from . import pi_core_stopped_mask_capture as stopped
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_capability_grant import parse_runtime_capability_grant


PLAN = "aragorn/pi-core-stopped-mask-coordinator-plan/v1"
SPINE_PLAN = "aragorn/pi-core-stopped-mask-and-handles-plan/v1"
REPORT = "aragorn/pi-core-mask-capture-entry/v1"
_ADMITTED = Path("/var/lib/aragorn/admitted")
_PYTHON = Path("/opt/aragorn-cpython/bin/python3.12")
_CORE = ("pi_core_mask_capture_entry", "pi_core_mask_capture_release", "pi_core_native_supervisor",
         "pi_core_node_source_observer", "pi_core_source_observer", "pi_core_stopped_mask_capture",
         "pi_core_stopped_mask_view", "pi_core_mask_probe", "pi_core_mask_custody", "pi_core_state_admission",
         "pi_core_state_masks", "pi_core_state_mounts", "pi_core_state_exposure", "pi_core_manager_state_view",
         "pi_core_configuration_carrier")


_SPINE_CORE = ("pi_core_stopped_worker_walk", "pi_core_worker_walk_evidence")


def _custody(source_loader, host_custody, deadline, *, worker_spine=False):
    if worker_spine:
        # The protected loader must have executed these pinned bytes before the claim.
        from . import pi_core_stopped_worker_walk, pi_core_worker_walk_evidence
    host_pin, rows, host = entry._custody(source_loader, host_custody, deadline)
    pins = source_loader.source_digests
    for name in _CORE + (_SPINE_CORE if worker_spine else ()):
        path = "opt/aragorn/src/aragorn/" + name + ".py"
        pin = entry._pin(pins.get(path))
        entry._require(sum(row.get("module") == "aragorn." + name and row.get("path") == path and
                           row.get("digest") == pin for row in rows) == 1, "MASK_SOURCE_NOT_CONSUMED")
    entry._require(host["python_executable"] == str(_PYTHON), "MASK_UNEXPECTED_INTERPRETER")
    return host_pin, entry._pin(host_custody._expected[_PYTHON]["digest"])


def _plan(plan, host_pin):
    entry._exact(plan, ("schema", "host_profile_digest", "cas_root", "context", "deployment",
                        "launch", "revoked_context_ids", "runtime_conformance_digest", "service_configuration", "capture"))
    entry._require(plan["schema"] in (PLAN, SPINE_PLAN) and plan["host_profile_digest"] == host_pin, "MASK_PLAN_BINDING")
    entry._path(plan["cas_root"])
    entry._pin(plan["runtime_conformance_digest"])
    service = entry._configuration_section(plan["service_configuration"])
    entry._require(plan["schema"] != SPINE_PLAN or "carrier" in service, "HANDLE_CAPTURE_REQUIRES_PROTECTED_CONFIGURATION")
    for ref in (plan["context"], plan["deployment"], plan["launch"]):
        entry._reference(ref)
    revoked = plan["revoked_context_ids"]
    entry._require(type(revoked) is list and len(revoked) <= 4096 and
                   [entry._pin(p) for p in revoked] == sorted(set(revoked)), "MASK_REVOKED_CONTEXTS")
    c = plan["capture"]
    entry._exact(c, ("store", "receipt_directory", "volume_device", "backing_devices", "fs_type", "attempt_id"))
    entry._path(c["store"])
    entry._path(c["receipt_directory"])
    entry._require(type(c["attempt_id"]) is str and re.fullmatch(r"[0-9a-f]{32}", c["attempt_id"])
                   and int(c["attempt_id"], 16) and type(c["backing_devices"]) is list, "MASK_CAPTURE_BINDING")
    stopped._volume(c["volume_device"], c["backing_devices"], c["fs_type"])
    if "carrier" in service:
        entry._require(service["carrier"]["device"] not in (c["volume_device"], *c["backing_devices"]),
                       "MASK_CONFIGURATION_CARRIER_ALIASES_STATE")
    return plan


def _result(raw, obs, *, worker_spine=False):
    entry._require(type(raw) is dict and raw.get("schema") == "aragorn/pi-core-stopped-mask-supervisor/v1"
                   and raw.get("authority") == "RETAINED_CAPTURE_ONLY_NOT_GATE_DENIAL_STORAGE_ADMISSION_OR_PHASE3_QUALIFICATION"
                   and raw.get("status") in ("CAPTURE_RETAINED_ONLY", "CAPTURE_RETAINED_INCONSISTENT", "REFUSED", "CLEANUP_HOLD"),
                   "MASK_NATIVE_RESULT")
    clean = raw.get("cleanup")
    verified = type(clean) is dict and clean.get("status") == "VERIFIED_OWNED_CLEANUP"
    status = raw["status"]
    retained = status in ("CAPTURE_RETAINED_ONLY", "CAPTURE_RETAINED_INCONSISTENT")
    receipt = raw.get("retention")
    if retained or receipt is not None:
        fields = ("capture_digest", "receipt_digest", "mask_consistent", "reason",
                  "activation_authorized", "installed_isolation_verified", "phase3_exit_eligible")
        entry._exact(receipt, fields + (("worker_spine_digest",) if worker_spine else ()))
        consistent = receipt["mask_consistent"]
        pins = (entry._pin(receipt["capture_digest"]), entry._pin(receipt["receipt_digest"]))
        if worker_spine:
            spine = entry._pin(receipt["worker_spine_digest"])
            entry._require(int(spine[7:], 16) and spine not in pins, "HANDLE_CAPTURE_MISSING_SEPARATE_MEMBER")
        entry._require(type(consistent) is bool and all(int(p[7:], 16) for p in pins) and pins[0] != pins[1]
                       and all(receipt[k] is False for k in ("activation_authorized", "installed_isolation_verified",
                                                             "phase3_exit_eligible"))
                       and ((consistent and receipt["reason"] is None) or (not consistent and
                            type(receipt["reason"]) is str and 0 < len(receipt["reason"]) <= 256)),
                       "MASK_NATIVE_RECEIPT")
        if retained:
            entry._require(consistent == (status == "CAPTURE_RETAINED_ONLY") and raw.get("failure") is None
                           and verified and all(clean.get(k) is True for k in ("unit_absent", "process_exit_observed",
                                                                               "cgroup_empty_or_absent", "socket_removed")),
                           "MASK_NATIVE_CLEANUP_OR_FINDING")
        obs.update(capture_digest=pins[0], receipt_digest=pins[1], mask_consistent=consistent)
    obs.update(status=status if verified else "CLEANUP_HOLD", cleanup_verified=verified and status != "CLEANUP_HOLD")


def run(plan_path, expected_plan_digest, *, release_digest, deadline_ns, source_loader, host_custody):
    """Require held plan, installed TCB and distinct single-use operator authority before calling B59."""
    obs = dict(schema=REPORT, status="REFUSED", capture_attempted=False, claim_confirmed=False,
               owned_inputs_closed=False, cleanup_verified=False, mask_consistent=None, capture_digest=None,
               receipt_digest=None, activation_authorized=False, phase3_exit_eligible=False)
    inputs, failure = None, None
    claim_started, opening, leaving, body_failure = False, False, False, None
    configuration_close_uncertain = False
    try:
        entry._require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, "MASK_ROOT_REQUIRED")
        deadline = entry._deadline(deadline_ns)
        host_pin, interpreter = _custody(source_loader, host_custody, deadline)
        path, plan_pin, release_pin = entry._path(str(plan_path)), entry._pin(expected_plan_digest), entry._pin(release_digest)
        entry._require(len({host_pin, plan_pin, release_pin}) == 3, "MASK_SEPARATE_RELEASE_REQUIRED")
        inputs = entry._Inputs(deadline)
        plan = _plan(inputs.read(path, plan_pin, entry._PLAN_LIMIT), host_pin)
        worker_spine = plan["schema"] == SPINE_PLAN
        context, deployment = inputs.ref(plan["context"]), inputs.ref(plan["deployment"])
        config = entry._launch(inputs.ref(plan["launch"]), "UNAVAILABLE")
        source = config.source_observation
        entry._require(type(source) is dict and source.get("schema") == restricted.PROFILE_SCHEMA
                       and canonical_digest(source) == config.source_observation_digest, "MASK_RESTRICTED_SOURCE_REQUIRED")
        node.validate_node_profile(source)
        for name, field in (("pi_core_source_observer", "producer_digest"), ("pi_core_node_source_observer", "node_observer_digest")):
            entry._require(source["pins"][field] == source_loader.source_digests["opt/aragorn/src/aragorn/" + name + ".py"],
                           "MASK_OBSERVER_NOT_INSTALLED")
        c, service = plan["capture"], plan["service_configuration"]
        capture = stopped.StoppedMaskCapture(entry._path(c["store"]), entry._path(c["receipt_directory"]),
            c["attempt_id"], plan["deployment"]["digest"], config.source_observation_digest, interpreter,
            c["volume_device"], tuple(c["backing_devices"]), c["fs_type"], worker_spine=worker_spine)
        cas_root, config_root = entry._path(plan["cas_root"]), entry._path(service["deployment_path"])
        inputs.hold_directory(cas_root)
        cas = CAS(cas_root, read_only=True)
        args = entry._configuration_args(service, inputs, deadline)
        opening = True
        with entry.configuration.hold_pi_service_configuration(**args) as held:
            opening = False
            try:
                configs = held.configurations
                grant = parse_runtime_capability_grant(canonical_json(configs["action"]["capability_grant"]), int(time.time()))
                profile = entry.process.runtime_process_profile(configs["sensor"]["observation_binding"]["runtime_profile"])
                entry._require(canonical_json(grant) == canonical_json(configs["sensor"]["capability_grant"]) and
                               profile.digest == grant["runtime_profile_digest"] and
                               profile.runtime_digest == grant["runtime_digest"] and
                               held.identities["worker"] == {"uid": config.worker_uid, "gid": config.worker_gid},
                               "MASK_HELD_CONFIGURATION_DIFFERS")
                inputs.guard()
                def check_sources():
                    entry._require(_custody(source_loader, host_custody, deadline, worker_spine=worker_spine) ==
                                   (host_pin, interpreter), "MASK_HOST_CHANGED")
                check_sources()
                held.guard(deadline=deadline)
                claim_started = True
                claim = release.claim_capture_release(inputs, release_digest=release_pin, plan_digest=plan_pin,
                    host_profile_digest=host_pin, capture=capture, deadline=deadline, protected_paths=(
                        config.root_directory, config.runtime_directory, config.activation_directory,
                        config_root, cas_root, _ADMITTED, native._BOOTSTRAP))
                entry._require(int(entry._pin(claim)[7:], 16), "MASK_INVALID_CLAIM")
                obs["claim_confirmed"] = True

                def before_start():
                    inputs.guard()
                    held.guard(deadline=deadline)
                    check_sources()
                    # The installed grant may expire during native setup, independently of the release.
                    parse_runtime_capability_grant(canonical_json(grant), int(time.time()))
                    return release.guard_capture_start(inputs, release_digest=release_pin, claim_digest=claim,
                                                      capture=capture, deadline=deadline)

                obs["capture_attempted"] = True
                try:
                    raw = native.run_native_pi_stopped_mask_capture(cas, context, profile=profile, grant=grant,
                        protected_root=_ADMITTED, runtime_conformance_digest=plan["runtime_conformance_digest"],
                        deployment=deployment, revoked_context_ids=tuple(plan["revoked_context_ids"]),
                        now_unix=int(time.time()), deadline=deadline, config=config, capture=capture,
                        _before_start=before_start)
                except BaseException as exc:
                    partial = getattr(exc, "pi_stopped_mask_observation", None)
                    if type(partial) is dict:
                        _result(partial, obs, worker_spine=worker_spine)
                    raise
                _result(raw, obs, worker_spine=worker_spine)
                inputs.guard()
                check_sources()
            except BaseException as exc:
                body_failure = exc
                raise
            finally:
                leaving = True
        leaving = False
    except BaseException as exc:
        failure = exc
        configuration_close_uncertain = opening or (leaving and exc is not body_failure)
        obs["status"] = "CLEANUP_HOLD" if configuration_close_uncertain or claim_started else "REFUSED"
        obs["cleanup_verified"] = False
    finally:
        if inputs is not None:
            try:
                inputs.close()
                obs["owned_inputs_closed"] = not configuration_close_uncertain
            except BaseException as exc:
                failure = failure or exc
                obs.update(status="CLEANUP_HOLD", cleanup_verified=False)
    if failure is not None:
        error = entry.PiCoordinatorEntryError("MASK_CAPTURE_REFUSED_OR_CLEANUP_HOLD")
        error.observation = obs
        raise error from failure
    if worker_spine and obs["status"] == "CAPTURE_RETAINED_ONLY" and obs["owned_inputs_closed"]:
        # Bind the actual spent claim on this return, not a claim reconstructed later from the plan.
        obs.update(schema="aragorn/pi-core-mask-capture-entry/v2", capture_authority=dict(
            host_profile_digest=host_pin, plan_digest=plan_pin, release_digest=release_pin, claim_digest=claim))
    return obs
