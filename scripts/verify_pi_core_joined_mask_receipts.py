"""Compare independently supplied admission and stopped-worker receipts. No acquisition or writes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from aragorn.cas import CAS, CASError
from aragorn.pi_core_mask_custody import replay_mask_observation
from aragorn.pi_core_state_admission import _doc, _need, _same, verify_state_archive_v2
from aragorn.pi_core_stopped_mask_capture import _verify_slice


def _separate(roots):
    # Check namespace aliases too, without claiming independent machines or administrators.
    chains = []
    for root in roots:
        _need(isinstance(root, Path) and root.is_absolute() and root != Path("/") and
              root.resolve(strict=True) == root, "expected existing unlinked absolute evidence directory")
        chain = []
        for part in (root, *root.parents):
            info = part.stat()
            chain.append((info.st_dev, info.st_ino))
        _need(all(chain[0] not in other and other[0] not in chain for other in chains), "overlapping evidence roots")
        chains.append(chain)
    return chains


def _owned_join(archive, pins, nomination, binding, spine, worker_raw, capture_pin, receipt_pin, configuration_pin):
    from aragorn import pi_core_mask_capture_entry as entry, pi_core_mask_capture_release as release
    from aragorn import pi_core_restricted_profile as fixed
    from aragorn.oci_worker_protocol import canonical_digest
    from aragorn.pi_core_coordinator_entry import _launch
    from aragorn.pi_core_node_source_observer import validate_node_profile
    from aragorn.pi_core_service_configuration import PiServiceConfigurationError, validate_service_configurations
    from aragorn.pi_core_service_entry import PiServiceEntryError
    from aragorn.pi_core_state_admission import _dev, _keys, _pin, _uint, _uuid
    from aragorn.pi_core_state_mounts import direct_mount_inventory
    from aragorn.runtime_action_broker import RuntimeActionBrokerError
    from aragorn.runtime_action_observation_publisher import RuntimeActionObservationPublisherError
    from scripts.prepare_pi_core_coordinator_host import host_contract
    from scripts.verify_pi_core_installed_bundle_readback import SPINE_V2_WRAPPER_PIN, _document

    plan_pin, release_pin, claim_pin, owner_pin = (_pin(pin) for pin in pins)
    boot, invocation, attempt = nomination
    _uuid(boot)
    _need(all(type(s) is str and re.fullmatch(r"[0-9a-f]{32}",s) and int(s,16) for s in (invocation,attempt)),
          "independently nominated invocation and attempt required")
    _same([binding["clock"]["boot_id"],binding["invocation"],binding["attempt_id"]], [boot,invocation,attempt],
          "different nominated worker capture attempt, boot or invocation")
    plan = _document(archive,plan_pin,1 << 20)
    grant = _document(archive,release_pin,8192)
    claim = _document(archive,claim_pin,4096)
    owner = _document(archive,owner_pin,64 << 10,stdout=True)
    host_pin = _pin(plan["host_profile_digest"])
    _need(len(set((*pins,host_pin,capture_pin,receipt_pin))) == 7, "capture evidence pins must be distinct")
    authority = dict(host_profile_digest=host_pin,plan_digest=plan_pin,release_digest=release_pin,claim_digest=claim_pin)
    _same(owner, dict(schema="aragorn/pi-core-mask-capture-report/v2",entry_status="CAPTURE_RETAINED_ONLY",
                      capture_attempted=True,claim_confirmed=True,owned_inputs_closed=True,cleanup_verified=True,
                      mask_consistent=True,capture_digest=capture_pin,receipt_digest=receipt_pin,
                      activation_authorized=False,phase3_exit_eligible=False,status="CAPTURE_RETAINED_ONLY",
                      wrapper_stage="POST_CALL_CUSTODY",wrapper_cleanup={"host":"CLOSED","source_loader":"CLOSED"},
                      entry_call_attempted=True,capture_authority=authority),
          "original v2 capture authority, retained pins or cleanup differs")
    entry._plan(plan,host_pin)
    _need(plan["schema"] == entry.SPINE_PLAN, "protected stopped-worker spine plan required")
    _same(plan["service_configuration"]["configurations"]["digest"], configuration_pin,
          "different protected service configuration")
    c = plan["capture"]
    _same([c["attempt_id"],plan["deployment"]["digest"],c["volume_device"],c["backing_devices"],c["fs_type"]],
          [attempt,binding["deployment"],binding["storage"]["device"],binding["storage"]["backing_devices"],binding["storage"]["fs_type"]],
          "different protected plan capture or state volume")
    fixed_grant = dict(schema="aragorn/pi-core-stopped-mask-release/v1",scope=release.SPINE_SCOPE,plan_digest=plan_pin,
                       host_profile_digest=host_pin,deployment_digest=binding["deployment"],attempt_id=attempt,
                       boot_id=boot,max_starts=1)
    _keys(grant,(*fixed_grant,"not_before_unix_ns","expires_unix_ns","claim_directory"))
    _same({k:grant[k] for k in fixed_grant},fixed_grant,"different or non-single-use spine release")
    begin,end = (_uint(grant[k],high=1<<63) for k in ("not_before_unix_ns","expires_unix_ns"))
    _need(0 < end-begin <= release._WINDOW_NS,"invalid original release window")
    ledger = grant["claim_directory"]
    _keys(ledger,("dev","ino","mnt_id"))
    _uint(ledger["ino"])
    _uint(ledger["mnt_id"])
    _need(_dev(ledger["dev"]) not in (c["volume_device"],*c["backing_devices"]),"claim directory on state device")
    _same(claim,dict(schema="aragorn/pi-core-mask-start-claim/v1",status="SPENT",release_digest=release_pin,
                     plan_digest=plan_pin,boot_id=boot,attempt_id=attempt),"different original spent claim")

    cfg = _launch(_document(archive,plan["launch"]["digest"],4<<20),"UNAVAILABLE")
    expected = fixed.runtime_receipt(cfg.compiled_receipt["inputs"]["source_gate"])
    _same([cfg.compiled_receipt,cfg.compiled_receipt_digest],[expected,canonical_digest(expected)],
          "different protected worker build")
    profile = validate_node_profile(cfg.source_observation)
    _same([profile["schema"],cfg.source_observation_digest,canonical_digest(profile),cfg.worker_uid,cfg.worker_gid],
          [fixed.PROFILE_SCHEMA,binding["profile"],binding["profile"],binding["worker"]["uid"],binding["worker"]["gid"]],
          "different worker source profile or process principal")
    # Matching two filesystem observations is not enough: the observed cwd must
    # also be the version selected by the independently pinned service configuration.
    configs = _document(archive, configuration_pin, 1 << 20)
    try:
        # Checks all role identities, grants and profile digests without consulting a clock.
        checked = validate_service_configurations(configs)
    except (PiServiceConfigurationError, PiServiceEntryError,
            RuntimeActionBrokerError, RuntimeActionObservationPublisherError) as exc:
        raise ValueError("invalid protected service configurations") from exc
    capability = checked["action"]["capability_grant"]
    process = checked["sensor"]["observation_binding"]["runtime_profile"]
    _same(checked["action"]["identities"]["worker"], {k:binding["worker"][k] for k in ("uid", "gid")},
          "different configured worker principal")
    # The verified B71 version basename is <context-id hex>-<manifest hex>;
    # the separate plan pin names the context document, not its internal ID.
    manifest_pin = "sha256:" + Path(spine["admitted_path"]).name.split("-")[1]
    _same([capability["install_context_digest"], capability["source_manifest_digest"],
           process["runtime_digest"], process["executable_digest"], process["cgroup"], process["skill_path"]],
          [plan["context"]["digest"], manifest_pin,
           fixed.RUNTIME_DIGEST, profile["pins"]["node_digest"],
           "/system.slice/" + binding["unit"], spine["admitted_path"] + "/SKILL.md"],
          "configured grant, worker runtime, unit or admitted working directory differs")
    host = _document(archive,host_pin,2<<20)
    files = host_contract._profile(host)
    # The v1 wrapper never published authority pins. A self-consistent
    # purported v2 record from an older host profile cannot establish the join.
    for path, code_pin in (
        ("/opt/aragorn/bin/coordinator.py",SPINE_V2_WRAPPER_PIN),
        ("/opt/aragorn/src/aragorn/pi_core_mask_capture_entry.py","sha256:8b438621b7b0871bf1bd1b0cb791f144e7650723d66b6ae453608bee2d5ee8dc"),
    ):
        _need(files.get(Path(path),{}).get("digest") == code_pin,"host profile lacks reviewed v2 capture authority code")
    _same([host["python_executable"],files[entry._PYTHON]["digest"]],
          [str(entry._PYTHON),binding["interpreter"]],"different pinned manager interpreter")
    for module, key in (("pi_core_source_observer","producer_digest"),("pi_core_node_source_observer","node_observer_digest")):
        _same(files[Path("/opt/aragorn/src/aragorn")/(module+".py")]["digest"],profile["pins"][key],
              "worker source observer not in pinned host profile")

    # Existing B71/B58 replay already checked actual held statx objects, their
    # raw namespace, all three inherited FDs, and all forbidden state aliases.
    # Read permission flags from these original mount rows, never the manager.
    mounts = direct_mount_inventory(worker_raw)
    for path,key in (("/","root"),(spine["admitted_path"],"cwd")):
        row = mounts[path]
        _need(b"ro" in row.options and row.mount_id == spine[key]["mnt_id"] and row.device == spine[key]["dev"],
              "stopped worker root and admitted cwd require matching read-only mounts")
    return dict(owned_worker_spine_records_matched=True, mask_capture_owner=owner_pin,
                worker_root_and_admitted_cwd_read_only=True, worker_permissions_verified=False,
                full_worker_namespace_walk_verified=False, sensor_health_verified=False,
                worker_socket_lookup_observed=False, worker_process_relative_links_verified=False,
                independent_live_claim_verified=False)


def verify_joined_masks(*, archive, profile_pin, latest_pin, witness_pin, store, receipt_directory,
                        capture_pin, receipt_pin, require_manager_state=False, require_worker_spine=False,
                        require_owned_worker_spine=False, plan_pin=None, release_pin=None, claim_pin=None,
                        owner_pin=None, boot_id=None, invocation_id=None, attempt_id=None):
    """Validate both original formats, then join their overlapping facts; do not manufacture either witness."""
    _need(type(require_manager_state) is bool and type(require_worker_spine) is bool,
          "invalid manager-state or worker-spine requirement")
    pins, nomination = (plan_pin,release_pin,claim_pin,owner_pin),(boot_id,invocation_id,attempt_id)
    _need(type(require_owned_worker_spine) is bool and
          all((v is not None) == require_owned_worker_spine for v in (*pins,*nomination)),
          "strict worker spine requires all independent pins and nominations; none on historical replay")
    _need(type(archive) is CAS and archive.read_only is True, "admission CAS must already be read-only")
    paths = (archive.root, store, receipt_directory)
    roots = _separate(paths)
    admitted = verify_state_archive_v2(archive, profile_pin, latest_pin, witness_pin,
                                       strict_worker_devices=require_owned_worker_spine)
    local = replay_mask_observation(store=store, receipt_directory=receipt_directory,
                                    capture_digest=capture_pin, receipt_digest=receipt_pin)
    binding, view, proof = (json.loads(local[key]) for key in ("bindings", "vantage", "proof"))
    has_spine = binding["schema"] == "aragorn/pi-core-stopped-mask-binding/v3"
    has_manager_state = has_spine or binding["schema"] == "aragorn/pi-core-stopped-mask-binding/v2"
    spine = {}
    _need(has_spine == ("worker_spine" in local), "mismatched worker-spine custody version")
    manager_state = _verify_slice(binding, view, proof, local["worker"], local["manager"],
                                  **({"worker_spine_raw": local["worker_spine"], "spine_projection": spine}
                                     if has_spine else {}))
    _need(not require_manager_state or has_manager_state, "manager-state evidence required; legacy mask receipt")
    _need(not require_worker_spine or has_spine, "worker-spine evidence required; legacy mask receipt")
    _need(not require_owned_worker_spine or has_spine, "owned worker spine requires an original B71 receipt")

    head, capture, outer = (_doc(archive, pin) for pin in (latest_pin, admitted["capture"], witness_pin))
    # Each dereference is content-addressed. The two capture and profile digest *types* differ.
    _same(binding["deployment"], capture["deployment"], "different deployment")
    _same(binding["clock"]["boot_id"], head["boot_id"], "different boot")
    _same(binding["storage"], {"device": capture["mapping"]["device"], "backing_devices":
          capture["mapping"]["backing_devices"], "fs_type": capture["volume"]["fs_type"]}, "different state mapping")
    for role, key in (("pi", "worker"), ("manager", "manager")):
        _same(binding[key], head["subjects"][role], "different subject: " + role)
        pin = "sha256:" + hashlib.sha256(local[key]).hexdigest()
        _same(pin, capture["roles"][role]["mountinfo"], "different raw mountinfo: " + role)
    _same(proof["witness"], outer["proof"], "different mask observation")
    if has_manager_state:
        _need(manager_state is not None, "missing verified manager-state projection")
        source_roots, target_stats = manager_state
        _same(source_roots, capture["source_roots"], "different manager-state source roots")
        _same(target_stats, capture["roles"]["manager"]["targets"], "different manager-state bind targets")

    walk = json.loads(archive.read(capture["pi_exposure"], max_bytes=32 << 20))["walk"]
    _same(walk["root"], view["worker_root"], "different worker root")
    _same(walk["tree"]["/dev"], dict(stat=view["worker_dev"], before=proof["names_before"],
                                     after=proof["names_after"]), "different /dev view")
    if has_spine:
        for key in ("before", "after", "root", "cwd", "fds"):
            _same(walk[key], spine[key], "different external stopped-worker " + key)
        # B58 accepts a cwd anywhere within the versions tree. B71 requires
        # the specific installed path, not an unrelated directory or an alias.
        path = spine["admitted_path"]
        _need(path in walk["tree"] and "before" in walk["tree"][path], "missing exact external admitted cwd")
        _same(walk["tree"][path]["stat"], spine["cwd"], "different external admitted cwd object")
    strict = (_owned_join(archive,pins,nomination,binding,spine,local["worker"],capture_pin,receipt_pin,
                          capture["configuration"])
              if require_owned_worker_spine else {})
    # B58 already checked every marked leaf against this exact proof and rejected extra/hidden paths.
    _need(_separate(paths) == roots, "evidence directory changed")
    return {**admitted, **strict, "mask_capture_binding": capture_pin, "local_receipt": receipt_pin,
            "manager_state_roots_and_targets_matched": has_manager_state,
            "stopped_worker_handles_and_admitted_cwd_matched": has_spine,
            "local_full_namespace_walk_observed": False,
            "same_capture_interval_verified": False, "external_freshness_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("archive", "store", "receipt-directory"):
        parser.add_argument("--" + arg, type=Path, required=True)
    for arg in ("profile-pin", "latest-pin", "witness-pin", "capture-pin", "receipt-pin"):
        parser.add_argument("--" + arg, required=True)
    parser.add_argument("--require-manager-state", action="store_true",
                        help="refuse historical mask receipts without measured manager state roots and bind targets")
    parser.add_argument("--require-worker-spine", action="store_true",
                        help="require actual stopped-worker handles and the admitted cwd to match the independent walk")
    parser.add_argument("--require-owned-worker-spine",action="store_true",
                        help="require original capture authority, nominated stopped worker and read-only root/cwd; no launch approval")
    for name in ("plan-pin","release-pin","claim-pin","owner-pin","boot-id","invocation-id","attempt-id"):
        parser.add_argument("--"+name)
    args = vars(parser.parse_args(argv))
    try:
        args["archive"] = CAS(args["archive"], read_only=True)
        result = verify_joined_masks(**args)
    except (CASError, OSError, ValueError, RuntimeError, TypeError, KeyError, RecursionError, IndexError) as exc:
        print("Joined mask evidence refused: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
