"""Compare a private B70 export, protected bootstrap outcome/plan and independently pinned B58 archive."""
import argparse
import json
from pathlib import Path
import sys
import time

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.pi_core_configuration_carrier import ROOT as CARRIER_ROOT, validate_carrier
from aragorn.pi_core_sensor_state_evidence import validate_sensor_configuration_mounts, verify_sensor_state
from aragorn.pi_core_state_admission import _doc, _keys, _need, _pin, _same, _uint, _uuid, verify_state_archive_v2
from aragorn.pi_core_state_mounts import ACTION
from scripts.verify_pi_core_joined_mask_receipts import _separate


def _object(archive, pin, limit, *, stdout_line=False):
    raw = archive.read(_pin(pin), max_bytes=limit)
    obj = json.loads(raw)
    _need(type(obj) is dict and canonical_json(obj) + (b"\n" if stdout_line else b"") == raw,
          "noncanonical protected plan or original wrapper stdout")
    return obj


def _strict_owner(archive, plan, owner):
    from aragorn.pi_core_coordinator_entry import _plan
    from scripts.verify_pi_core_owned_socket_directories import _custody

    # Exact success shape of the sensor-enabled public wrapper, not an arbitrary
    # report with a selected set of positive fields or a fabricated private result.
    _keys(owner, ("schema", "authority", "phase3_exit_eligible", "entry_status", "managed_call_attempted",
                  "managed_status", "managed_result_digest", "managed_cleanup_complete", "owned_inputs_closed",
                  "entry_failure_stage", "plan_digest", "deployment_digest", "host_before", "host_after",
                  "source_before", "source_after", "sensor_state_observation", "status", "wrapper_stage",
                  "wrapper_cleanup", "entry_call_attempted"))
    host_pin = _pin(plan["host_profile_digest"])
    # 'None' is not an alternate runtime path: this pure plan parser only uses
    # plan_path to separate provider secrets; this path requires UNAVAILABLE.
    required = {"aragorn." + name for name in (
        "pi_core_coordinator_entry", "pi_core_managed_bootstrap", "pi_core_service_lifecycle",
        "pi_core_sensor_state_entry", "pi_core_sensor_state_observer",
        "pi_core_sensor_state_custody", "pi_core_sensor_state_evidence", "pi_core_state_dm_mapping",
        "pi_core_state_backing_leaf", "pi_core_state_luks_headers")}
    try:
        _plan(plan, host_pin, None, allow_sensor_state=True)
        profile = _object(archive, host_pin, 2 << 20)
        _custody(owner, profile, host_pin, required_before=required, required_after=required)
    except RuntimeError as exc:
        raise ValueError("protected managed plan or owner source custody refused") from exc


def verify_joined_sensor_state(*, archive, profile_pin, latest_pin, witness_pin, plan_pin, owner_pin,
                              store, receipt_directory, capture_pin, receipt_pin, require_same_manager=False,
                              require_filesystem_uuid=False, require_direct_crypt_mapping=False, require_backing_leaf=False,
                              require_inline_luks_headers=False, require_current_volume_and_sensor=False):
    from aragorn.pi_core_sensor_state_custody import RECEIPTS, STORE, replay_sensor_observation, sensor_evidence_mount
    _need(type(archive) is CAS and archive.read_only is True and type(require_same_manager) is bool
          and type(require_filesystem_uuid) is bool and type(require_direct_crypt_mapping) is bool and type(require_backing_leaf) is bool
          and type(require_inline_luks_headers) is bool and type(require_current_volume_and_sensor) is bool,
          "read-only independent evidence store required")
    paths = (archive.root, store, receipt_directory)
    identities = _separate(paths)
    admitted = verify_state_archive_v2(archive, profile_pin, latest_pin, witness_pin,
                                       strict_worker_devices=require_current_volume_and_sensor)
    capture = _doc(archive, admitted["capture"])
    head = _doc(archive, latest_pin)
    plan = _object(archive, plan_pin, 1 << 20)
    owner = _object(archive, owner_pin, (256 << 10) + 8192, stdout_line=True)
    raw = replay_sensor_observation(store=store, receipt_directory=receipt_directory,
                                   capture_digest=capture_pin, receipt_digest=receipt_pin)
    r = json.loads(raw["record"])
    _keys(r, ("schema", "attempt_id", "host_profile_digest", "plan_digest", "deployment_digest",
              "configuration_digest", "launch_digest", "identity", "clock", "storage", "view",
              "manager_mountinfo_digest", "sensor_mountinfo_digest"))
    _need(r["schema"] == "aragorn/pi-core-sensor-state-record/v1" and
          owner["schema"] == "aragorn/pi-core-coordinator-report/v1" and
          owner["authority"] == "MANAGED_RESULT_DIGEST_ONLY_NOT_RAW_EFFECT_EVIDENCE" and
          plan["schema"] == "aragorn/pi-core-coordinator-plan/v1" and plan["mode"] == "UNAVAILABLE" and
          plan["provider"] is None, "unrecognized sensor record, plan or public owner report")
    _need(owner["status"] == "MANAGED_BOOTSTRAP_RETURNED_NOT_QUALIFIED" and
          owner["entry_status"] == "MANAGED_CALL_RETURNED_NOT_QUALIFIED" and owner["wrapper_stage"] == "POST_CALL_CUSTODY"
          and owner["entry_call_attempted"] is True and owner["managed_call_attempted"] is True
          and owner["managed_status"] == "BOOTSTRAP_COMPLETE" and owner["phase3_exit_eligible"] is False
          and owner["managed_cleanup_complete"] is True and owner["owned_inputs_closed"] is True
          and owner["entry_failure_stage"] is None, "bootstrap did not finish with verified cleanup")
    _pin(owner["managed_result_digest"])
    _same(owner["wrapper_cleanup"], dict(host="CLOSED", source_loader="CLOSED"), "wrapper cleanup held")
    c = plan["sensor_state_observation"]
    has_uuid = type(c) is dict and "filesystem_uuid" in c
    direct = type(c) is dict and "state_volume_layout" in c
    leaf = type(c) is dict and "observe_backing_leaf" in c
    headers = type(c) is dict and "luks_header_profile" in c
    _keys(c, ("attempt_id", "storage", "clock", "store", "receipt_directory") + (("filesystem_uuid",) if has_uuid else ())
          + (("state_volume_layout",) if direct else ()) + (("observe_backing_leaf",) if leaf else ())
          + (("luks_header_profile",) if headers else ()))
    _need(not require_filesystem_uuid or has_uuid, "filesystem UUID observation required; historical protected plan")
    _need(not require_direct_crypt_mapping or direct, "direct crypt mapping observation required; historical protected plan")
    _need(not require_backing_leaf or leaf, "backing leaf observation required; historical protected plan")
    _need(not require_inline_luks_headers or headers, "current inline LUKS2 metadata required; historical protected plan")
    _need(not leaf or (c["observe_backing_leaf"] is True and direct and has_uuid),
          "backing leaf observation requires explicit direct crypt mapping and filesystem UUID")
    _need(not headers or leaf, "current inline LUKS2 metadata requires the whole-disk backing leaf")
    if require_current_volume_and_sensor:
        _need(has_uuid and direct and leaf and headers, "current volume and sensor require the complete v5 observation")
        _strict_owner(archive, plan, owner)
    uuid_args = {}
    if has_uuid:
        # This value comes from the independently pinned profile and role archive,
        # not from the raw ioctl replies or the protected capture plan alone.
        uuid_value = _uuid(c["filesystem_uuid"])
        _same(uuid_value, capture["volume"]["filesystem_uuid"], "filesystem UUID differs from independent admission")
        uuid_args["expected_filesystem_uuid"] = uuid_value
    if direct:
        _need(c["state_volume_layout"] == "DIRECT_LUKS2_INLINE_HEADER_V1" and has_uuid and
              capture["mapping"]["type"] == "dm-crypt" and len(capture["mapping"]["backing_devices"]) == 1,
              "direct crypt mapping requires the approved layout, filesystem UUID and one independent data device")
        uuid_args["require_direct_crypt_mapping"] = True
    if leaf:
        uuid_args["require_backing_leaf"] = True
    if headers:
        from aragorn.pi_core_state_luks_headers import validate_header_profile
        profile = c["luks_header_profile"]
        validate_header_profile(profile)
        expected_encryption_uuid = _uuid(capture["volume"]["encryption_uuid"])
        _need(expected_encryption_uuid != uuid_value and expected_encryption_uuid == profile["encryption_uuid"],
              "LUKS2 volume identity differs from independent admission or aliases the filesystem UUID")
        uuid_args["luks_header_profile"] = profile
    _same([c["store"], c["receipt_directory"]], [str(STORE), str(RECEIPTS)], "foreign guest evidence destinations")
    config = plan["service_configuration"]
    _keys(config, ("deployment_path", "receipt_digest", "manifest", "configurations", "carrier"))
    carrier = validate_carrier(config["carrier"])
    _pin(config["receipt_digest"])
    _need(config["deployment_path"] == str(CARRIER_ROOT / "installed") and
          carrier["device"] not in (c["storage"]["device"], *c["storage"]["backing_devices"]),
          "missing isolated protected configuration carrier")
    for name in ("configurations", "manifest"):
        _keys(config[name], ("path", "digest"))
        _pin(config[name]["digest"])
        _same(config[name]["path"], str(CARRIER_ROOT / "inputs" / (name + ".json")),
              "configuration reference outside approved carrier")
    _same({k: r[k] for k in ("attempt_id", "storage", "clock")}, {k: c[k] for k in ("attempt_id", "storage", "clock")},
          "capture differs from protected sensor plan")
    _same([r["plan_digest"], owner["plan_digest"], r["host_profile_digest"], r["launch_digest"],
           r["deployment_digest"], owner["deployment_digest"], r["configuration_digest"]],
          [plan_pin, plan_pin, _pin(plan["host_profile_digest"]), _pin(plan["launch"]["digest"]),
           _pin(plan["deployment"]["digest"]), plan["deployment"]["digest"],
           _pin(plan["service_configuration"]["configurations"]["digest"])], "protected plan or owner pins differ")
    identity = r["identity"]
    observed = owner["sensor_state_observation"]
    _same(observed, dict(status="RETAINED_SENSOR_STATE_ONLY", capture_digest=capture_pin, receipt_digest=receipt_pin,
                         sensor_identity_digest=canonical_digest(identity)), "owner generation or consistent sensor receipt differs")
    view = r["view"]
    version = 5 if headers else 4 if leaf else 3 if direct else 2 if has_uuid else 1
    _need(view["schema"] == f"aragorn/pi-core-sensor-state-view/v{version}", "filesystem UUID plan and sensor view version disagree")
    for key in ("host_before", "host_after"):
        host = owner[key]
        _need(host["schema"] == "aragorn/pi-core-coordinator-host-observation/v1" and
              host["authority"] == "PINNED_HOST_TCB_ONLY_NOT_CONSUMED_CODE_OR_PHASE3" and host["phase3_exit_eligible"] is False,
              "missing wrapper host custody")
        _same([host["host_profile_digest"], host["pid"]], [r["host_profile_digest"], view["manager"]["pid"]],
              "manager is not the owner of this host profile")
    for field in ("manager_mountinfo_digest", "sensor_mountinfo_digest", "clock"):
        _same(r[field], view[field], "retained sensor record and view disagree")
    finding = verify_sensor_state(view, raw["manager"], raw["sensor"], identity=identity, storage=c["storage"],
                                  **uuid_args)
    _need(not has_uuid or finding.get("state_filesystem_uuid_matched") is True,
          "filesystem UUID has no verified raw observation")
    leaf_finding = {}
    if leaf:
        _need(finding.get("kernel_whole_disk_leaf_matched") is True, "no verified kernel whole-disk leaf observation")
        leaf_finding = dict(kernel_whole_disk_leaf_matched=True,
                            observed_backing_diskseq=_uint(finding.get("observed_backing_diskseq")))
    if direct:
        _need(finding.get("active_dm_crypt_single_backing_matched") is True,
              "direct crypt mapping has no verified kernel observation")
        _same([finding["observed_mapping_device"], [finding["observed_sole_kernel_dependency"]]],
              [capture["mapping"]["device"], capture["mapping"]["backing_devices"]],
              "observed active mapping or kernel dependency differs from independent admission")
    if headers:
        _need(all(finding.get(k) is True for k in ("current_inline_luks2_metadata_matched",
                  "encryption_uuid_measured", "inline_luks2_header_verified")) and
              finding.get("observed_encryption_uuid") == expected_encryption_uuid,
              "current inline LUKS2 metadata has no matching observed encryption UUID")
    guest_evidence = sensor_evidence_mount(raw["manager"], raw["sensor"], c["storage"])
    _need(guest_evidence.device != carrier["device"], "evidence medium aliases the approved configuration carrier")
    # Bound local parsing effort, not the original guest observation interval.
    validate_sensor_configuration_mounts(raw["manager"], raw["sensor"], carrier["device"], deadline=time.monotonic() + 30.0)

    _same([r["deployment_digest"], r["configuration_digest"], r["clock"]["boot_id"], r["storage"]],
          [capture["deployment"], capture["configuration"], head["boot_id"], dict(device=capture["mapping"]["device"],
           backing_devices=capture["mapping"]["backing_devices"], fs_type=capture["volume"]["fs_type"])],
          "separate admission observation belongs to another deployment, configuration, boot or storage mapping")
    _same(finding["source_roots"], capture["source_roots"], "independent state source directories differ")
    prior_sensor = head["subjects"]["sensor"]
    _same([prior_sensor["uid"], prior_sensor["gid"]], [identity["uid"], identity["gid"]], "different sensor role")
    _same({k: v for k, v in capture["roles"]["sensor"]["targets"][ACTION].items() if k != "mount_id"},
          finding["source_roots"][ACTION], "different independent sensor target")
    # Mount IDs and processes need not be shared by two separately scheduled observations.
    def matched(role):
        subject = head["subjects"][role]
        return (canonical_json({k: view[role][k] for k in subject}) == canonical_json(subject)
                and capture["roles"][role]["mountinfo"] == r[role + "_mountinfo_digest"]
                and canonical_json(capture["roles"][role]["targets"]) == canonical_json(finding[role + "_targets"]))
    manager_same, sensor_same = matched("manager"), matched("sensor")
    _need(not require_same_manager or manager_same, "independent manager generation or mounts differ")
    strict = {}
    if require_current_volume_and_sensor:
        _need(manager_same and sensor_same and finding.get("sensor_read_only_bind_matched") is True,
              "independent manager or read-only sensor generation, mount table or targets differ")
        from aragorn.pi_core_service_configuration import validate_service_configurations
        # Matching capture pins don't establish that the protected configuration issued these principals.
        configs = _object(archive, capture["configuration"], 1 << 20)
        try:
            action = validate_service_configurations(configs)["action"]
        except RuntimeError as exc:
            raise ValueError("invalid protected service configurations") from exc
        principals = {role: {k: head["subjects"]["pi" if role == "worker" else role][k] for k in ("uid", "gid")}
                      for role in ("worker", "action", "sensor", "provider")}
        _same(action["identities"], principals, "configured role principals differ from independent admission")
        _same(action["capability_grant"]["install_context_digest"], plan["context"]["digest"],
              "configured grant differs from the protected installation context")
        strict.update(current_volume_and_sensor_records_matched=True, configured_role_principals_matched=True)
    _need(_separate(paths) == identities, "evidence directory changed")
    # The external archive binds expected storage and the private raw observation
    # corroborates the active target/dependency. Only v5 also corroborates the
    # two current inline metadata copies against the protected pins; that does
    # not identify the header used for the original unlock or parse its JSON.
    mapping = dict(active_dm_crypt_single_backing_matched=True, observed_mapping_device=finding["observed_mapping_device"],
        observed_sole_kernel_dependency=finding["observed_sole_kernel_dependency"], encryption_uuid_measured=headers,
        inline_luks2_header_verified=headers, physical_backing_identity_verified=False, authenticated_unlock_verified=False,
        external_attachment_verified=False, exclusive_writer_verified=False) if direct else {}
    if headers:
        mapping.update(current_inline_luks2_metadata_matched=True, header_at_original_unlock_verified=False,
                       luks2_json_semantics_verified=False, independent_full_header_byte_replay=False)
    return {**admitted, **mapping, **leaf_finding, **strict, "capture_binding": capture_pin, "local_receipt": receipt_pin, "plan": plan_pin, "owner": owner_pin,
            "sensor_read_only_bind_matched": True, "independent_state_source_roots_matched": True,
            "guest_evidence_mount_topology_matched": True,
            "manager_configuration_carrier_mount_matched": True, "sensor_configuration_file_mount_matched": True,
            "state_filesystem_uuid_matched": has_uuid,
            "configuration_image_bytes_verified_by_replay": False,
            "owner_sensor_generation_matched": True, "archive_sensor_subject_and_mount_bytes_matched": sensor_same,
            "archive_manager_subject_and_mount_bytes_matched": manager_same, "sensor_health_verified": False,
            "same_capture_interval_verified": False, "physical_asset_verified": False, "external_freshness_verified": False,
            "worker_isolation_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "store", "receipt-directory"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("profile-pin", "latest-pin", "witness-pin", "plan-pin", "owner-pin", "capture-pin", "receipt-pin"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--require-same-manager", action="store_true")
    parser.add_argument("--require-filesystem-uuid", action="store_true",
                        help="require both measured filesystem UUID replies, the protected plan, and independent admission to agree")
    parser.add_argument("--require-direct-crypt-mapping", action="store_true",
                        help="require the active dm-crypt target and its sole kernel dependency; not header proof")
    parser.add_argument("--require-backing-leaf", action="store_true",
                        help="require a kernel whole-disk leaf observation; not proof of physical or exclusive attachment")
    parser.add_argument("--require-inline-luks-headers", action="store_true",
                        help="require both current checksummed inline LUKS2 metadata copies and pins, not original unlock provenance")
    parser.add_argument("--require-current-volume-and-sensor", action="store_true",
                        help="require v5 volume and read-only sensor records for the same manager and sensor generations and configured principals; not unlock or qualification")
    args = vars(parser.parse_args(argv))
    try:
        args["archive"] = CAS(args["archive"], read_only=True)
        print(json.dumps(verify_joined_sensor_state(**args), sort_keys=True))
    except (CASError, OSError, KeyError, TypeError, ValueError, RecursionError) as exc:
        print("Sensor state evidence refused: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
