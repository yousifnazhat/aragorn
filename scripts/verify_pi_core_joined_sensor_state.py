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
from aragorn.pi_core_state_admission import _doc, _keys, _need, _pin, _same, verify_state_archive_v2
from aragorn.pi_core_state_mounts import ACTION
from scripts.verify_pi_core_joined_mask_receipts import _separate


def _object(archive, pin, limit, *, stdout_line=False):
    raw = archive.read(_pin(pin), max_bytes=limit)
    obj = json.loads(raw)
    _need(type(obj) is dict and canonical_json(obj) + (b"\n" if stdout_line else b"") == raw,
          "noncanonical protected plan or original wrapper stdout")
    return obj


def verify_joined_sensor_state(*, archive, profile_pin, latest_pin, witness_pin, plan_pin, owner_pin,
                              store, receipt_directory, capture_pin, receipt_pin, require_same_manager=False):
    from aragorn.pi_core_sensor_state_custody import RECEIPTS, STORE, replay_sensor_observation, sensor_evidence_mount
    _need(type(archive) is CAS and archive.read_only is True and type(require_same_manager) is bool,
          "read-only independent evidence store required")
    paths = (archive.root, store, receipt_directory)
    identities = _separate(paths)
    admitted = verify_state_archive_v2(archive, profile_pin, latest_pin, witness_pin)
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
    _keys(c, ("attempt_id", "storage", "clock", "store", "receipt_directory"))
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
    for key in ("host_before", "host_after"):
        host = owner[key]
        _need(host["schema"] == "aragorn/pi-core-coordinator-host-observation/v1" and
              host["authority"] == "PINNED_HOST_TCB_ONLY_NOT_CONSUMED_CODE_OR_PHASE3" and host["phase3_exit_eligible"] is False,
              "missing wrapper host custody")
        _same([host["host_profile_digest"], host["pid"]], [r["host_profile_digest"], view["manager"]["pid"]],
              "manager is not the owner of this host profile")
    for field in ("manager_mountinfo_digest", "sensor_mountinfo_digest", "clock"):
        _same(r[field], view[field], "retained sensor record and view disagree")
    finding = verify_sensor_state(view, raw["manager"], raw["sensor"], identity=identity, storage=c["storage"])
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
    manager_same = matched("manager")
    _need(not require_same_manager or manager_same, "independent manager generation or mounts differ")
    _need(_separate(paths) == identities, "evidence directory changed")
    return {**admitted, "capture_binding": capture_pin, "local_receipt": receipt_pin, "plan": plan_pin, "owner": owner_pin,
            "sensor_read_only_bind_matched": True, "independent_state_source_roots_matched": True,
            "guest_evidence_mount_topology_matched": True,
            "manager_configuration_carrier_mount_matched": True, "sensor_configuration_file_mount_matched": True,
            "configuration_image_bytes_verified_by_replay": False,
            "owner_sensor_generation_matched": True, "archive_sensor_subject_and_mount_bytes_matched": matched("sensor"),
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
