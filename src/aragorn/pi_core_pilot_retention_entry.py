"""Private retention around the original B109 managed call. Never a pilot release."""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat

from . import pi_core_coordinator_entry as entry
from . import pi_core_mask_capture_release as protected
from . import pi_core_pilot_output_custody as sink
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_state_mounts import direct_mount_inventory


RELEASE = Path("/etc/aragorn/approvals/pilot-output-retention.json")
BASE = Path("/run/aragorn-pilot-output-evidence")
SCOPE = "ONE_LOCAL_RAW_PILOT_OBSERVATION_NO_PROVIDER_OR_EFFECT_AUTHORITY"
_B109 = {
    "pi_core_coordinator_entry": "49477dc3438c4537442acee85a8c2ac28cc10980a1b0de340876fa50af9b8d83",
    "pi_core_managed_bootstrap": "7f94de4fa10104dd6eaa7877e4a8a6e244b84278549f76f6370009bac8e09d6b",
    "pi_core_native_supervisor": "c95143585fae1cbaf534ba8cfeff7a1178c524ccf15473cfa46361496e1ed9d6",
    "pi_core_pilot_output_observer": "932d2585f5757c4c2ead987c7d54f9f147efc048a71aead0b785384beb1d4dbd",
}
_SERVICE = ("sha256:e2979db65fa3bca5543d6a9ecb2918df2d81c11d75334f93cbaa77ef60e75144",
            "sha256:ee0322af9ae39ec491b58a912fc2aade83514ef754cb385415c6ec71bf4416fe",
            "sha256:ff3ef6d0f83bff9873c2cdc89a6d574550ee3e57710424abcbc9fff70ad7e8d7")
_need = entry._require


def _source(loader, host, deadline):
    host_pin, rows, _ = entry._custody(loader, host, deadline)
    for name in (*_B109, "pi_core_pilot_retention_entry", "pi_core_pilot_output_custody"):
        path = "opt/aragorn/src/aragorn/" + name + ".py"
        pin = entry._pin(loader.source_digests.get(path))
        selected = [r for r in rows if r.get("path") == path or r.get("module") == "aragorn." + name]
        _need(selected == [dict(module="aragorn." + name, path=path, digest=pin)] and
              (name not in _B109 or pin == "sha256:" + _B109[name]), "PRIVATE_CALLER_SOURCE_DIFFERS")
    return host_pin


def _binding(doc, plan, plan_pin, host_pin):
    entry._exact(doc, {"schema", "scope", "base_payload_digest", "host_profile_digest", "plan_digest",
                       "deployment_digest", "path_digest", "attempt_id", "boot_id", "not_before_unix_ns",
                       "expires_unix_ns", "mount_id", "roots"})
    runtime = plan["service_runtime"]
    descriptor = plan["pilot_output"]["path_descriptor"]
    path_pin = canonical_digest(descriptor)
    _need(doc["schema"] == "aragorn/pi-core-pilot-output-local-release/v1" and doc["scope"] == SCOPE
          and doc["base_payload_digest"] == sink.B109_PAYLOAD_DIGEST
          and doc["host_profile_digest"] == host_pin != sink.B109_HOST_PROFILE_DIGEST
          and doc["plan_digest"] == plan_pin and doc["deployment_digest"] == plan["deployment"]["digest"]
          and doc["path_digest"] == path_pin and plan["mode"] == "PROTECTED"
          and plan["pilot_output"]["reader_source_digest"] == "sha256:" + _B109["pi_core_pilot_output_observer"]
          and (runtime["manifest"]["digest"], runtime["runtime_binding"]["digest"], runtime["receipt_digest"]) == _SERVICE,
          "PRIVATE_RELEASE_BINDING")
    _need(type(doc["attempt_id"]) is str and re.fullmatch("[0-9a-f]{32}", doc["attempt_id"])
          and int(doc["attempt_id"], 16) and type(doc["mount_id"]) is int and 0 < doc["mount_id"] < 2**64
          and type(doc["roots"]) is list and len(doc["roots"]) == 2, "PRIVATE_RELEASE_DESTINATION")
    for row in doc["roots"]:
        _need(type(row) is list and len(row) == 5 and all(type(n) is int and 0 <= n < 2**64 for n in row)
              and row[0] != descriptor["root_device"] and row[1] > 0 and
              row[2:] == [stat.S_IFDIR | 0o700, 0, 0], "PRIVATE_RELEASE_ROOT_IDENTITY")
    store, receipts = map(tuple, doc["roots"])
    _need(store[0] == receipts[0] and store != receipts, "PRIVATE_RELEASE_ALIASED_ROOTS")
    return dict(store=BASE / "cas", receipt_directory=BASE / "receipts", expected_roots=(store, receipts),
                attempt_id=doc["attempt_id"], expected_path_digest=path_pin,
                deployment_digest=doc["deployment_digest"], plan_digest=plan_pin)


def _location(doc, plan, deadline):
    protected._window(doc, deadline)
    boot, raw = protected._kernel_inputs(deadline)
    mounts = direct_mount_inventory(raw)
    p = str(BASE)
    row, parent = mounts.get(p), mounts.get(str(BASE.parent))
    device = doc["roots"][0][0]
    _need(boot == doc["boot_id"] and row and parent and row.parent == parent.mount_id and
          parent.filesystem == b"tmpfs" and row.mount_id == doc["mount_id"] and row.root == "/" and
          row.no_optional_fields and row.filesystem in (b"ext4", b"xfs") and
          row.device == f"{os.major(device)}:{os.minor(device)}" and not row.device.startswith("0:") and
          {b"rw", b"noexec", b"nosuid", b"nodev"} <= row.options and b"rw" in row.super_options and
          all(k == p or (not k.startswith(p + "/") and m.device != row.device and m.source != row.source)
              for k, m in mounts.items()), "PRIVATE_EVIDENCE_MOUNT_OR_BOOT")
    # A read-only input CAS under the private output store isn't an independent archive.
    cas = entry._path(plan["cas_root"])
    _need(not (cas.is_relative_to(BASE) or BASE.is_relative_to(cas)), "PRIVATE_INPUT_CAS_OVERLAP")


def _record(observation):
    managed = observation.get("managed_result") if type(observation) is dict else None
    worker = managed.get("worker") if type(managed) is dict else None
    return worker.get("pilot_output_observation") if type(worker) is dict else None


@contextmanager
def _authority(plan_path, plan_pin, *, release_digest, deadline_ns, source_loader, host_custody):
    _need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, "PRIVATE_ROOT_REQUIRED")
    deadline = entry._deadline(deadline_ns)
    host_pin = _source(source_loader, host_custody, deadline)
    path = entry._path(str(plan_path))
    _need(path != RELEASE and len({host_pin, entry._pin(plan_pin), entry._pin(release_digest)}) == 3,
          "PRIVATE_SEPARATE_RELEASE_REQUIRED")
    inputs = entry._Inputs(deadline)
    try:
        plan = entry._plan(inputs.read(path, plan_pin, entry._PLAN_LIMIT), host_pin, path, allow_pilot_output=True)
        _need("pilot_output" in plan, "PRIVATE_PILOT_READER_REQUIRED")
        doc = inputs.read(RELEASE, release_digest, 4096)
        args = dict(_binding(doc, plan, plan_pin, host_pin), release_digest=release_digest)

        def storage_guard():
            inputs.guard()
            _location(doc, plan, deadline)

        def guard():
            _need(_source(source_loader, host_custody, deadline) == host_pin, "PRIVATE_SOURCE_CHANGED")
            storage_guard()

        def claim():
            return sink.preflight(**args, deadline=deadline, mount_id=doc["mount_id"], topology_guard=storage_guard)

        def publish(observation):
            record = _record(observation)
            _need(type(record) is dict and observation.get("managed_call_attempted") is True and
                  observation.get("schema") == "aragorn/pi-core-coordinator-observation/v1" and
                  observation.get("plan_digest") == plan_pin and observation.get("deployment_digest") ==
                  args["deployment_digest"] and observation.get("phase3_exit_eligible") is False,
                  "PRIVATE_ORIGINAL_OBSERVATION_REQUIRED")
            # The activation ID is assigned during launch, not by this release. The B109 reader
            # bound it to prepared START. Offline replay independently joins it to the action.
            return sink.retain(**args, deadline=deadline, expected_activation_id=record["activation_id"],
                               observation_raw=canonical_json(record), mount_id=doc["mount_id"], topology_guard=storage_guard)

        yield guard, claim, publish
    except BaseException as original:
        try:
            inputs.close()
        except BaseException:
            original.add_note("PRIVATE_RELEASE_INPUT_CLEANUP_UNCONFIRMED")
        raise
    else:
        inputs.close()


def run(plan_path, expected_plan_digest, *, release_digest, deadline_ns, source_loader, host_custody):
    opts = dict(deadline_ns=deadline_ns, source_loader=source_loader, host_custody=host_custody)
    with _authority(plan_path, expected_plan_digest, release_digest=release_digest, **opts) as (guard, claim, publish):
        guard()
        claim()
        guard()
        try:
            observation = entry.run(plan_path, expected_plan_digest, **opts)
        except entry.PiCoordinatorEntryError as original:
            carried = getattr(original, "observation", None)
            if _record(carried) is not None:
                try:
                    guard()
                    publish(carried)
                    guard()
                except BaseException:
                    original.add_note("PRIVATE_OUTPUT_RETENTION_UNCONFIRMED_DO_NOT_RETRY")
            raise
        try:
            guard()
            if _record(observation) is not None:
                publish(observation)
            else:
                _need(observation.get("status") in {"CLEANUP_HOLD", "REFUSED_OR_INDETERMINATE"},
                      "PRIVATE_OUTPUT_OBSERVATION_MISSING")
            guard()
        except Exception as cause:
            error = entry.PiCoordinatorEntryError("PRIVATE_OUTPUT_RETENTION_UNCONFIRMED_DO_NOT_RETRY")
            error.observation = dict(observation, status="REFUSED_OR_INDETERMINATE", failure_stage="PRIVATE_RETENTION")
            raise error from cause
        return observation
