"""Compare original, independently nominated managed task records offline.

The result is fixed-output consistency, not proof of installed code, mode, a
real acquisition, source of a write, or an independently validated clock.
"""
import re

from . import native_phase3_workload_json_sum_verify as json_sum
from . import native_phase3_workload_line_count_verify as line_count
from . import native_phase3_workload_sha256_verify as sha256_task
from .cas import CAS
from .native_phase3_workload_copy_readback_verify import _INPUT as COPY_BYTES
from .native_phase3_workload_json_sum_contract import validate_boundaries, validate_request
from .oci_worker_protocol import canonical_digest
from .phase3_exit_qualification import _digest
from .phase3_reference_tasks import describe_tasks
from .pi_core_phase3_qualification import _blob, _document, verify_managed_copy_output
from .pi_core_state_admission import _keys, _need, _pin, _same, _uint, _uuid


_LIMIT = (1 << 16) - 1  # The strict document reader accounts for one framing LF.
_COMPUTE = {"BENIGN_JSON_SUM": json_sum.verify, "BENIGN_LINE_COUNT": line_count.verify,
            "BENIGN_SHA256": sha256_task.verify}


def _ticket(ticket, request, is_copy):
    keys = {"schema", "request", "environment_digest", "clock", "pi_peer", "service_peer", "manager_peer"}
    _keys(ticket, keys | ({"copy"} if is_copy else set()))
    _need(ticket["schema"] == "aragorn/pi-core-task-ticket/v1", "wrong managed task ticket")
    _same(ticket["request"], request, "ticket does not authorize this request")
    _pin(ticket["environment_digest"])
    clock = ticket["clock"]
    _keys(clock, ("clock_id", "boot_id", "time_namespace_inode"))
    _need(clock["clock_id"] == "CLOCK_BOOTTIME", "ticket requires the guest boottime clock")
    _uuid(clock["boot_id"])
    _uint(clock["time_namespace_inode"])
    peers = [ticket[k] for k in ("manager_peer", "pi_peer", "service_peer")]
    for pid_uid_gid in peers:
        _need(type(pid_uid_gid) is list and len(pid_uid_gid) == 3, "invalid ticket peer")
        _uint(pid_uid_gid[0], 1, 1 << 31)
        for identity in pid_uid_gid[1:]:
            _uint(identity, 0, 1 << 32)
    _need(peers[0][1:] == [0, 0] and all(len(set(col)) == 3 for col in zip(*peers)),
          "distinct manager, Pi and task service roles required")
    if is_copy:
        _keys(ticket["copy"], ("directory_identity", "fixture_digest"))
        _pin(ticket["copy"]["fixture_digest"])


def _copy_record(record, retained, ticket, request_digest):
    _keys(record, ("schema", "request_digest", "guest", "directory_identity", "fixture_digest",
                   "file_identity", "content_hex", "content_digest", "exclusive_writer_verified", "phase3_exit_eligible"))
    _need(record["schema"] == "aragorn/pi-core-task-copy-observation/v1" and record["request_digest"] == request_digest
          and record["exclusive_writer_verified"] is False and record["phase3_exit_eligible"] is False,
          "copy observation authority or request differs")
    guest = record["guest"]
    numbers = ("pid", "start_ticks", "uid", "gid", "observer_mount_ns", "service_mount_ns",
               "observer_mount_id", "service_mount_id", "time_ns")
    _keys(guest, (*numbers, "unit", "invocation_id", "boot_id"))
    for k in numbers:
        _uint(guest[k])
    _need(guest["unit"] == "aragorn-pi-task.service" and type(guest["invocation_id"]) is str
          and re.fullmatch("[0-9a-f]{32}", guest["invocation_id"]) and int(guest["invocation_id"],16)
          and guest["observer_mount_ns"] != guest["service_mount_ns"]
          and [guest[k] for k in ("pid", "uid", "gid")] == ticket["service_peer"]
          and guest["boot_id"] == ticket["clock"]["boot_id"]
          and guest["time_ns"] == ticket["clock"]["time_namespace_inode"], "copy process or clock differs")
    directory = retained["directory_identity"]
    _need([directory["uid"], directory["gid"]] == ticket["service_peer"][1:], "copy directory has different owner")
    _same(record["directory_identity"], directory, "observed directory differs")
    _same(record["file_identity"], retained["identity"], "observed inode metadata differs")
    fixture = dict(schema="aragorn/pi-core-task-copy-fixture/v1", request_digest=request_digest,
                   guest=guest, directory_identity=directory)
    expected = dict(directory_identity=directory, fixture_digest=canonical_digest(fixture))
    _same(ticket["copy"], expected, "independently nominated copy fixture differs")
    _need(record["fixture_digest"] == retained["fixture_digest"] == expected["fixture_digest"]
          and record["content_hex"] == COPY_BYTES.hex()
          and record["content_digest"] == _digest(COPY_BYTES) == ticket["request"]["input_digest"],
          "recorded original copy contents or fixture differ")


def verify_portable(raw, request, boundaries, *, evidence_cas, ticket_pin, sidecar_pin, reference_source_pin):
    """All three pins must come from independent custody, never from a worker reply."""
    _need(type(evidence_cas) is CAS and evidence_cas.read_only is True, "read-only evidence CAS required")
    _need(type(raw) is bytes and 0 < len(raw) <= _LIMIT, "bounded retained receipt required")
    validate_request(request)
    validate_boundaries(boundaries)
    receipt_digest = _digest(raw)
    _need(_blob(evidence_cas, receipt_digest, _LIMIT) == raw, "raw receipt differs from original")
    receipt = _document(raw)
    ticket = _document(_blob(evidence_cas, ticket_pin, _LIMIT))
    sidecar = _document(_blob(evidence_cas, sidecar_pin, _LIMIT))
    descriptors = describe_tasks(_blob(evidence_cas, reference_source_pin, 1 << 20))
    matches = [d for d in descriptors.values() if canonical_digest(d) == request["task_digest"]
               and d["input"]["digest"] == request["input_digest"]]
    _need(len(matches) == 1, "nominated reference source, task or input differs")
    descriptor = matches[0]
    task = descriptor["template_id"]
    is_copy = task == "BENIGN_COPY_READBACK"
    _ticket(ticket, request, is_copy)
    _keys(receipt, ("schema", "request_digest", "deployment_digest", "boundaries", "observation"))
    request_digest = canonical_digest(request)
    _keys(sidecar, ("schema", "request_digest", "receipt_digest", "ticket_digest", "boundaries",
                    "pi_response", "service_response", "copy_observation"))
    _need(sidecar["schema"] == "aragorn/pi-core-fixed-task-roundtrip/v1" and
          sidecar["request_digest"] == request_digest and sidecar["receipt_digest"] == receipt_digest
          and sidecar["ticket_digest"] == ticket_pin, "round-trip sidecar has different bindings")
    _same(sidecar["boundaries"], boundaries, "outer round-trip marks differ")
    # Offline equality corroborates the recorded echo; only live service custody
    # can establish when and by whom its unpredictable challenge was generated.
    service_reply = sidecar["service_response"]
    _keys(service_reply, ("schema", "request_digest", "ticket_digest", "observation", "service_nonce"))
    nonce = service_reply["service_nonce"]
    _need(type(nonce) is str and re.fullmatch("[0-9a-f]{64}", nonce), "invalid service completion nonce")
    reply = dict(schema="aragorn/pi-core-fixed-task-response/v1", request_digest=request_digest,
                 ticket_digest=ticket_pin, observation=receipt["observation"], service_nonce=nonce)
    for name in ("pi_response", "service_response"):
        _same(sidecar[name], reply, "original peer response differs from receipt: " + name)
    if not is_copy:
        _need(sidecar["copy_observation"] is None, "unexpected copy authority")
        return _COMPUTE[task](raw, request, boundaries)
    verify_managed_copy_output(raw, request, boundaries, descriptor)
    _copy_record(sidecar["copy_observation"], receipt["observation"]["retained_file"], ticket, request_digest)
    return dict(receipt_digest=receipt_digest, request_digest=request_digest,
                deployment_digest=request["deployment_digest"], semantics={"completed": True})
