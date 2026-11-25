"""Opt-in protected fixed-task service and outer round-trip adapter."""
from contextlib import contextmanager, ExitStack
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import time

from . import phase3_reference_tasks as original, pi_core_task_reference as reference, runtime_action_broker as wire
from . import pi_core_identity_handoff as transport, runtime_process_profile as process
from . import native_phase3_workload_json_sum_verify as sum_reader
from . import native_phase3_workload_line_count_verify as count_reader
from . import native_phase3_workload_sha256_verify as sha_reader
from .native_phase3_workload_copy_readback import _retained_identity
from .native_phase3_workload_json_sum_contract import validate_boundaries, validate_request
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_phase3_qualification import verify_managed_copy_output
from .pi_core_task_copy_observation import ManagedCopyObserver


_ORIGINAL = "sha256:6cbb4c8d34bf8ac2b9be93d45ad8db4220954e7d4481a2960fcd8063ffbc3011"
_COMPUTE = {"BENIGN_JSON_SUM": sum_reader.verify, "BENIGN_LINE_COUNT": count_reader.verify, "BENIGN_SHA256": sha_reader.verify}
_COPY = "BENIGN_COPY_READBACK"


def _require(ok, reason):
    if not ok:
        raise ValueError("FIXED_TASK_" + reason)


def _ticket(value, pin):
    _require(type(value) is dict and canonical_digest(value) == pin, "TICKET_PIN")
    t = json.loads(canonical_json(value))
    required = {"schema", "request", "environment_digest", "clock", "pi_peer", "service_peer", "manager_peer"}
    _require(set(t) in (required, required | {"copy"}) and t["schema"] == "aragorn/pi-core-task-ticket/v1", "TICKET")
    validate_request(t["request"])
    _require(re.fullmatch(r"sha256:[0-9a-f]{64}", t["environment_digest"])
             and type(t["clock"]) is dict and set(t["clock"]) == {"clock_id", "boot_id", "time_namespace_inode"}
             and t["clock"]["clock_id"] == "CLOCK_BOOTTIME" and
             re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", t["clock"]["boot_id"])
             and type(t["clock"]["time_namespace_inode"]) is int and t["clock"]["time_namespace_inode"] > 0, "CLOCK_OR_ENVIRONMENT")
    peers = [t[k] for k in ("manager_peer", "pi_peer", "service_peer")]
    _require(all(type(p) is list and len(p) == 3 and all(type(x) is int for x in p)
                 and 0 < p[0] < 2**31 and all(0 <= x < 2**32 for x in p[1:]) for p in peers)
             and peers[0][1:] == [0, 0] and all(len(set(col)) == 3 for col in zip(*peers)), "SEPARATE_ROLE_IDENTITIES")
    _require(original._digest(Path(original.__file__).read_bytes()) == _ORIGINAL, "REFERENCE_PREDECESSOR")
    descriptors = original.describe_tasks(Path(reference.__file__).read_bytes())
    eligible = [d for d in descriptors.values() if canonical_digest(d) == t["request"]["task_digest"]
                and d["input"]["digest"] == t["request"]["input_digest"]]
    _require(len(eligible) == 1, "DESCRIPTOR_OR_INPUT")
    return t, eligible[0]


def _copy_ticket(t, desc):
    copy = t.get("copy")
    if desc["template_id"] != _COPY:
        _require("copy" not in t, "UNEXPECTED_COPY_AUTHORITY")
        return
    _require(type(copy) is dict and set(copy) == {"directory_identity", "fixture_digest"}
             and re.fullmatch(r"sha256:[0-9a-f]{64}", copy["fixture_digest"]), "COPY_AUTHORITY")
    d = copy["directory_identity"]
    _require(type(d) is dict and set(d) == {"device", "inode", "mode", "uid", "gid"}
             and all(type(n) is int and n >= 0 for n in d.values()) and d["inode"] > 0 and d["mode"] == 0o700
             and [d["uid"], d["gid"]] == t["service_peer"][1:], "COPY_DIRECTORY")


@contextmanager
def _edge(connection, peer, local, clock, deadline):
    transport.validate_deadline(deadline)
    _require(sys.platform == "linux" and hasattr(time, "CLOCK_BOOTTIME") and type(connection) is socket.socket
             and connection.getsockopt(socket.SOL_SOCKET, transport._DOMAIN) == socket.AF_UNIX
             and connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM, "LOCAL_STREAM_REQUIRED")
    _require(tuple(wire._peer_credentials(connection)) == tuple(peer), "PEER")
    fd = process.open_peer_pidfd(connection, peer[0])
    def guard():
        transport.require_peer_live(connection, tuple(peer), fd, deadline)
        _require([os.getpid(), os.geteuid(), os.getegid()] == local and
                 Path("/proc/sys/kernel/random/boot_id").read_text("ascii").strip() == clock["boot_id"]
                 and os.stat("/proc/thread-self/ns/time").st_ino == clock["time_namespace_inode"], "LOCAL_IDENTITY_OR_CLOCK")
        # A confined nonroot task may not inspect the root manager's namespace.
        # The manager checks its peers; the independent context holder verifies the rest.
        if local[1] == 0:
            _require(os.stat(f"/proc/{peer[0]}/ns/time").st_ino == clock["time_namespace_inode"], "PEER_CLOCK")
    try:
        guard()
        yield guard
        guard()
    finally:
        os.close(fd)


def _read(conn, deadline):
    return wire._read_frame(conn, deadline)


def _write(conn, doc, deadline):
    wire._send_frame(conn, canonical_json(doc), deadline)
    conn.shutdown(socket.SHUT_WR)  # The receiver requires EOF for this one-shot bounded frame.


def _call(t, pin):
    return dict(schema="aragorn/pi-core-fixed-task-request/v1", request_digest=canonical_digest(t["request"]), ticket_digest=pin)


def _environment(t, guard):
    _require(callable(guard) and guard() == t["environment_digest"], "ENVIRONMENT_CUSTODY")


def serve_one(ticket, ticket_pin, *, pi, witness, guard, deadline, copy_directory_fd=None):
    """Consume one caller-owned channel pair under an independently held service invocation.

    Caller owns fresh ticket issuance, durable one-shot claim, socket and directory lifetime.
    Neither wire input nor reply can select a service implementation, fd, file name or mode.
    """
    t, desc = _ticket(ticket, ticket_pin)
    _copy_ticket(t, desc)
    is_copy = desc["template_id"] == _COPY
    _require((type(copy_directory_fd) is int and copy_directory_fd >= 0) if is_copy else copy_directory_fd is None,
             "COPY_FD")
    _require(pi is not witness, "ALIASED_STREAM")
    call = _call(t, ticket_pin)
    with _edge(pi, t["pi_peer"], t["service_peer"], t["clock"], deadline) as pi_guard, \
            _edge(witness, t["manager_peer"], t["service_peer"], t["clock"], deadline) as witness_guard:
        def held():
            pi_guard()
            witness_guard()
            _environment(t, guard)
        held()
        _require(canonical_json(_read(pi, deadline)) == canonical_json(call), "REQUEST_NOMINATION")
        held()
        raw = original.reference_inputs()[desc["input"]["ref"]]
        kw = dict(directory_fd=copy_directory_fd, directory_identity=t["copy"]["directory_identity"], guard=held) if is_copy else {}
        result = reference.execute_reference_task(desc["template_id"], raw, **kw)
        observation = dict(task=desc, result=result)
        if is_copy:
            observation["retained_file"] = dict(basename=original.COPY_TARGET, **t["copy"],
                                               identity=_retained_identity(copy_directory_fd, len(raw)))
        # Pi already knows the fixed task and scheduled input. Only after it
        # finishes can the service disclose this unpredictable per-execution value.
        reply = dict(call, schema="aragorn/pi-core-fixed-task-response/v1", observation=observation,
                     service_nonce=secrets.token_hex(32))
        held()
        _write(witness, reply, deadline)
        _write(pi, reply, deadline)
        held()


def measure_via_pi(request, mark, *, ticket, ticket_pin, pi, witness, guard, deadline, retain, copy_observation=None):
    """Manager-side leaf. Only the supplied collector mark clock owns durations.

    The native owner must provide the actual environment guard, live channels, claim
    and private evidence retention; no caller-provided runner issues a task here.
    """
    t, desc = _ticket(ticket, ticket_pin)
    _require(canonical_json(request) == canonical_json(t["request"]) and callable(mark) and callable(retain),
             "REQUEST_OR_RETENTION")
    is_copy = desc["template_id"] == _COPY
    _require(type(copy_observation) is ManagedCopyObserver if is_copy else copy_observation is None, "COPY_OBSERVER")
    _copy_ticket(t, desc)
    _require(pi is not witness, "ALIASED_STREAM")
    call, record = _call(t, ticket_pin), None
    with ExitStack() as stack:
        pi_guard = stack.enter_context(_edge(pi, t["pi_peer"], t["manager_peer"], t["clock"], deadline))
        service_guard = stack.enter_context(_edge(witness, t["service_peer"], t["manager_peer"], t["clock"], deadline))
        def held():
            pi_guard()
            service_guard()
            _environment(t, guard)
        held()
        observe = stack.enter_context(copy_observation.observing(call["request_digest"], deadline=deadline)) if is_copy else None
        start = mark("TASK_ACCEPTED")
        _write(pi, call, deadline)
        response = _read(pi, deadline)
        original_response = _read(witness, deadline)
        # Include both complete replies. A fast Pi frame cannot exclude work
        # performed before the authentic service witness finished its response.
        end = mark("TASK_COMPLETED")
        held()
        bounds = dict(TASK_ACCEPTED=start, TASK_COMPLETED=end)
        validate_boundaries(bounds)
        _require(type(response) is dict and set(response) == set(call) | {"observation", "service_nonce"}
                 and type(response["service_nonce"]) is str and re.fullmatch(r"[0-9a-f]{64}", response["service_nonce"])
                 and canonical_json(original_response) == canonical_json(response)
                 and response == dict(call, schema="aragorn/pi-core-fixed-task-response/v1",
                                      observation=response["observation"], service_nonce=response["service_nonce"]),
                 "INDEPENDENT_SERVICE_RESPONSE")
        receipt = canonical_json(dict(schema="aragorn/phase3-local-measurement-receipt/v1", request_digest=call["request_digest"],
                                      deployment_digest=t["request"]["deployment_digest"], boundaries=bounds, observation=response["observation"]))
        if is_copy:
            verify_managed_copy_output(receipt, t["request"], bounds, desc)
            record = observe()
            retained = response["observation"]["retained_file"]
            _require(all(record[k] == retained[k] == t["copy"][k] for k in ("directory_identity", "fixture_digest"))
                     and record["file_identity"] == retained["identity"] and record["content_digest"] == t["request"]["input_digest"]
                     and [record["guest"][k] for k in ("pid", "uid", "gid")] == t["service_peer"]
                     and record["guest"]["boot_id"] == t["clock"]["boot_id"]
                     and record["guest"]["time_ns"] == t["clock"]["time_namespace_inode"], "COPY_INDEPENDENT_READBACK")
        else:
            _COMPUTE[desc["template_id"]](receipt, t["request"], bounds)
        evidence = dict(schema="aragorn/pi-core-fixed-task-roundtrip/v1", ticket_digest=ticket_pin,
            request_digest=call["request_digest"], receipt_digest=original._digest(receipt), service_response=original_response,
            pi_response=response, boundaries=bounds, copy_observation=record)
        held()
    raw = canonical_json(evidence)
    _require(retain(raw) == original._digest(raw), "PRIVATE_RETENTION")
    return receipt
