"""Publish one acquired provider request, never global health or effect authority.

The caller owns the authenticated worker, source observer, lineage and broker
lock. These boundary checks consume that owner's returned snapshot; they do not
replace independent source/loader replay or establish arbitrary V8 execution.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import pi_core_provider_mediation as mediation
from . import pi_core_source_observation_verify as source_fields
from . import pi_core_worker_identity as identity
from . import runtime_action_broker as broker
from . import runtime_action_decision as decision
from . import runtime_active_skill_lineage as lineage_contract
from . import runtime_capability_grant as capability
from .oci_worker_protocol import canonical_digest, canonical_json


class PiProviderObservationError(RuntimeError):
    pass


_MAX_RAW = 4 * 1024 * 1024
_MAX_EVENTS = 4096
_ATTRIBUTION = ("runtime_digest", "session_id", "run_id", "tool_call_id", "active_skill_digest")
_BINDINGS = {"gate_digest", "node_digest", "producer_digest", "node_observer_digest",
             "source_inventory_digest", "loader_inventory_digest", "deployment_digest",
             "runtime_digest", "profile_digest"}
_KINDS = {"ARMED", "STOP", "RESUME", "ALL_STOP", "STDIO", "GATE_RELEASE", "EXEC",
          "READ_ENTER", "READ_EXIT", "LOADER_READ_ENTER", "LOADER_READ_EXIT",
          "IO_ENTER", "IO_EXIT", "MAP_ENTER", "MAP_EXIT", "CLONE_REQUEST", "THREAD",
          "THREAD_START", "THREAD_EXIT", "FD_CREATE", "CHALLENGE"}


def _require(condition, code):
    if not condition:
        raise PiProviderObservationError(code)


def _uint(value, minimum=0):
    _require(type(value) is int and minimum <= value <= 2**64 - 1,
             "PROVIDER_SOURCE_INTEGER")
    return value


def _exact(value, fields):
    _require(type(value) is dict and set(value) == fields, "PROVIDER_SOURCE_FIELDS")
    return value


def _read_coverage(record, events):
    sources = record["sources"]
    required = record["required_sources"]
    _require(type(sources) is list and 0 < len(sources) <= 512 and
             type(required) is list and 0 < len(required) <= 512 and
             all(type(path) is str for path in required) and len(set(required)) == len(required),
             "PROVIDER_SOURCE_INVENTORY")
    rows, ranges, pending, seen = {}, {}, {}, set()
    for row in sources:
        _exact(row, {"path", "digest", "identity", "readonly_view"})
        path = row["path"]
        _require(type(path) is str and path.startswith("/") and path not in rows and
                 row["readonly_view"] is True, "PROVIDER_SOURCE_INVENTORY")
        source_fields._identity(row["identity"])
        broker._require_digest(row["digest"], "provider source digest")
        rows[path], ranges[path] = row, []
    _require(set(required) <= set(rows), "PROVIDER_REQUIRED_SOURCE_ABSENT")
    for event in events:
        if event["kind"] == "READ_ENTER":
            call = _uint(event["call_id"], 1)
            path = event["path"]
            _require(call not in seen and path in rows and event["digest"] == rows[path]["digest"] and
                     event["identity"] == rows[path]["identity"], "PROVIDER_SOURCE_READ_JOIN")
            _uint(event["offset"])
            _uint(event["count"])
            pending[call] = event
            seen.add(call)
        elif event["kind"] == "READ_EXIT":
            entry = pending.pop(_uint(event["call_id"], 1), None)
            _require(entry is not None and event["pid"] == entry["pid"] and
                     event["identity"] == entry["identity"], "PROVIDER_SOURCE_READ_JOIN")
            result, error = event["result"], event["is_error"]
            _require(type(result) is int and type(error) is bool and
                     (error and -4095 <= result < 0 or not error and 0 <= result <= entry["count"] and
                      entry["offset"] + result <= entry["identity"]["size"]), "PROVIDER_SOURCE_READ_RESULT")
            if not error:
                ranges[entry["path"]].append((entry["offset"], entry["offset"] + result))
    _require(not pending, "PROVIDER_SOURCE_PENDING_READ")
    for path in required:
        end = 0
        _require(bool(ranges[path]), "PROVIDER_REQUIRED_SOURCE_UNREAD")
        for low, high in sorted(ranges[path]):
            _require(low <= end, "PROVIDER_SOURCE_DELIVERY_GAP")
            end = max(end, high)
        _require(end == rows[path]["identity"]["size"], "PROVIDER_SOURCE_DELIVERY_INCOMPLETE")


def validate_provider_source_capture(source_capture, activation, *, boundary_boottime_ns):
    """Check the actual owner's bounded HELD boundary, not independent replay."""
    activation = identity.validate_activation(activation)
    raw = canonical_json(source_capture)
    _require(0 < len(raw) <= _MAX_RAW, "PROVIDER_SOURCE_RECORD_BOUND")
    record = _exact(json.loads(raw), {"schema", "architecture", "bindings", "worker", "clock",
        "sources", "required_sources", "loaders", "state", "events", "accounting"})
    _require(record["schema"] == "aragorn/pi-core-node-source-observation/v2" and
             record["architecture"] == "linux-arm64" and record["state"] == "HELD",
             "PROVIDER_SOURCE_HELD_REQUIRED")
    bindings = _exact(record["bindings"], _BINDINGS)
    for pin in bindings.values():
        broker._require_digest(pin, "provider source binding")
    _require(all(bindings[key] == activation[key] for key in ("runtime_digest", "deployment_digest")) and
             bindings["node_digest"] == activation["executable_digest"], "PROVIDER_SOURCE_DEPLOYMENT")
    worker = source_fields._worker(record["worker"])
    _require(all(worker[key] == activation[target] for key, target in
                 (("pid", "pid"), ("start_ticks", "start_time_ticks"), ("uid", "uid"),
                  ("gid", "gid"), ("cgroup", "cgroup"))), "PROVIDER_SOURCE_WORKER")
    clock = source_fields._clock(record["clock"])
    _require(clock["boot_id"] == activation["boot_id"], "PROVIDER_SOURCE_CLOCK")
    boundary = _uint(boundary_boottime_ns, 1)
    events = record["events"]
    _require(type(events) is list and 0 < len(events) <= _MAX_EVENTS, "PROVIDER_SOURCE_EVENT_BOUND")
    counts = {kind: 0 for kind in _KINDS}
    tasks = {worker["pid"]: worker["start_ticks"]}
    stops, resumes, calls, io_calls = {}, {}, {}, {}
    barrier = None
    challenges, last_challenge, stamp = set(), -1, 0
    for sequence, event in enumerate(events, 1):
        _require(type(event) is dict and event.get("kind") in _KINDS and
                 type(event.get("seq")) is int and event["seq"] == sequence,
                 "PROVIDER_SOURCE_EVENT_SEQUENCE")
        tick = _uint(event["boottime_ns"], 1)
        _require(stamp <= tick <= boundary, "PROVIDER_SOURCE_EVENT_CLOCK")
        stamp, kind = tick, event["kind"]
        counts[kind] += 1
        if kind == "THREAD":
            pid = _uint(event["pid"], 1)
            _require(pid not in tasks and len(tasks) < 64, "PROVIDER_SOURCE_THREAD")
            tasks[pid] = _uint(event["start_ticks"], 1)
        elif kind == "THREAD_EXIT":
            pid = event["pid"]
            _require(pid in tasks and pid != worker["pid"] and tasks[pid] == event["start_ticks"],
                     "PROVIDER_SOURCE_THREAD")
            del tasks[pid]
            calls.pop(pid, None)
        elif kind == "STOP":
            pid = event["pid"]
            _require(pid in tasks and event["start_ticks"] == tasks[pid], "PROVIDER_SOURCE_STOP")
            stops[pid] = event
            if event["op"] == "ENTRY":
                _require(pid not in calls, "PROVIDER_SOURCE_PENDING_CALL")
                calls[pid] = event
            elif event["op"] == "EXIT":
                calls.pop(pid, None)
        elif kind == "RESUME":
            resumes[event["pid"]] = event
        elif kind == "ALL_STOP":
            barrier = event
        elif kind == "EXEC":
            _require(event["pid"] == worker["pid"] and event["digest"] == bindings["node_digest"],
                     "PROVIDER_SOURCE_EXECUTABLE")
        elif kind == "IO_ENTER":
            pid, call_id = event["pid"], _uint(event["call_id"], 1)
            _require(pid in calls and calls[pid]["seq"] == call_id and call_id not in io_calls,
                     "PROVIDER_SOURCE_IO_JOIN")
            io_calls[call_id] = pid
        elif kind == "IO_EXIT":
            _require(io_calls.pop(_uint(event["call_id"], 1), None) == event["pid"],
                     "PROVIDER_SOURCE_IO_JOIN")
        elif kind == "CHALLENGE":
            _exact(event, {"seq", "boottime_ns", "kind", "nonce", "issued_ns", "deadline_ns",
                           "epoch", "tasks", "stops_before", "stops_after", "all_stopped"})
            nonce, issued, deadline = event["nonce"], _uint(event["issued_ns"], 1), _uint(event["deadline_ns"], 1)
            _require(type(nonce) is str and re.fullmatch(r"[0-9a-f]{64}", nonce) is not None and
                     nonce not in challenges and last_challenge < issued <= tick < deadline and
                     deadline - issued == 100_000_000, "PROVIDER_SOURCE_CHALLENGE")
            _require(event["all_stopped"] is True and event["tasks"] ==
                     [dict(pid=pid, start_ticks=tasks[pid]) for pid in sorted(tasks)] and
                     barrier is not None and _uint(event["epoch"], 1) == barrier["epoch"] and
                     event["tasks"] == barrier["tasks"] and barrier["stop_seqs"] ==
                     [stops.get(pid, {}).get("seq") for pid in sorted(tasks)] and
                     _uint(event["stops_after"]) == counts["STOP"] and
                     event["stops_after"] - _uint(event["stops_before"]) >= len(tasks),
                     "PROVIDER_SOURCE_CHALLENGE_TASKS")
            for pid in tasks:
                stop, resumed = stops.get(pid), resumes.get(pid)
                _require(stop is not None and resumed is not None and
                         issued <= resumed["boottime_ns"] <= stop["boottime_ns"] <= tick and
                         resumed["seq"] < stop["seq"] and stop["status"] & 255 == 127,
                         "PROVIDER_SOURCE_CHALLENGE_PROGRESS")
            _require(all(call["syscall"] in {22, 72, 73, 98} or call["seq"] in io_calls
                         for call in calls.values()), "PROVIDER_SOURCE_PENDING_INPUT")
            challenges.add(nonce)
            last_challenge = tick
    _require(events[0]["kind"] == "ARMED" and counts["EXEC"] == 1 and
             events[-1]["kind"] == "CHALLENGE" and boundary - stamp <= 200_000_000,
             "PROVIDER_SOURCE_FRESH_CHALLENGE_REQUIRED")
    expected = dict(stops_acquired=counts["STOP"], reads_entered=counts["READ_ENTER"],
        reads_exited=counts["READ_EXIT"], bytes_read=sum(max(event["result"], 0) for event in events
                                                    if event["kind"] == "READ_EXIT"),
        pending_reads=counts["READ_ENTER"] - counts["READ_EXIT"], refusals=0,
        events_retained=len(events), threads_observed=1 + counts["THREAD"], threads_exited=counts["THREAD_EXIT"],
        maps_entered=counts["MAP_ENTER"], maps_exited=counts["MAP_EXIT"],
        io_entered=counts["IO_ENTER"], io_exited=counts["IO_EXIT"], pending_syscalls=len(calls))
    _exact(record["accounting"], set(expected))
    _require(all(_uint(record["accounting"][key]) == value for key, value in expected.items()) and
             expected["pending_reads"] == 0 and counts["MAP_ENTER"] == counts["MAP_EXIT"] and
             counts["LOADER_READ_ENTER"] == counts["LOADER_READ_EXIT"] and
             counts["IO_ENTER"] - counts["IO_EXIT"] == len(io_calls) and
             all(pid in calls and calls[pid]["seq"] == call_id for call_id, pid in io_calls.items()),
             "PROVIDER_SOURCE_LOSS_ACCOUNTING")
    _read_coverage(record, events)
    challenge = {key: events[-1][key] for key in ("nonce", "issued_ns", "deadline_ns")}
    return dict(challenge=challenge, clock=clock, boundary_boottime_ns=boundary)


def publish_provider_observation(control_fd, config, *, request, approval, activation,
                                 measured, lineage, grant, source_capture, boundary_boottime_ns, now_unix):
    """Advance only the held observation anchor; the subsequent broker decides."""
    request = mediation.validate_provider_request(request)
    activation = identity.validate_activation(activation)
    approval, digests = mediation._approval(approval, request, activation)
    action = approval["request"]
    now = broker._uint(now_unix, "provider observation time")
    _require(action["issued_at_unix"] <= now < action["expires_at_unix"] and
             action["expires_at_unix"] - action["issued_at_unix"] <= decision._MAX_REQUEST_LIFETIME_SECONDS,
             "PROVIDER_OBSERVATION_ACTION_EXPIRED")
    measured = capability._profile_attribution({"runtime_attribution": measured})
    _require(all(measured[key] == activation[key] for key in identity._ATTRIBUTION_FIELDS),
             "PROVIDER_OBSERVATION_MEASURED_IDENTITY")
    _require(type(lineage) is dict and lineage.get("schema") == lineage_contract.VERIFIED_LINEAGE_SCHEMA and
             lineage.get("authority") == lineage_contract.VERIFIED_LINEAGE_AUTHORITY and
             lineage.get("runtime_skill_path") == measured["skill_path"], "PROVIDER_OBSERVATION_LINEAGE")
    profile = identity.process.RuntimeProcessProfile(measured["runtime_digest"], measured["executable_digest"],
        measured["cgroup"], Path(measured["skill_path"]), measured["profile_digest"])
    identity._lineage_matches(lineage, activation, profile, Path("/var/lib/aragorn/admitted"))
    grant = capability.parse_runtime_capability_grant(canonical_json(grant), now)
    pairs = {"runtime_profile_digest": "profile_digest", "runtime_digest": "runtime_digest",
             "active_skill_digest": "active_skill_digest", "source_manifest_digest": "source_manifest_digest",
             "install_context_digest": "install_context_digest", "policy_digest": "policy_digest"}
    _require(all(grant[key] == activation[target] for key, target in pairs.items()) and
             grant["policy_version"] == action["policy_version"], "PROVIDER_OBSERVATION_GRANT")
    validate_provider_source_capture(source_capture, activation, boundary_boottime_ns=boundary_boottime_ns)
    policy, _ = decision._policy(broker._load_control(control_fd, config.policy_path, config, "provider observation policy"))
    _require(config.expected_runtime_digest == activation["runtime_digest"] and
             canonical_digest(policy) == action["policy_digest"] and policy["version"] == action["policy_version"] and
             policy["sensor_digest"] == grant["sensor_digest"], "PROVIDER_OBSERVATION_POLICY")
    anchor = broker._load_control(control_fd, config.observation_path, config, "provider observation anchor")
    broker._observation(anchor, broker._uint(anchor.get("observed_at_unix"), "provider observation anchor time"))
    _require(anchor["sensor_digest"] == policy["sensor_digest"] and
             (anchor["active"] is None) == (anchor["measured_action"] is None), "PROVIDER_OBSERVATION_ANCHOR")
    if anchor["active"] is not None:
        decision._active(anchor["active"])
        decision._measured_action(anchor["measured_action"])
    attribution = {key: action[key] for key in _ATTRIBUTION}
    observation = dict(schema="aragorn/runtime-action-observation/v1",
        authority="SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY", sequence=anchor["sequence"] + 1,
        sensor_digest=policy["sensor_digest"], observed_at_unix=now,
        expires_at_unix=min(now + broker._MAX_OBSERVATION_LIFETIME_SECONDS,
                            action["expires_at_unix"], grant["expires_at_unix"]),
        active=decision._active(dict(schema="aragorn/runtime-active-context/v1", **attribution)),
        measured_action=decision._measured_action(dict(schema="aragorn/measured-runtime-action/v1", **attribution, **digests)))
    broker._publish_control_locked(control_fd, config.observation_path, observation,
                                   canonical_json(observation), config, now)
    return json.loads(canonical_json(observation))
