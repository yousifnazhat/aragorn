"""Replay a privately retained managed result against separately held plan, owner and attempt pins.

No CAS writes, sockets, processes, or reads from guest paths. The public owner
stdout commits to the original private bytes but cannot recreate them.
"""
import argparse
import json
from pathlib import Path
import re
import stat
import sys

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.phase3_deployment import build_phase3_deployment_identity
from aragorn.pi_core_coordinator_entry import _launch, _plan
from aragorn.pi_core_owned_socket_directories import verify_owned_socket_directories
from aragorn.pi_core_restricted_profile import GATE_BYTES, RUNTIME_DIGEST, runtime_receipt, validate_profile
from aragorn.pi_core_service_source import _inventory
from aragorn.pi_core_source_observer import MAX_EVENTS, OPTIONS
from aragorn.pi_core_source_observation_verify import _clock, _identity, _worker
from aragorn.runtime_process_profile import runtime_process_profile
from aragorn.pi_core_state_admission import _keys, _need, _pin, _same, _uint, _uuid
from scripts.prepare_pi_core_coordinator_host import host_contract
from scripts.verify_pi_core_installed_bundle_readback import _document


_MODULES = {"aragorn.pi_core_coordinator_entry", "aragorn.pi_core_managed_bootstrap",
            "aragorn.pi_core_native_supervisor", "aragorn.pi_core_node_source_observer",
            "aragorn.pi_core_source_observer", "aragorn.pi_core_owned_socket_directories"}


def _custody(owner, profile, profile_pin):
    files = host_contract._profile(profile)
    host = owner["host_before"]
    _same(host, owner["host_after"], "manager host identity changed")
    _need(host["schema"] == "aragorn/pi-core-coordinator-host-observation/v1" and
          host["authority"] == "PINNED_HOST_TCB_ONLY_NOT_CONSUMED_CODE_OR_PHASE3" and
          host["phase3_exit_eligible"] is False and host["host_profile_digest"] == profile_pin and
          host["python_executable"] == profile["python_executable"] and type(host["files"]) is int and
          host["files"] == len(files), "manager host profile differs")
    _uint(host["pid"], high=1 << 31)
    src = _inventory({str(path)[1:]: row["digest"] for path,row in files.items()
                      if str(path).startswith("/opt/aragorn/src/aragorn/")})
    first, last = owner["source_before"], owner["source_after"]
    _need(type(first) is list and type(last) is list and 0 < len(first) <= len(last) <= 512,
          "missing protected source custody")
    _same(first, last[:len(first)], "source loader did not preserve its initial observations")
    seen = set()
    for row in last:
        _keys(row, ("module", "path", "digest"))
        name = row["module"]
        _need(type(name) is str and name in src and name not in seen and
              (row["path"], _pin(row["digest"])) == src[name][:2], "invalid consumed source")
        seen.add(name)
    _need(_MODULES <= seen and any(r["module"] == "aragorn.pi_core_coordinator_entry" for r in first),
          "manager did not retain consumed source for the socket observation")
    return {name:src[name][1] for name in seen}


def _stop(trace, record):
    events = trace["events"]
    _need(type(events) is list and 0 < len(events) <= MAX_EVENTS, "missing original bounded source events")
    seq = _uint(record["gate_stop_seq"], high=len(events)+1)
    pid, ticks = record["worker"]["pid"], record["worker"]["start_ticks"]
    last_ns = 0
    for i, event in enumerate(events, 1):
        _same(event["seq"], i, "source event sequence changed")
        now = _uint(event["boottime_ns"])
        _need(now >= last_ns and event["kind"] != "REFUSED", "regressed or refused source history")
        last_ns = now
    stop = events[seq-1]
    _need(stop.get("kind") == "STOP", "gate_stop_seq does not identify a stop")
    _same([stop[k] for k in ("kind", "event", "op", "pid", "start_ticks")], ["STOP", 128, "NONE", pid, ticks],
          "different owned gate stop")
    _need(type(stop["status"]) is int and stop["status"] in ((128 << 16) | (sig << 8) | 127 for sig in (5,19)),
          "unexpected gate wait status")
    armed = events[0]
    _same([seq, armed["kind"], armed["tasks"], armed["options"]], [2,"ARMED",[pid],OPTIONS],
          "not the original singleton arming and stop")
    gate = _identity(armed["gate_identity"])
    _need(gate["uid"] == gate["gid"] == 0 and gate["nlink"] == 1 and
          stat.S_ISREG(gate["mode"]) and bool(gate["mode"] & stat.S_IXUSR) and
          not gate["mode"] & 0o7022 and gate["size"] == GATE_BYTES, "not the approved gate file shape")
    resume = next((e for e in events[seq:] if e["kind"] == "RESUME"), None)
    _need(resume is not None and resume["pid"] == pid and resume["start_ticks"] == ticks and
          resume["request"] in ("SYSCALL","CONT"),
          "missing original end of stopped interval")
    held = events[seq:resume["seq"]-1]
    _need(len(held) >= 2 and held[0]["kind"] == "ALL_STOP" and held[1]["kind"] == "STDIO" and
          all(e["kind"] == "ALL_STOP" for e in held[2:]), "missing original gate barrier or stdio survey")
    for barrier in (held[0], *held[2:]):
        _same([barrier["tasks"], barrier["stop_seqs"]], [[dict(pid=pid, start_ticks=ticks)],[seq]],
              "different task or stop at singleton barrier")
    _same(held[0]["epoch"], held[1]["epoch"], "stdio survey used another barrier")
    a, b = record["before_start"], record["stopped"]
    _need(a["closed_boottime_ns"] <= armed["boottime_ns"] <= stop["boottime_ns"] <= held[1]["boottime_ns"] <=
          b["opened_boottime_ns"] < b["closed_boottime_ns"] <= resume["boottime_ns"],
          "socket observation is outside the owned gate stop")
    _same([events[-1][k] for k in ("kind","pid","status")], ["CLEANUP",pid,"EXIT_OBSERVED"],
          "terminal owned process exit not retained")


def verify_socket_directories(archive, *, plan_pin, owner_pin, managed_pin, deployment_pin, boot_id, invocation_id):
    _need(type(archive) is CAS and archive.read_only is True, "private read-only CAS required")
    _uuid(boot_id)
    _need(type(invocation_id) is str and re.fullmatch("[0-9a-f]{32}", invocation_id) and int(invocation_id,16),
          "expected independently nominated unit invocation")
    plan = _document(archive, plan_pin, 1 << 20)
    owner = _document(archive, owner_pin, (256 << 10) + 8192, stdout=True)
    managed = _document(archive, managed_pin, 4 << 20)
    _need(plan["schema"] == "aragorn/pi-core-coordinator-plan/v1" and plan["mode"] == "PROTECTED"
          and type(plan["provider"]) is dict and "sensor_state_observation" not in plan and
          _pin(plan["deployment"]["digest"]) == deployment_pin, "not the approved provider-capable deployment")
    _need(owner["schema"] == "aragorn/pi-core-coordinator-report/v1" and
          owner["authority"] == "MANAGED_RESULT_DIGEST_ONLY_NOT_RAW_EFFECT_EVIDENCE" and
          owner["status"] == "MANAGED_BOOTSTRAP_RETURNED_NOT_QUALIFIED" and
          owner["entry_status"] == "MANAGED_CALL_RETURNED_NOT_QUALIFIED" and owner["wrapper_stage"] == "POST_CALL_CUSTODY"
          and owner["entry_failure_stage"] is None and owner["phase3_exit_eligible"] is False and
          all(owner[k] is True for k in ("entry_call_attempted","managed_call_attempted","managed_cleanup_complete","owned_inputs_closed"))
          and owner["managed_status"] == "BOOTSTRAP_COMPLETE" and
          owner["wrapper_cleanup"] == {"host":"CLOSED","source_loader":"CLOSED"} and
          [owner[k] for k in ("plan_digest","deployment_digest","managed_result_digest")] ==
          [plan_pin,deployment_pin,managed_pin], "owner did not confirm these exact completed private bytes")
    host_pin = _pin(plan["host_profile_digest"])
    # Path/secret alias checks at acquisition remain the original owner's job.
    # No location for the original plan is invented from the local CAS layout.
    _plan(plan, host_pin, None)
    consumed = _custody(owner, _document(archive, host_pin, 2 << 20), host_pin)
    bindings = _document(archive, deployment_pin, 2 << 20)
    build_phase3_deployment_identity(bindings)
    _need(bindings["runtime_commit_or_image"] == RUNTIME_DIGEST, "deployment has a different worker runtime")
    cfg = _launch(_document(archive, plan["launch"]["digest"], 4 << 20), "PROTECTED")
    expected_runtime = runtime_receipt(cfg.compiled_receipt["inputs"]["source_gate"])
    _same(cfg.compiled_receipt, expected_runtime, "different restricted worker build")
    _same(cfg.compiled_receipt_digest, canonical_digest(expected_runtime), "unbound restricted build receipt")
    _pin(cfg.provider_route_digest)
    profile = cfg.source_observation
    validate_profile(profile)
    _need(canonical_digest(profile) == cfg.source_observation_digest, "unbound worker source profile")
    _same([profile["pins"]["node_observer_digest"],profile["pins"]["producer_digest"]],
          [consumed["aragorn.pi_core_node_source_observer"],consumed["aragorn.pi_core_source_observer"]],
          "worker source acquisition code differs from actual consumed host inventory")
    configs = _document(archive, plan["service_configuration"]["configurations"]["digest"], 1 << 20)
    principal = configs["action"]["identities"]["worker"]
    _same(principal, dict(uid=cfg.worker_uid,gid=cfg.worker_gid), "service and launcher principals differ")
    process = runtime_process_profile(configs["sensor"]["observation_binding"]["runtime_profile"])
    _need(process.runtime_digest == RUNTIME_DIGEST and process.executable_digest == profile["pins"]["node_digest"],
          "service bound to a different worker process profile")
    w, services = managed["worker"], managed["services"]
    _need(managed["schema"] == "aragorn/pi-core-managed-bootstrap-result/v1" and
          managed["authority"] == "SERVICE_AND_WORKER_BOOTSTRAP_ONLY_NOT_USEFUL_TASK_OR_PHASE3" and
          managed["status"] == w["status"] == "BOOTSTRAP_COMPLETE" and managed["provider_configured"] is True and
          all(managed[k] is False for k in ("provider_available","useful_task_verified","loaded_code_verified","phase3_exit_eligible"))
          and w["schema"] == "aragorn/pi-core-native-supervisor-result/v1" and
          w["authority"] == "BOOTSTRAP_AND_OWNED_CLEANUP_ONLY_NOT_EFFECT_RUN_OR_PHASE3_QUALIFICATION" and
          w["failure"] is None and "failure_evidence" not in w and "failure_evidence" not in managed and
          services["schema"] == "aragorn/pi-core-service-lifecycle/v1" and services["status"] == "CLOSED" and
          services["provider_mode"] == "CONTROLLED_CREDENTIAL_FIXED_ADDRESS" and services["phase3_exit_eligible"] is False and
          w["cleanup"]["status"] == services["cleanup"]["status"] == "VERIFIED_OWNED_CLEANUP" and
          w["request_channel"]["cleanup"] == "VERIFIED_OWNED_REQUEST_CLEANUP" and
          w["provider_channel"]["cleanup"] == "VERIFIED_OWNED_PROVIDER_CLEANUP" and
          w["identity_registration"]["status"] == "REVOKED" and type(w["bootstrap"]) is dict,
          "missing protected worker/service return or owned cleanup")
    _need(all(w["cleanup"][k] is True for k in ("unit_absent", "process_exit_observed", "cgroup_empty_or_absent",
                                                 "activation_withdrawn", "socket_removed")),
          "incomplete worker cleanup")
    boot = w["bootstrap"]
    _need(boot["schema"] == "aragorn/pi-core-bootstrap-observation/v1" and
          boot["authority"] == "BOOTSTRAP_STATUS_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY" and boot["release_sent"] is True and
          boot["result"]["schema"] == "aragorn/pi-core-bootstrap-result/v2" and
          boot["activation_digest"] == _pin(w["activation_digest"]), "absent or unrelated protected bootstrap")
    r = w["owned_socket_directories"]
    _keys(r, ("schema","status","deployment_digest","source_profile_digest","immutable_launch_digest","worker","clock",
              "before_start","stopped","gate_stop_seq"))
    _need(r["schema"] == "aragorn/pi-core-manager-socket-membership/v1" and r["status"] == "MATCHED_MANAGER_MEMBERSHIP_ONLY"
          and r["deployment_digest"] == deployment_pin and r["immutable_launch_digest"] == _pin(w["immutable_launch_digest"]),
          "missing complete membership from this worker")
    worker, clock = _worker(r["worker"]), _clock(r["clock"])
    _need(clock["boot_id"] == boot_id and type(w["unit"]) is str and re.fullmatch(r"aragorn-pi-[0-9a-f]{32}\.service", w["unit"]),
          "different worker boot or unit")
    _same([worker[k] for k in ("pid","start_ticks","uid","gid","cgroup","unit","invocation_id")],
          [w["pid"],w["start_time_ticks"],cfg.worker_uid,cfg.worker_gid,"/system.slice/"+w["unit"],w["unit"],invocation_id],
          "wrong generation or launch principal")
    _need(w["invocation_id"] == invocation_id and worker["cgroup"] == process.cgroup,
          "different supervisor invocation or configured worker cgroup")
    source = w["source_observation"]
    trace = source["capture"]
    _need(source["closed"] is True and source["authority"] == "SOURCE_ACQUISITION_ONLY_NOT_V8_EXECUTION_OR_PHASE3_QUALIFICATION"
          and source["profile_digest"] == r["source_profile_digest"] == cfg.source_observation_digest and
          trace["schema"] == "aragorn/pi-core-node-source-observation/v2" and trace["architecture"] == "linux-arm64"
          and trace["state"] == "CLOSED", "no terminal protected source record")
    _same(trace["bindings"], dict(profile["pins"], deployment_digest=deployment_pin, runtime_digest=RUNTIME_DIGEST,
                                 profile_digest=r["source_profile_digest"]), "unbound source capture")
    _same([trace["worker"], trace["clock"]], [worker,clock], "different source capture generation/clock")
    finding = verify_owned_socket_directories(r["before_start"], r["stopped"], worker_uid=cfg.worker_uid, worker_gid=cfg.worker_gid)
    for edge in (r["before_start"], r["stopped"]):
        _same([edge["manager"]["pid"],edge["boot_id"],edge["time_namespace_inode"]],
              [owner["host_before"]["pid"],boot_id,clock["time_namespace_inode"]],
              "different manager or clock at socket observation")
    _stop(trace, r)
    return dict(schema="aragorn/pi-core-manager-socket-membership-finding/v1", owner=owner_pin, plan=plan_pin,
                managed_result=managed_pin, deployment=deployment_pin, boot_id=boot_id, invocation_id=invocation_id,
                gate_stop_seq=r["gate_stop_seq"], stopped_window_joined=True, worker_connection_verified=False,
                local_full_namespace_walk_observed=False, activation_authorized=False, **finding)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    for name in ("owner-pin","plan-pin","managed-pin","deployment-pin","boot-id","invocation-id"):
        parser.add_argument("--"+name, required=True)
    args = vars(parser.parse_args(argv))
    try:
        args["archive"] = CAS(args["archive"], read_only=True)
        print(json.dumps(verify_socket_directories(**args), sort_keys=True))
        return 0
    except (CASError, ValueError, TypeError, RuntimeError, OSError, KeyError, IndexError, AttributeError):
        print("Socket membership replay refused: incomplete or conflicting protected evidence.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
