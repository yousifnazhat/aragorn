"""Read-only service identity and sensor-unit configuration, not measurement eligibility.

The pin must come from the protected owner's independent release. Neither matching
unit states nor snapshots prove healthy continuous instrumentation or exclusive use.
"""
from contextlib import ExitStack
import os
from pathlib import Path
import re

from . import pi_core_native_supervisor as native, pi_core_source_observer as sources
from . import pi_core_sensor_state_observer as proc, pi_core_stopped_mask_view as kernel
from .native_phase3_workload_json_sum_contract import validate_request
from .oci_worker_protocol import canonical_digest
from .pi_core_identity_handoff import validate_deadline
from .pi_core_state_admission import _keys, _need, _pin, _same, _uint, _uuid

_TASK = "aragorn-pi-task.service"
_SENSOR = "aragorn-pi-sensor.service"
_UNIT = "/usr/lib/systemd/system/" + _TASK
_WRAPPER = "/opt/aragorn/bin/pi-fixed-task.py"
_PYTHON = "/opt/aragorn-cpython/bin/python3.12"
_ARGV = ("\0".join((_PYTHON, "-I", "-S", "-B", _WRAPPER)) + "\0").encode("ascii")
_FIELDS = ("Id","LoadState","ActiveState","SubState","MainPID","ExecMainPID","ControlPID","InvocationID",
           "ControlGroup","FragmentPath","NeedDaemonReload","DropInPaths")
_PEERS = ("manager_peer","pi_peer","service_peer")


def _invocation(i):
    _need(type(i) is str and re.fullmatch("[0-9a-f]{32}",i) and int(i,16), "invalid nominated invocation")


def _nomination(ticket, n, pin):
    _keys(n, ("schema","request_digest","clock",*_PEERS,"service_invocation_id","sensor_invocation_id","sensor_pid","service_code"))
    _need(n["schema"] == "aragorn/pi-task-guest-nomination/v1" and canonical_digest(n) == _pin(pin)
          and ticket.get("environment_digest") == pin and ticket.get("schema") == "aragorn/pi-core-task-ticket/v1",
          "substituted guest nomination or ticket")
    validate_request(ticket["request"])
    _need(n["request_digest"] == canonical_digest(ticket["request"]), "different scheduled task or mode")
    _keys(n["clock"], ("clock_id","boot_id","time_namespace_inode"))
    _need(n["clock"]["clock_id"] == "CLOCK_BOOTTIME", "invalid nominated clock")
    _uint(n["clock"]["time_namespace_inode"])
    _uuid(n["clock"]["boot_id"])
    _same(ticket["clock"], n["clock"], "different nominated clock")
    for key in _PEERS:
        p = n[key]
        _same(ticket[key], p, "different nominated peer")
        _need(type(p) is list and len(p) == 3, "invalid nominated peer")
        _uint(p[0],1,1 << 31)
        for ident in p[1:]:
            _uint(ident,0,1 << 32)
    _need(n["manager_peer"][1:] == [0,0] and all(len(set(column)) == 3 for column in zip(*(n[k] for k in _PEERS))),
          "task roles must be distinct")
    _keys(n["service_code"], ("unit_digest","wrapper_digest","interpreter_digest"))
    for v in n["service_code"].values():
        _pin(v)
    _invocation(n["service_invocation_id"])
    if ticket["request"]["mode"] == "instrumented":
        _invocation(n["sensor_invocation_id"])
        _uint(n["sensor_pid"],1,1 << 31)
        _need(n["sensor_invocation_id"] != n["service_invocation_id"] and n["sensor_pid"] not in {n[k][0] for k in _PEERS},
              "sensor is not an independent invocation")
    else:
        _need(n["sensor_invocation_id"] is None and type(n["sensor_pid"]) is int and n["sensor_pid"] == 0,
              "baseline nominates an active sensor")


def _show(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= 4096 and raw.endswith(b"\n"), "missing bounded unit readback")
    pairs = [row.split("=",1) for row in raw.decode("ascii").splitlines()]
    _need(len(pairs) == len(_FIELDS) and all(len(pair) == 2 for pair in pairs), "invalid or duplicate unit fields")
    result = dict(pairs)
    _keys(result, _FIELDS)
    return result


def _active(unit, pid, invocation, fragment):
    return dict(Id=unit,LoadState="loaded",ActiveState="active",SubState="running",MainPID=str(pid),ExecMainPID=str(pid),
                ControlPID="0",InvocationID=invocation,ControlGroup="/system.slice/"+unit,
                FragmentPath=fragment,NeedDaemonReload="no",DropInPaths="")


def bound_environment(ticket, *, nomination, nomination_pin, installed_service_pin, service_show, sensor_show, clock):
    """Check separately sourced owner readbacks; success identifies the nominated configuration only."""
    n = nomination
    _nomination(ticket,n,nomination_pin)
    _same(clock,n["clock"],"observed clock differs")
    _need(_pin(installed_service_pin) == canonical_digest(n["service_code"]), "installed task service differs")
    _need(_show(service_show) == _active(_TASK,n["service_peer"][0],n["service_invocation_id"],_UNIT),
          "different task unit, code path or invocation")
    sensor = _show(sensor_show)
    if ticket["request"]["mode"] == "instrumented":
        expected = _active(_SENSOR,n["sensor_pid"],n["sensor_invocation_id"],"/run/systemd/transient/"+_SENSOR)
        _need(sensor == expected, "instrumented sensor invocation unavailable or changed")
    else:
        _need(native._absent(sensor) and sensor["Id"] == _SENSOR and sensor["ExecMainPID"] == "0"
              and sensor["NeedDaemonReload"] == "no" and not any(sensor[k] for k in ("ControlGroup","FragmentPath","DropInPaths")),
              "baseline requires observed absence of the fixed transient sensor")
    return nomination_pin


def _unit_show(name, deadline):
    code, raw = native._command(("/usr/bin/systemctl","show","--all","--property="+",".join(_FIELDS),name),deadline)
    _need(code == 0 or (name == _SENSOR and code in (1,4) and native._absent(_show(raw))), "systemd readback failed")
    return raw


def _service_code(stack, service_pid, service_proc, mount, deadline):
    # Hash the visible wrapper (embeds its source inventory), the actual interpreter,
    # and the unit fragment as seen by both PID 1 and the service. No path comes from Pi.
    def fixed(pid, path):
        fd = sources._open_view(pid, Path(path))
        stack.callback(os.close,fd)
        _need(os.fstatvfs(fd).f_flag & os.ST_RDONLY, "task code is not on read-only media")
        return fd
    unity = fixed(1,_UNIT)
    view = fixed(service_pid,_UNIT)
    wrapper = fixed(service_pid,_WRAPPER)
    interpreter = fixed(service_pid,_PYTHON)
    exe = kernel._magic(stack,service_proc,"exe",os.O_RDONLY,mount)
    _need(os.path.samestat(os.fstat(unity),os.fstat(view)) and os.path.samestat(os.fstat(exe),os.fstat(interpreter)),
          "different executing interpreter or unit fragment")
    cmd = kernel._proc_child(stack,service_proc,"cmdline",os.O_RDONLY,mount)
    _need(os.read(cmd,len(_ARGV)+1) == _ARGV, "different task service executable arguments")
    return {key:sources._hash(fd,deadline,64 << 20)[0] for key,fd in (
        ("unit_digest",unity),("wrapper_digest",wrapper),("interpreter_digest",exe))}


def observe_task_guest(ticket, *, nomination, nomination_pin, deadline):
    """Read fresh observations in the already-owned root manager; queries but never starts/stops units."""
    validate_deadline(deadline)
    kernel._platform()
    _nomination(ticket,nomination,nomination_pin)
    _need(nomination["manager_peer"] == [os.getpid(),os.geteuid(),os.getegid()], "not the nominated manager")
    with ExitStack() as stack:
        root,mount = kernel._proc(stack)
        roles = {key:nomination[key][0] for key in _PEERS}
        if nomination["sensor_pid"]:
            roles["sensor"] = nomination["sensor_pid"]
        handles, procs = [], {}
        for key,pid in roles.items():
            handle = os.pidfd_open(pid,0)
            stack.callback(os.close,handle)
            native.process.require_live_pidfd(handle)
            handles.append(handle)
            _,procs[key] = kernel._role(stack,root,pid,mount)
        def snapshot():
            ns = {proc._namespace(stack,f,"time",mount) for f in procs.values()}
            _need(len(ns)==1, "peers do not share a time namespace")
            for key,name in (("service_peer",_TASK),("sensor",_SENSOR)):
                if key in procs:
                    _need(kernel._read(procs[key],"cgroup",8192,mount,deadline) == ("0::/system.slice/"+name+"\n").encode(),
                          "wrong service cgroup")
            clock = dict(clock_id="CLOCK_BOOTTIME",boot_id=proc._boot_id(stack,root,mount,deadline),time_namespace_inode=ns.pop())
            return dict(service_show=_unit_show(_TASK,deadline),sensor_show=_unit_show(_SENSOR,deadline),clock=clock)
        seen = snapshot()
        code = _service_code(stack,roles["service_peer"],procs["service_peer"],mount,deadline)
        _need(seen == snapshot(), "unit or guest changed during observation")
        for fd in handles:
            native.process.require_live_pidfd(fd)
        validate_deadline(deadline)
        seen["installed_service_pin"] = canonical_digest(code)
        bound_environment(ticket,nomination=nomination,nomination_pin=nomination_pin,**seen)
        return seen
