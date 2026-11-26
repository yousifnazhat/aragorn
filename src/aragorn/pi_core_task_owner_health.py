"""Join task-owner custody to present worker observation; never infer instrumented sensor health."""
import time

from . import pi_core_source_observer as source
from .native_phase3_workload_json_sum_contract import validate_request
from .pi_core_identity_handoff import validate_deadline
from .pi_core_provider_observation import validate_provider_source_capture
from .pi_core_state_admission import _keys, _need, _same
from .pi_core_worker_identity import validate_activation


def guard_task_health(ticket, *, source_observer, activation, worker, deadline):
    """Require a fresh live challenge for this claimed worker; return its original evidence.

    The caller supplies the stopped-role record and separately guards the observed
    mode. Even a healthy source observer does not measure a second sensor's losses.
    """
    validate_deadline(deadline)
    validate_request(ticket["request"])
    _need(ticket["request"]["mode"] == "baseline", "instrumented sensor loss acquisition unavailable")
    _need(type(source_observer) is source.PiSourceObserver, "owned worker source observer required")
    _keys(worker, ("pid","uid","gid","start_ticks","unit","invocation_id"))
    a = validate_activation(activation)
    _same([worker[k] for k in ("pid","uid","gid")], ticket["pi_peer"], "health worker differs from ticket")
    _need(worker["unit"] == "aragorn-pi-task-worker.service" and a["cgroup"] == "/system.slice/" + worker["unit"] and
          a["start_time_ticks"] == worker["start_ticks"] and a["boot_id"] == ticket["clock"]["boot_id"] and
          a["deployment_digest"] == ticket["request"]["deployment_digest"], "foreign worker activation or deployment")
    _same([a[k] for k in ("pid","uid","gid")], ticket["pi_peer"], "foreign worker activation")

    issued = source._tick()
    capture = source_observer.guard_source_health(activation=a, deadline=deadline)
    _need(type(capture) is dict, "missing held sensor health observation")
    boundary = validate_provider_source_capture(capture, a, boundary_boottime_ns=source._tick())
    _same(capture["worker"], worker | {"cgroup":a["cgroup"]}, "health belongs to another worker invocation")
    _same(boundary["clock"], ticket["clock"], "health belongs to another boot or time namespace")
    _need(issued <= boundary["challenge"]["issued_ns"], "replayed source challenge")
    # Validation itself consumes freshness; use the same 200 ms maximum as the source reader.
    _need(0 <= source._tick() - capture["events"][-1]["boottime_ns"] <= 200_000_000 and
          time.monotonic_ns() < a["expires_at_monotonic_ns"], "task health expired during validation")
    validate_deadline(deadline)
    return capture
