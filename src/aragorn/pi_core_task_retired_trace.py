"""One-use retirement seal and independent replay of a private fixed-task trace."""
from time import monotonic

from . import pi_core_mask_custody as custody, pi_core_pilot_output_custody as sink
from . import pi_core_task_trace_store as traces
from .cas import CAS
from .oci_worker_protocol import canonical_json
from .pi_core_source_observation_verify import _document, _fields, _require, _same
from .pi_core_task_tracer_lifetime import StaticTracerLifetime


def _context(reader,fd,roots,binding,receipt):
    published = traces._receipt_pair(reader,fd,binding,receipt)
    _same(published["roots"],roots,"TERMINAL_TRACE_ROOTS")
    subject = _document(reader.read(binding,max_bytes=64<<10))
    ctx = dict(binding_digest=binding,receipt_digest=receipt,roots=roots)
    claim = canonical_json(dict(schema="aragorn/static-task-terminal-intent/v1",**ctx))
    prefix = "task-trace-"+binding[7:]
    return subject,ctx,claim,(prefix+"-terminal-intent.json",prefix+"-terminal.json")


def _terminal(record,binding,worker,clock):
    _fields(record,{"schema","binding_digest","worker","clock","pidfd_events","unit_state"})
    _require(record["schema"]=="aragorn/static-task-tracer-terminal/v1" and record["binding_digest"]==binding,
             "TERMINAL_BINDING")
    _same(record["worker"],worker,"TERMINAL_WORKER")
    _same(record["clock"],clock,"TERMINAL_CLOCK")
    state = _fields(record["unit_state"],{"Id","ActiveState","SubState","MainPID","ControlPID","InvocationID"})
    # Linux POLLIN, optionally POLLHUP. A closed handle, failed unit or missing PID is not an exit proof.
    _require(type(record["pidfd_events"]) is int and record["pidfd_events"] in (1,17)
             and (state["Id"],state["ActiveState"],state["SubState"],state["MainPID"],state["ControlPID"])==
             (worker["unit"],"inactive","dead","0","0")
             and state["InvocationID"] in (worker["invocation_id"],"","0"*32),"ORIGINAL_WORKER_NOT_TERMINAL")


def seal_retired_trace(*,store,receipt_directory,expected_roots,binding_digest,receipt_digest,lifetime,deadline):
    """Spend the terminal slot before asking the original lifetime for its one observation."""
    binding,receipt = custody._pin(binding_digest),custody._pin(receipt_digest)
    _require(type(lifetime) is StaticTracerLifetime and lifetime.binding_digest==binding,"ORIGINAL_LIFETIME_REQUIRED")
    with custody._roots(store,receipt_directory,deadline) as (fd,guard,roots):
        _same(roots,expected_roots,"TERMINAL_ROOTS_CHANGED")
        reader = CAS(store,read_only=True)
        subject,ctx,claim,names = _context(reader,fd,roots,binding,receipt)
        sink._absent(fd,names)
        writer = CAS(store)
        sink._mark(writer,reader,fd,receipt_directory,names[0],claim,guard)
        terminal = lifetime.terminal()
        _terminal(terminal,binding,subject["worker"],subject["clock"])
        marker = canonical_json(dict(schema="aragorn/static-task-retired-trace/v1",terminal=terminal,**ctx))
        return sink._mark(writer,reader,fd,receipt_directory,names[1],marker,guard)


def replay_after_retirement(*,store,receipt_directory,expected_roots,binding_digest,receipt_digest,terminal_digest,**expected):
    """Only external pins and a reopened private store. No source process or writer is needed."""
    binding,receipt,pin = map(custody._pin,(binding_digest,receipt_digest,terminal_digest))
    with custody._roots(store,receipt_directory,monotonic()+30) as (fd,guard,roots):
        _same(roots,expected_roots,"TERMINAL_ROOTS_CHANGED")
        reader = CAS(store,read_only=True)
        subject,ctx,claim,names = _context(reader,fd,roots,binding,receipt)
        def markers():
            claimed = custody._digest(claim)
            _require(custody._receipt(fd,names[0],claimed)==claim==reader.read(claimed,max_bytes=4096),"TERMINAL_INTENT")
            raw = custody._receipt(fd,names[1],pin)
            _require(raw==reader.read(pin,max_bytes=4096),"TERMINAL_MARKER_CHANGED")
            return raw
        raw = markers()
        marker = _document(raw)
        terminal = marker["terminal"]
        _same(marker,dict(schema="aragorn/static-task-retired-trace/v1",terminal=terminal,**ctx),"TERMINAL_LINK")
        _terminal(terminal,binding,subject["worker"],subject["clock"])
        _same([terminal["worker"],terminal["clock"]],[expected["expected_worker"],expected["expected_clock"]],
              "TERMINAL_EXPECTED_GENERATION")
        result = traces.replay_retired_task_trace(store=store,receipt_directory=receipt_directory,expected_roots=expected_roots,
                                                  binding_digest=binding,receipt_digest=receipt,**expected)
        _require(markers()==raw,"TERMINAL_MARKER_CHANGED")
        guard()
        return result | dict(retirement="RECORDED_ORIGINAL_WORKER_TERMINAL",terminal_digest=pin)
