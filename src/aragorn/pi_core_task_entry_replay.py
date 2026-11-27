"""Independent recorded entrypoint delivery for the packaged static task."""
from .oci_worker_protocol import canonical_digest
from .pi_core_node_source_observation_verify import verify_pi_node_source_observation
from .pi_core_restricted_profile import ENTRY_PATH, GATE_PATH, NODE_ARGV, NODE_SHA256
from .pi_core_source_observation_verify import _digest, _document, _fields, _identity, _pin, _require, _same, _uint


# Independently reviewed task-worker-v1/build.json and unit; not the earlier restricted bundle.
_UNIT = "aragorn-pi-task-worker.service"
_UNIT_PATH = "/usr/lib/systemd/system/"+_UNIT
_PINS = {_UNIT_PATH:"sha256:136338c6b771a8081a26fb5098a3551ae73b6537bf29971d75bec60cd2540618",
         GATE_PATH:"sha256:2a54fd7f91e1349ceecad3ac27ec6d111230c1913f4030ae91a67fa4210cab7a",
         NODE_ARGV[0]:"sha256:"+NODE_SHA256,
         ENTRY_PATH:"sha256:062508c46c4dcfa5bf5663ce3681b5347715af79e0db1c9414d5e5cf40f1afcb"}


def _original(cas, pin, schema, fields):
    raw = cas.read(_pin(pin), max_bytes=64<<10)
    _require(_digest(raw)==pin,"STATIC_REPLAY_SIDECAR_PIN")
    doc = _fields(_document(raw), {"schema",*fields.split()})
    _require(doc["schema"]==schema,"STATIC_REPLAY_SIDECAR_SCHEMA")
    return doc


def verify_task_entry_read(raw, *, binding_digest, authorization_digest, exec_digest, transition_digest, **replay_inputs):
    """Caller nominates the original CAS pins independently of the candidate trace."""
    cas = replay_inputs["evidence_cas"]
    b = _original(cas,binding_digest,"aragorn/static-task-source-binding/v1",
                  "observation claim_digest ticket_digest worker clock files gate_argv_hex node_argv_hex")
    worker,clock,files = b["worker"],b["clock"],b["files"]
    _same(worker,replay_inputs["expected_worker"],"STATIC_REPLAY_WORKER")
    _same(clock,replay_inputs["expected_clock"],"STATIC_REPLAY_CLOCK")
    argv = ("\0".join(NODE_ARGV)+"\0").encode()
    _require(b["observation"]=="STOPPED_BINDING_ONLY" and worker["unit"]==_UNIT
             and worker["cgroup"]=="/system.slice/"+_UNIT and b["node_argv_hex"]==argv.hex()
             and b["gate_argv_hex"]==(GATE_PATH.encode()+b"\0"+argv).hex(),"STATIC_REPLAY_WORKER_BINDING")
    _fields(files,set(_PINS))
    for path,pin in _PINS.items():
        item = _fields(files[path],{"digest","identity"})
        _require(item["digest"]==pin,"STATIC_REPLAY_PACKAGE_DIGEST")
        _identity(item["identity"])
    _same(files[GATE_PATH]["identity"],replay_inputs["expected_gate_identity"],"STATIC_REPLAY_GATE_IDENTITY")
    pins = replay_inputs["expected_bindings"]
    _require((pins["node_digest"],pins["gate_digest"])==(_PINS[NODE_ARGV[0]],_PINS[GATE_PATH]),"STATIC_REPLAY_CODE")

    auth = _original(cas,authorization_digest,"aragorn/static-task-gate-order/v1",
                     "binding_digest claim_digest node_argv_hex first after_publication final pre_exec")
    _require(auth["binding_digest"]==binding_digest and auth["claim_digest"]==_pin(b["claim_digest"])
             and auth["node_argv_hex"]==argv.hex(),"STATIC_REPLAY_AUTHORIZATION")
    _pin(b["ticket_digest"])
    for label,site,phase in (("first","first","stopped"),("after_publication","first","stopped"),
                             ("final","final","stopped"),("pre_exec","final","traced-gate")):
        row = auth[label]
        _same([row["worker"],row["clock"],row["gate_identity"]],[worker,clock,files[GATE_PATH]["identity"]],
              "STATIC_REPLAY_GATE_GENERATION")
        _require((row["site"],row["phase"],row["gate_digest"])==(site,phase,_PINS[GATE_PATH]),"STATIC_REPLAY_GATE_SITE")
    execution = _original(cas,exec_digest,"aragorn/static-task-node-exec/v1","authorization_digest wait node")
    _require(execution["authorization_digest"]==authorization_digest,"STATIC_REPLAY_EXEC_AUTHORIZATION")
    node = _fields(execution["node"],{"worker","clock","node_identity","node_digest","node_argv_hex","tracer_tid"})
    _same([node["worker"],node["clock"]],[worker,clock],"STATIC_REPLAY_EXEC_WORKER")
    _uint(node["tracer_tid"],1,(1<<31)-1)
    _same([node["node_identity"],node["node_digest"],node["node_argv_hex"]],
          [files[NODE_ARGV[0]]["identity"],pins["node_digest"],argv.hex()],"STATIC_REPLAY_NODE_EXECUTABLE")
    pid = worker["pid"]
    # These are the recorded Linux arm64 signal values, not the replay host's.
    _same(execution["wait"],dict(signo=17,code=4,status=1029,pid=pid,uid=worker["uid"],former_tid=pid),
          "STATIC_REPLAY_PENDING_EXEC_STOP")
    link = _original(cas,transition_digest,"aragorn/static-task-consumed-exec/v1","exec_digest stop_seq stop_digest")
    _require(link["exec_digest"]==exec_digest,"STATIC_REPLAY_EXEC_STOP_LINK")

    # Recompute syscall entry/exit pairs, actual byte intervals, thread membership and full coverage.
    # This also verifies CAS originals, instrumentation accounting and the independent observation pin.
    result = verify_pi_node_source_observation(raw,**replay_inputs)
    record = _document(raw)
    seq = _uint(link["stop_seq"],1,len(record["events"]))
    stop = record["events"][seq-1]
    _require(stop["kind"]=="STOP" and stop["event"]==4 and stop["seq"]==seq and stop["pid"]==pid
             and stop["start_ticks"]==worker["start_ticks"] and stop["event_message"]==pid
             and stop["status"]==(execution["wait"]["status"] << 8 | 127)
             and canonical_digest(stop)==link["stop_digest"],"STATIC_REPLAY_CONSUMED_EXEC_STOP")
    entries = [row for row in record["sources"] if row["path"]==ENTRY_PATH]
    _require(ENTRY_PATH in record["required_sources"] and len(entries)==1,"STATIC_REPLAY_REQUIRED_ENTRY")
    entry = entries[0]
    _same([entry["identity"],entry["digest"]],[files[ENTRY_PATH]["identity"],_PINS[ENTRY_PATH]],
          "STATIC_REPLAY_ENTRY_IDENTITY")
    return dict(schema="aragorn/static-task-entry-replay/v1",status="CONSISTENT_RECORDED_STATIC_ENTRY_DELIVERY",
                binding_digest=binding_digest,transition_digest=transition_digest,
                observation_digest=result["observation_digest"],entrypoint_digest=entry["digest"],
                entrypoint_bytes=entry["identity"]["size"],acquisition_authenticity_verified=False,
                v8_execution_verified=False,sensor_health_verified=False,effect_authorized=False,phase3_qualified=False)
