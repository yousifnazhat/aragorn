"""Private local retention and independent readback of fixed-worker trace originals."""
from copy import deepcopy
from time import monotonic

from . import pi_core_mask_custody as private, pi_core_pilot_output_custody as publication
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_source_observation_verify import _document
from .pi_core_state_admission import _keys, _need, _pin, _same
from .pi_core_task_entry_replay import verify_task_entry_read


_PARTS = ("binding","authorization","exec","transition")
_MANIFEST_PINS = tuple(k+"_digest" for k in _PARTS) + ("expected_observation_digest",)
_DOCS = dict(expected_profile_raw="profile_digest",source_inventory_raw="source_inventory_digest",
             loader_inventory_raw="loader_inventory_digest")
_EXPECTED = ("expected_bindings","expected_worker","expected_clock","expected_gate_identity","expected_root_peer",
             "expected_root_endpoints","expected_challenge","boundary_boottime_ns")
_LIMIT = 4 << 20


def _names(binding_digest):
    base = "task-trace-" + _pin(binding_digest)[7:]
    return base+"-publishing.json",base+"-receipt.json"


def _receipt_pair(reader, fd, binding_digest, receipt_digest):
    """Verify named receipt and publication against both the external pin and the private CAS."""
    pub_name,done_name = _names(binding_digest)
    def read(name,pin):
        raw = private._receipt(fd,name,_pin(pin))
        _need(raw==reader.read(pin,max_bytes=4096),"private trace marker differs from CAS")
        return _document(raw)
    done = read(done_name,receipt_digest)
    _keys(done,("schema","publishing_digest","binding_digest"))
    _need(done["schema"]=="aragorn/static-task-trace-receipt/v1" and done["binding_digest"]==binding_digest,
          "wrong private trace receipt")
    publication = read(pub_name,done["publishing_digest"])
    _keys(publication,("schema","expected_context_digest","pins","roots"))
    pins = publication["pins"]
    _keys(pins,_MANIFEST_PINS)
    _need(publication["schema"]=="aragorn/static-task-trace-publication/v1"
          and pins["binding_digest"]==binding_digest,"wrong private trace publication")
    for pin in (*pins.values(),publication["expected_context_digest"]): _pin(pin)
    return publication


def _replay(reader, pins, expected):
    _keys(expected,_EXPECTED)
    bindings = expected["expected_bindings"]
    docs = {key:reader.read(_pin(bindings[field]),max_bytes=_LIMIT) for key,field in _DOCS.items()}
    raw = reader.read(pins["expected_observation_digest"],max_bytes=_LIMIT)
    return verify_task_entry_read(raw,**pins,**expected,**docs,evidence_cas=reader)


def retain_task_trace(*, store, receipt_directory, expected_roots, records, observation_raw, deadline,
                      guard, replay_inputs):
    """Publish once in an existing nominated private CAS. Failed evidence and spent slots stay put."""
    _keys(records,_PARTS)
    _keys(replay_inputs,(*_EXPECTED,*_DOCS))
    expected = deepcopy({key:replay_inputs[key] for key in _EXPECTED})
    docs = {key:replay_inputs[key] for key in _DOCS}
    records = records.copy()
    _need(callable(guard) and all(type(b) is bytes and 0<len(b)<=64<<10 for b in records.values())
          and all(type(b) is bytes and 0<len(b)<=_LIMIT for b in (observation_raw,*docs.values())),
          "bounded original trace bytes and custody required")
    pins = {k+"_digest":private._digest(raw) for k,raw in records.items()}
    pins["expected_observation_digest"] = private._digest(observation_raw)
    for key,field in _DOCS.items():
        _need(private._digest(docs[key])==_pin(expected["expected_bindings"][field]),"different trace input original")
    name,done_name = _names(pins["binding_digest"])
    guard()
    with private._roots(store,receipt_directory,deadline) as (fd,path_guard,roots):
        _same(roots,expected_roots,"nominated private trace roots changed")
        def checked():
            path_guard()
            guard()
        reader = CAS(store,read_only=True)  # Refuse missing or uninitialized roots.
        writer = CAS(store)
        checked()
        publication._absent(fd,(name,done_name))
        claim = canonical_json(dict(schema="aragorn/static-task-trace-publication/v1",pins=pins,
                                    expected_context_digest=canonical_digest(expected),roots=roots))
        start = publication._mark(writer,reader,fd,receipt_directory,name,claim,checked)
        for raw in (*records.values(),observation_raw,*docs.values()):
            publication._store(writer,reader,raw,checked)
        _replay(reader,pins,expected)
        checked()
        done = canonical_json(dict(schema="aragorn/static-task-trace-receipt/v1",
                                   publishing_digest=start,binding_digest=pins["binding_digest"]))
        return publication._mark(writer,reader,fd,receipt_directory,done_name,done,checked)


def replay_retired_task_trace(*, store, receipt_directory, expected_roots, binding_digest, receipt_digest, **expected):
    """Fresh read-only verification. This storage receipt is not proof of process retirement."""
    _keys(expected,_EXPECTED)
    expected = deepcopy(expected)
    with private._roots(store,receipt_directory,monotonic()+30) as (fd,guard,roots):
        _same(roots,expected_roots,"nominated private trace roots changed")
        reader = CAS(store,read_only=True)
        publication = _receipt_pair(reader,fd,binding_digest,receipt_digest)
        _same(publication["roots"],roots,"retained trace destination differs")
        _need(publication["expected_context_digest"]==canonical_digest(expected),"different trace replay context")
        result = _replay(reader,publication["pins"],expected)
        guard()
        _receipt_pair(reader,fd,binding_digest,receipt_digest)
        return result
