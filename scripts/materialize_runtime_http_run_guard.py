"""Pure, finite HTTP94 successors for the published refusal-only RUN client.

Inputs are bytes supplied and independently pinned by Root. Nothing is opened,
installed, imported from the project, executed, or represented as deployment here.
"""

import hashlib
import json
import re


PREFIX = "src/aragorn/"
HTTP = PREFIX + "runtime_http_broker.py"
MEASUREMENT = PREFIX + "runtime_broker_decision_measurement.py"
PLAN = PREFIX + "runtime_broker_measurement_plan.py"
VERIFY = PREFIX + "runtime_broker_decision_measurement_verify.py"
SERVICE = PREFIX + "runtime_action_service_v5.py"
CAPABILITY = PREFIX + "runtime_http_capability.py"
COLLECTION = PREFIX + "native_phase3_http_collection_verify.py"
INPUTS = {
    HTTP: (18373, "fff489d9a315d53c79bd44f6266465788e55876d2e14e363d84713857f0b9d50"),
    MEASUREMENT: (19164, "cb374ad8d1b7dc591fa554ab0590e8c39eb3ac287589ce26da67b4d5fc0e454e"),
    PLAN: (13206, "5789d265c779ad4d5674d7dabe0cd65a289274da6663369d5d17a8557fa78c30"),
    VERIFY: (21956, "0354718223c4f65d2d92908817a0ac29dc3f6e5fcc873933eee8afa65672860f"),
    SERVICE: (4146, "a3e829d2e60f26dd91cbb14967ddf2a747414ce8f125b4f207dbce7a5e1e86c7"),
    CAPABILITY: (13577, "3ec5d0b7d213a0ebaf24f06c6ef94d405ba38b187ec4d1be0d1d5e1391d5391e"),
    COLLECTION: (40268, "d19c8042dac3d84e3f9d0cd86442093755767d74a6e368346a7311a9af53e03a"),
}
REPORT = (68263, "88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9")
ACTION = (30923, "c9b8ba087dd9f302c648e7b1b68ea291ff29d7df88c54ac6eb603f4b7d1b68ad")
_HTTP_SOURCES = (
    "native_phase3_http_canary_contract.py", "runtime_http_action.py",
    "runtime_http_broker.py", "runtime_http_ingress.py", "runtime_http_capability.py",
    "runtime_action_worker.py", "runtime_action_observation_publisher.py",
    "runtime_action_observation_publisher_v2.py", "runtime_capability_grant.py",
    "runtime_action_broker_v2.py", "runtime_action_broker_v3.py",
    "runtime_native_tool_receipts.py", "runtime_worker_ingress_measurement.py",
    "runtime_action_service.py",
)
_CODES = (
    "INPUT_REFUSED", "IDENTITY_CHANGED", "CLOCK_REFUSED", "DEADLINE_EXPIRED",
    "READER_UNAVAILABLE", "READER_REFUSED", "LOSS_UNAVAILABLE",
    "CHECKPOINT_UNAVAILABLE", "RETENTION_FAILED", "CLEANUP_FAILED",
    "PROTOCOL_REFUSED", "INTERNAL_REFUSAL",
)


class HttpRunGuardRenderError(ValueError):
    """A pinned predecessor, finite anchor or supplied dependency was refused."""


def _require(condition, message):
    if not condition:
        raise HttpRunGuardRenderError(message)


def _pin(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _matches(raw, expected):
    return (type(raw) is bytes and len(raw) == expected[0]
            and hashlib.sha256(raw).hexdigest() == expected[1])


def _change(raw, before, after):
    before, after = before.encode("ascii"), after.encode("ascii")
    _require(before != after and raw.count(before) == 1 and after not in raw,
             "finite source anchor changed")
    changed = raw.replace(before, after)
    _require(changed.count(after) == 1 and changed.replace(after, before) == raw,
             "source replacement is not reversible")
    return changed


def _changes(raw, pairs):
    for before, after in pairs:
        raw = _change(raw, before, after)
    return raw


def _section(raw, start, end):
    a, b = start.encode("ascii"), end.encode("ascii")
    _require(raw.count(a) == raw.count(b) == 1, "source section changed")
    first, last = raw.index(a), raw.index(b)
    _require(first < last, "source section order changed")
    return raw[first:last + len(b)].decode("ascii")


def _predecessors(original):
    """Literal provenance only; never call or import a historical transformer."""
    out = dict(original)
    raw = out[MEASUREMENT]
    raw = _changes(raw, (
        ("class Trace:\n    pending: dict\n", "class Trace:\n    pending: dict\n    profiled_submission_raw: bytes\n"),
        ("        trace = Trace(\n", '        profiled = {**legacy, "schema": "aragorn/runtime-observed-create-submission/v2", "runtime_attribution": attribution}\n'
         "        profiled_raw = canonical_json(profiled)\n"
         '        _require(0 < len(profiled_raw) <= _LIMIT and canonical_digest(profiled) == submission_digest)\n'
         "        trace = Trace(\n"),
        ('                "runtime_attribution_digest": canonical_digest(attribution),\n            }\n        )\n',
         '                "runtime_attribution_digest": canonical_digest(attribution),\n            },\n            profiled_submission_raw=profiled_raw,\n        )\n'),
        ("            evidence = {\n", "            _require(type(trace.profiled_submission_raw) is bytes and 0 < len(trace.profiled_submission_raw) <= _LIMIT)\n"
         '            profiled = broker._parse_canonical_document(trace.profiled_submission_raw, "retained profiled submission")\n'
         '            _require(canonical_digest(profiled) == trace.pending["submission_digest"])\n'
         "            profiled_digest = put(profiled)\n"
         '            _require(profiled_digest == trace.pending["submission_digest"])\n'
         "            evidence = {\n"),
        ("            for pin in (\n", "            for pin in (\n                profiled_digest,\n"),
        ("aragorn/runtime-broker-decision-measurement/v1", "aragorn/runtime-broker-decision-measurement/v2"),
        ("aragorn/runtime-broker-decision-measurement-complete/v1", "aragorn/runtime-broker-decision-measurement-complete/v2"),
        ("EXISTING_CONSUMPTION_CHECKS_CAN_REFUSE_REPLAY_OR_MIXED_VERDICT_BLOCKS", "RECORDED_EFFECTIVE_BLOCK_DOES_NOT_PROVE_BROKER_REASON_OR_POLICY_CAUSALITY"),
    ))
    addition = "".join('    "' + name + '",\n' for name in _HTTP_SOURCES)
    raw = _changes(raw, (
        ("_SOURCES = {\n", "_SOURCES = {\n" + addition),
        ("_require(_PLAN is None and type(raw) is bytes and 0 < len(raw) <= 4096)", "_require(_PLAN is None and type(raw) is bytes and 0 < len(raw) <= 8192)"),
        ('if result.get("effect_status") == "CREATED":', 'if result.get("effect_status") in {"CREATED", "SENT"}:'),
        ('profiled = {**legacy, "schema": "aragorn/runtime-observed-create-submission/v2", "runtime_attribution": attribution}',
         'profiled = {**legacy, "schema": ("aragorn/runtime-observed-http-submission/v2" if legacy.get("schema") == "aragorn/runtime-observed-http-submission/v1" else "aragorn/runtime-observed-create-submission/v2"), "runtime_attribution": attribution}'),
    ))
    out[MEASUREMENT] = raw
    for name in (PLAN, VERIFY):
        raw = _changes(out[name], (
            ("from __future__ import annotations\n", "from __future__ import annotations\n\nfrom . import native_phase3_http_collection_verify as _http_collection\n"),
            ("_SOURCES = {\n", "_SOURCES = {\n" + addition),
        ))
        if name == PLAN:
            raw = _change(raw, '_require(len(binding_raw) <= 4096, "binding exceeds credential boundary")', '_require(len(binding_raw) <= 8192, "binding exceeds credential boundary")')
            part = _section(raw, '    _require(\n        set(descriptor) == {"schema", "root_device", "root_inode", "target_name"}\n', '        "unsupported protected action descriptor",\n    )\n')
            raw = _change(raw, part, '    if descriptor.get("schema") == "aragorn/runtime-http-endpoint/v1":\n'
                          "        _http_collection.validate_plan_descriptor(\n"
                          "            descriptor, grant, pins, attempt_id, expected_boot_id\n"
                          "        )\n    else:\n" + "".join("    " + line for line in part.splitlines(keepends=True)))
        else:
            raw = _changes(raw, (
                ("plan = _exact(_parse(raw, 4096), _BINDING_KEYS)", "plan = _exact(_parse(raw, 8192), _BINDING_KEYS)"),
                ('    claim, lease = state["claim"], state["claim"]["lease"]\n',
                 '    if profiled.get("schema") == _http_collection.PROFILED:\n'
                 "        return _http_collection.native_join(plan, pending, state, profiled, grant_raw, path)\n"
                 '    claim, lease = state["claim"], state["claim"]["lease"]\n'),
            ))
        out[name] = raw
    for name in (MEASUREMENT, PLAN, VERIFY):
        out[name] = _change(out[name], "_SOURCES = {\n", '_SOURCES = {\n    "runtime_http_readiness.py",\n')
    out[SERVICE] = _changes(out[SERVICE], (
        ("from __future__ import annotations\n", "from __future__ import annotations\n\nfrom . import runtime_broker_decision_measurement as _measurement\n"),
        ("if len(arguments) != 2:", "if len(arguments) != 3:"),
        ('"RUNTIME_BINDING_CREDENTIAL CAPABILITY_GRANT_CREDENTIAL",', '"RUNTIME_BINDING_CREDENTIAL CAPABILITY_GRANT_CREDENTIAL MEASUREMENT_CREDENTIAL",'),
        ("_run(Path(arguments[0]), Path(arguments[1]))", "_run(Path(arguments[0]), Path(arguments[1]), Path(arguments[2]))"),
        ("def _run(runtime_binding_path: Path, capability_grant_path: Path) -> None:", "def _run(runtime_binding_path: Path, capability_grant_path: Path, measurement_path: Path) -> None:"),
        ("    state = initialize_runtime_capability_grant(grant_broker)\n",
         '    measurement_path = _credential_path(measurement_path, broker_uid, credential_name="decision-measurement-binding")\n'
         '    _measurement.configure(_read_credential_bytes(measurement_path, broker_uid, label="decision measurement binding", max_bytes=8192), broker_uid)\n'
         "    state = initialize_runtime_capability_grant(grant_broker)\n"),
        ("    serve_runtime_action_broker_v5(config)\n", "    # Same MainPID, cgroup, namespaces, credentials and service restrictions.\n"
         "    # Startup must fail closed if the root-provisioned one-shot probe fails.\n"
         "    from .runtime_http_readiness import run_startup_readiness\n"
         "    run_startup_readiness()\n    serve_runtime_action_broker_v5(config)\n"),
    ))
    return out


_DETACH = '''def _run_guard_detached(value):
    if type(value) is dict:
        return {key: _run_guard_detached(item) for key, item in value.items()}
    if type(value) is list:
        return [_run_guard_detached(item) for item in value]
    if type(value) is tuple:
        return tuple(_run_guard_detached(item) for item in value)
    return value


'''

_HTTP_HELPERS = '''_RUN_OWNER = (os.getpid(), threading.main_thread().ident)
_RUN_ATTEMPTED = False
_RUN_GUARD = None
_RUN_OBSERVED = dict(opening=None, check=None, finish=None, close=None,
                     error=None, cleanup_errors=(), transport=None)
_RUN_CODES = frozenset(%CODES%)
_RUN_PRIMARY = (KeyboardInterrupt, SystemExit, MemoryError)


def _run_guard_owner():
    if (os.getpid(), threading.get_ident()) != _RUN_OWNER:
        raise broker.RuntimeActionBrokerError("HTTP guard observation owner changed")


%DETACH%def retained_http_guard_observation():
    """Supplemental process-local observations; no retention or health authority."""
    _run_guard_owner()
    return _run_guard_detached(_RUN_OBSERVED)


def _run_guard_error(error, *, cleanup=False):
    if _RUN_OBSERVED["error"] is None:
        _RUN_OBSERVED["error"] = error
    elif cleanup:
        _RUN_OBSERVED["cleanup_errors"] = (_RUN_OBSERVED["cleanup_errors"] + (error,))[:32]


def _run_guard_failure_code(error):
    code = getattr(error, "failure_code", None)
    if type(code) is not str or code not in _RUN_CODES:
        return "INTERNAL_REFUSAL"
    return code


def _run_guard_check(control_fd, lock_fd, config, request, effect, deadline):
    global _RUN_ATTEMPTED, _RUN_GUARD
    _run_guard_owner()
    if _RUN_ATTEMPTED:
        raise broker.RuntimeActionBrokerError("HTTP guard attempt already consumed")
    _RUN_ATTEMPTED = True
    try:
        _RUN_GUARD = _run_client.begin_http_guard_locked(
            control_fd, lock_fd, config, request_raw=canonical_json(request),
            effect_raw=canonical_json(effect), deadline_monotonic=deadline)
        _RUN_OBSERVED["opening"] = _RUN_GUARD.opening_result
        checked = _RUN_GUARD.before_connect()
        _RUN_OBSERVED["check"] = checked
        # The public client has authenticated and validated this exact response.
        response = json.loads(checked["response_raw"])
        codes = response["error_codes"]
        if (response["status"] != "REFUSED" or type(codes) is not list or not codes
                or any(type(code) is not str or code not in _RUN_CODES for code in codes)
                or codes != sorted(set(codes))):
            raise broker.RuntimeActionBrokerError("HTTP guard response refused")
        return ["BROKER_RUN_" + code for code in codes], codes[0]
    except BaseException as error:
        _run_guard_error(error)
        if isinstance(error, _RUN_PRIMARY):
            raise
        code = _run_guard_failure_code(error)
        return ["BROKER_RUN_" + code], code


def _run_guard_terminal(transport, failure_code):
    """Attempt both public terminal operations before the borrowed lock is released."""
    primary = None
    raw = None
    try:
        if transport is not None:
            raw = canonical_json(transport)
            if not 0 < len(raw) <= 32768:
                raise broker.RuntimeActionBrokerError("HTTP guard transport bound")
            _RUN_OBSERVED["transport"] = raw
    except BaseException as error:
        _run_guard_error(error, cleanup=True)
        primary = error
        raw = None
    if _RUN_GUARD is not None:
        try:
            _RUN_OBSERVED["finish"] = _RUN_GUARD.finish(
                transport_raw=raw, failure_code=failure_code or "TRANSPORT_REFUSED")
        except BaseException as error:
            _run_guard_error(error, cleanup=True)
            if primary is None or (isinstance(error, _RUN_PRIMARY) and not isinstance(primary, _RUN_PRIMARY)):
                primary = error
        try:
            _RUN_OBSERVED["close"] = _RUN_GUARD.close()
        except BaseException as error:
            _run_guard_error(error, cleanup=True)
            if primary is None or (isinstance(error, _RUN_PRIMARY) and not isinstance(primary, _RUN_PRIMARY)):
                primary = error
    original = _RUN_OBSERVED["error"]
    if primary is None and original is not None and (getattr(original, "cleanup_failures", ())
                                                    or getattr(original, "unresolved_owner", None) is not None):
        primary = original
    return primary


'''

_ACCESSOR = '''_GUARD_PLAN_RAW = None
_GUARD_PROCESS_RAW = None
_GUARD_OWNER = None


def current_http_guard_pending(*, expected_request_digest, expected_grant_digest):
    """Return immutable original pending bytes for this pre-final trace only."""
    _require(_GUARD_OWNER is not None
             and (os.getpid(), threading.get_ident(), threading.get_native_id()) == _GUARD_OWNER
             and threading.current_thread() is threading.main_thread())
    _digest(expected_request_digest)
    _digest(expected_grant_digest)
    trace = _CURRENT.get()
    _require(isinstance(trace, Trace) and trace.final is None
             and _GUARD_PLAN_RAW is not None and _GUARD_PROCESS_RAW is not None)
    _require(canonical_json(_PLAN) == _GUARD_PLAN_RAW
             and canonical_json(trace.pending["binding"]) == _GUARD_PLAN_RAW
             and canonical_json(_PROCESS) == _GUARD_PROCESS_RAW
             and canonical_json(trace.pending["process"]) == _GUARD_PROCESS_RAW
             and canonical_json(_identity()) == _GUARD_PROCESS_RAW
             and trace.pending["action_request_digest"] == expected_request_digest
             and trace.pending["binding"]["grant_digest"] == expected_grant_digest)
    _sources(_PLAN)
    _inputs(_PLAN)
    raw = canonical_json(trace.pending)
    _require(type(trace.guard_pending_raw) is bytes and 0 < len(raw) <= 131072
             and raw == trace.guard_pending_raw)
    return raw


'''

_SERVICE_HELPERS = '''_BOOTSTRAP_OWNER = (os.getpid(), threading.main_thread().ident)
_BOOTSTRAP_ATTEMPTED = False
_BOOTSTRAP_TRANSFER = None
_BOOTSTRAP_CONFIGURATION = None
_BOOTSTRAP_OBSERVED = dict(bootstrap_raw=None, configuration_result=None,
                          transfer_close_result=None, error=None, cleanup_errors=())


%DETACH%def retained_broker_reader_bootstrap_observation():
    """Original source-local startup observations, not external retention."""
    if (os.getpid(), threading.get_ident()) != _BOOTSTRAP_OWNER:
        raise RuntimeActionServiceError("bootstrap observation owner changed")
    return _run_guard_detached(_BOOTSTRAP_OBSERVED)


def _bootstrap_reader(capability_raw, measurement_raw):
    global _BOOTSTRAP_ATTEMPTED, _BOOTSTRAP_TRANSFER, _BOOTSTRAP_CONFIGURATION
    retained_broker_reader_bootstrap_observation()
    if _BOOTSTRAP_ATTEMPTED:
        raise RuntimeActionServiceError("bootstrap attempt already consumed")
    _BOOTSTRAP_ATTEMPTED = True
    transferred = False
    primary = None
    try:
        fixture_raw, _ = _run_http.read_service_credential("http-fixture")
        for raw, bound in ((capability_raw, 65536), (measurement_raw, 8192), (fixture_raw, 16384)):
            if type(raw) is not bytes or not 0 < len(raw) <= bound:
                raise RuntimeActionServiceError("bootstrap credential bound")
        start = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        if type(start) is not int or not 0 <= start < 2**63 - 4000000000:
            raise RuntimeActionServiceError("bootstrap clock refused")
        _BOOTSTRAP_TRANSFER = _run_bootstrap.receive_broker_reader_bootstrap(
            capability_grant_raw=capability_raw,
            expected_capability_grant_digest="sha256:" + hashlib.sha256(capability_raw).hexdigest(),
            measurement_binding_raw=measurement_raw,
            expected_measurement_binding_digest="sha256:" + hashlib.sha256(measurement_raw).hexdigest(),
            fixture_binding_raw=fixture_raw,
            expected_fixture_binding_digest="sha256:" + hashlib.sha256(fixture_raw).hexdigest(),
            startup_deadline_ns=start + 4000000000)
        configuration = _BOOTSTRAP_TRANSFER.take_configuration()
        _BOOTSTRAP_CONFIGURATION = configuration
        transferred = True
        _BOOTSTRAP_OBSERVED["bootstrap_raw"] = configuration["bootstrap_raw"]
        arguments = {key: value for key, value in configuration.items() if key != "bootstrap_raw"}
        _BOOTSTRAP_OBSERVED["configuration_result"] = _run_client.configure_broker_reader_guard(**arguments)
    except BaseException as error:
        _BOOTSTRAP_OBSERVED["error"] = error
        primary = error
    finally:
        if transferred:
            try:
                _BOOTSTRAP_OBSERVED["transfer_close_result"] = _BOOTSTRAP_TRANSFER.close()
            except BaseException as error:
                _BOOTSTRAP_OBSERVED["cleanup_errors"] = (_BOOTSTRAP_OBSERVED["cleanup_errors"] + (error,))[:32]
                if primary is None or (isinstance(error, (KeyboardInterrupt, SystemExit, MemoryError))
                                       and not isinstance(primary, (KeyboardInterrupt, SystemExit, MemoryError))):
                    primary = error
    if primary is not None:
        raise primary


'''


def _http(raw):
    helpers = _HTTP_HELPERS.replace("%CODES%", repr(_CODES)).replace("%DETACH%", _DETACH)
    raw = _changes(raw, (
        ("import math\n", "import math\nimport json\nimport threading\n\nfrom . import native_phase3_broker_reader_client as _run_client\n"),
        ("def mediate_observed_http(", helpers + "def mediate_observed_http("),
        ("    transport = None\n    try:\n", "    transport = None\n    run_started = False\n    run_failure_code = None\n    try:\n"),
        ("            nonlocal final_reasons, authorization_calls\n", "            nonlocal final_reasons, authorization_calls\n            nonlocal run_started, run_failure_code\n"),
        ("            if not finalized:\n                finalize(final_decision, final_observation, final_reasons)\n",
         "            if not final_reasons:\n"
         "                if authorization_calls != 1:\n"
         "                    raise broker.RuntimeActionBrokerError(\"HTTP refusal profile has no payload phase\")\n"
         "                _run_guard_owner()\n"
         "                if _RUN_ATTEMPTED:\n"
         "                    raise broker.RuntimeActionBrokerError(\"HTTP guard attempt already consumed\")\n"
         "                run_started = True\n"
         "                final_reasons, run_failure_code = _run_guard_check(\n"
         "                    control_fd, lock_fd, config, request, effect, deadline)\n"
         "            if not finalized:\n                finalize(final_decision, final_observation, final_reasons)\n"),
        ("            transport = http.execute_http_effect(\n", "            try:\n                transport = http.execute_http_effect(\n"),
        ("                effect,\n                fixture_binding=binding,\n                deadline_monotonic=deadline,\n                authorize_effect=authorize_effect,\n            )\n",
         "                    effect,\n                    fixture_binding=binding,\n                    deadline_monotonic=deadline,\n                    authorize_effect=authorize_effect,\n                )\n"
         "            except BaseException as transport_error:\n"
         "                transport = getattr(transport_error, \"observation\", None)\n"
         "                if transport is None:\n"
         "                    transport = getattr(transport_error, \"http_action_observation\", None)\n"
         "                saved = _RUN_OBSERVED[\"error\"] if run_started else None\n"
         "                if isinstance(saved, _RUN_PRIMARY):\n"
         "                    saved.http_action_observation = transport\n"
         "                    raise saved\n"
         "                raise\n"),
        ("            if not isinstance(error, Exception):\n                raise\n",
         "            if not isinstance(error, Exception) or isinstance(error, MemoryError):\n                raise\n"),
        ("        active_error = sys.exc_info()[1]\n        try:\n",
         "        active_error = sys.exc_info()[1]\n"
         "        terminal_error = None\n"
         "        if run_started:\n"
         "            if active_error is not None:\n"
         "                _run_guard_error(active_error)\n"
         "            if run_failure_code is None:\n"
         "                run_failure_code = (_run_guard_failure_code(_RUN_OBSERVED[\"error\"])\n"
         "                                    if _RUN_OBSERVED[\"error\"] is not None else \"TRANSPORT_REFUSED\")\n"
         "            try:\n"
         "                terminal_error = _run_guard_terminal(transport, run_failure_code)\n"
         "            except BaseException as error:\n"
         "                terminal_error = error\n"
         "            if terminal_error is not None and (active_error is None\n"
         "                    or isinstance(terminal_error, _RUN_PRIMARY) and not isinstance(active_error, _RUN_PRIMARY)):\n"
         "                active_error = terminal_error\n"
         "        try:\n"),
        ("        if cleanup is not None:\n", "        if cleanup is not None and run_started:\n            _run_guard_error(cleanup, cleanup=True)\n        if cleanup is not None:\n"),
        ("            if active_error is not None and not isinstance(active_error, Exception):\n",
         "            if active_error is not None and (not isinstance(active_error, Exception) or isinstance(active_error, MemoryError)):\n"),
        ("            if not isinstance(cleanup, Exception):\n", "            if not isinstance(cleanup, Exception) or isinstance(cleanup, MemoryError):\n"),
    ))
    # The source function is the last definition. Appending stays inside its finally.
    _require(raw.endswith(b'            ) from cleanup\n'), "HTTP terminal source boundary changed")
    raw += b'''        if terminal_error is not None:
            if active_error is not None and active_error is not terminal_error:
                raise active_error from terminal_error
            raise terminal_error
'''
    return raw


def _measurement(raw):
    raw = _changes(raw, (
        ("import time\n", "import time\nimport threading\n"),
        ("def configure(raw: bytes, expected_uid: int) -> None:\n", _ACCESSOR + "def configure(raw: bytes, expected_uid: int) -> None:\n"),
        ("    global _PLAN, _PROCESS\n", "    global _PLAN, _PROCESS, _GUARD_PLAN_RAW, _GUARD_PROCESS_RAW, _GUARD_OWNER\n"),
        ("        _PLAN, _PROCESS = plan, process\n",
         "        _require(threading.current_thread() is threading.main_thread())\n"
         "        plan_raw, process_raw = canonical_json(plan), canonical_json(process)\n"
         "        owner = (os.getpid(), threading.get_ident(), threading.get_native_id())\n"
         "        _require(owner[0] == process[\"pid\"] and owner[0] == owner[2])\n"
         "        _GUARD_PLAN_RAW, _GUARD_PROCESS_RAW, _GUARD_OWNER = plan_raw, process_raw, owner\n"
         "        _PLAN, _PROCESS = plan, process\n"),
        ("    profiled_submission_raw: bytes\n", "    profiled_submission_raw: bytes\n    guard_pending_raw: bytes = b\"\"\n"),
        ("        def retain_pending(fd: int) -> None:\n",
         "        trace.guard_pending_raw = canonical_json(trace.pending)\n"
         "        _require(0 < len(trace.guard_pending_raw) <= 131072)\n\n"
         "        def retain_pending(fd: int) -> None:\n"),
    ))
    return raw


def _service(raw):
    return _changes(raw, (
        ("from . import runtime_broker_decision_measurement as _measurement\n",
         "from . import runtime_broker_decision_measurement as _measurement\n"
         "from . import native_phase3_broker_reader_client as _run_client\n"
         "from . import native_phase3_broker_reader_bootstrap as _run_bootstrap\n"
         "from . import runtime_http_action as _run_http\nimport hashlib\nimport os\nimport threading\nimport time\n"),
        ("def main(argv: Sequence[str] | None = None) -> int:\n",
         _SERVICE_HELPERS.replace("%DETACH%", _DETACH) + "def main(argv: Sequence[str] | None = None) -> int:\n"),
        ('    _measurement.configure(_read_credential_bytes(measurement_path, broker_uid, label="decision measurement binding", max_bytes=8192), broker_uid)\n',
         '    measurement_raw = _read_credential_bytes(measurement_path, broker_uid, label="decision measurement binding", max_bytes=8192)\n'
         "    _measurement.configure(measurement_raw, broker_uid)\n"),
        ("    # Same MainPID, cgroup, namespaces, credentials and service restrictions.\n",
         "    _bootstrap_reader(capability_grant, measurement_raw)\n"
         "    # Same MainPID, cgroup, namespaces, credentials and service restrictions.\n"),
    ))


def _compatibility(raw, independent):
    reasons = repr(tuple("BROKER_RUN_" + code for code in _CODES))
    if not independent:
        anchor = '    if decision["verdict"] == "BLOCK" and reasons == decision["reason_codes"]:\n'
        check = ('    if (decision["verdict"] == "ALLOW" and decision["reason_codes"] == []\n'
                 '            and result["effect_status"] == "NOT_PERFORMED"\n'
                 '            and result["payload_decision"] is None\n'
                 '            and reasons == sorted(set(reasons))\n'
                 '            and set(reasons) <= frozenset(' + reasons + ')):\n'
                 '        return True\n')
        return _change(raw, anchor, check + anchor)
    anchor = '                decision["verdict"] == "BLOCK"\n'
    check = ('                (decision["verdict"] == "ALLOW" and decision["reason_codes"] == []\n'
             '                 and result["effect_status"] == "NOT_PERFORMED"\n'
             '                 and reasons == sorted(set(reasons))\n'
             '                 and set(reasons) <= frozenset(' + reasons + '))\n'
             '                or decision["verdict"] == "BLOCK"\n')
    return _change(raw, anchor, check)


def render(original, *, predecessor_report_raw, dependency_sources, expected_dependency_pins):
    """Return exactly seven finite successors; the supplied closure is Root-reviewed."""
    _require(type(original) is dict and set(original) == set(INPUTS), "seven source keys required")
    _require(_matches(predecessor_report_raw, REPORT), "actual HTTP94 report pin changed")
    report = json.loads(predecessor_report_raw)
    sources = {row["name"]: row for row in report["source_inputs"]}
    files = {row["source_name"]: row for row in report["files"]}
    for name, expected in INPUTS.items():
        _require(_matches(original[name], expected), "original source pin changed")
        _require(sources[name]["bytes"] == expected[0]
                 and sources[name]["digest"] == "sha256:" + expected[1], "report original join changed")
    _require(type(dependency_sources) is dict and type(expected_dependency_pins) is dict
             and 1 <= len(dependency_sources) <= 128
             and set(dependency_sources) == set(expected_dependency_pins), "dependency pin keys differ")
    names = {name.removeprefix(PREFIX) for name in INPUTS}
    _require(not names.intersection(dependency_sources), "generated output supplied as dependency")
    total = 0
    for name, raw in dependency_sources.items():
        _require(type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}\.py", name), "invalid source basename")
        _require(type(raw) is bytes and 0 < len(raw) <= 16777216, "dependency byte bound")
        total += len(raw)
        _require(total <= 67108864, "dependency total bound")
        pin = expected_dependency_pins[name]
        _require(type(pin) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", pin)
                 and _pin(raw) == pin, "dependency source pin changed")
    _require({"native_phase3_broker_reader_client.py", "native_phase3_broker_reader_bootstrap.py",
              "runtime_http_action.py", "__init__.py"} <= set(dependency_sources), "required dependencies absent")
    _require(_matches(dependency_sources["runtime_http_action.py"], ACTION), "actual repaired HTTP action required")
    action_row = files[PREFIX + "runtime_http_action.py"]
    _require(action_row["bytes"] == ACTION[0] and action_row["digest"] == "sha256:" + ACTION[1], "action report join changed")
    out = _predecessors(original)
    for name, raw in out.items():
        row = files[name]
        _require(row["path"] == "/usr/lib/aragorn/aragorn/" + name.removeprefix(PREFIX)
                 and row["bytes"] == len(raw) and row["digest"] == _pin(raw), "generated predecessor differs from actual report")
    out[HTTP] = _http(out[HTTP])
    out[MEASUREMENT] = _measurement(out[MEASUREMENT])
    out[SERVICE] = _service(out[SERVICE])
    out[CAPABILITY] = _compatibility(out[CAPABILITY], False)
    out[COLLECTION] = _compatibility(out[COLLECTION], True)
    inventory = sorted(names | set(dependency_sources))
    _require(len(inventory) <= 128, "finite source inventory bound")
    replacement = "_SOURCES = {\n" + "".join('    "' + name + '",\n' for name in inventory) + "}"
    for name in (MEASUREMENT, PLAN, VERIFY):
        sections = re.findall(rb"(?m)^_SOURCES = \{\n[^}]*\n\}", out[name])
        _require(len(sections) == 1, "measurement inventory section changed")
        old = sections[0].decode("ascii")
        out[name] = _change(out[name], old, replacement)
    return out
