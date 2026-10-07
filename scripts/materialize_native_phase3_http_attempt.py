"""Finite HTTP94 guest successor of the retained common attempt lifecycle.

The old controller supplies custody, partial retention and four-service cleanup.
Only its fixed writer, workload and verification seams change; rendering neither
activates a fixture nor runs a capture.
"""

from __future__ import annotations

import hashlib

SOURCE = "scripts/runtime_native_common_attempt.py"
SNAPSHOT = "scripts/runtime_native_measurement_evidence_snapshot.py"
INPUTS = {
    SOURCE: (41842, "434588e3aaf00e93488e3ddb793b5ed29acf681c1a66cd227882ebb357a5b613"),
    SNAPSHOT: (
        37832,
        "1980a44c5d7e58f8b92bd53ba56c42358cedd3fb64fc51b3f8b39cef5c3eb204",
    ),
}
READY_WRITER_PIN = (
    57857,
    "168222f4a96684dd5f248a88d22693935b1d77178fe1216616bdf1454898a380",
)


class NativeHttpAttemptRenderError(ValueError):
    """An exact predecessor or finite seam changed."""


def _change(raw, before, after, count=1):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != count or after in raw:
        raise NativeHttpAttemptRenderError("HTTP guest anchor changed")
    changed = raw.replace(before, after)
    if changed.replace(after, before) != raw:
        raise NativeHttpAttemptRenderError("HTTP guest reversal changed")
    return changed


def _section(raw, start, end, replacement):
    start, end = start.encode("ascii"), end.encode("ascii")
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise NativeHttpAttemptRenderError("HTTP guest section changed")
    old = raw[raw.index(start) : raw.index(end)]
    return _change(raw, old.decode("ascii"), replacement)


def render_writer(ready_writer_raw):
    """Keep stopped prerequisites, but check custody after the actual activation."""
    if (
        type(ready_writer_raw) is not bytes
        or (len(ready_writer_raw), hashlib.sha256(ready_writer_raw).hexdigest())
        != READY_WRITER_PIN
    ):
        raise NativeHttpAttemptRenderError("HTTP activation writer predecessor changed")
    raw = _change(
        ready_writer_raw,
        "            def guard():\n",
        "            def guard(*, require_stopped=True):\n",
    )
    raw = _change(
        raw,
        "                _http_provision._stopped()\n\n            def gateway_reader(path):",
        "                if require_stopped:\n                    _http_provision._stopped()\n\n            def gateway_reader(path):",
    )
    return _change(
        raw,
        "                _http_writer_cleanup(sys.exception(), guard)\n",
        "                _http_writer_cleanup(sys.exception(), lambda: guard(require_stopped=False))\n",
    )


_DESCRIPTOR = '''@contextmanager
def _protected_descriptor(native, inputs):
    """Hold the actual credential-bound endpoint, not a create-file surrogate."""
    raw = inputs[str(setup.http.BINDING_PATH)]
    binding = http_verify.fixture_binding(json.loads(raw))
    _require(canonical_json(binding) == raw, "HTTP_FIXTURE_NONCANONICAL")
    with owned_http_fixture(binding["fixture"]) as held:
        def guard():
            held.guard()
            _require(setup._writer_readback(native, inputs), "HTTP_WRITER_READBACK_REFUSED")
        guard()
        try:
            yield canonical_json(http_verify.endpoint_descriptor(binding)), guard
        finally:
            setup._close_preserving(guard, "HTTP_ENDPOINT_FINAL_CUSTODY_REFUSED")


'''

_VERIFY = '''def _verify(work, measured, clocks, expected, broker, accounts, request,
            binding_raw, sources, reader, fixture_raw, sink_identity, readiness_nonce):
    records = measured["records"]
    work_records = work["records"]
    verified = http_verify.verify_native_http_collection(
        completion_raw=_raw(records["completion"]),
        expected_completion_digest=records["completion"]["digest"],
        expected_binding_raw=binding_raw,
        expected_binding_digest=request["measurement_binding_digest"],
        expected_broker=broker, input_cas=reader, evidence_cas=reader,
        ingress_raws={name: _raw(records[name]) for name in ("startup", "ingress", "attempt", "action")},
        expected_ingress_digests={name: records[name]["digest"] for name in ("startup", "ingress", "attempt", "action")},
        expected_worker=expected["worker"],
        expected_worker_binding_digest=request["expected_file_digests"][identity.prior._WORKER],
        expected_genesis_digest=request["expected_file_digests"][identity.prior._GENESIS],
        fixture_binding_raw=fixture_raw,
        expected_fixture_binding_digest=workload._digest(fixture_raw),
        clock_before_raw=clocks["before"], clock_after_raw=clocks["after"],
        expected_clock_before_digest=workload._digest(clocks["before"]),
        expected_clock_after_digest=workload._digest(clocks["after"]),
        sink_raw=_raw(work_records["sink"]), expected_sink_digest=work_records["sink"]["digest"],
        expected_sink_identity=sink_identity, expected_readiness_nonce=readiness_nonce,
        driver_raw=_raw(work_records["driver"]), expected_driver_record_digest=work_records["driver"]["digest"],
        terminal_raw=_raw(work_records["terminal"]), expected_terminal_digest=work_records["terminal"]["digest"],
    )
    _require(verified["ingress"]["gateway_peer"] == {
        key: expected["gateway"][key] for key in ("pid", "uid", "gid")},
        "HTTP_GATEWAY_PROCESS_JOIN_CHANGED")
    return {"http_collection": verified}


def _http_records(report, native, genesis):
    """Only fixed public HTTP evidence leaves the collector's private root."""
    records = {}
    def record(name, value):
        raw = canonical_json(value)
        _require(0 < len(raw) <= 192 * 1024, "HTTP_WORKLOAD_RECORD_BOUND_CHANGED")
        records[name] = {"text": raw.decode("ascii"), "bytes": len(raw), "digest": workload._digest(raw)}
    if report.get("sink") is not None:
        record("sink", report["sink"])
    if report.get("driver") is not None:
        driver = report["driver"]
        record("driver", driver["document"])
        _require(driver["digest"] == records["driver"]["digest"]
                 and driver["bytes"] == records["driver"]["bytes"], "HTTP_DRIVER_RECORD_CHANGED")
    report["records"] = records
    terminal = native._snapshot(genesis, 2)["receipts"][1]
    record("terminal", terminal)
    return report


'''

_SETUP = """        phase = "NINE_WRITER_HTTP_SETUP"
        prepare_native = native._prepare
        def record_http_intent(raw):
            _require(not http_inputs and type(raw) is bytes, "HTTP_WRITER_INTENT_NOT_ONCE")
            binding = http_verify.fixture_binding(json.loads(raw))
            _require(binding["fixture"] == expected_http_fixture and canonical_json(binding) == raw,
                     "HTTP_WRITER_FIXTURE_CHANGED")
            http_held.guard()
            http_inputs[str(setup.http.BINDING_PATH)] = raw
        def record_readiness_intent(raw):
            _require(set(http_inputs) == {str(setup.http.BINDING_PATH)} and type(raw) is bytes,
                     "READINESS_WRITER_INTENT_NOT_ONCE")
            binding = http_verify.fixture_binding(json.loads(http_inputs[str(setup.http.BINDING_PATH)]))
            expected_ready = setup.readiness.build_readiness_input(
                fixture_binding=binding, readiness_nonce=common["readiness_nonce"])
            _require(canonical_json(expected_ready) == raw, "READINESS_WRITER_INTENT_CHANGED")
            http_held.guard()
            http_inputs[str(setup.readiness.CREDENTIAL)] = raw
        def prepare_http():
            return prepare_native(expected_http_fixture=expected_http_fixture,
                http_attempt_id=common["http_attempt_id"], http_binding_writer=record_http_intent,
                readiness_nonce=common["readiness_nonce"], readiness_binding_writer=record_readiness_intent)
        with patch.object(native, "_prepare", prepare_http):
            setup.predecessor._prepare(native, before_activation, state=result["setup_state"])
"""

_WORK = """                    work = http_collection.collect_native_http_attempt(
                        request=built["scheduled_request"], expected_fixture=expected_http_fixture,
                        readiness_nonce=common["readiness_nonce"],
                        expected_driver_digest=expected_driver_digest,
                        expected_node_digest=pins["/usr/local/bin/node"],
                    )
                except BaseException as error:
                    work = getattr(error, "http_native_collection", None)
                    raise
"""

_SNAPSHOT_HELPERS = """def _http_ingress(body, plan):
    _exact(body, {"worker_request", "worker_request_digest", "gateway_peer"})
    peer = _exact(body["gateway_peer"], {"pid", "uid", "gid"})
    _require(all(type(value) is int and 0 < value < 2**31 for value in peer.values()),
             "PUBLIC_HTTP_GATEWAY_PEER_CHANGED")
    request = http_action.validate_worker_request(body["worker_request"])
    _require(request["attempt_id"] == plan["attempt_id"]
             and canonical_digest(request) == body["worker_request_digest"]
             and canary.digest(canary.canary_request(request["attempt_id"])) == plan["payload_digest"],
             "PUBLIC_HTTP_INGRESS_CHANGED")
    return request


def _http_attempt(body, request, genesis):
    _exact(body, {"attempt", "attempt_digest", "receipt_state", "receipt_state_digest", "genesis_digest", "worker_request_digest"})
    receipt = _exact(body["attempt"], {"schema", "authority", "genesis_digest", "sequence", "previous_digest", "event"})
    state = _exact(body["receipt_state"], {"schema", "authority", "genesis_digest", "receipts"})
    native_receipts._event(receipt["event"], terminal=False)
    rows = state["receipts"]
    _require(receipt["schema"] == "aragorn/native-tool-receipt/v1"
        and state["schema"] == "aragorn/native-tool-receipt-state/v1"
        and receipt["authority"] == state["authority"] == worker._RECEIPT_AUTHORITY
        and receipt["genesis_digest"] == state["genesis_digest"] == body["genesis_digest"] == genesis
        and canonical_digest(receipt) == body["attempt_digest"]
        and canonical_digest(state) == body["receipt_state_digest"]
        and canonical_digest(request) == body["worker_request_digest"]
        and type(rows) is list and 1 <= len(rows) <= 1024 and len(rows) % 2 == 1
        and all(protected._pin(pin) for pin in rows) and len(set(rows)) == len(rows)
        and rows[-1] == body["attempt_digest"]
        and type(receipt["sequence"]) is int and receipt["sequence"] == len(rows)
        and receipt["previous_digest"] == (genesis if len(rows) == 1 else rows[-2]),
        "PUBLIC_HTTP_ATTEMPT_CHANGED")
    event = receipt["event"]
    _require(event["tool_name"] == http_verify.TOOL
        and event["worker_request_digest"] == canonical_digest(request)
        and all(event[key] == request[key] for key in ("session_id", "run_id", "tool_call_digest")),
        "PUBLIC_HTTP_ATTEMPT_CORRELATION_CHANGED")


"""


def _snapshot(raw):
    raw = _change(
        raw,
        "from aragorn.oci_worker_protocol import canonical_digest, canonical_json\n",
        "from aragorn.oci_worker_protocol import canonical_digest, canonical_json\n"
        "from aragorn import native_phase3_http_collection_verify as http_verify\n"
        "from aragorn import native_phase3_http_canary_contract as canary\n"
        "from aragorn import runtime_http_action as http_action\n"
        "from aragorn import runtime_http_broker as http_broker\n"
        "from aragorn import runtime_http_capability as http_capability\n"
        "from aragorn import runtime_native_tool_receipts as native_receipts\n",
    )
    raw = _change(
        raw,
        'SCHEMA = "aragorn/native-measurement-evidence-snapshot/v1"',
        'SCHEMA = "aragorn/native-http-measurement-evidence-snapshot/v1"',
    )
    raw = _change(
        raw,
        '    namespace,\n):\n    records = report["records"]\n',
        '    namespace,\n    fixture_binding,\n):\n    records = report["records"]\n',
    )
    start = "    verified = worker.verify_worker_ingress_records(\n"
    end = '    startup = _parse(_raw(records["startup"]), worker.MAX_RECORD_BYTES)\n'
    raw = _section(
        raw,
        start,
        end,
        "    verified = http_verify.verify_http_worker_ingress(\n"
        "        {name: _raw(records[name]) for name in worker.STAGES},\n"
        '        expected_record_digests=report["record_digests"], expected_worker=expected_worker,\n'
        "        expected_binding_digest=worker_binding, expected_genesis_digest=genesis,\n"
        '        expected_fixture_binding=fixture_binding, expected_attempt_id=plan["attempt_id"])\n',
    )
    raw = _change(
        raw,
        'verified["worker_request_digest"] == request_pin',
        'canonical_digest(verified["worker_request"]) == request_pin',
    )
    raw = _change(
        raw,
        'and verified["action_request_digest"]\n',
        'and canonical_digest(verified["action_request"])\n',
    )
    raw = _change(
        raw,
        "def _classify_public(name, raw, report, plan, epoch, broker, binding, genesis):\n",
        _SNAPSHOT_HELPERS
        + "def _classify_public(name, raw, report, plan, epoch, broker, binding, genesis):\n",
    )
    raw = _section(
        raw,
        "    def result(item):\n",
        "    if name in worker.STAGES:\n        value = worker._parse",
        "    def result(item):\n"
        '        state_pin = report["broker_blob_digests"]["consumed_grant_state"]\n'
        '        state = effective.v4._state(_parse(_raw(report["broker_blobs"][state_pin])), plan["grant_digest"])\n'
        '        http_capability.validate_broker_result(item, state["claim"]["profile_claim"])\n\n',
    )
    raw = _change(
        raw,
        """            _, payload = worker._ingress(body)
            _require(
                protected._digest(payload) == plan["payload_digest"],
                "PUBLIC_INGRESS_PAYLOAD_CHANGED",
            )""",
        "            _http_ingress(body, plan)",
    )
    start = '        elif name == "attempt":\n'
    end = "        else:\n            _exact(\n                body,\n"
    raw = _section(
        raw,
        start,
        end,
        '        elif name == "attempt":\n'
        '            ingress = _parse(_raw(report["records"]["ingress"]), worker.MAX_RECORD_BYTES)\n'
        '            _http_attempt(body, _http_ingress(ingress["body"], plan), genesis)\n',
    )
    raw = _change(
        raw,
        '        legacy["schema"] = "aragorn/runtime-observed-create-submission/v1"\n'
        "        core._observed_submission(legacy)\n"
        '        action, _, payload = core._request_effect(submission["envelope"])\n',
        '        legacy["schema"] = http_broker.SUBMISSION_SCHEMA\n'
        "        http_broker.observed_submission(legacy)\n"
        '        action, effect = http_broker.request_effect(submission["envelope"])\n'
        '        _require(effect["attempt_id"] == plan["attempt_id"], "PUBLIC_HTTP_EFFECT_CHANGED")\n'
        '        payload = canary.canary_request(effect["attempt_id"])\n',
    )
    raw = _change(
        raw,
        "    expected_worker_helper_digest,\n):\n",
        "    expected_worker_helper_digest,\n    expected_http_fixture_binding_raw,\n):\n",
    )
    raw = _change(
        raw,
        '        broker = effective.prior._process(expected_broker_process, plan["boot_id"])\n',
        '        broker = effective.prior._process(expected_broker_process, plan["boot_id"])\n'
        "        fixture_binding = http_verify.fixture_binding(_parse(expected_http_fixture_binding_raw, 4096))\n"
        "        _require(canonical_json(fixture_binding) == expected_http_fixture_binding_raw\n"
        '            and fixture_binding["fixture"]["container_id"] == expected_container_id\n'
        '            and fixture_binding["fixture"]["boot_id"] == plan["boot_id"]\n'
        '            and fixture_binding["expected_broker_uid"] == broker["uid"]\n'
        '            and fixture_binding["expected_broker_gid"] == broker["gid"]\n'
        '            and all(plan[key] == pin for key, pin in http_verify.action_digests(plan["attempt_id"], fixture_binding).items()),\n'
        '            "HTTP_SNAPSHOT_FIXTURE_ACTION_CHANGED")\n',
    )
    raw = _change(
        raw,
        "                    namespace,\n                ),\n",
        "                    namespace,\n                    fixture_binding,\n                ),\n",
    )
    return raw


def render(original):
    """Produce one exact installed guest source, with no side effects."""
    if type(original) is not dict or not set(INPUTS) <= set(original):
        raise NativeHttpAttemptRenderError("HTTP guest source inventory changed")
    for name, pin in INPUTS.items():
        value = original[name]
        if (
            type(value) is not bytes
            or (len(value), hashlib.sha256(value).hexdigest()) != pin
        ):
            raise NativeHttpAttemptRenderError("HTTP guest predecessor pin changed")
    raw = original[SOURCE]
    raw = _change(
        raw,
        "from aragorn.oci_worker_protocol import canonical_json\n",
        "from aragorn.oci_worker_protocol import canonical_json\n"
        "from aragorn import native_phase3_http_collection as http_collection\n"
        "from aragorn import native_phase3_http_collection_verify as http_verify\n"
        "from aragorn import native_phase3_http_canary_contract as canary\n"
        "from aragorn import native_phase3_http_broker_ready_capture as broker_ready\n"
        "from aragorn.native_phase3_http_fixture import owned_http_fixture\n",
    )
    raw = _change(
        raw,
        'SCHEMA = "aragorn/native-common-attempt/v1"',
        'SCHEMA = "aragorn/native-http-attempt/v1"',
    )
    raw = _change(
        raw,
        '_PAYLOAD = b"Aragorn P3.7b distinct worker create\\n"\n',
        "# Payload bytes come from the exact selected finite HTTP canary.\n",
    )
    raw = _change(
        raw,
        '    "baseline_capture_raw",\n}\n_PLAN_ARGUMENTS',
        '    "baseline_capture_raw",\n    "http_attempt_id",\n    "readiness_nonce",\n}\n_PLAN_ARGUMENTS',
    )
    raw = _change(
        raw,
        '    "/usr/lib/aragorn/aragorn/native_phase3_ingress_interval_verify.py",\n)',
        '    "/usr/lib/aragorn/aragorn/native_phase3_ingress_interval_verify.py",\n'
        '    "/usr/lib/aragorn/aragorn/native_phase3_http_collection.py",\n'
        '    "/usr/lib/aragorn/aragorn/native_phase3_http_collection_verify.py",\n'
        '    "/usr/lib/aragorn/aragorn/native_phase3_http_broker_ready_capture.py",\n'
        '    "/usr/lib/aragorn/aragorn/native_phase3_http_readiness_verify.py",\n'
        '    "/usr/lib/aragorn/aragorn/native_phase3_http_fixture.py",\n'
        '    "/usr/lib/aragorn/aragorn/native_phase3_http_sink.py",\n'
        "    http_collection.DRIVER_PATH,\n)",
    )
    raw = _change(
        raw,
        "        _, metadata = workload._read_fixed(path, 0o444, 2 * 1024 * 1024)\n",
        "        mode = 0o644 if path in {\n"
        '            "/usr/lib/aragorn/aragorn/native_phase3_http_collection.py",\n'
        '            "/usr/lib/aragorn/aragorn/native_phase3_http_collection_verify.py",\n'
        '            "/usr/lib/aragorn/aragorn/native_phase3_http_fixture.py",\n'
        '            "/usr/lib/aragorn/aragorn/native_phase3_http_sink.py",\n'
        "        } else 0o444\n"
        "        _, metadata = workload._read_fixed(path, mode, 2 * 1024 * 1024)\n",
    )
    raw = _change(
        raw,
        "    # In particular the fixed old bootstrap is checked before package._native.\n"
        "    records.update(\n"
        "        workload._sources(\n"
        "            pins[workload.SOURCE_PATH],\n"
        "            pins[workload.SINK_SOURCE_PATH],\n"
        "            pins[workload.REVOCATION_SOURCE_PATH],\n"
        "        )\n"
        "    )\n",
        "    # Keep the frozen bootstrap checks, not its superseded workload pins.\n"
        "    _require(os.path.abspath(workload.__file__) == workload.SOURCE_PATH,\n"
        '             "INSTALLED_WORKLOAD_PATH_CHANGED")\n'
        '    replaced_identity = "/usr/lib/aragorn/aragorn/native_phase3_common_identity.py"\n'
        '    replaced_driver = "/opt/aragorn/native-blocked-create-driver-v1.mjs"\n'
        "    _require(workload.DRIVER_PATH == replaced_driver\n"
        '        and http_collection.DRIVER_PATH == "/opt/aragorn/native-http-attempt-driver-v1.mjs"\n'
        "        and {replaced_identity, http_collection.DRIVER_PATH} <= set(records),\n"
        '        "HTTP_SOURCE_REPLACEMENT_INVENTORY_CHANGED")\n'
        "    fixed = {\n"
        "        **workload._FIXED_SOURCES,\n"
        "        workload.SOURCE_PATH: (None, workload._pin(pins[workload.SOURCE_PATH]), 0o444),\n"
        "        workload.SINK_SOURCE_PATH: (None, workload._pin(pins[workload.SINK_SOURCE_PATH]), 0o444),\n"
        "        workload.REVOCATION_SOURCE_PATH: (None, workload._pin(pins[workload.REVOCATION_SOURCE_PATH]), 0o444),\n"
        "    }\n"
        "    for path, (size, pin, mode) in fixed.items():\n"
        "        if path in {replaced_identity, replaced_driver}:\n"
        "            continue\n"
        "        raw, metadata = workload._read_fixed(path, mode, 1024 * 1024)\n"
        "        _require(metadata[\"digest\"] == pin and (size is None or len(raw) == size),\n"
        '                 "FIXED_SOURCE_PIN_CHANGED")\n'
        "        records[path] = metadata\n",
    )
    raw = _section(
        raw,
        "@contextmanager\ndef _protected_descriptor(native):\n",
        "def _raw(record):\n",
        _DESCRIPTOR,
    )
    raw = _section(raw, "def _verify(\n", "def run_native_common_attempt(\n", _VERIFY)
    raw = _change(
        raw,
        "    *, common_arguments, plan_arguments, expected_setup_digest, expected_source_digests\n",
        "    *, common_arguments, plan_arguments, expected_setup_digest, expected_source_digests,\n"
        "    expected_http_fixture, expected_driver_digest\n",
    )
    raw = _change(
        raw,
        '        "process_verification": None,\n',
        '        "process_verification": None,\n        "broker_readiness": None,\n',
    )
    raw = _change(
        raw,
        '    phase, cleanup_required, captured_inputs = "INPUTS", False, {}\n',
        '    phase, cleanup_required, captured_inputs = "INPUTS", False, {}\n'
        "    http_inputs, ready_stack, ready, ready_report = {}, ExitStack(), None, None\n"
        "    http_held, sink_identity = None, None\n",
    )
    raw = _change(
        raw,
        '        container = common["container_id"]\n',
        '        container = common["container_id"]\n'
        "        canary.validate_fixture(expected_http_fixture)\n"
        '        canary.canary_bytes(common["http_attempt_id"])\n'
        '        canary.readiness_request(common["readiness_nonce"])\n'
        '        _require(expected_http_fixture["container_id"] == container\n'
        '                 and common["http_attempt_id"] == plan["selected_attempt_id"]\n'
        "                 and sources[http_collection.DRIVER_PATH] == expected_driver_digest,\n"
        '                 "HTTP_ATTEMPT_FIXTURE_OR_SOURCE_JOIN_CHANGED")\n',
    )
    raw = _change(
        raw,
        '        result["sources_before"] = _source_guard(sources)\n',
        '        result["sources_before"] = _source_guard(sources)\n'
        "        http_held = stack.enter_context(owned_http_fixture(expected_http_fixture))\n"
        "        sink_identity = http_held.identity\n",
    )
    raw = _change(
        raw,
        "            workload._absent(run, Path(workload.ATTEMPT_ROOT).name)\n",
        "            workload._absent(run, Path(http_collection.ATTEMPT_ROOT).name)\n",
    )
    raw = _change(
        raw,
        "            nonlocal phase, session, built, descriptor, request\n",
        "            nonlocal phase, session, built, descriptor, request, ready\n",
    )
    raw = _change(
        raw,
        "            captured_inputs.update(inputs)\n",
        "            _require(set(http_inputs) == {str(setup.http.BINDING_PATH), str(setup.readiness.CREDENTIAL)},\n"
        '                     "HTTP_NINE_WRITER_INTENTS_MISSING")\n'
        "            inputs = dict(inputs) | http_inputs\n"
        '            state["provisioning_file_digests"].update({path: workload._digest(raw) for path, raw in http_inputs.items()})\n'
        "            captured_inputs.update(inputs)\n",
    )
    raw = _change(
        raw,
        "                _protected_descriptor(native)\n",
        "                _protected_descriptor(native, inputs)\n",
    )
    raw = _change(
        raw,
        '                "execute": sources[workload.SOURCE_PATH],\n',
        '                "execute": sources["/usr/lib/aragorn/aragorn/native_phase3_http_collection.py"],\n',
    )
    raw = _change(
        raw,
        '                    "/usr/lib/aragorn/aragorn/native_phase3_blocked_create_verify.py"\n',
        '                    "/usr/lib/aragorn/aragorn/native_phase3_http_collection_verify.py"\n',
    )
    raw = _change(
        raw,
        "payload_raw=_PAYLOAD,",
        'payload_raw=canary.canary_request(common["http_attempt_id"]),',
        count=2,
    )
    raw = _change(
        raw,
        '            phase = "FIRST_ACTIVATION"\n',
        '            retain("http_fixture_binding", inputs[str(setup.http.BINDING_PATH)])\n'
        '            retain("http_sink_identity", canonical_json(sink_identity))\n'
        "            ready = ready_stack.enter_context(broker_ready.capture_broker_readiness(\n"
        '                expected_fixture=expected_http_fixture, attempt_id=common["http_attempt_id"],\n'
        '                readiness_nonce=common["readiness_nonce"],\n'
        '                expected_source_digest=sources["/usr/lib/aragorn/aragorn/native_phase3_http_broker_ready_capture.py"]))\n'
        '            phase = "FIRST_ACTIVATION"\n',
    )
    raw = _change(
        raw,
        '        phase = "SEVEN_WRITER_SETUP"\n'
        "        setup.predecessor._prepare(\n"
        '            native, before_activation, state=result["setup_state"]\n'
        "        )\n",
        _SETUP,
    )
    raw = _change(
        raw,
        '            try:\n                phase = "CLOCK_BEFORE"\n',
        '            phase = "BROKER_SAME_PROCESS_LISTENER"\n'
        '            ready_report = ready.finish(expected_broker_identity={"fixture": expected_http_fixture, **expected["broker"]})\n'
        "            ready_stack.close()\n"
        '            _require(ready_report["cleanup_complete"] is True, "BROKER_READINESS_CLEANUP_UNCONFIRMED")\n'
        '            result["broker_readiness"] = ready_report\n'
        '            retain("broker_readiness", canonical_json(ready_report))\n'
        '            for role in ("request", "claim", "result", "sink", "listener_witness"):\n'
        "                record = ready_report[role]\n"
        '                raw = canonical_json(record["document"])\n'
        '                _require(record["digest"] == workload._digest(raw) and record["bytes"] == len(raw),\n'
        '                         "READINESS_RECORD_CHANGED")\n'
        '                retain("readiness_" + role, raw)\n'
        '            retain("readiness_sink_identity", canonical_json(ready.sink_identity))\n'
        '            try:\n                phase = "CLOCK_BEFORE"\n',
    )
    raw = _section(
        raw,
        "                    work = workload.run_native_blocked_create_workload(\n",
        "            except BaseException as error:\n                if primary is None:\n",
        _WORK,
    )
    raw = _change(
        raw,
        '                if work is not None:\n                    result["workload"] = {\n',
        "                if work is not None:\n"
        '                    failure("HTTP_WORKLOAD_RECORDS_REFUSED", lambda: _http_records(work, native, pins[identity.prior._GENESIS]))\n'
        '                    result["workload"] = {\n',
    )
    raw = _change(
        raw,
        """                            <= {
                                "identity_before",
                                "identity_after",
                                "receipt_before",
                                "receipt_after",
                                "sink_before",
                                "sink_after",
                                "driver_input",
                                "driver",
                            },""",
        '                            <= {"driver", "sink", "terminal"},',
    )
    raw = _change(
        raw,
        '            reader,\n        )\n        retain("independent_verification",',
        "            reader,\n            captured_inputs[str(setup.http.BINDING_PATH)],\n"
        '            sink_identity, common["readiness_nonce"],\n        )\n'
        '        result["verification"]["broker_readiness"] = {"round_trip": ready_report["verification"],\n'
        '            "listener": ready_report["listener_verification"]}\n'
        '        retain("independent_verification",',
    )
    raw = _change(
        raw,
        '    finally:\n        if native is not None and result["installed_sources"] is not None:\n',
        "    finally:\n"
        '        failure("BROKER_READINESS_CONTEXT_CLOSE_REFUSED", ready_stack.close)\n'
        "        if ready_report is None and ready is not None:\n"
        "            ready_report = ready.report\n"
        '        if result["broker_readiness"] is None and ready_report is not None:\n'
        '            result["broker_readiness"] = ready_report\n'
        "            if reader is not None:\n"
        '                failure("PARTIAL_READINESS_RETENTION_REFUSED", lambda: retain("broker_readiness", canonical_json(ready_report)))\n'
        '        if native is not None and result["installed_sources"] is not None:\n',
    )
    raw = _change(
        raw,
        "        captured_inputs.clear()\n",
        "        captured_inputs.clear()\n        http_inputs.clear()\n",
    )
    raw = _change(
        raw,
        '                            expected_container_id=container,\n                            expected_worker=expected["worker"],\n',
        "                            expected_container_id=container,\n"
        "                            expected_http_fixture_binding_raw=captured_inputs[str(setup.http.BINDING_PATH)],\n"
        '                            expected_worker=expected["worker"],\n',
    )
    raw = _change(
        raw,
        '        result["refusal"] = {"phase": phase, "reason": "FIXED_COMMON_ATTEMPT_REFUSED"}\n',
        "        if ready_report is None:\n"
        '            ready_report = getattr(error, "http_broker_readiness_observation", None)\n'
        '        result["refusal"] = {"phase": phase, "reason": "FIXED_HTTP_ATTEMPT_REFUSED"}\n',
    )
    raw = _change(
        raw,
        'result["status"] = "BOUNDED_NATIVE_ATTEMPT_VERIFIED"',
        'result["status"] = "BOUNDED_NATIVE_HTTP_ATTEMPT_VERIFIED"',
    )
    return {SOURCE: raw, SNAPSHOT: _snapshot(original[SNAPSHOT])}
