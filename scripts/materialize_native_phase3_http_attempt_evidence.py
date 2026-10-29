"""Finite HTTP94 export and retained-evidence successors of frozen controllers.

Only source bytes are returned. No guest, capture, transport or replay is run.
The host binds these installed bytes separately from their signed predecessors.
"""

from __future__ import annotations

import hashlib

GUEST = "scripts/runtime_native_common_attempt_capture.py"
PUBLIC = "src/aragorn/native_phase3_common_attempt_capture.py"
RETENTION = "scripts/retain_native_common_measurement_inputs.py"
MEASUREMENT = "src/aragorn/native_phase3_common_measurement_capture.py"
INPUTS = {
    GUEST: (26887, "501ce0e2ccd59fdf76b5735a289dd46cbfcffc6e646c5a31c258670138f06d1f"),
    PUBLIC: (29064, "fe69b35825468aa86df062a561688542e2f37636e889b0609937f0e66fbaad5d"),
    RETENTION: (
        39448,
        "8e8447cbf0ccaa9f0831382e9ae43a9fef6b6bd3d54feb96e293c79027a3c60a",
    ),
    MEASUREMENT: (
        19141,
        "d910033eb1c62ad8c709af7bdcfd0ee2515e14aed23be43607d51ed5c0a38ad9",
    ),
}
READINESS_ROLES = (
    "broker_readiness",
    "readiness_request",
    "readiness_claim",
    "readiness_result",
    "readiness_sink",
    "readiness_listener_witness",
    "http_fixture_binding",
    "http_sink_identity",
    "readiness_sink_identity",
)
_OLD_WORK_NAMES = """            "identity_before",
            "identity_after",
            "receipt_before",
            "receipt_after",
            "sink_before",
            "sink_after",
            "driver_input",
            "driver","""


class NativeHttpAttemptEvidenceRenderError(ValueError):
    """A frozen source or finite replacement boundary changed."""


def _change(raw, before, after, changes, count=1):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != count or after in raw:
        raise NativeHttpAttemptEvidenceRenderError("HTTP evidence anchor changed")
    result = raw.replace(before, after)
    if result.replace(after, before) != raw:
        raise NativeHttpAttemptEvidenceRenderError("HTTP evidence reversal changed")
    changes.append((before, after))
    return result


def _function(raw, name, replacement, changes):
    marker = ("def " + name + "(").encode("ascii")
    if raw.count(marker) != 1:
        raise NativeHttpAttemptEvidenceRenderError("HTTP evidence function changed")
    start = raw.index(marker)
    end = raw.find(b"\n\ndef ", start + len(marker))
    if end < 0:
        end = len(raw)
    return _change(
        raw, raw[start:end].decode("ascii"), replacement.rstrip() + "\n", changes
    )


def _roles(raw, changes):
    raw = _change(
        raw,
        _OLD_WORK_NAMES,
        '            "driver",\n            "sink",\n            "terminal",',
        changes,
    )
    return _change(
        raw,
        '        "independent_verification",\n',
        '        "independent_verification",\n'
        + "".join('        "' + name + '",\n' for name in READINESS_ROLES),
        changes,
    )


_PUBLIC_HTTP_INPUTS = """    # Only the two explicitly classified HTTP metadata inputs are public.
    # Grant, policy, gateway token and every other writer input remain private.
    public_http = {}
    for role, path in (("http_fixture_binding", "/etc/aragorn/runtime-http-fixture.json"),
                       ("readiness_request", "/etc/aragorn/runtime-http-readiness.json")):
        pins = roles.get(role, set())
        _require(len(pins) == 1, "HTTP public metadata input absent")
        pin = next(iter(pins))
        _require(pin == state["provisioning_file_digests"][path],
                 "HTTP metadata differs from installed writer")
        public_http[role] = base._parse(exported[pin], 4096)
    fixture = http.fixture_binding(public_http["http_fixture_binding"])
    readiness = public_http["readiness_request"]
    _require(set(readiness) == {"schema", "readiness_nonce", "fixture_binding_digest", "timeout_ms"}
             and readiness["schema"] == "aragorn/runtime-http-readiness-input/v1"
             and readiness["fixture_binding_digest"] == _digest(canonical_json(fixture))
             and readiness["readiness_nonce"] == bound["common_arguments"]["readiness_nonce"]
             and fixture["fixture"]["container_id"] == container
             and type(readiness["timeout_ms"]) is int and readiness["timeout_ms"] == 500,
             "HTTP metadata input joins changed")
    allowed_public = {state["provisioning_file_digests"][path] for path in
                      ("/etc/aragorn/runtime-http-fixture.json", "/etc/aragorn/runtime-http-readiness.json")}
    _require(not (set(state["provisioning_file_digests"].values()) - allowed_public).intersection(exported),
             "private writer pin exported")
"""


_HTTP_RECORDS = '''def verify_native_common_measurement_records(
    *, capture, plan, public_cas, private_input_cas, expected_worker,
    expected_broker_process, expected_gateway, expected_sink_accounts,
    expected_http_sink_identity, expected_readiness_sink_identity,
):
    """Replay exact native HTTP and broker-readiness bytes; perform no live work."""
    try:
        read = _reader(public_cas)
        _separate_stores(public_cas, private_input_cas)
        report = capture["guest"]["attempt"]
        work = public.base._parse(read(report["workload"]["digest"]), public.MAX_PUBLIC_BLOB)
        measured = public.base._parse(read(report["snapshot"]["digest"]), public.MAX_PUBLIC_BLOB)

        def record(row):
            _require(type(row) is dict and set(row) == {"text", "digest", "bytes"}
                     and type(row["text"]) is str and type(row["bytes"]) is int,
                     "measurement record shape changed")
            raw = row["text"].encode("utf-8")
            _require(0 < len(raw) == row["bytes"] <= public.MAX_PUBLIC_BLOB
                     and public._digest(raw) == row["digest"] and read(row["digest"]) == raw,
                     "measurement record bytes changed")
            return raw

        _require(set(work["records"]) == {"driver", "sink", "terminal"}
                 and set(measured["records"]) == {"startup", "ingress", "attempt", "action", "pending", "completion"},
                 "HTTP finite record inventory changed")
        records, work_records = measured["records"], work["records"]
        fixture_raw = _role(capture, "http_fixture_binding", read)
        _require(fixture_raw == plan["fixture_binding_raw"], "HTTP fixture binding changed")
        fixture = http.fixture_binding(public.base._parse(fixture_raw, 4096))
        _require(public._digest(fixture_raw) == plan["request"]["expected_file_digests"][_HTTP_FIXTURE],
                 "HTTP fixture differs from prepared request")
        for role, expected in (("http_sink_identity", expected_http_sink_identity),
                               ("readiness_sink_identity", expected_readiness_sink_identity)):
            _require(canonical_json(expected) == _role(capture, role, read),
                     "caller sink identity differs from independent observation")
        before, after = (_role(capture, role, read) for role in ("clock_before", "clock_after"))
        readiness = {name: _role(capture, "readiness_" + name, read)
                     for name in ("request", "claim", "result", "sink")}
        readiness_input = public.base._parse(readiness["request"], 4096)
        _require(public._digest(readiness["request"]) == plan["request"]["expected_file_digests"]["/etc/aragorn/runtime-http-readiness.json"],
                 "HTTP readiness differs from prepared request")
        expected_identity = {"fixture": fixture["fixture"],
                             **{key: expected_broker_process[key] for key in _EPOCH}}
        readiness_result = readiness_verify.verify_broker_readiness(
            **{name + "_raw": raw for name, raw in readiness.items()},
            expected_digests={name: public._digest(raw) for name, raw in readiness.items()},
            expected_fixture_binding=fixture, expected_broker_identity=expected_identity,
            expected_sink_identity=expected_readiness_sink_identity)
        witness_raw = _role(capture, "readiness_listener_witness", read)
        listener_result = listener.verify_listener_witness(
            witness_raw=witness_raw, expected_raw_digest=public._digest(witness_raw),
            expected_broker_identity=expected_identity)
        witness = public.base._parse(witness_raw, public.MAX_PUBLIC_BLOB)
        ready_result = public.base._parse(readiness["result"], 16384)
        _require(witness["observed_boottime_ns"] >= ready_result["interval"]["finished_ns"],
                 "broker listener observation predates readiness completion")
        broker_readiness = {"round_trip": readiness_result, "listener": listener_result}
        _require(report["broker_readiness"]["cleanup_complete"] is True
                 and canonical_json(report["broker_readiness"]["verification"]) == canonical_json(readiness_result)
                 and canonical_json(report["broker_readiness"]["listener_verification"]) == canonical_json(listener_result),
                 "broker readiness replay differs")
        for name, raw in (readiness | {"listener_witness": witness_raw}).items():
            entry = report["broker_readiness"][name]
            _require(set(entry) == {"document", "digest", "bytes"}
                     and type(entry["bytes"]) is int and entry["bytes"] == len(raw)
                     and entry["digest"] == public._digest(raw)
                     and canonical_json(entry["document"]) == raw,
                     "broker readiness retained record differs")
        result = {
            "http_collection": http.verify_native_http_collection(
                completion_raw=record(records["completion"]),
                expected_completion_digest=records["completion"]["digest"],
                expected_binding_raw=plan["binding_raw"], expected_binding_digest=plan["binding_digest"],
                expected_broker=expected_broker_process, input_cas=private_input_cas, evidence_cas=public_cas,
                ingress_raws={name: record(records[name]) for name in ("startup", "ingress", "attempt", "action")},
                expected_ingress_digests={name: records[name]["digest"] for name in ("startup", "ingress", "attempt", "action")},
                expected_worker=expected_worker,
                expected_worker_binding_digest=plan["request"]["expected_file_digests"][_WORKER],
                expected_genesis_digest=plan["request"]["expected_file_digests"][_GENESIS],
                fixture_binding_raw=fixture_raw, expected_fixture_binding_digest=public._digest(fixture_raw),
                clock_before_raw=before, clock_after_raw=after,
                expected_clock_before_digest=public._digest(before), expected_clock_after_digest=public._digest(after),
                sink_raw=record(work_records["sink"]), expected_sink_digest=work_records["sink"]["digest"],
                expected_sink_identity=expected_http_sink_identity, expected_readiness_nonce=readiness_input["readiness_nonce"],
                driver_raw=record(work_records["driver"]), expected_driver_record_digest=work_records["driver"]["digest"],
                terminal_raw=record(work_records["terminal"]), expected_terminal_digest=work_records["terminal"]["digest"]),
            "broker_readiness": broker_readiness,
        }
        _require(result["http_collection"]["ingress"]["gateway_peer"] == expected_gateway,
                 "HTTP request peer differs from independently observed gateway")
        _require(canonical_json(result) == canonical_json(report["verification"])
                 == _role(capture, "independent_verification", read),
                 "independent HTTP replay differs from guest result")
        return result
    except Exception:
        raise NativeCommonMeasurementCaptureError("independent HTTP measurement record replay refused") from None
'''


_STAGED_DRIVER = '''def _generated_driver(report, bound):
    """The driver is an exact HTTP94 staged file, not a second installation."""
    expected = inputs.HTTP_DRIVER_REPORT
    _require(type(report) is dict and set(report) == {
        "schema", "path", "mode", "bytes", "digest", "stage_owned"}
        and report == expected and report["stage_owned"] is True
        and report["schema"] == "aragorn/native-http-staged-driver/v1"
        and report["path"] == "/opt/aragorn/native-http-attempt-driver-v1.mjs"
        and report["mode"] == "0444" and type(report["bytes"]) is int,
        "staged HTTP driver changed")
    stage = base._parse(bound["stage_raw"], inputs.MAX_BUNDLE)
    rows = [row for row in stage["files"] if row["path"] == report["path"]]
    _require(len(rows) == 1 and all(rows[0][key] == report[key]
        for key in ("path", "mode", "bytes", "digest")), "driver differs from common HTTP94 stage")
'''


_READINESS_EXPORT = '''def _readiness_export_complete(result):
    """Never authorize fixture destruction after unclassified listener partials."""
    report = result["attempt"]
    if report is None:
        return True
    journal = report["public_blob_attempts"]
    if not any(row["role"] in {"http_sink_identity", "broker_readiness"} for row in journal):
        return True
    try:
        readiness = report["broker_readiness"]
        _require(type(readiness) is dict and readiness["status"] == "OBSERVED"
                 and readiness["cleanup_complete"] is True and readiness["cleanup_errors"] == [],
                 "HTTP_READINESS_INCOMPLETE")
        exported = {row["digest"]: row["text"].encode("utf-8") for row in result["public_blobs"]}
        expected = {"broker_readiness": canonical_json(readiness)}
        for name in ("request", "claim", "result", "sink", "listener_witness"):
            record = readiness[name]
            raw = canonical_json(record["document"])
            _require(set(record) == {"document", "digest", "bytes"}
                     and type(record["bytes"]) is int and len(raw) == record["bytes"]
                     and _IDENTITY._digest(raw) == record["digest"], "HTTP_READINESS_RECORD_CHANGED")
            expected["readiness_" + name] = raw
        for role, raw in expected.items():
            pin = _IDENTITY._digest(raw)
            _require(exported.get(pin) == raw and any(row["role"] == role and row["digest"] == pin for row in journal),
                     "HTTP_READINESS_ROLE_NOT_EXPORTED")
        for role in ("http_fixture_binding", "http_sink_identity", "readiness_sink_identity"):
            pins = {row["digest"] for row in journal if row["role"] == role}
            _require(len(pins) == 1 and next(iter(pins)) in exported, "HTTP_READINESS_IDENTITY_NOT_EXPORTED")
        return True
    except Exception:
        return False


'''


def _guest(raw, changes):
    raw = _roles(raw, changes)
    raw = _change(
        raw,
        'SCHEMA = "aragorn/native-common-attempt-guest/v1"',
        'SCHEMA = "aragorn/native-http-attempt-guest/v1"',
        changes,
    )
    raw = _change(
        raw,
        '"BOUNDED_NATIVE_ATTEMPT_VERIFIED"',
        '"BOUNDED_NATIVE_HTTP_ATTEMPT_VERIFIED"',
        changes,
        count=3,
    )
    raw = _change(
        raw,
        'inspected["source_raws"][source]',
        'inspected["installed_source_raws"][source]',
        changes,
        count=2,
    )
    raw = _change(
        raw,
        "def _run(container, expected_bundle_digest):\n",
        """def _http_fixture(container):
    attempt.setup.predecessor._environment(container, (0, 0))
    boot = _IDENTITY.process._read_virtual_file(
        __import__("pathlib").Path("/proc/sys/kernel/random/boot_id"), 64).decode("ascii")
    _require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\\n", boot),
             "HTTP_BOOT_OBSERVATION_REFUSED")
    namespace = os.stat("/proc/self/ns/net")
    fixture = {"container_id": container, "boot_id": boot.strip(),
               "netns_device": namespace.st_dev, "netns_inode": namespace.st_ino}
    attempt.canary.validate_fixture(fixture)
    with attempt.owned_http_fixture(fixture) as held:
        held.guard()
    return fixture


def _run(container, expected_bundle_digest):
""",
        changes,
    )
    raw = _change(
        raw,
        '                expected_source_digests=inspected["expected_source_digests"],\n',
        '                expected_source_digests=inspected["expected_source_digests"],\n'
        "                expected_http_fixture=_http_fixture(container),\n"
        '                expected_driver_digest=inspected["expected_source_digests"][attempt.http_collection.DRIVER_PATH],\n',
        changes,
    )
    raw = _change(
        raw,
        "def _report(value):\n",
        _READINESS_EXPORT + "def _report(value):\n",
        changes,
    )
    return _change(
        raw,
        '    result["interrupted"] = bool(interrupts)\n',
        "    if not _readiness_export_complete(result):\n"
        '        result["postcondition_failures"].append("HTTP_READINESS_EXPORT_INCOMPLETE")\n'
        '    result["interrupted"] = bool(interrupts)\n',
        changes,
    )


def _public(raw, changes):
    raw = _roles(raw, changes)
    raw = _change(
        raw,
        "from . import native_phase3_common_attempt_inputs as inputs\n",
        "from . import native_phase3_common_attempt_inputs as inputs\n"
        "from . import native_phase3_http_collection_verify as http\n",
        changes,
    )
    for before, after, count in (
        (
            "aragorn/native-common-attempt-capture/v1",
            "aragorn/native-http-attempt-capture/v1",
            1,
        ),
        (
            "aragorn/native-common-attempt-guest/v1",
            "aragorn/native-http-attempt-guest/v1",
            1,
        ),
        ("aragorn/native-common-attempt/v1", "aragorn/native-http-attempt/v1", 1),
        (
            "aragorn/native-common-attempt-public-replay/v1",
            "aragorn/native-http-attempt-public-replay/v1",
            1,
        ),
        (
            "aragorn/native-common-measurement-input-retention/v1",
            "aragorn/native-http-measurement-input-retention/v1",
            1,
        ),
        ("BOUNDED_NATIVE_ATTEMPT_VERIFIED", "BOUNDED_NATIVE_HTTP_ATTEMPT_VERIFIED", 1),
    ):
        raw = _change(raw, before, after, changes, count=count)
    raw = _change(
        raw,
        """    _require(
        not set(state["provisioning_file_digests"].values()).intersection(exported),
        "private writer pin exported",
    )
""",
        _PUBLIC_HTTP_INPUTS,
        changes,
    )
    raw = _change(
        raw,
        '        ("verification", "independent_verification"),\n',
        '        ("verification", "independent_verification"),\n'
        '        ("broker_readiness", "broker_readiness"),\n',
        changes,
    )
    before = """            {
                "identity_before",
                "identity_after",
                "receipt_before",
                "receipt_after",
                "sink_before",
                "sink_after",
                "driver_input",
                "driver",
            }
"""
    raw = _change(raw, before, '            {"driver", "sink", "terminal"}\n', changes)
    raw = _change(
        raw,
        '''    plan = report["plan"]
    _require(
        plan["status"] == "ORIGINAL_PLAN_PREPARED_NOT_PROVISIONED"''',
        '''    plan = report["plan"]
    _require(plan["http_binding"] == {
        "fixture_binding_digest": _digest(canonical_json(fixture)),
        "readiness_input_digest": _digest(canonical_json(readiness)),
        "readiness_nonce": readiness["readiness_nonce"]}, "HTTP plan metadata differs")
    _require(
        plan["status"] == "ORIGINAL_PLAN_PREPARED_NOT_PROVISIONED"''',
        changes,
    )
    raw = _change(
        raw,
        '        "measurement_completion",\n',
        '        "measurement_completion",\n'
        + "".join('        "' + name + '",\n' for name in READINESS_ROLES),
        changes,
    )
    raw = _change(
        raw,
        'guest["controller_sources"][path], bound["source_raws"][path]',
        'guest["controller_sources"][path], bound["installed_source_raws"][path]',
        changes,
    )
    return _function(raw, "_generated_driver", _STAGED_DRIVER, changes)


def _retention(raw, changes):
    return _change(
        raw,
        'SCHEMA = "aragorn/native-common-measurement-input-retention/v1"',
        'SCHEMA = "aragorn/native-http-measurement-input-retention/v1"',
        changes,
    )


def _measurement(raw, changes):
    raw = _change(
        raw,
        "from . import native_phase3_blocked_create_verify as blocked\n"
        "from . import native_phase3_ingress_interval_verify as interval\n",
        "from . import native_phase3_http_collection_verify as http\n"
        "from . import native_phase3_http_readiness_verify as readiness_verify\n"
        "from . import native_phase3_http_broker_ready_capture as listener\n",
        changes,
    )
    raw = _change(
        raw,
        '_SINK = "/usr/lib/aragorn/aragorn/native_phase3_denied_create_sink.py"\n',
        '_HTTP_FIXTURE = "/etc/aragorn/runtime-http-fixture.json"\n',
        changes,
    )
    raw = _change(
        raw,
        'bound["source_raws"][source]',
        'bound["installed_source_raws"][source]',
        changes,
        count=2,
    )
    raw = _change(
        raw,
        '            "sink_source_digest": bound["expected_source_digests"][_SINK],\n',
        '            "fixture_binding_raw": _role(capture, "http_fixture_binding", read),\n',
        changes,
    )
    raw = _function(
        raw, "verify_native_common_measurement_records", _HTTP_RECORDS, changes
    )
    marker = b"def verify_native_common_measurement_capture("
    section = raw[raw.index(marker) :].decode("ascii")
    changed = section.replace(
        "    expected_sink_accounts,\n):",
        "    expected_sink_accounts,\n"
        "    expected_http_sink_identity,\n    expected_readiness_sink_identity,\n):",
        1,
    )
    changed = changed.replace(
        "            expected_sink_accounts,\n        ) = json.loads(",
        "            expected_sink_accounts,\n            expected_http_sink_identity,\n"
        "            expected_readiness_sink_identity,\n        ) = json.loads(",
        1,
    )
    changed = changed.replace(
        "                    expected_sink_accounts,\n                ]",
        "                    expected_sink_accounts,\n                    expected_http_sink_identity,\n"
        "                    expected_readiness_sink_identity,\n                ]",
        1,
    )
    changed = changed.replace(
        "        result = verify_native_common_measurement_records(\n",
        "        result = verify_native_common_measurement_records(\n"
        "            expected_http_sink_identity=expected_http_sink_identity,\n"
        "            expected_readiness_sink_identity=expected_readiness_sink_identity,\n",
        1,
    )
    changed = changed.replace(
        "aragorn/native-common-measurement-capture-verification/v1",
        "aragorn/native-http-measurement-capture-verification/v1",
    )
    changed = changed.replace(
        "ONE_RETAINED_ATTRIBUTED_CREATE_NOT_FULL_CAMPAIGN_OR_PRIVATE_SEVEN_WRITER_REPLAY",
        "ONE_RETAINED_NATIVE_HTTP_ATTEMPT_NOT_FULL_CAMPAIGN_OR_PRIVATE_NINE_WRITER_REPLAY",
    )
    return _change(raw, section, changed, changes)


def render(original):
    """Render four exact source-owned replacements; never evaluate them."""
    result = {}
    for name, transform in (
        (GUEST, _guest),
        (PUBLIC, _public),
        (RETENTION, _retention),
        (MEASUREMENT, _measurement),
    ):
        raw = original[name]
        if (
            type(raw) is not bytes
            or (len(raw), hashlib.sha256(raw).hexdigest()) != INPUTS[name]
        ):
            raise NativeHttpAttemptEvidenceRenderError(
                "HTTP evidence predecessor changed"
            )
        changes = []
        result[name] = transform(raw, changes)
        reversed_raw = result[name]
        for before, after in reversed(changes):
            reversed_raw = reversed_raw.replace(after, before)
        if reversed_raw != raw:
            raise NativeHttpAttemptEvidenceRenderError(
                "HTTP evidence transformation changed"
            )
    return result
