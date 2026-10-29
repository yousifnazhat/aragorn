"""Fabricated offline records only; no native deployment or provider evidence."""
from copy import deepcopy
import json
import unittest

from aragorn import native_phase3_admission_restart as consumer
from aragorn.oci_worker_protocol import canonical_json
from test_native_admission_direct_write import _fixture, _file, _pin

BASE = 1767225600000000000
SECOND = 1000000000


def denial_bytes():
    reason = "unauthorized: gateway token mismatch (set gateway.remote.token to match gateway.auth.token)"
    value = {"ok": False, "error": {"type": "gateway_transport_error", "kind": "closed",
             "message": "gateway closed (1008): " + reason, "code": 1008, "reason": reason},
             "gateway": {"url": "ws://127.0.0.1:18789", "urlSource": "local loopback", "bindDetail": "Bind: loopback"}}
    return ((json.dumps(value, indent=2) + "\n").encode(),
            ("gateway connect failed: GatewayClientRequestError: " + reason + "\n").encode())


def clock(at):
    ns = int(at * SECOND)
    return {"monotonic_before_ns": ns, "realtime_ns": BASE + ns, "monotonic_after_ns": ns}


def command(argv, *, pid, start, end, stdout=b"", stderr=b"", code=0):
    first, last = clock(start), clock(end)
    return {"argv": list(argv), "pid": pid, "start_time_ticks": pid * 10,
            "started_realtime_ns": first["realtime_ns"], "completed_realtime_ns": last["realtime_ns"],
            "started_monotonic_ns": first["monotonic_before_ns"],
            "completed_monotonic_ns": last["monotonic_after_ns"],
            "start_clock": first, "completion_clock": last,
            "exit_code": code, "stdout_base64": consumer.encode(stdout), "stderr_base64": consumer.encode(stderr),
            "group_cleanup": True, "leader_reaped": True, "cleanup_failures": []}


def log(message, second, **fields):
    return canonical_json({"message": message, "time": f"2026-01-01T00:00:{second:02d}.000+00:00",
                           "hostname": "inert", **fields}) + b"\n"


def retained_snapshot(bindings, phase, prefix, *, previous=None, start, end, cursor):
    raw = canonical_json({"schema": consumer.SNAPSHOT_SCHEMA, "capture_nonce": bindings["capture_nonce"],
        "phase": phase, "context_digest": bindings["context_digest"],
        "previous_snapshot_digest": consumer.digest(consumer.decode(previous["raw_base64"], consumer.MAX_ENVELOPE))
            if previous else None,
        "file_identity": {"dev": 1, "ino": 400, "mode": 0o100600, "uid": 992, "gid": 992, "nlink": 1},
        "prefix_bytes": len(prefix), "prefix_digest": consumer.digest(prefix), "raw_base64": consumer.encode(prefix),
        "cursor": cursor * 64, "acquisition": {"clock": "CLOCK_MONOTONIC",
            "started_ns": int(start * SECOND), "completed_ns": int(end * SECOND)},
        "emission_clock": {"clock": "CLOCK_REALTIME", "timezone": "UTC", "precision_ns": 1000000},
        "complete": True})
    return {"raw_base64": consumer.encode(raw), "call_started_ns": int((start - .01) * SECOND),
            "call_completed_ns": int((end + .01) * SECOND),
            "deadline_ns": 30 * SECOND if phase == "AFTER" else int((start - .01) * SECOND) + 3 * SECOND}


def fixture():
    old, _ = _fixture()
    boundary = deepcopy(old["before"])
    bindings = {"container": "c" * 64, "gateway": deepcopy(boundary["gateway"]),
        "namespaces": {"mnt": 777, "pid": 778, "user": 779, "time": 780},
        "capture_nonce": "a" * 64, "context_digest": _pin("protected-context"),
        "runtime_inventory_digest": _pin("runtime-inventory"), "config_digest": _pin("fresh-config"),
        "entry_digest": _pin("entry"), "admitted_digest": boundary["admitted"]["digest"],
        "source_pins": {path: _pin(path) for path in consumer.SOURCE_PATHS}}
    boundary["config"] = _file(bindings["config_digest"], uid=992)
    boundary["entry"] = _file(bindings["entry_digest"])
    boundary["sources"] = {path: _file(pin) for path, pin in bindings["source_pins"].items()}
    pre, post = [], []
    for target, offset in ((pre, 1), (post, 16)):
        for index, (argv, original) in enumerate(zip(consumer.CATALOGS, old["commands_before"], strict=True)):
            start = offset + index
            target.append(command(argv, pid=100 + start, start=start, end=start + .1,
                                  stdout=original["stdout"].encode()))
        stdout, stderr = denial_bytes()
        target.append(command(consumer.DENIAL_ARGV, pid=104 + offset, start=offset + 4,
                              end=offset + 4.1, stdout=stdout, stderr=stderr, code=1))
    initial = log("gateway ready", 0)
    after = initial + b"".join((log("signal SIGUSR1 received", 11),
        log("received SIGUSR1; restarting", 12, traceId="native-present"),
        log("shutdown completed cleanly in 7ms", 13),
        log("restart mode: in-process restart (OPENCLAW_NO_RESPAWN)", 14), log("gateway ready", 15)))
    snapshots = []
    for phase, prefix, start, end, cursor in (
        ("INITIAL", initial, .1, .2, "1"), ("BOUNDARY", initial, 6, 6.1, "2"),
        ("AFTER", after, 15.1, 15.2, "3")):
        snapshots.append(retained_snapshot(bindings, phase, prefix, previous=snapshots[-1] if snapshots else None,
                                          start=start, end=end, cursor=cursor))
    value = {"schema": consumer.SCHEMA, "status": "OBSERVED", "bindings": deepcopy(bindings),
             "before": boundary, "dispatch_boundary": deepcopy(boundary), "after": deepcopy(boundary),
             "commands_before": pre, "commands_after": post,
             "restart": command(consumer.ARGV, pid=110, start=10, end=12.5,
                                stderr=canonical_json(consumer.restart_response(42))),
             "lifecycle": snapshots, "markers": consumer.markers(initial, initial, after),
             "refusal": None, "partial": [], "cleanup_failures": [],
             "limitations": list(consumer.LIMITATIONS), **dict.fromkeys(consumer.shared.FALSE_FLAGS, False)}
    return value, bindings


def verify(value, bindings):
    raw = canonical_json(value)
    return consumer.verify_native_admission_restart(raw, expected_raw_digest=consumer.digest(raw),
                                                    expected_bindings=bindings)


def mutate_snapshot(value, index, change):
    row = value["lifecycle"][index]
    parsed = consumer.parse(consumer.decode(row["raw_base64"], consumer.MAX_ENVELOPE))
    change(parsed)
    row["raw_base64"] = consumer.encode(canonical_json(parsed))


class RestartConsumerTests(unittest.TestCase):
    def test_same_gateway_pid_new_config_trace_presence_and_false_flags(self):
        value, bindings = fixture()
        saved = deepcopy(value)
        result = verify(value, bindings)
        self.assertEqual(result["status"], "BOUNDED_RESTART_JOINS_VERIFIED")
        self.assertEqual(value, saved)
        self.assertEqual(value["before"]["gateway"], value["after"]["gateway"])
        self.assertNotEqual(bindings["config_digest"], consumer.shared.CONFIG_PIN)
        self.assertEqual(value["markers"][0]["trace"]["traceId"], {"present": False})
        self.assertEqual(value["markers"][2]["trace"]["traceId"]["value"], "native-present")
        self.assertTrue(all(result[k] is False for k in consumer.shared.FALSE_FLAGS))

    def test_restart_schema_exit_output_channels_and_types(self):
        for field, replacement in (("delayMs", True), ("pid", 43), ("coalesced", True),
                ("signal", "SIGTERM"), ("cooldownMsApplied", 1), ("emitHooksQueued", True)):
            value, bindings = fixture()
            response = consumer.restart_response(42)
            response["restart"][field] = replacement
            value["restart"]["stderr_base64"] = consumer.encode(canonical_json(response))
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify(value, bindings)
        for change in ({"exit_code": 1}, {"stdout_base64": consumer.encode(b"diagnostic")},
                       {"stderr_base64": consumer.encode(b'{"ok":true,"ok":true}')}):
            value, bindings = fixture()
            value["restart"].update(change)
            with self.assertRaises(ValueError):
                verify(value, bindings)

    def test_denial_controls_are_exact_and_not_catalog_exit_contract(self):
        for side in ("commands_before", "commands_after"):
            for key, replacement in (("exit_code", 0), ("stdout_base64", consumer.encode(b'{"ok":false}')),
                                     ("stderr_base64", "")):
                value, bindings = fixture()
                value[side][-1][key] = replacement
                with self.subTest(side=side, key=key), self.assertRaises(ValueError):
                    verify(value, bindings)

    def test_snapshot_bounds_canonical_context_identity_chain_and_clock(self):
        mutations = [lambda s: s.update(complete=False), lambda s: s.update(capture_nonce="b" * 64),
            lambda s: s.update(context_digest=_pin("wrong")), lambda s: s.update(cursor="1" * 64),
            lambda s: s.update(previous_snapshot_digest=_pin("wrong")),
            lambda s: s["file_identity"].update(mode=0o100644),
            lambda s: s["file_identity"].update(ino=401),
            lambda s: s["acquisition"].update(clock="CLOCK_REALTIME"),
            lambda s: s["emission_clock"].update(precision_ns=True),
            lambda s: s.update(prefix_bytes=True), lambda s: s.update(extra=True),
            lambda s: s.update(raw_base64=s["raw_base64"] + "="),
            lambda s: s.update(prefix_digest=_pin("wrong"))]
        for change in mutations:
            value, bindings = fixture()
            mutate_snapshot(value, 2, change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify(value, bindings)
        value, bindings = fixture()
        value["lifecycle"][2]["raw_base64"] = consumer.encode(b"x" * (consumer.MAX_ENVELOPE + 1))
        with self.assertRaises(ValueError):
            verify(value, bindings)

    def test_actual_markers_missing_duplicate_order_trace_and_clock_refuse(self):
        value, _ = fixture()
        raws = [consumer.parse(consumer.decode(r["raw_base64"], consumer.MAX_ENVELOPE)) for r in value["lifecycle"]]
        initial, boundary, after = [consumer.decode(r["raw_base64"], 1048576) for r in raws]
        lines = after.splitlines(keepends=True)
        for altered in (b"".join(lines[:-1]), after + lines[-1],
                        b"".join(lines[:1] + [lines[2], lines[1]] + lines[3:]),
                        after.replace(b"SIGUSR1", b"SIGTERM"), after.replace(b"cleanly", b"uncleanly"),
                        after.replace(b"00:00:15.000", b"00:00:10.000")):
            with self.assertRaises(ValueError):
                consumer.markers(initial, boundary, altered)
        value, bindings = fixture()
        value["markers"][0]["trace"]["traceId"] = {"present": True, "value": None}
        with self.assertRaises(ValueError):
            verify(value, bindings)

    def test_protected_state_sources_catalog_and_caller_pins(self):
        for change in (lambda v: v["after"]["admitted"].update(digest=_pin("changed")),
                       lambda v: v["after"]["config"].update(digest=consumer.shared.CONFIG_PIN),
                       lambda v: v["after"]["gateway"].update(start_time_ticks=999),
                       lambda v: v["after"]["roots"][consumer.shared.ROOTS[0]].update(read_only=False),
                       lambda v: v["after"]["sources"][consumer.PROBE]["identity"].__setitem__(3, 992)):
            value, bindings = fixture()
            change(value)
            with self.assertRaises(ValueError):
                verify(value, bindings)
        value, bindings = fixture()
        for side in ("commands_before", "commands_after"):
            row = value[side][3]
            catalog = consumer.parse(consumer.decode(row["stdout_base64"], consumer.shared.MAX_COMMAND))
            catalog["skills"].append({"name": "other", "eligible": True})
            row["stdout_base64"] = consumer.encode(canonical_json(catalog))
        with self.assertRaises(ValueError):
            verify(value, bindings)
        value, bindings = fixture()
        bindings["config_digest"] = _pin("independently-different")
        with self.assertRaises(ValueError):
            verify(value, bindings)

    def test_client_reuse_timing_precision_snapshot_call_and_clock_step(self):
        mutations = [lambda v: v["commands_after"][0].update(pid=v["commands_before"][0]["pid"]),
            lambda v: v["lifecycle"][1].update(call_started_ns=0),
            lambda v: v["lifecycle"][2].update(deadline_ns=14 * SECOND),
            lambda v: v["restart"].update(completed_realtime_ns=BASE + 14 * SECOND),
            lambda v: v["restart"].update(started_realtime_ns=BASE + 12 * SECOND)]
        for change in mutations:
            value, bindings = fixture()
            change(value)
            with self.assertRaises(ValueError):
                verify(value, bindings)
        value, bindings = fixture()
        row = value["commands_after"][-1]
        row["completed_realtime_ns"] += SECOND
        row["completion_clock"]["realtime_ns"] += SECOND
        with self.assertRaisesRegex(ValueError, "CLOCK_DISCONTINUITY"):
            verify(value, bindings)

    def test_record_framing_utf8_duplicates_and_line_caps(self):
        for raw in (b"", b'{}', b"\n", b'{"message":"x","message":"y"}\n',
                    b'{"x":NaN}\n', b'\xff\n', b'{}\r\n', b'{}\n' * 513,
                    b'{"x":"' + b'x' * 65536 + b'"}\n'):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                consumer.records(raw)

    def test_raw_catalog_equality_and_precision_inequality_are_not_weakened(self):
        value, bindings = fixture()
        row = value["commands_after"][3]
        raw = consumer.decode(row["stdout_base64"], consumer.shared.MAX_COMMAND)
        row["stdout_base64"] = consumer.encode(raw.rstrip() + b" \n")
        with self.assertRaisesRegex(ValueError, "RAW_GATEWAY_CATALOG_CHANGED"):
            verify(value, bindings)
        value, bindings = fixture()
        row = value["restart"]
        row["completion_clock"] = clock(12)
        row["completed_realtime_ns"] = BASE + 12 * SECOND
        row["completed_monotonic_ns"] = 12 * SECOND
        with self.assertRaisesRegex(ValueError, "CAUSAL_CLOCK"):
            verify(value, bindings)

    def test_scheduled_only_partial_promoted_or_rebound_observations_refuse(self):
        for change in ({"lifecycle": []}, {"status": "REFUSED"}, {"partial": [{"kind": "lifecycle"}]},
                       {"route_qualified": True}, {"cleanup_failures": ["failed"]}):
            value, bindings = fixture()
            value.update(change)
            with self.assertRaises(ValueError):
                verify(value, bindings)
        value, bindings = fixture()
        raw = canonical_json(value)
        with self.assertRaises(ValueError):
            consumer.verify_native_admission_restart(raw, expected_raw_digest=_pin("wrong"), expected_bindings=bindings)
