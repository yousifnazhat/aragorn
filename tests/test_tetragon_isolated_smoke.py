"""Fixed-artifact replay, not a new capture or a RUN/Phase3 qualifier.

Reads only the exact retained JSON and inert helper reference. The helper is
never imported/executed. Its retained bytes do not attest execution. Reported
container removal is not independently attested here; VM removal was verified
separately and has no command receipt in this artifact. No live checks occur.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unittest
from pathlib import Path
from unittest import mock

from aragorn import runtime_tetragon_process as process

_ROOT = Path(__file__).resolve().parents[1]
_OBSERVATION = "benchmark/evidence/tetragon-isolated-exec-exit-smoke-v1-2026-09-13.json"
_HELPER = "benchmark/evidence/reference/tetragon-isolated-exec-exit-smoke-v1-2026-09-13.py.txt"
_PINS = (
    (189925, "sha256:3f64362ab12391e5d44c7ce781e4963c8b37262707ec89095d83e719d1bf17de"),
    (11356, "sha256:edf33a066505e98d4e5baeb703a8dcb36d8aec4b33237844d408564e92fe9b80"),
)
_STREAM = (
    47343,
    "sha256:bfd3a0f1789e2fc8d0d51439b80b4c2ccc345e36ea09683bb5094e2d5ad66ebb",
)
_PROFILE = "aragorn-tetragon-check-20260913-a7d1148"
_ID = "1578fc9d262eb0127e14611e26fc0835d0d4436b1fd6aeaf8ae01dff221f37a6"
_IMAGE = "quay.io/cilium/tetragon@sha256:1bffeee60f1d47e367d237129e576729d14fe8db748440328aded8a6091c4a40"
_BINARY = "/opt/aragorn-tetragon-fixture/a7d1148/true"
_EOF = "Error: failed to receive events: rpc error: code = Unavailable desc = error reading from server: EOF\n"
_BPF = "tetragon_bpf_missed_events_total"
_FALSE = (
    "release_signature_verified",
    "source_to_binary_reproduction_verified",
    "loss_metric_qualification",
    "complete_event_coverage",
    "phase3_eligible",
    "run_conformance_eligible",
)


def _check(condition):
    if not condition:
        raise ValueError("fixed smoke evidence changed")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(raw, pin):
    _check(type(raw) is bytes and len(raw) == pin[0])
    _check(_digest(raw) == pin[1])


def _read(path, pin):
    with path.open("rb") as stream:
        raw = stream.read(pin[0] + 1)
    _pin(raw, pin)
    return raw


def _load(raw, helper):
    # Both fixed byte bounds/hashes precede any JSON parsing. Never parse the
    # helper as Python or use it to issue commands. Original JSON has no LF.
    _pin(raw, _PINS[0])
    _pin(helper, _PINS[1])
    document = process._json(raw, _PINS[0][0])
    _check(process._canonical(document) == raw)
    return document


def _metrics(raw):
    # This is a tiny fixed-scrape assertion, not a general Prometheus adapter.
    _check(type(raw) is str and len(raw) <= 1048576)
    lines, result = raw.splitlines(), {}
    for family in process.LOSS_METRICS:
        samples = [
            line for line in lines if line.startswith((family + " ", family + "{"))
        ]
        types = [line for line in lines if line.startswith("# TYPE " + family + " ")]
        helps = [line for line in lines if line.startswith("# HELP " + family + " ")]
        if family == _BPF:
            _check(not samples and not types and not helps)
            result[family] = None  # Absent/unknown, NEVER zero.
            continue
        _check(types == ["# TYPE " + family + " counter"] and len(helps) == 1)
        wanted = {family + " 0"}
        if family == "tetragon_handler_errors_total":
            wanted = {
                family + '{error="' + error + '",opcode="' + str(opcode) + '"} 0'
                for error in ("event_handler_failed", "unknown_opcode")
                for opcode in (0, 5, 7, 13, 14, 15, 16, 23, 24, 25, 26, 27, 28)
            }
        _check(len(samples) == len(wanted) and set(samples) == wanted)
        result[family] = {"series": len(samples), "value": 0}
    return result


def _sensor(snapshot):
    container = snapshot["container"]
    pid = container["State"]["Pid"]
    _check(type(pid) is int and pid > 0)
    for name in ("process", "info", "health", "metrics"):
        _check(
            type(snapshot[name]["exit_code"]) is int
            and snapshot[name]["exit_code"] == 0
            and snapshot[name]["stderr"] == ""
        )
    native = json.loads(snapshot["process"]["stdout"])
    _check(native["stat"].startswith(str(pid) + " (tetragon) "))
    fields = native["stat"][native["stat"].rindex(") ") + 2 :].split()
    _check(re.fullmatch(r"[1-9][0-9]*", fields[19]) is not None)
    _check(
        native["cgroup"] == "0::/docker/" + _ID + "\n"
        and native["exe"] == "/usr/bin/tetragon"
    )
    _check(
        re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", native["boot"])
        is not None
    )
    info = json.loads(snapshot["info"]["stdout"])
    _check(
        info["Name"] == "tetragon"
        and info["Version"] == "v1.7.0"
        and info["Build"]["Commit"] == ""
    )
    _check(info["Conf"]["enable-process-environment-variables"] is False)
    _check(snapshot["health"]["stdout"] == "Health Status: running\n")
    return pid, int(fields[19]), native["cgroup"], native["exe"], native["boot"]


def _marker_joins(records, markers, node):
    _check(len(records) == 6 and len(markers) == 3)
    _check(len({m["pid"] for m in markers}) == 3)
    identities = []
    for index, marker in enumerate(markers):
        pair = records[index * 2 : index * 2 + 2]
        _check(
            [next(k for k in e if k.startswith("process_")) for e in pair]
            == ["process_exec", "process_exit"]
        )
        _check(type(marker["pid"]) is int and type(marker["parent_pid"]) is int)
        _check(type(marker["exit_code"]) is int and marker["exit_code"] == 0)
        for event, kind in zip(pair, ("process_exec", "process_exit"), strict=True):
            body = event[kind]
            _check(event["node_name"] == node)
            _check(
                body["process"]["pid"] == marker["pid"]
                and body["parent"]["pid"] == marker["parent_pid"]
            )
            _check(body["process"]["binary"] == _BINARY)
            identities.extend(
                [body["process"], body["parent"], *body.get("ancestors", [])]
            )
        first, last = pair[0]["process_exec"], pair[1]["process_exit"]
        _check(first["process"]["exec_id"] == last["process"]["exec_id"])
        _check(last.get("status", 0) == 0 and not last.get("signal"))
    process._identities(identities)


def _replay(document):
    _check(document["schema"] == "aragorn/tetragon-isolated-exec-exit-smoke/v1")
    _check(
        document["authority"]
        == "OWNED_VM_SELECTED_MARKERS_ONLY_NOT_CONTINUOUS_COVERAGE_OR_RUN_AUTHORITY"
    )
    _check(
        document["status"] == "OBSERVED"
        and document["profile"] == _PROFILE
        and document["image"] == _IMAGE
    )
    _check(all(document[name] is False for name in _FALSE))
    _check(document["owned_container_removed"] is True)  # Report, not attestation.
    before, final = document["before"], document["final"]
    _check(before["container"]["State"] == final["container"]["State"])
    _check(_sensor(before) == _sensor(final))
    _check(before["info"]["stdout"] == final["info"]["stdout"])
    for item, status in (
        (document["container_initial"], "created"),
        (before["container"], "running"),
        (final["container"], "running"),
        (document["shutdown"]["container"], "exited"),
    ):
        host, state = item["HostConfig"], item["State"]
        _check(
            item["Id"] == _ID
            and item["Image"] == _IMAGE.split("@")[1]
            and item["Config"]["Image"] == _IMAGE
        )
        _check(item["Config"]["Labels"] == {"dev.aragorn.fixture-owner": _PROFILE})
        _check(item["Config"] == document["container_initial"]["Config"])
        expected_host = dict(document["container_initial"]["HostConfig"])
        _check(expected_host["OomKillDisable"] is False)
        if status != "created":
            # Docker's retained post-start inspect changes this optional field
            # from false to null; all other host fields remain identical.
            expected_host["OomKillDisable"] = None
        _check(host == expected_host)
        _check(
            host["NetworkMode"] == "none"
            and host["Privileged"] is True
            and host["PidMode"] == host["CgroupnsMode"] == "host"
        )
        _check(
            host["SecurityOpt"] == ["no-new-privileges", "label=disable"]
            and host["Binds"] is None
            and host["PortBindings"] == {}
        )
        _check(
            host["Mounts"]
            == [
                {
                    "Type": "bind",
                    "Source": "/sys/kernel/btf/vmlinux",
                    "Target": "/var/lib/tetragon/btf",
                    "ReadOnly": True,
                }
            ]
        )
        _check(
            item["Mounts"]
            == [
                {
                    "Type": "bind",
                    "Source": "/sys/kernel/btf/vmlinux",
                    "Destination": "/var/lib/tetragon/btf",
                    "Mode": "",
                    "RW": False,
                    "Propagation": "rprivate",
                }
            ]
        )
        _check(state["Status"] == status and state["Running"] is (status == "running"))
        _check(
            all(
                state[key] is False
                for key in ("Dead", "OOMKilled", "Paused", "Restarting")
            )
        )
        _check(
            state["ExitCode"] == 0
            and state["Error"] == ""
            and item["RestartCount"] == 0
        )
    reader = document["reader"]
    _check(
        type(reader["exit_code"]) is int
        and reader["exit_code"] == 1
        and reader["stderr"] == _EOF
    )
    _check(
        reader["argv"]
        == [
            "docker",
            "--context",
            "colima-" + _PROFILE,
            "exec",
            _ID,
            "/usr/bin/tetra",
            "--server-address",
            "unix:///var/run/tetragon/tetragon.sock",
            "--timeout",
            "5s",
            "--retries",
            "1",
            "--max-recv-size",
            "65536",
            "getevents",
            "--output",
            "json",
            "--event-types",
            "PROCESS_EXEC,PROCESS_EXIT",
            "--process",
            "^" + _BINARY + "$",
            "--reconnect=false",
        ]
    )
    stream = reader["stdout"].encode("utf-8")
    _pin(stream, _STREAM)
    lines = stream.splitlines(keepends=True)
    _check(len(lines) == 6 and all(line.endswith(b"\n") for line in lines))
    parsed = [process._event(line) for line in lines]
    _check(all(e["wall_time_ordering_verified"] is False for e in parsed))
    _check(
        all(
            all(v is None for v in e["unavailable_attribution"].values())
            for e in parsed
        )
    )
    records = [e["vendor_record"] for e in parsed]
    _marker_joins(
        records, document["markers"], before["container"]["Config"]["Hostname"]
    )
    metrics = _metrics(before["metrics"]["stdout"])
    _check(metrics == _metrics(final["metrics"]["stdout"]))
    return records, metrics


class TetragonIsolatedSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = _read(_ROOT / _OBSERVATION, _PINS[0])
        cls.helper = _read(_ROOT / _HELPER, _PINS[1])
        cls.document = _load(cls.raw, cls.helper)

    def test_fixed_original_bytes_six_records_and_snapshot_joins(self):
        self.assertFalse(self.raw.endswith(b"\n"))
        records, metrics = _replay(self.document)
        self.assertEqual(len(records), 6)
        self.assertIsNone(metrics[_BPF])
        self.assertEqual(
            sum(value["series"] for value in metrics.values() if value is not None), 32
        )
        self.assertEqual(_sensor(self.document["before"])[0:2], (4737, 127972))

    def test_bounds_hashes_and_inert_helper_precede_json_parse(self):
        for original, pin in ((self.raw, _PINS[0]), (self.helper, _PINS[1])):
            path = mock.MagicMock()
            stream = path.open.return_value.__enter__.return_value
            stream.read.return_value = original
            self.assertEqual(_read(path, pin), original)
            path.open.assert_called_once_with("rb")
            stream.read.assert_called_once_with(pin[0] + 1)
            for invalid in (
                None,
                bytearray(original),
                b"",
                original[:-1],
                original + b"\n",
            ):
                with (
                    mock.patch(
                        __name__ + "._digest",
                        side_effect=AssertionError("hashed invalid bound"),
                    ),
                    self.assertRaises(ValueError),
                ):
                    _pin(invalid, pin)
        for raw, helper in (
            (b"x" + self.raw[1:], self.helper),
            (self.raw, b"x" + self.helper[1:]),
        ):
            with (
                mock.patch.object(
                    process,
                    "_json",
                    side_effect=AssertionError("parsed unpinned input"),
                ),
                self.assertRaises(ValueError),
            ):
                _load(raw, helper)

    def test_marker_and_cached_identity_contradictions(self):
        records, _ = _replay(self.document)
        node = self.document["before"]["container"]["Config"]["Hostname"]
        for mutation in (
            "count",
            "pid",
            "parent",
            "binary",
            "exec-id",
            "start",
            "node",
            "order",
        ):
            changed, markers = (
                copy.deepcopy(records),
                copy.deepcopy(self.document["markers"]),
            )
            if mutation == "count":
                changed.pop()
            elif mutation == "order":
                changed[0], changed[1] = changed[1], changed[0]
            elif mutation == "pid":
                markers[0]["pid"] += 1
            elif mutation == "parent":
                markers[0]["parent_pid"] += 1
            elif mutation == "node":
                changed[0]["node_name"] = "unrelated"
            else:
                name = {
                    "binary": "binary",
                    "exec-id": "exec_id",
                    "start": "start_time",
                }[mutation]
                changed[1]["process_exit"]["process"][name] = (
                    "2026-09-13T08:18:06Z" if mutation == "start" else "unrelated"
                )
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                _marker_joins(changed, markers, node)

    def test_missing_metric_cannot_be_filled_and_present_counters_stay_exact(self):
        raw = self.document["before"]["metrics"]["stdout"]
        singleton = "tetragon_observer_ringbuf_events_lost_total 0"
        for changed in (
            raw + _BPF + " 0\n",
            raw + "# TYPE " + _BPF + " counter\n",
            raw.replace(singleton, singleton[:-1] + "1"),
            raw + singleton + "\n",
            raw.replace(singleton + "\n", ""),
        ):
            with self.assertRaises(ValueError):
                _metrics(changed)

    def test_reader_failure_false_ceilings_and_reported_cleanup_are_not_promoted(self):
        for field in _FALSE:
            for value in (True, 0, None):
                document = copy.deepcopy(self.document)
                document[field] = value
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    _replay(document)
        for mutation in (
            "reader-code",
            "reader-message",
            "cleanup",
            "mount",
            "process-start",
            "parent-scope",
        ):
            document = copy.deepcopy(self.document)
            if mutation == "reader-code":
                document["reader"]["exit_code"] = 0
            elif mutation == "reader-message":
                document["reader"]["stderr"] = ""
            elif mutation == "cleanup":
                document["owned_container_removed"] = False
            elif mutation == "mount":
                document["final"]["container"]["Mounts"][0]["RW"] = True
            else:
                native = json.loads(document["final"]["process"]["stdout"])
                if mutation == "process-start":
                    native["stat"] = native["stat"].replace(" 127972 ", " 127973 ")
                else:
                    native["cgroup"] = "0::/docker/" + "a" * 64 + "\n"
                document["final"]["process"]["stdout"] = json.dumps(native)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                _replay(document)


if __name__ == "__main__":
    unittest.main()
