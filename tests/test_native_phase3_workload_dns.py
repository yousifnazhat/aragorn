"""Fabricated retained records only; no sockets, clocks, native effects or fixtures."""

import copy
import hashlib
import unittest
from unittest.mock import patch

from aragorn import native_phase3_workload_dns_canary as builder
from aragorn import native_phase3_workload_dns_verify as consumer
from aragorn.oci_worker_protocol import canonical_json


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def row(raw, sequence=0, timestamp=100):
    return {
        "sequence": sequence, "peer_host": "127.0.0.1", "peer_port": 40000,
        "received_boottime_ns": timestamp, "wire_bytes": len(raw), "raw_hex": raw.hex(),
        "msg_trunc": False, "msg_ctrunc": False, "receive_error": None,
        "disposition": "ACCEPTED",
    }


class DnsCanaryTests(unittest.TestCase):
    def setUp(self):
        fixture = {"container_id": "a" * 64, "boot_id": "12345678-1234-1234-1234-123456789abc",
                   "netns_device": 4, "netns_inode": 5}
        init = {"pid": 1, "start_time_ticks": 1, "uid": 0, "gid": 0}
        observer = {"fixture": fixture, "init_process": init, "socket_inode": 20,
                    "process": {"pid": 2, "start_time_ticks": 3, "uid": 0, "gid": 0}}
        client = {"fixture": copy.deepcopy(fixture), "init_process": copy.deepcopy(init),
                  "process": {"pid": 3, "start_time_ticks": 4, "uid": 1000, "gid": 1000}}
        clock = {"clock_id": "CLOCK_BOOTTIME", "boot_id": fixture["boot_id"],
                 "time_namespace_device": 4, "time_namespace_inode": 6,
                 "monotonic_offset_ns": -10, "boottime_offset_ns": 0}
        interval = {"readiness_started_ns": 10, "started_ns": 100, "finished_ns": 2_000_000_100}
        self.expected = {
            "expected_attempt_id": "p3-lab-a026", "expected_readiness_nonce": "a" * 32,
            "expected_endpoint": {"host": "127.0.0.1", "port": 47632, "transport": "UDP"},
            "expected_observer": observer, "expected_readiness_client": client,
            "expected_clock_domain": clock, "expected_interval": interval,
            "expected_loss_source_digest": "sha256:" + "b" * 64,
        }
        common = {
            "authority": "OWNED_LAB_RAW_DATAGRAM_OBSERVATION_ONLY", "attempt_id": "p3-lab-a026",
            "readiness_nonce": "a" * 32, "endpoint": self.expected["expected_endpoint"],
            "observer_identity_before": observer, "observer_identity_after": copy.deepcopy(observer),
            "clock_domain": clock, "interval": interval, "complete": True, "socket_closed": True,
            "errors": [], **dict.fromkeys(consumer.FALSE_FLAGS, False),
        }
        # Literal wire fixtures are independent of both production implementations.
        self.query = bytes.fromhex("001a00000001000000000000") + b"\x14p3canary-p3-lab-a026\x05exfil\x07invalid\x00\x00\x01\x00\x01"
        probe = bytes.fromhex("ffff00000001000000000000") + b"\x0daragorn-ready\x20" + b"a" * 32 + b"\x07invalid\x00\x00\x01\x00\x01"
        self.observation = {
            **copy.deepcopy(common), "schema": "aragorn/native-dns-canary-observation/v1",
            "datagrams": [row(self.query)],
            "readiness": {"request": row(probe, timestamp=20),
                          "response_hex": (probe[:2] + b"\x80\x00" + probe[4:]).hex(),
                          "response_sent_ns": 30, "client_received_ns": 40, "client_identity": client},
        }
        before = {"boottime_ns": 5, "received_datagrams": 7, "socket_drops": 1,
                  "observer_drops": 0, "receive_errors": 0, "truncated_datagrams": 0}
        self.coverage = {
            **copy.deepcopy(common), "schema": "aragorn/native-dns-canary-coverage/v1",
            "observation_digest": "", "loss_source_digest": self.expected["expected_loss_source_digest"],
            "exclusive_socket": True, "final_queue_drained": True, "before": before,
            "after": {**before, "boottime_ns": interval["finished_ns"], "received_datagrams": 9},
        }

    def verify(self, observation=None, coverage=None, expected=None):
        observation = self.observation if observation is None else observation
        coverage = copy.deepcopy(self.coverage if coverage is None else coverage)
        raw = canonical_json(observation)
        coverage["observation_digest"] = digest(raw)
        coverage_raw = canonical_json(coverage)
        return consumer.verify_dns_observation(
            raw, coverage_raw, expected_observation_digest=digest(raw),
            expected_coverage_digest=digest(coverage_raw),
            **(self.expected if expected is None else expected),
        )

    def test_exact_builder_wire_all_reserved_attempts_and_readiness(self):
        self.assertEqual((builder.HOST, builder.PORT, builder.TRANSPORT), ("127.0.0.1", 47632, "UDP"))
        for number in range(26, 51):
            attempt = f"p3-lab-a{number:03}"
            expected = number.to_bytes(2, "big") + self.query[2:].replace(b"a026", f"a{number:03}".encode())
            self.assertEqual(builder.canary_request(attempt), expected)
        self.assertEqual(builder.readiness_request("a" * 32), bytes.fromhex(self.observation["readiness"]["request"]["raw_hex"]))
        for bad in (None, True, 26, "p3-lab-a025", "p3-lab-a051", "p3-lab-a026\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.canary_request(bad)
        for bad in (None, 1, "A" * 32, "a" * 31, "a" * 32 + "\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.readiness_request(bad)

    def test_consumer_independent_and_exact_claim_ceiling(self):
        with patch.object(builder, "canary_request", side_effect=AssertionError), patch.object(
            builder, "readiness_request", side_effect=AssertionError
        ):
            result = self.verify()
        self.assertEqual(set(result), {"schema", "status", "attempt_id", "observation_digest",
                                      "coverage_digest", "datagrams", "captured_bytes", "marker_present",
                                      "limitations", *consumer.FALSE_FLAGS})
        self.assertEqual(result["status"], "CONSISTENT_BOUNDED_DATAGRAM_EVIDENCE")
        self.assertEqual(result["captured_bytes"], len(self.query))
        self.assertIs(result["marker_present"], True)
        self.assertTrue(all(result[k] is False for k in consumer.FALSE_FLAGS))
        self.assertIn("NO_CAUSAL_ATTRIBUTION_BLOCKED_EXFILTRATION_OR_QUALIFICATION", result["limitations"])

    def test_empty_interval_and_zero_length_packet_are_not_blocking(self):
        for rows in ([], [row(b"")]):
            observation, coverage = copy.deepcopy(self.observation), copy.deepcopy(self.coverage)
            observation["datagrams"] = rows
            coverage["after"]["received_datagrams"] = 8 + len(rows)
            result = self.verify(observation, coverage)
            self.assertEqual(result["datagrams"], len(rows))
            self.assertEqual(result["captured_bytes"], 0)
            self.assertIs(result["marker_present"], False)
            self.assertIs(result["blocked_pre_effect"], False)

    def test_scan_malformed_refused_case_and_other_attempt_contamination(self):
        for disposition in ("ACCEPTED", "MALFORMED", "REFUSED"):
            observation = copy.deepcopy(self.observation)
            observation["datagrams"] = [{**row(b"broken\xffP3CANARY-P3-LAB-A026"), "disposition": disposition}]
            self.assertIs(self.verify(observation)["marker_present"], True)
            for other in (1, 25, 27, 50, 51, 100):
                observation["datagrams"][0].update(row(f"p3canary-p3-lab-a{other:03}".encode()))
                observation["datagrams"][0]["disposition"] = disposition
                with self.subTest(disposition=disposition, other=other), self.assertRaises(ValueError):
                    self.verify(observation)

    def test_partial_attempt_prefix_is_not_presence(self):
        for number in range(26, 51):
            attempt = f"p3-lab-a{number:03}"
            marker = b"p3canary-" + attempt.encode("ascii")
            self.assertEqual(len(marker), 20)
            for disposition in ("ACCEPTED", "MALFORMED", "REFUSED"):
                for payload, present in ((marker[:-1], False), (marker[:-1] + b"x", False), (marker, True)):
                    observation, coverage = copy.deepcopy(self.observation), copy.deepcopy(self.coverage)
                    expected = copy.deepcopy(self.expected)
                    observation["attempt_id"] = coverage["attempt_id"] = attempt
                    expected["expected_attempt_id"] = attempt
                    observation["datagrams"] = [{**row(payload), "disposition": disposition}]
                    with self.subTest(attempt=attempt, disposition=disposition, payload=payload):
                        result = self.verify(observation, coverage, expected)
                        self.assertIs(result["marker_present"], present)
                        self.assertEqual(result["attempt_id"], attempt)

    def test_datagram_refusals(self):
        changes = {"sequence": [True, 1], "peer_host": ["127.0.0.2"], "peer_port": [True, 0, 65536],
                   "received_boottime_ns": [99, 2_000_000_101, True], "wire_bytes": [True, 0],
                   "raw_hex": ["a", "GG", "AA", "00" * 4097], "msg_trunc": [True, 0],
                   "msg_ctrunc": [True], "receive_error": ["REFUSED"], "disposition": ["IGNORED"]}
        for key, values in changes.items():
            for value in values:
                observation = copy.deepcopy(self.observation)
                observation["datagrams"][0][key] = value
                with self.subTest(key=key, value=str(value)[:30]), self.assertRaises(ValueError):
                    self.verify(observation)
        observation = copy.deepcopy(self.observation)
        observation["datagrams"] *= 16
        with self.assertRaises(ValueError):
            self.verify(observation)
        observation["datagrams"] = [row(b"", 0, 102), row(b"", 1, 101)]
        coverage = copy.deepcopy(self.coverage)
        coverage["after"]["received_datagrams"] = 10
        with self.assertRaises(ValueError):
            self.verify(observation, coverage)

    def test_maximum_retained_rows_bytes_and_interval_edges(self):
        observation, coverage = copy.deepcopy(self.observation), copy.deepcopy(self.coverage)
        observation["datagrams"] = [row(b"x" * 4096, i, 100 + i) for i in range(15)]
        observation["datagrams"][-1]["received_boottime_ns"] = 2_000_000_100
        coverage["after"]["received_datagrams"] = 23
        result = self.verify(observation, coverage)
        self.assertEqual(result["datagrams"], 15)
        self.assertEqual(result["captured_bytes"], 15 * 4096)
        self.assertIs(result["marker_present"], False)

    def test_missing_extra_and_strict_flags(self):
        for document_name in ("observation", "coverage"):
            for key in getattr(self, document_name):
                observation, coverage = copy.deepcopy(self.observation), copy.deepcopy(self.coverage)
                del (observation if document_name == "observation" else coverage)[key]
                # verify() intentionally supplies the cross-pin; exercise that missing key below.
                if key == "observation_digest":
                    continue
                with self.subTest(document=document_name, key=key), self.assertRaises(ValueError):
                    self.verify(observation, coverage)
            for key, value in [("extra", 1), ("complete", 1), ("socket_closed", False),
                               ("errors", ["FAILED"])] + [(k, 0) for k in consumer.FALSE_FLAGS]:
                observation, coverage = copy.deepcopy(self.observation), copy.deepcopy(self.coverage)
                (observation if document_name == "observation" else coverage)[key] = value
                with self.subTest(document=document_name, key=key), self.assertRaises(ValueError):
                    self.verify(observation, coverage)

    def test_binding_substitution(self):
        paths = [("attempt_id",), ("readiness_nonce",), ("endpoint", "port"),
                 ("observer_identity_before", "socket_inode"),
                 ("observer_identity_after", "process", "start_time_ticks"),
                 ("observer_identity_after", "fixture", "netns_inode"),
                 ("clock_domain", "boottime_offset_ns"), ("interval", "finished_ns")]
        for document_name in ("observation", "coverage"):
            for path in paths:
                observation, coverage = copy.deepcopy(self.observation), copy.deepcopy(self.coverage)
                target = observation if document_name == "observation" else coverage
                for part in path[:-1]:
                    target = target[part]
                value = target[path[-1]]
                target[path[-1]] = value + 1 if type(value) is int else value + "x"
                with self.subTest(document=document_name, path=path), self.assertRaises(ValueError):
                    self.verify(observation, coverage)

    def test_expected_context_is_validated_not_just_equal(self):
        changes = [("expected_endpoint", "port", True), ("expected_clock_domain", "clock_id", "CLOCK_MONOTONIC"),
                   ("expected_clock_domain", "monotonic_offset_ns", -2**63 - 1),
                   ("expected_clock_domain", "boottime_offset_ns", 2**63),
                   ("expected_interval", "finished_ns", 101), ("expected_interval", "started_ns", True)]
        for name, key, value in changes:
            expected = copy.deepcopy(self.expected)
            expected[name][key] = value
            observation, coverage = copy.deepcopy(self.observation), copy.deepcopy(self.coverage)
            for document in (observation, coverage):
                document[name.removeprefix("expected_")] = expected[name]
            with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                self.verify(observation, coverage, expected)
        for field in ("pid", "start_time_ticks", "uid", "gid"):
            expected = copy.deepcopy(self.expected)
            expected["expected_observer"]["process"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(expected=expected)
        expected = copy.deepcopy(self.expected)
        expected["expected_readiness_client"]["process"]["pid"] = 2
        with self.assertRaises(ValueError):
            self.verify(expected=expected)

    def test_readiness_requires_distinct_exact_exchange_and_client(self):
        for path, value in [(("response_hex",), ""), (("response_sent_ns",), 19),
                            (("client_received_ns",), 100), (("client_received_ns",), True),
                            (("request", "raw_hex"), self.query.hex()),
                            (("request", "disposition"), "REFUSED"),
                            (("client_identity", "process", "pid"), 99)]:
            observation = copy.deepcopy(self.observation)
            target = observation["readiness"]
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.verify(observation)

    def test_coverage_loss_resets_overflow_and_incomplete_evidence(self):
        for key in self.coverage["before"]:
            for value in (-1, True, 2**63):
                coverage = copy.deepcopy(self.coverage)
                coverage["after"][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.verify(coverage=coverage)
        for key in ("socket_drops", "observer_drops", "receive_errors", "truncated_datagrams"):
            coverage = copy.deepcopy(self.coverage)
            coverage["after"][key] += 1
            with self.subTest(loss=key), self.assertRaises(ValueError):
                self.verify(coverage=coverage)
        for key, value in (("socket_drops", 0), ("received_datagrams", 8), ("boottime_ns", 99)):
            coverage = copy.deepcopy(self.coverage)
            coverage["after"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(coverage=coverage)
        for key, value in (("loss_source_digest", "sha256:" + "c" * 64),
                           ("exclusive_socket", False), ("final_queue_drained", 1)):
            coverage = copy.deepcopy(self.coverage)
            coverage[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(coverage=coverage)

    def test_raw_pins_canonical_json_bounds_and_cross_pin(self):
        observation_raw = canonical_json(self.observation)
        coverage = {**self.coverage, "observation_digest": digest(observation_raw)}
        coverage_raw = canonical_json(coverage)
        for raw in (b"", b" " * 262144, b"{", observation_raw + b"\n",
                    observation_raw.replace(b'"complete":true', b'"complete":true,"complete":true'),
                    observation_raw.replace(b'"sequence":0', b'"sequence":NaN')):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                consumer.verify_dns_observation(raw, coverage_raw,
                    expected_observation_digest=digest(raw), expected_coverage_digest=digest(coverage_raw), **self.expected)
        for side in ("observation", "coverage"):
            pins = {"expected_observation_digest": digest(observation_raw), "expected_coverage_digest": digest(coverage_raw)}
            pins[f"expected_{side}_digest"] = "sha256:" + "0" * 64
            with self.subTest(side=side), self.assertRaises(ValueError):
                consumer.verify_dns_observation(observation_raw, coverage_raw, **pins, **self.expected)
        for cross_pin in (None, "sha256:" + "0" * 64):
            altered = copy.deepcopy(coverage)
            if cross_pin is None:
                del altered["observation_digest"]
            else:
                altered["observation_digest"] = cross_pin
            raw = canonical_json(altered)
            with self.assertRaises(ValueError):
                consumer.verify_dns_observation(observation_raw, raw,
                    expected_observation_digest=digest(observation_raw), expected_coverage_digest=digest(raw), **self.expected)
