"""New fabricated packet cases only; no observer, transport or historical fixture."""

import base64
import copy
import hashlib
import json
import unittest

from aragorn.native_phase3_broker_reader_protocol import (
    validate_guard_request, validate_guard_response,
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def pin(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def artifact(raw):
    return {"base64": base64.b64encode(raw).decode("ascii"), "bytes": len(raw), "digest": pin(raw)}


def fabricated_pair():
    request = {
        "schema": "aragorn/native-phase3-broker-reader-request/v1",
        "exchange_id": "a" * 64, "phase": "BEFORE_CONNECT",
        "context_digest": pin(b"context"), "epoch_digest": pin(b"epoch"),
        "request_digest": pin(b"request"), "effect_digest": pin(b"effect"),
        "deadline_boottime_ns": 500, "previous_response_digest": None,
    }
    bindings = {key: pin(key.encode("ascii")) for key in
                ("epoch", "challenge", "request", "process", "clock", "loss_scope", "policy")}
    loss = {
        "epoch_digest": bindings["epoch"], "challenge_digest": bindings["challenge"],
        "request_digest": bindings["request"], "scope_digest": bindings["loss_scope"],
        "before": {"start_ns": 1, "end_ns": 2, "counters": [3, 4]},
        "after": {"start_ns": 20, "end_ns": 21, "counters": [3, 4]},
    }
    evidence = artifact(b"fabricated-reader-bytes")
    response = {
        "schema": "aragorn/native-phase3-broker-reader-response/v1",
        "request_packet_digest": pin(canonical(request)),
        **{key: request[key] for key in ("exchange_id", "phase", "context_digest",
                                        "epoch_digest", "request_digest", "effect_digest")},
        "received_ns": 10, "finished_ns": 22, "status": "EVIDENCE", "error_codes": [],
        "reader_connection_epoch": "b" * 64, "bindings": bindings,
        "reader_evidence": evidence, "reader_summary": artifact(b"opaque-summary"),
        "reader_retention": {"digest": evidence["digest"], "bytes": evidence["bytes"]},
        "loss_record": artifact(canonical(loss)), "checkpoint_record": artifact(b"opaque-checkpoint"),
        "acquisition_authenticity_verified": False, "sensor_health_verified": False,
        "effect_authorized": False, "run_qualified": False, "phase3_qualified": False,
    }
    return request, response


class BrokerReaderProtocolTests(unittest.TestCase):
    def setUp(self):
        self.request, self.response = fabricated_pair()
        self.request_raw = canonical(self.request)

    def parse(self, response):
        return validate_guard_response(canonical(response), request_raw=self.request_raw)

    def reject_response(self, response):
        with self.assertRaises(ValueError):
            self.parse(response)

    def test_detached_structural_packets_and_opaque_artifacts(self):
        parsed = validate_guard_request(self.request_raw)
        parsed["phase"] = "changed"
        self.assertEqual(validate_guard_request(self.request_raw), self.request)
        parsed_response = self.parse(self.response)
        self.assertEqual(parsed_response, self.response)
        parsed_response["bindings"]["epoch"] = "changed"
        self.assertEqual(self.parse(self.response), self.response)
        for key in ("acquisition_authenticity_verified", "sensor_health_verified",
                    "effect_authorized", "run_qualified", "phase3_qualified"):
            self.assertIs(self.parse(self.response)[key], False)

    def test_canonical_ascii_duplicate_nonfinite_and_trailing_refusals(self):
        for raw in (self.request_raw + b"\n", b" " + self.request_raw,
                    self.request_raw[:-1] + b',"phase":"BEFORE_CONNECT"}',
                    self.request_raw.replace(b'"deadline_boottime_ns":500', b'"deadline_boottime_ns":NaN'),
                    self.request_raw.replace(b'"deadline_boottime_ns":500', b'"deadline_boottime_ns":1e999'),
                    b'"\xff"', b"[" * 2000 + b"]" * 2000, bytearray(self.request_raw)):
            with self.subTest(raw_type=type(raw).__name__, length=len(raw)), self.assertRaises(ValueError):
                validate_guard_request(raw)
        with self.assertRaises(ValueError):
            validate_guard_response(canonical(self.response) + b"{}", request_raw=self.request_raw)

    def test_request_exact_fields_pins_phase_and_uint(self):
        mutants = []
        for key, value in (("phase", "AFTER_CONNECT"), ("exchange_id", "A" * 64),
                           ("deadline_boottime_ns", True), ("deadline_boottime_ns", 0),
                           ("deadline_boottime_ns", 2**63), ("context_digest", "sha256:" + "g" * 64),
                           ("previous_response_digest", pin(b"previous")), ("extra", 1)):
            item = dict(self.request)
            item[key] = value
            mutants.append(item)
        item = dict(self.request)
        del item["effect_digest"]
        mutants.append(item)
        for item in mutants:
            with self.subTest(item=item), self.assertRaises(ValueError):
                validate_guard_request(canonical(item))
        second = dict(self.request, phase="BEFORE_PAYLOAD_SEND", previous_response_digest=pin(b"previous"))
        self.assertEqual(validate_guard_request(canonical(second)), second)
        second["previous_response_digest"] = None
        with self.assertRaises(ValueError):
            validate_guard_request(canonical(second))

    def test_packet_bounds_are_enforced_before_parse(self):
        for raw in (b"", b" " * 4097):
            with self.assertRaises(ValueError):
                validate_guard_request(raw)
        for raw in (b"", b" " * 262145):
            with self.assertRaises(ValueError):
                validate_guard_response(raw, request_raw=self.request_raw)

    def test_response_echoes_flags_and_error_enum(self):
        for key in ("request_packet_digest", "exchange_id", "phase", "context_digest",
                    "epoch_digest", "request_digest", "effect_digest"):
            with self.subTest(key=key):
                item = copy.deepcopy(self.response)
                item[key] = "substitution"
                self.reject_response(item)
        for key in ("acquisition_authenticity_verified", "sensor_health_verified",
                    "effect_authorized", "run_qualified", "phase3_qualified"):
            for value in (True, 0, None):
                with self.subTest(key=key, value=value):
                    self.reject_response(dict(self.response, **{key: value}))
        for codes in (["UNKNOWN"], ["READER_REFUSED", "READER_REFUSED"],
                      ["READER_REFUSED", "INPUT_REFUSED"], [True], "READER_REFUSED"):
            self.reject_response(dict(self.response, status="REFUSED", error_codes=codes))
        self.reject_response(dict(self.response, status="REFUSED", error_codes=[]))
        self.reject_response(dict(self.response, status="EVIDENCE", error_codes=["READER_REFUSED"]))
        self.reject_response(dict(self.response, healthy=True))

    def test_artifact_strict_base64_length_digest_and_decoded_bounds(self):
        for key, value in (("base64", "!"), ("base64", "Zg==\n"), ("base64", "Zh=="),
                           ("bytes", 0), ("bytes", True), ("bytes", 1), ("digest", pin(b"wrong")),
                           ("extra", 0)):
            item = copy.deepcopy(self.response)
            item["reader_summary"][key] = value
            self.reject_response(item)
        for name, maximum in (("reader_evidence", 131072), ("reader_summary", 32768),
                              ("checkpoint_record", 16384), ("loss_record", 8192)):
            with self.subTest(artifact=name):
                item = copy.deepcopy(self.response)
                item[name] = artifact(b"x" * (maximum + 1))
                self.reject_response(item)
        item = copy.deepcopy(self.response)
        item["reader_summary"] = artifact(b"\x00\xff")
        self.assertEqual(self.parse(item), item)  # Opaque is deliberately not a semantic JSON claim.

    def test_retention_join_and_partial_refusal_preserve_available_bytes(self):
        partial = dict(self.response, status="REFUSED", error_codes=["RETENTION_FAILED"],
                       reader_retention=None, checkpoint_record=None)
        self.assertEqual(self.parse(partial), partial)
        absent = dict(partial, **{key: None for key in ("reader_evidence", "reader_summary", "bindings",
                                                       "reader_connection_epoch", "loss_record")})
        self.assertEqual(self.parse(absent), absent)
        for key in ("reader_retention", "reader_evidence", "reader_summary", "reader_connection_epoch",
                    "bindings", "loss_record", "checkpoint_record"):
            self.reject_response(dict(self.response, **{key: None}))
        for receipt in ({"digest": pin(b"other"), "bytes": 23},
                        {"digest": self.response["reader_evidence"]["digest"], "bytes": True}):
            self.reject_response(dict(self.response, reader_retention=receipt))

    def test_loss_binding_substitutions_and_missing_binding_refuse(self):
        loss = json.loads(base64.b64decode(self.response["loss_record"]["base64"]))
        for key in ("epoch_digest", "challenge_digest", "request_digest", "scope_digest"):
            changed = dict(loss, **{key: pin(b"other")})
            self.reject_response(dict(self.response, loss_record=artifact(canonical(changed))))
        self.reject_response(dict(self.response, status="REFUSED", error_codes=["LOSS_UNAVAILABLE"], bindings=None))
        for key in ("epoch", "request"):
            item = copy.deepcopy(self.response)
            item["bindings"][key] = pin(b"other")
            self.reject_response(item)

    def test_unknown_reset_increased_loss_and_late_packets_are_structural_evidence(self):
        loss = json.loads(base64.b64decode(self.response["loss_record"]["base64"]))
        for counters in ([None, 4], [2, 4], [4, 4]):
            changed = copy.deepcopy(loss)
            changed["after"]["counters"] = counters
            item = dict(self.response, loss_record=artifact(canonical(changed)))
            self.assertEqual(self.parse(item), item)
        loss["after"] = None
        item = dict(self.response, loss_record=artifact(canonical(loss)), received_ns=600, finished_ns=601)
        self.assertEqual(self.parse(item), item)  # Actual receipt freshness is the journal's job.

    def test_loss_sample_exact_keys_counter_shape_and_times(self):
        original = json.loads(base64.b64decode(self.response["loss_record"]["base64"]))
        for field, value in (("counters", []), ("counters", [0] * 33), ("counters", [1]),
                             ("counters", [True, 4]), ("counters", [-1, 4]),
                             ("counters", [2**63, 4]), ("end_ns", 19), ("start_ns", False), ("extra", 1)):
            loss = copy.deepcopy(original)
            loss["after"][field] = value
            self.reject_response(dict(self.response, loss_record=artifact(canonical(loss))))
        for key, value in (("received_ns", False), ("finished_ns", 9), ("reader_connection_epoch", "0" * 63)):
            self.reject_response(dict(self.response, **{key: value}))


if __name__ == "__main__":
    unittest.main()
