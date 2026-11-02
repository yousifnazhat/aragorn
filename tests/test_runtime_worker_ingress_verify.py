"""Inert retained-record fixtures only; no worker execution or timing evidence."""

import base64
from copy import deepcopy
import hashlib
import unittest

from aragorn import runtime_worker_ingress_verify as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


WORKER = {"pid": 100, "start_time_ticks": 1234, "uid": 997, "gid": 997}
BINDING = {
    "schema": "aragorn/runtime-action-worker-binding/v1",
    "runtime_digest": "sha256:" + "a" * 64,
    "active_skill_digest": "sha256:" + "b" * 64,
    "policy_digest": "sha256:" + "c" * 64,
    "policy_version": 1,
}
GENESIS = "sha256:" + "d" * 64
OTHER = "sha256:" + "e" * 64
STAGES = ("startup", "ingress", "attempt", "action")
FLAGS = (
    "common_deployment_fully_verified",
    "route_qualified",
    "phase3_eligible",
    "live_deployment_attested",
    "metrics_eligible",
    "application_acknowledged",
    "effect_observed",
    "broker_decision_observed",
    "elapsed_time_derived",
    "clock_domain_verified",
    "boot_observed",
)


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _rechain(records):
    previous = None
    for stage in STAGES:
        records[stage]["previous_digest"] = previous
        previous = canonical_digest(records[stage])


def _rehash_attempt(records, *, fix_tail=True):
    body = records["attempt"]["body"]
    body["attempt_digest"] = canonical_digest(body["attempt"])
    if fix_tail:
        body["receipt_state"]["receipts"][-1] = body["attempt_digest"]
    body["receipt_state_digest"] = canonical_digest(body["receipt_state"])
    records["action"]["body"]["attempt_digest"] = body["attempt_digest"]


def _fixture():
    payload = b"inert worker ingress fixture\n"
    request = {
        "schema": "aragorn/runtime-action-worker-request/v1",
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "target_name": "inert-result.txt",
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "session_id": "inert-session",
        "run_id": "inert-run",
        "tool_call_digest": "sha256:" + "1" * 64,
    }
    attempt = {
        "schema": "aragorn/native-tool-receipt/v1",
        "authority": "WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
        "genesis_digest": GENESIS,
        "sequence": 1,
        "previous_digest": GENESIS,
        "event": {
            "schema": "aragorn/native-tool-attempt/v1",
            "authority": "AUTHENTICATED_GATEWAY_REPORT_ONLY_NOT_CAUSATION_EFFECT_OR_RUN_AUTHORITY",
            "tool_name": "aragorn_runtime_create",
            "session_id": request["session_id"],
            "run_id": request["run_id"],
            "session_key_digest": "sha256:" + "2" * 64,
            "tool_call_digest": request["tool_call_digest"],
            "params_digest": "sha256:" + "3" * 64,
            "params_bytes": 16,
            "worker_request_digest": canonical_digest(request),
        },
    }
    state = {
        "schema": "aragorn/native-tool-receipt-state/v1",
        "authority": "WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
        "genesis_digest": GENESIS,
        "receipts": [canonical_digest(attempt)],
    }
    action = {
        "schema": "aragorn/runtime-action-request/v1",
        "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        **{
            key: BINDING[key]
            for key in (
                "runtime_digest",
                "active_skill_digest",
                "policy_digest",
                "policy_version",
            )
        },
        "session_id": request["session_id"],
        "run_id": request["run_id"],
        "tool_call_id": request["tool_call_digest"],
        "operation_digest": canonical_digest(
            {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
        ),
        "path_digest": "sha256:" + "4" * 64,
        "payload_digest": _digest(payload),
        "issued_at_unix": 1000,
        "expires_at_unix": 1005,
    }
    bodies = {
        "startup": {},
        "ingress": {
            "worker_request": request,
            "worker_request_digest": canonical_digest(request),
            "gateway_peer": {"pid": 200, "uid": 992, "gid": 992},
        },
        "attempt": {
            "attempt": attempt,
            "attempt_digest": canonical_digest(attempt),
            "receipt_state": state,
            "receipt_state_digest": canonical_digest(state),
            "genesis_digest": GENESIS,
            "worker_request_digest": canonical_digest(request),
        },
        "action": {
            "action_request": action,
            "action_request_digest": canonical_digest(action),
            "worker_request_digest": canonical_digest(request),
            "attempt_digest": canonical_digest(attempt),
        },
    }
    records = {
        stage: {
            "schema": "aragorn/native-worker-ingress-record/v1",
            "authority": "WORKER_LOCAL_DURABLE_INGRESS_JOINS_NOT_EFFECT_OR_RUN_AUTHORITY",
            "stage": stage,
            "previous_digest": None,
            "worker_binding": deepcopy(BINDING),
            "worker_binding_digest": canonical_digest(BINDING),
            "worker_identity": {**WORKER, "uids": [997] * 4, "gids": [997] * 4},
            "time_namespace": {"device": 4, "inode": 4026531834},
            "boottime_ns": (index + 1) * 100,
            "body": bodies[stage],
            "decision": dict.fromkeys(FLAGS, False),
            "limitations": [
                "AUTHENTICATED_NON_RECEIPT_FRAME_BEFORE_OPEN_ATTEMPT_GATE_NOT_NATIVE_CALL_START",
                "LOCAL_WORKER_OWNED_STORE_NOT_HOSTILE_OWNER_OR_ROOT_RESISTANT",
                "STARTUP_AND_ONE_INGRESS_ONLY_NO_RETRY_REPAIR_OR_RESET",
                "SELF_ACTIVE_TIME_NAMESPACE_ONLY_NO_BOOT_ID_OR_CROSS_PROCESS_CLOCK_PROOF",
                "POINT_IN_TIME_IDENTITY_READBACKS_NOT_CONTINUOUS_IMMUTABILITY",
                "NO_BROKER_DECISION_EFFECT_ACK_ELAPSED_TIME_OR_QUALIFICATION",
                "SYNC_RETENTION_ADDS_UNQUALIFIED_OVERHEAD_NO_HARD_DEADLINE",
            ],
        }
        for index, stage in enumerate(STAGES)
    }
    _rechain(records)
    return records, {
        "expected_worker": dict(WORKER),
        "expected_binding_digest": canonical_digest(BINDING),
        "expected_genesis_digest": GENESIS,
        "expected_record_digests": {
            stage: canonical_digest(row) for stage, row in records.items()
        },
    }


class WorkerIngressVerificationTests(unittest.TestCase):
    def setUp(self):
        self.records, self.arguments = _fixture()

    def verify(self, records=None, *, rechain=True, **updates):
        records = deepcopy(self.records if records is None else records)
        if rechain:
            _rechain(records)
        arguments = {
            **self.arguments,
            "expected_record_digests": {
                stage: canonical_digest(row) for stage, row in records.items()
            },
            **updates,
        }
        return subject.verify_worker_ingress_records(
            *(canonical_json(records[stage]) for stage in STAGES), **arguments
        )

    def test_valid_record_chain_is_bounded_and_returns_actual_joined_pins(self):
        result = self.verify()
        self.assertEqual(result["status"], "RETAINED_WORKER_INGRESS_CHAIN_VERIFIED")
        self.assertEqual(
            result["record_digests"], self.arguments["expected_record_digests"]
        )
        self.assertEqual(result["worker_binding_digest"], canonical_digest(BINDING))
        self.assertEqual(
            result["worker_identity"], self.records["startup"]["worker_identity"]
        )
        self.assertEqual(
            result["stage_boottime_ns"],
            {stage: (index + 1) * 100 for index, stage in enumerate(STAGES)},
        )
        self.assertEqual(
            result["action_request_digest"],
            self.records["action"]["body"]["action_request_digest"],
        )
        self.assertEqual(
            result["worker_request_digest"],
            self.records["ingress"]["body"]["worker_request_digest"],
        )
        self.assertEqual(
            result["attempt_digest"], self.records["attempt"]["body"]["attempt_digest"]
        )
        self.assertEqual(result["decision"], dict.fromkeys(FLAGS, False))
        self.assertEqual(result["limitations"], list(subject.LIMITATIONS))
        for absent in (
            "boot_id",
            "elapsed_ns",
            "broker_finalized_boottime_ns",
            "worker_request",
            "action_request",
        ):
            self.assertNotIn(absent, result)
        result["worker_identity"]["uid"] = 1
        self.assertEqual(self.records["startup"]["worker_identity"]["uid"], 997)

    def test_open_receipt_prefix_links_are_checked_without_whole_history_claim(self):
        body = self.records["attempt"]["body"]
        prefix = ["sha256:" + "5" * 64, "sha256:" + "6" * 64]
        body["attempt"]["sequence"] = 3
        body["attempt"]["previous_digest"] = prefix[-1]
        body["receipt_state"]["receipts"] = [*prefix, body["attempt_digest"]]
        _rehash_attempt(self.records)
        result = self.verify()
        self.assertEqual(result["attempt_digest"], body["attempt_digest"])
        self.assertTrue(
            any("NOT_WHOLE_HISTORY" in item for item in result["limitations"])
        )
        body["attempt"]["previous_digest"] = prefix[0]
        _rehash_attempt(self.records)
        with self.assertRaisesRegex(
            subject.WorkerIngressVerificationError, "sequence or retained tail"
        ):
            self.verify()

    def test_record_schema_chain_fields_and_claim_ceilings_are_strict(self):
        for stage in STAGES:
            for field, value in (
                ("schema", "unreviewed"),
                ("authority", "QUALIFIED"),
                ("stage", "other"),
                ("previous_digest", OTHER),
                ("limitations", []),
                ("boot_id", "unbound"),
            ):
                changed = deepcopy(self.records)
                changed[stage][field] = value
                with (
                    self.subTest(stage=stage, field=field),
                    self.assertRaises(subject.WorkerIngressVerificationError),
                ):
                    self.verify(changed, rechain=False)
        for field in FLAGS:
            for value in (True, 0):
                changed = deepcopy(self.records)
                changed["action"]["decision"][field] = value
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaisesRegex(
                        subject.WorkerIngressVerificationError, "claim ceiling"
                    ),
                ):
                    self.verify(changed)
        self.records["startup"]["body"]["clock_domain_verified"] = True
        with self.assertRaisesRegex(
            subject.WorkerIngressVerificationError, "startup body"
        ):
            self.verify()

    def test_caller_pins_worker_binding_and_genesis_are_required(self):
        for updates in (
            {
                "expected_record_digests": {
                    **self.arguments["expected_record_digests"],
                    "action": OTHER,
                }
            },
            {
                "expected_record_digests": {
                    "startup": self.arguments["expected_record_digests"]["startup"]
                }
            },
            {"expected_worker": {**WORKER, "pid": True}},
            {"expected_worker": {**WORKER, "uid": 998}},
            {"expected_binding_digest": OTHER},
            {"expected_genesis_digest": OTHER},
        ):
            with (
                self.subTest(updates=updates),
                self.assertRaises(subject.WorkerIngressVerificationError),
            ):
                self.verify(**updates)
        changed = deepcopy(self.records)
        binding = {**BINDING, "policy_version": True}
        for row in changed.values():
            row["worker_binding"] = binding
            row["worker_binding_digest"] = canonical_digest(binding)
        with self.assertRaisesRegex(
            subject.WorkerIngressVerificationError, "binding contract"
        ):
            self.verify(changed, expected_binding_digest=canonical_digest(binding))

    def test_stable_nonboolean_process_namespace_and_stamp_contracts(self):
        for stage in STAGES:
            for field, value in (
                ("pid", True),
                ("start_time_ticks", 1235),
                ("uid", 998),
                ("gids", [997, 997, True, 997]),
            ):
                changed = deepcopy(self.records)
                changed[stage]["worker_identity"][field] = value
                with (
                    self.subTest(stage=stage, field=field),
                    self.assertRaises(subject.WorkerIngressVerificationError),
                ):
                    self.verify(changed)
        for namespace in (
            {"device": 4, "inode": 0},
            {"device": True, "inode": 1},
            {"device": 4, "inode": 123},
            {"device": 4, "inode": 1, "offset_ns": 0},
        ):
            changed = deepcopy(self.records)
            changed["action"]["time_namespace"] = namespace
            with (
                self.subTest(namespace=namespace),
                self.assertRaises(subject.WorkerIngressVerificationError),
            ):
                self.verify(changed)
        for stamp in (True, -1, 2**63, 100, 99):
            changed = deepcopy(self.records)
            changed["ingress"]["boottime_ns"] = stamp
            with (
                self.subTest(stamp=stamp),
                self.assertRaises(subject.WorkerIngressVerificationError),
            ):
                self.verify(changed)

    def test_ingress_requires_actual_worker_request_payload_and_peer_shapes(self):
        for field, value in (
            ("schema", "other"),
            ("authority", "EFFECT_AUTHORITY"),
            ("target_name", "../escape"),
            ("session_id", ""),
            ("payload_base64", "YQ==\n"),
            ("payload_base64", base64.b64encode(b"x" * (32 * 1024 + 1)).decode()),
            ("tool_call_digest", "invalid"),
            ("extra", True),
        ):
            changed = deepcopy(self.records)
            body = changed["ingress"]["body"]
            body["worker_request"][field] = value
            body["worker_request_digest"] = canonical_digest(body["worker_request"])
            with (
                self.subTest(field=field, value=str(value)[:30]),
                self.assertRaises(subject.WorkerIngressVerificationError),
            ):
                self.verify(changed)
        for peer in (
            {"pid": True, "uid": 992, "gid": 992},
            {"pid": 200, "uid": 0, "gid": 992},
            {"pid": 200, "uid": 992, "gid": 992, "trusted": True},
        ):
            changed = deepcopy(self.records)
            changed["ingress"]["body"]["gateway_peer"] = peer
            with (
                self.subTest(peer=peer),
                self.assertRaisesRegex(
                    subject.WorkerIngressVerificationError, "gateway peer"
                ),
            ):
                self.verify(changed)

    def test_attempt_event_request_and_tail_state_tampering_is_refused_after_rehash(
        self,
    ):
        for mode in (
            "session",
            "run",
            "tool-call",
            "worker-request",
            "tool-name",
            "params-bool",
            "params-large",
            "sequence-bool",
            "genesis",
            "duplicate-tail",
            "even-tail",
            "wrong-tail",
            "state-schema",
        ):
            changed = deepcopy(self.records)
            body = changed["attempt"]["body"]
            receipt, state = body["attempt"], body["receipt_state"]
            event = receipt["event"]
            if mode in ("session", "run"):
                event[mode + "_id"] = "other"
            elif mode == "tool-call":
                event["tool_call_digest"] = OTHER
            elif mode == "worker-request":
                event["worker_request_digest"] = OTHER
            elif mode == "tool-name":
                event["tool_name"] = "read"
            elif mode.startswith("params-"):
                event["params_bytes"] = (
                    True if mode == "params-bool" else 16 * 1024 * 1024 + 1
                )
            elif mode == "sequence-bool":
                receipt["sequence"] = True
            elif mode == "genesis":
                receipt["genesis_digest"] = OTHER
            elif mode == "duplicate-tail":
                state["receipts"] = [OTHER, OTHER, body["attempt_digest"]]
                receipt.update(sequence=3, previous_digest=OTHER)
            elif mode == "even-tail":
                state["receipts"] = [OTHER, body["attempt_digest"]]
                receipt.update(sequence=2, previous_digest=OTHER)
            elif mode == "wrong-tail":
                state["receipts"][-1] = OTHER
            else:
                state["schema"] = "unreviewed"
            _rehash_attempt(changed, fix_tail=mode != "wrong-tail")
            with (
                self.subTest(mode=mode),
                self.assertRaises(subject.WorkerIngressVerificationError),
            ):
                self.verify(changed)

    def test_action_must_match_binding_request_attempt_payload_operation_and_lifetime(
        self,
    ):
        for field, value in (
            ("runtime_digest", OTHER),
            ("active_skill_digest", OTHER),
            ("policy_digest", OTHER),
            ("policy_version", True),
            ("session_id", "other"),
            ("run_id", "other"),
            ("tool_call_id", OTHER),
            ("operation_digest", OTHER),
            ("path_digest", "invalid"),
            ("payload_digest", OTHER),
            ("issued_at_unix", True),
            ("expires_at_unix", 1006),
            ("expires_at_unix", 2**63),
            ("authority", "EFFECT_AUTHORITY"),
            ("extra", True),
        ):
            changed = deepcopy(self.records)
            body = changed["action"]["body"]
            body["action_request"][field] = value
            body["action_request_digest"] = canonical_digest(body["action_request"])
            with (
                self.subTest(field=field, value=value),
                self.assertRaises(subject.WorkerIngressVerificationError),
            ):
                self.verify(changed)
        for field in (
            "attempt_digest",
            "worker_request_digest",
            "action_request_digest",
        ):
            changed = deepcopy(self.records)
            changed["action"]["body"][field] = OTHER
            with (
                self.subTest(field=field),
                self.assertRaises(subject.WorkerIngressVerificationError),
            ):
                self.verify(changed)

    def test_raw_records_require_canonical_pinned_bounded_integer_only_json(self):
        raws = [canonical_json(self.records[stage]) for stage in STAGES]
        for replacement, message in (
            (raws[0] + b"\n", "not canonical"),
            (b'{"x":1,"x":2}', "duplicate"),
            (b'{"x":1.0}', "noninteger"),
            (b'{"x":NaN}', "noninteger"),
            (b"x" * (subject.MAX_RECORD_BYTES + 1), "oversized"),
            (bytearray(raws[0]), "invalid or oversized"),
        ):
            pins = {
                **self.arguments["expected_record_digests"],
                "startup": _digest(replacement),
            }
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(subject.WorkerIngressVerificationError, message),
            ):
                subject.verify_worker_ingress_records(
                    replacement,
                    *raws[1:],
                    **{**self.arguments, "expected_record_digests": pins},
                )


if __name__ == "__main__":
    unittest.main()
