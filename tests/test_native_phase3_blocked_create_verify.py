"""Inert structural composition, never blocked-workload acceptance evidence.

Existing data constructors are composed, not historical test methods. Both real
worker/broker consumers run on temporary CAS bytes; no native driver, sink reader,
process, clock, service or policy mutation runs in these tests.
"""

from copy import deepcopy
import base64
import json
import stat
import unittest
from unittest.mock import patch

from aragorn import native_phase3_blocked_create_verify as subject
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests.test_native_phase3_ingress_interval_verify import JoinedData

CONTAINER = "b" * 64
SOURCE = "sha256:" + "e" * 64


def _js(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _sized(value):
    raw = canonical_json(value)
    return {"document": value, "bytes": len(raw), "digest": subject._digest(raw)}


class BlockedCreateData:
    def __init__(self):
        self.joined = JoinedData()
        j, b = self.joined, self.joined.broker
        b.process["gid"] = j.worker["gid"]
        self.call = "aragorn" + "1" * 32
        call_pin = subject._digest(self.call.encode())
        b.path["target_name"] = subject.TARGET
        b.request.update(
            path_digest=b.put(b.inputs, b.path),
            payload_digest=subject._digest(subject.PAYLOAD),
            tool_call_id=call_pin,
        )
        b.profiled["envelope"]["effect"].update(
            target_name=subject.TARGET,
            payload_base64=base64.b64encode(subject.PAYLOAD).decode(),
        )
        b.profiled["measured_action"].update(
            {
                key: b.request[key]
                for key in ("path_digest", "payload_digest", "tool_call_id")
            }
        )
        b.state["claim"]["lease"].update(
            {key: b.request[key] for key in ("path_digest", "payload_digest")}
        )
        b.plan.update(
            {key: b.request[key] for key in ("path_digest", "payload_digest")}
        )
        b.result["target_name"] = subject.TARGET
        j._rebuild_broker_request()
        request = j.records["ingress"]["body"]["worker_request"]
        request.update(
            target_name=subject.TARGET,
            payload_base64=base64.b64encode(subject.PAYLOAD).decode(),
            tool_call_digest=call_pin,
        )
        j.records["action"]["body"]["action_request"] = deepcopy(b.request)
        self.gateway = deepcopy(j.records["ingress"]["body"]["gateway_peer"])
        self.genesis = {
            "schema": "aragorn/native-tool-receipt-genesis/v1",
            "authority": "ROOT_PROVISIONED_WORKER_RECEIPT_STREAM_NOT_RUN_AUTHORITY",
            "stream_id": "sha256:" + "f" * 64,
            "worker_uid": j.worker["uid"],
            "worker_gid": j.worker["gid"],
            **{
                key: j.worker_binding[key]
                for key in ("runtime_digest", "policy_digest", "policy_version")
            },
        }
        self.genesis_pin = canonical_digest(self.genesis)
        body = j.records["attempt"]["body"]
        body["genesis_digest"] = self.genesis_pin
        body["attempt"].update(
            genesis_digest=self.genesis_pin, previous_digest=self.genesis_pin
        )
        body["receipt_state"]["genesis_digest"] = self.genesis_pin
        self.session_pin = body["attempt"]["event"]["session_key_digest"]
        self.params = {
            "content": subject.PAYLOAD.decode(),
            "target_name": subject.TARGET,
            "__aragorn_run_id": request["run_id"],
            "__aragorn_session_id": request["session_id"],
            "__aragorn_session_key_digest": self.session_pin,
            "__aragorn_tool_call_digest": call_pin,
        }
        params_raw = _js(self.params).encode()
        body["attempt"]["event"].update(
            params_digest=subject._digest(params_raw), params_bytes=len(params_raw)
        )
        j._rechain()
        self.source_result = {
            "schema": "aragorn/runtime-action-worker-result/v1",
            "authority": "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
            "status": "COMPLETED",
            "request_digest": canonical_digest(request),
            "broker_result": deepcopy(b.result),
        }
        text = canonical_json(
            {
                "schema": "aragorn/runtime-action-worker-tool-result-text/v1",
                "message": "Inert recorded BLOCK, not runtime evidence.",
                "result": self.source_result,
            }
        ).decode()
        callback = {
            "content": [{"type": "text", "text": text}],
            "details": {
                "schema": "aragorn/runtime-action-worker-openclaw-details/v1",
                "status": "blocked",
                "source_result": self.source_result,
            },
        }
        native_callback = {
            "params_json": _js(self.params),
            "result_json": _js(callback),
        }
        projection = {
            name: {
                "bytes": len(native_callback[name + "_json"].encode()),
                "digest": subject._digest(native_callback[name + "_json"].encode()),
            }
            for name in ("params", "result")
        }
        self.receipt_before = self._snapshot([])
        attempt = deepcopy(body["attempt"])
        terminal = {
            "schema": "aragorn/native-tool-receipt/v1",
            "authority": subject.receipts._RETAINED_AUTHORITY,
            "genesis_digest": self.genesis_pin,
            "sequence": 2,
            "previous_digest": canonical_digest(attempt),
            "event": {
                "schema": "aragorn/native-tool-terminal/v1",
                "authority": subject.receipts._AUTHORITY,
                "tool_name": "aragorn_runtime_create",
                **{key: attempt["event"][key] for key in subject.receipts._CORRELATION},
                "attempt_digest": canonical_digest(attempt),
                "outcome": "RETURNED",
                "result_digest": projection["result"]["digest"],
                "result_bytes": projection["result"]["bytes"],
                "error_code": None,
            },
        }
        self.receipt_after = self._snapshot([attempt, terminal])
        command = {
            "completed_at": "2026-01-01T00:00:01.000Z",
            "started_at": "2026-01-01T00:00:00.000Z",
            "error": None,
            "exit_code": 0,
            "pid": 50,
            "signal": None,
            "stderr_bytes": 0,
            "stdout_bytes": 10,
        }
        nested = self.source_result["broker_result"]
        observed = {
            "schema": "aragorn/openclaw-worker-driver-relay-summary/v1",
            "source_schema": self.source_result["schema"],
            "source_authority": self.source_result["authority"],
            "status": "COMPLETED",
            "request_digest": canonical_digest(request),
            "broker_result": {
                "source_schema": nested["schema"],
                "source_authority": nested["authority"],
                **{
                    key: nested[key]
                    for key in (
                        "verdict",
                        "effect_status",
                        "reason_codes",
                        "target_name",
                    )
                },
            },
        }
        provider = [
            {
                "authorization_valid": True,
                "contract_valid": True,
                "content_type": "application/json",
                "emitted_tool_call_id": self.call if index == 1 else None,
                "message_prefix_continuity_valid": None if index == 1 else True,
                "method": "POST",
                "path": "/v1/chat/completions",
                "received_at": "2026-01-01T00:00:01.000Z",
                "request_bytes": 10,
                "sequence": index,
                "tool_contract_valid": True,
                "tool_result_summary_digest": None
                if index == 1
                else canonical_digest(observed),
            }
            for index in (1, 2)
        ]
        self.driver = {
            "schema": subject.DRIVER_SCHEMA,
            "authority": subject.DRIVER_AUTHORITY,
            "status": "OBSERVED",
            "container_id": CONTAINER,
            "tool_name": "aragorn_runtime_create",
            "gateway": {
                "system_info": {
                    "command": deepcopy(command),
                    "response": {"pid": self.gateway["pid"]},
                }
            },
            "provider": {"request_count": 2, "error_count": 0, "records": provider},
            "turn": {
                "identifiers": {
                    "run_id": request["run_id"],
                    "session_id": request["session_id"],
                    "session_key_digest": self.session_pin,
                    "tool_call_digest": request["tool_call_digest"],
                    "request_digest": canonical_digest(request),
                    "tool_call_id": self.call,
                },
                "send": {"command": deepcopy(command), "run_id": request["run_id"]},
                "wait": {
                    "command": deepcopy(command),
                    "run_id": request["run_id"],
                    "status": "ok",
                },
                "history": {
                    "command": deepcopy(command),
                    "session_id": request["session_id"],
                },
            },
            "native_callback": native_callback,
            "native_projection": projection,
            "worker_request": _sized(deepcopy(request)),
            "source_result": _sized(self.source_result),
            "relay": {
                "observed": observed,
                "details_checks": {
                    "exact_transcript_details_schema_and_status": True,
                    "transcript_details_source_result_matches_public_content": True,
                },
            },
            "transcript_checks": {
                "exact_rpc_history_shape_without_details": True,
                "exact_transcript_rpc_tool_result_join": True,
                "transcript_regular_nonsymlink_bounded": True,
            },
            "read_transcript": None,
            "raw_callback_projection_is_source_derived": True,
            **dict.fromkeys(
                (
                    "native_ack_wire_capture",
                    "phase3_eligible",
                    "run_conformance_eligible",
                    "sink_observed",
                    "attribution_verified",
                    "elapsed_time_derived",
                ),
                False,
            ),
        }
        # Staging group is deliberately distinct from both broker process GID
        # and worker runtime GID. No account equality is inferred from UID.
        self.accounts = {
            "broker_uid": b.process["uid"],
            "broker_gid": 1003,
            "runtime_gid": j.worker["gid"],
        }
        source = {
            "bytes": 3,
            "digest": SOURCE,
            "identity": [1, 30, stat.S_IFREG | 0o444, 0, 0, 1, 3, 1, 1],
        }
        sink = {
            "schema": "aragorn/native-denied-create-sink/v1",
            "authority": "LOCAL_HELD_DIRECTORY_READBACK_NOT_EFFECT_OR_CAUSALITY_PROOF",
            "container_id": CONTAINER,
            "observer_source_digest": SOURCE,
            "observer_source": source,
            "path_descriptor": deepcopy(b.path),
            "accounts": self.accounts,
            "directories": {
                "protected": {
                    "path": "/var/lib/aragorn-runtime-action/protected",
                    "identity": [
                        b.path["root_device"],
                        b.path["root_inode"],
                        stat.S_IFDIR | 0o710,
                        self.accounts["broker_uid"],
                        self.accounts["runtime_gid"],
                    ],
                    "empty": True,
                    "scan_complete": True,
                    "entry_count_lower_bound": 0,
                },
                "staging": {
                    "path": "/var/lib/aragorn-runtime-action/staging",
                    "identity": [
                        b.path["root_device"],
                        b.path["root_inode"] + 1,
                        stat.S_IFDIR | 0o700,
                        self.accounts["broker_uid"],
                        self.accounts["broker_gid"],
                    ],
                    "empty": True,
                    "scan_complete": True,
                    "entry_count_lower_bound": 0,
                },
            },
            "target": {"name": subject.TARGET, "status": "ABSENT", "identity": None},
            "limitations": list(subject._SINK_LIMITATIONS),
            **dict.fromkeys(subject._SINK_FLAGS, False),
        }
        self.sink_before, self.sink_after = deepcopy(sink), deepcopy(sink)
        self.sink_before["phase"], self.sink_after["phase"] = "BEFORE", "AFTER"

    def _snapshot(self, receipts):
        state = {
            "schema": "aragorn/native-tool-receipt-state/v1",
            "authority": subject.receipts._RETAINED_AUTHORITY,
            "genesis_digest": self.genesis_pin,
            "receipts": [canonical_digest(row) for row in receipts],
        }
        return {
            "genesis": deepcopy(self.genesis),
            "state": state,
            "receipts": receipts,
            "state_digest": canonical_digest(state),
        }

    def arguments(self):
        args = self.joined.arguments()
        for key in list(args):
            if "clock" in key:
                del args[key]
        args.update(
            expected_genesis_digest=self.genesis_pin,
            expected_gateway=deepcopy(self.gateway),
            expected_container_id=CONTAINER,
            expected_sink_source_digest=SOURCE,
            expected_sink_accounts=deepcopy(self.accounts),
        )
        for name in (
            "driver",
            "receipt_before",
            "receipt_after",
            "sink_before",
            "sink_after",
        ):
            raw = canonical_json(getattr(self, name))
            pin = self.joined.retain(self.joined.broker.evidence, raw)
            args[name + "_raw"] = raw
            args["expected_" + name + "_digest"] = pin
        return args

    def close(self):
        self.joined.close()


class NativeBlockedCreateVerifyTests(unittest.TestCase):
    def fixture(self):
        fixture = BlockedCreateData()
        self.addCleanup(fixture.close)
        return fixture

    def test_real_component_join_does_not_promote_prevention_or_timing(self):
        fixture = self.fixture()
        args = fixture.arguments()
        with (
            patch.object(CAS, "put", side_effect=AssertionError("CAS write")),
            patch.object(CAS, "put_expected", side_effect=AssertionError("CAS write")),
            patch("time.clock_gettime_ns", side_effect=AssertionError("clock read")),
        ):
            result = subject.verify_native_blocked_create(**args)
        self.assertEqual(
            result["status"], "RETAINED_BLOCKED_CREATE_WORKLOAD_JOINS_VERIFIED"
        )
        self.assertEqual(result["recorded_return"]["verdict"], "BLOCK")
        self.assertEqual(result["decision"], dict.fromkeys(subject.FALSE_FLAGS, False))
        self.assertNotIn("broker_interval", result)
        self.assertNotIn("semantics", result)
        self.assertNotEqual(
            fixture.accounts["broker_gid"], fixture.joined.broker.process["gid"]
        )
        self.assertNotEqual(
            fixture.accounts["broker_gid"], fixture.accounts["runtime_gid"]
        )

    def test_changed_callback_actual_bytes_not_only_hashes_refuses(self):
        fixture = self.fixture()
        callback = json.loads(fixture.driver["native_callback"]["result_json"])
        callback["details"]["status"] = "completed"
        raw = _js(callback).encode()
        fixture.driver["native_callback"]["result_json"] = raw.decode()
        fixture.driver["native_projection"]["result"] = {
            "bytes": len(raw),
            "digest": subject._digest(raw),
        }
        fixture.receipt_after["receipts"][1]["event"].update(
            result_bytes=len(raw), result_digest=subject._digest(raw)
        )
        fixture.receipt_after = fixture._snapshot(fixture.receipt_after["receipts"])
        with self.assertRaises(subject.NativeBlockedCreateVerificationError):
            subject.verify_native_blocked_create(**fixture.arguments())

    def test_native_terminal_must_match_source_derived_callback_projection(self):
        fixture = self.fixture()
        terminal = fixture.receipt_after["receipts"][1]
        terminal["event"]["result_digest"] = "sha256:" + "e" * 64
        fixture.receipt_after = fixture._snapshot(fixture.receipt_after["receipts"])
        with self.assertRaises(subject.NativeBlockedCreateVerificationError):
            subject.verify_native_blocked_create(**fixture.arguments())

    def test_actual_return_request_and_gateway_joins_refuse(self):
        for change in (
            lambda f: f.driver["source_result"]["document"]["broker_result"].update(
                reason_codes=["BROKER_REPLAY_BLOCKED"]
            ),
            lambda f: f.driver["worker_request"]["document"].update(
                run_id="another-run"
            ),
            lambda f: f.driver["gateway"]["system_info"]["response"].update(pid=12345),
            lambda f: f.driver.update(container_id="c" * 64),
        ):
            fixture = self.fixture()
            change(fixture)
            # Coherently rehash the driver's document records, not just stale pins.
            for key in ("source_result", "worker_request"):
                fixture.driver[key] = _sized(fixture.driver[key]["document"])
            with self.assertRaises(subject.NativeBlockedCreateVerificationError):
                subject.verify_native_blocked_create(**fixture.arguments())

    def test_receipt_prefix_genesis_and_worker_epoch_refuse(self):
        for kind in ("prefix", "genesis", "epoch"):
            fixture = self.fixture()
            if kind == "prefix":
                fixture.receipt_before = fixture._snapshot(
                    fixture.receipt_after["receipts"]
                )
            elif kind == "genesis":
                fixture.receipt_after["genesis"]["worker_uid"] += 1
            else:
                fixture.joined._worker_epoch(
                    {**fixture.joined.worker, "start_time_ticks": 99}
                )
            with self.assertRaises(subject.NativeBlockedCreateVerificationError):
                subject.verify_native_blocked_create(**fixture.arguments())

    def test_nonempty_or_replaced_sink_and_wrong_account_refuse(self):
        for change in (
            lambda f: f.sink_after["directories"]["protected"].update(
                empty=False, scan_complete=False, entry_count_lower_bound=1
            ),
            lambda f: f.sink_after["directories"]["staging"]["identity"].__setitem__(
                1, 9000
            ),
            lambda f: f.sink_after["directories"]["staging"]["identity"].__setitem__(
                4, f.accounts["runtime_gid"]
            ),
            lambda f: f.sink_after["path_descriptor"].update(root_inode=100),
            lambda f: f.sink_after["observer_source"]["identity"].__setitem__(1, 123),
            lambda f: f.sink_after.update(phase="BEFORE"),
        ):
            fixture = self.fixture()
            change(fixture)
            with self.assertRaises(subject.NativeBlockedCreateVerificationError):
                subject.verify_native_blocked_create(**fixture.arguments())

    def test_rehashed_broker_process_group_must_be_common_runtime_group(self):
        fixture = self.fixture()
        # The broker fixture owns this actual process dictionary in its pending
        # record. arguments() rehashes the pending/evidence/completion chain and
        # passes the same changed caller expectation, so no stale pin causes
        # this refusal. The independent sink/runtime group remains unchanged.
        fixture.joined.broker.process["gid"] = fixture.accounts["broker_gid"]
        with self.assertRaises(subject.NativeBlockedCreateVerificationError):
            subject.verify_native_blocked_create(**fixture.arguments())

    def test_claim_ceiling_and_exact_boolean_refuse(self):
        for change in (
            lambda f: f.driver.update(elapsed_time_derived=True),
            lambda f: f.sink_after.update(blocked_pre_effect=True),
            lambda f: f.sink_after["directories"]["protected"].update(empty=1),
            lambda f: f.driver["transcript_checks"].update(
                exact_transcript_rpc_tool_result_join=1
            ),
        ):
            fixture = self.fixture()
            change(fixture)
            with self.assertRaises(subject.NativeBlockedCreateVerificationError):
                subject.verify_native_blocked_create(**fixture.arguments())

    def test_writable_cas_missing_blob_and_wrong_pin_refuse(self):
        fixture = self.fixture()
        args = fixture.arguments()
        with self.assertRaises(subject.NativeBlockedCreateVerificationError):
            subject.verify_native_blocked_create(
                **(args | {"evidence_cas": fixture.joined.broker.evidence})
            )
        with self.assertRaises(subject.NativeBlockedCreateVerificationError):
            subject.verify_native_blocked_create(
                **(args | {"expected_driver_digest": "sha256:" + "f" * 64})
            )
        original = CAS.read

        def read(store, pin, **kwargs):
            if pin == args["expected_receipt_after_digest"]:
                raise CASError("inert missing receipt")
            return original(store, pin, **kwargs)

        with (
            patch.object(CAS, "read", read),
            self.assertRaises(subject.NativeBlockedCreateVerificationError),
        ):
            subject.verify_native_blocked_create(**args)

    def test_final_readback_loss_refuses(self):
        fixture = self.fixture()
        args = fixture.arguments()
        count = 0
        original = CAS.read

        def read(store, pin, **kwargs):
            nonlocal count
            if pin == args["expected_driver_digest"]:
                count += 1
                if count == 2:
                    raise CASError("inert final driver custody loss")
            return original(store, pin, **kwargs)

        with (
            patch.object(CAS, "read", read),
            self.assertRaises(subject.NativeBlockedCreateVerificationError),
        ):
            subject.verify_native_blocked_create(**args)
        self.assertEqual(count, 2)

    def test_caller_expectations_are_detached_before_cas_callbacks(self):
        fixture = self.fixture()
        args = fixture.arguments()
        original = CAS.read
        mutated = False

        def read(store, pin, **kwargs):
            nonlocal mutated
            if not mutated:
                mutated = True
                args["expected_gateway"]["uid"] += 100
                args["expected_sink_accounts"]["broker_gid"] += 100
            return original(store, pin, **kwargs)

        with patch.object(CAS, "read", read):
            result = subject.verify_native_blocked_create(**args)
        self.assertEqual(
            result["status"], "RETAINED_BLOCKED_CREATE_WORKLOAD_JOINS_VERIFIED"
        )
