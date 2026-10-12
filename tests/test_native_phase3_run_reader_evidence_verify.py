"""Handcrafted Linux retained bytes; no producer, runtime harness or live syscalls."""

import ast
import base64
from copy import deepcopy
import hashlib
import inspect
import json
import unittest

from aragorn import native_phase3_run_reader_evidence_verify as verifier


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def pin(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def ucred(pid=101, uid=997, gid=998, byteorder="little"):
    return pid.to_bytes(4, byteorder, signed=True) + uid.to_bytes(4, byteorder) + gid.to_bytes(4, byteorder)


def proc_stat(pid, ticks, comm="read (a) b) c"):
    fields = ["S", *["0" for _ in range(18)], str(ticks), "0", "0"]
    return f"{pid} ({comm}) {' '.join(fields)}\n".encode("ascii")


def proc_status(uid, gid):
    return (f"Name:\treader\nUid:\t{uid} {uid} {uid} {uid}\nGid:\t{gid} {gid} {gid} {gid}\n"
            "CapInh:\t0000\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n").encode("ascii")


def fixture(status="ACK", recv_attempted=False):
    anchor = "sha256:" + "a" * 64
    process = {"boot_id": "11111111-2222-3333-4444-555555555555", "reader_pid": 101,
               "reader_start_ticks": 12, "sensor_pid": 102, "sensor_start_ticks": 13,
               "reader_uid": 997, "reader_gid": 998, "sensor_uid": 0, "sensor_gid": 0,
               "reader_source_digest": anchor, "sensor_source_digest": anchor,
               "stream_digest": anchor, "program_map_digest": anchor}
    clock = {"boot_id": process["boot_id"], "clock_id": "CLOCK_BOOTTIME", "time_namespace_inode": 99}
    epoch = {"process": process, "clock": clock, "loss_scope": [anchor],
             "policy": {"timeout_ns": 100, "max_age_ns": 50}, "deployment_digest": anchor}
    bindings = {key: pin(encode(epoch[key])) for key in ("process", "clock", "loss_scope", "policy")}
    bindings.update(epoch=pin(encode(epoch)), request=anchor)
    challenge = {"epoch_digest": bindings["epoch"], "request_digest": anchor, "boundary": "BEFORE_FIRST_EFFECT",
                 "nonce": "b" * 64, "issued_ns": 100, "deadline_ns": 200, "sequence_before": 4}
    bindings["challenge"] = pin(encode(challenge))
    connection_epoch = "c" * 64
    claim = {"schema": "aragorn/native-phase3-run-reader-claim/v1", "connection_epoch": connection_epoch,
             "challenge": challenge}
    observer = {"pid": 5000, "start_time_ticks": 33, "uid": 501, "gid": 502,
                "time_namespace": {"device": 0, "inode": 99}}
    evidence = {
        "schema": "aragorn/native-phase3-run-reader-evidence/v1", "status": status,
        "claim_attempted": True, "claim_confirmed": True, "send_attempted": True,
        "sensor_health_verified": False, "effect_authorized": False, "run_qualified": False,
        "epoch_base64": b64(encode(epoch)), "challenge_base64": b64(encode(challenge)),
        "connection_epoch": connection_epoch,
        "observed_fields": ["reader_pid", "reader_start_ticks", "reader_uid", "reader_gid", "boot_id", "clock"],
        "supplied_process_fields": ["program_map_digest", "reader_source_digest", "sensor_gid", "sensor_pid",
                                    "sensor_source_digest", "sensor_start_ticks", "sensor_uid", "stream_digest"],
        "peer_credentials_base64": b64(ucred()), "claim_base64": b64(encode(claim)),
        "claim_readback_base64": b64(encode(claim)), "send_started_ns": 120, "send_finished_ns": 130,
        "send_call_flags": 0x4040, "send_bytes": len(encode(challenge)), "accepted_ns": 160 if status == "ACK" else 220,
        "failure_type": None, "cleanup_failure_count": 0, "cleanup_failure_types": [],
        "cleanup_failure_types_complete": True, "descriptor_cleanup": [[902, "OWNED", True], [901, "OWNED", True], [701, "OWNED", True]],
    }
    for edge, start, finish in (("before", 105, 110), ("after", 150 if status == "ACK" else 200, 155 if status == "ACK" else 215)):
        evidence.update({edge + "_started_ns": start, edge + "_finished_ns": finish,
                         edge + "_pidfd_info_base64": b64(b"flags:\t02000002\nPid:\t101\nNSpid:\t101\n"),
                         edge + "_boot_base64": b64((process["boot_id"] + "\n").encode()),
                         edge + "_namespaces": {"reader": {"device": 0, "inode": 99}, "observer": {"device": 0, "inode": 99}},
                         edge + "_processes": {"reader": {"pid": 101, "start_time_ticks": 12, "uid": 997, "gid": 998},
                                               "observer": {"pid": 5000, "start_time_ticks": 33, "uid": 501, "gid": 502}}})
        for role, pid, ticks, uid, gid in (("reader", 101, 12, 997, 998), ("observer", 5000, 33, 501, 502)):
            for suffix in ("stat_before", "stat_after"):
                evidence[f"{edge}_{role}_{suffix}_base64"] = b64(proc_stat(pid, ticks))
            evidence[f"{edge}_{role}_status_base64"] = b64(proc_status(uid, gid))
    reader = {"epoch_digest": bindings["epoch"], "challenge_digest": bindings["challenge"], "request_digest": anchor,
              "process_before": deepcopy(process), "process_after": deepcopy(process),
              "clock_before": deepcopy(clock), "clock_after": deepcopy(clock), "peer": {"pid": 101, "uid": 997, "gid": 998},
              "status": status, "sequence_after": 5 if status == "ACK" else 4,
              "ack_ns": 125 if status == "ACK" else None, "received_ns": 140 if status == "ACK" else None}
    if status == "ACK":
        response = {"schema": "aragorn/native-phase3-run-reader-response/v1", "epoch_digest": bindings["epoch"],
                    "challenge_digest": bindings["challenge"], "request_digest": anchor, "sequence_after": 5, "ack_ns": 125}
        evidence.update(recvmsg_call_flags=0x40000040, response_base64=b64(encode(response)),
                        controls=[[1, 2, b64(ucred())]], receive_flags=0x40000080, received_ns=140)
    elif recv_attempted:
        evidence["recvmsg_call_flags"] = 0x40000040
    arguments = {"bindings": bindings, "expected_observer": observer, "expected_connection_epoch": connection_epoch,
                 "credential_abi": "linux-le-ucred32-v1"}
    return evidence, reader, arguments


def verify(evidence, reader, arguments, **overrides):
    raw, summary = encode(evidence), encode(reader)
    # Mutation fixtures explicitly repin candidate bytes to exercise semantic joins.
    call = {**arguments, "expected_evidence_digest": pin(raw), "expected_reader_digest": pin(summary), **overrides}
    return verifier.verify_reader_evidence(raw, summary, **call)


def embedded_change(evidence, field, key, value):
    decoded = json.loads(base64.b64decode(evidence[field]))
    decoded[key] = value
    evidence[field] = b64(encode(decoded))


def reseal_fixture(evidence, reader, arguments):
    """Repin deliberately invalid structures to reach checks beyond hash mismatch."""
    epoch = json.loads(base64.b64decode(evidence["epoch_base64"]))
    challenge = json.loads(base64.b64decode(evidence["challenge_base64"]))
    bindings = arguments["bindings"]
    bindings.update({name: pin(encode(epoch[name])) for name in ("process", "clock", "loss_scope", "policy")})
    bindings["epoch"] = pin(encode(epoch))
    challenge["epoch_digest"] = bindings["epoch"]
    bindings["challenge"] = pin(encode(challenge))
    evidence["challenge_base64"] = b64(encode(challenge))
    claim = {"schema": "aragorn/native-phase3-run-reader-claim/v1",
             "connection_epoch": arguments["expected_connection_epoch"], "challenge": challenge}
    evidence["claim_base64"] = evidence["claim_readback_base64"] = b64(encode(claim))
    evidence["send_bytes"] = len(encode(challenge))
    for role in ("epoch", "challenge", "request"):
        reader[role + "_digest"] = bindings[role]
        embedded_change(evidence, "response_base64", role + "_digest", bindings[role])
    for edge in ("before", "after"):
        reader["process_" + edge] = deepcopy(epoch["process"])
        reader["clock_" + edge] = deepcopy(epoch["clock"])


class ReaderEvidenceTests(unittest.TestCase):
    def test_ack_before_send_return_and_all_result_ceilings(self):
        evidence, reader, args = fixture()
        self.assertEqual(len(evidence), 55)
        self.assertLess(reader["ack_ns"], evidence["send_finished_ns"])
        self.assertEqual(verify(evidence, reader, args), {
            "status": "CONSISTENT_READER_EVIDENCE", "evidence_digest": pin(encode(evidence)),
            "reader_digest": pin(encode(reader)), "reader_status": "ACK",
            "acquisition_authenticity_verified": False, "sensor_health_verified": False,
            "effect_authorized": False, "run_qualified": False})
        # No retention receipt exists: consistent bytes cannot establish leaf return.
        self.assertNotIn("retention", evidence)
        for flags in (0, 0x80, 0x40000000):
            evidence["receive_flags"] = flags
            self.assertEqual(verify(evidence, reader, args)["reader_status"], "ACK")

    def test_both_timeout_shapes_with_nonnull_peer_and_no_packet(self):
        for attempted in (False, True):
            with self.subTest(attempted=attempted):
                e, r, args = fixture("TIMEOUT", attempted)
                self.assertEqual(len(e), 51 if attempted else 50)
                self.assertEqual(verify(e, r, args)["reader_status"], "TIMEOUT")
                self.assertIsNone(r["ack_ns"])
                self.assertIsNone(r["received_ns"])
                self.assertEqual(r["sequence_after"], 4)
                for field, value in (("peer", None), ("sequence_after", 5), ("ack_ns", 100), ("received_ns", 200)):
                    changed = deepcopy(r)
                    changed[field] = value
                    with self.assertRaises(ValueError):
                        verify(e, changed, args)

    def test_exact_field_inventories_refuse_partial_extra_and_packet_timeout(self):
        for status in ("ACK", "TIMEOUT"):
            e, r, args = fixture(status)
            for field in e:
                with self.subTest(status=status, missing=field):
                    altered = deepcopy(e)
                    del altered[field]
                    with self.assertRaises(ValueError):
                        verify(altered, r, args)
            for field in ("extra", "overflow", "retention_success"):
                with self.subTest(status=status, extra=field):
                    with self.assertRaises(ValueError):
                        verify({**e, field: True}, r, args)
        e, r, args = fixture("TIMEOUT")
        for field, value in (("response_base64", b64(b"{}")), ("controls", []), ("receive_flags", 0), ("received_ns", None)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify({**e, field: value}, r, args)
        with self.assertRaises(ValueError):
            verify({**e, "status": "REFUSED"}, r, args)

    def test_caller_pins_observer_connection_and_abi_are_not_taken_from_evidence(self):
        e, r, args = fixture()
        for name in args["bindings"]:
            bad = deepcopy(args)
            bad["bindings"][name] = "sha256:" + "f" * 64
            with self.subTest(pin=name), self.assertRaises(ValueError):
                verify(e, r, bad)
        for changes in ({"expected_evidence_digest": "sha256:" + "f" * 64},
                        {"expected_reader_digest": "sha256:" + "f" * 64},
                        {"expected_connection_epoch": "d" * 64}, {"credential_abi": "linux-be-ucred32-v1"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify(e, r, args, **changes)
        for key in ("pid", "start_time_ticks", "uid", "gid"):
            bad = deepcopy(args)
            bad["expected_observer"][key] += 1
            with self.subTest(observer=key), self.assertRaises(ValueError):
                verify(e, r, bad)
        # Internally coherent replacement observer still fails independently held pins.
        changed = deepcopy(e)
        for edge in ("before", "after"):
            for suffix in ("stat_before", "stat_after"):
                changed[f"{edge}_observer_{suffix}_base64"] = b64(proc_stat(5001, 44))
            changed[edge + "_processes"]["observer"].update(pid=5001, start_time_ticks=44)
        with self.assertRaises(ValueError):
            verify(changed, r, args)

    def test_raw_json_and_base64_are_bounded_canonical_and_unambiguous(self):
        e, r, args = fixture()
        valid = encode(e)
        invalid = [b"", valid + b"\n", b" " * 131073, b"\xff", b'[{"x":1,"x":1}]',
                   b'{"status":"ACK","status":"ACK"}', b'{"x":NaN}', b"[" * 1500 + b"]" * 1500]
        for raw in invalid:
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                verifier.verify_reader_evidence(raw, encode(r), **args, expected_evidence_digest=pin(raw), expected_reader_digest=pin(encode(r)))
        for raw in (b" " * 32769, encode(r) + b" ", b'{"x":Infinity}'):
            with self.subTest(summary=raw[:30]), self.assertRaises(ValueError):
                verifier.verify_reader_evidence(valid, raw, **args, expected_evidence_digest=pin(valid), expected_reader_digest=pin(raw))
        for value in ("", "%%%", "YQ===", "YQ==\n", "\u00e9", b64(b"x" * 13), 12):
            with self.subTest(base64=value), self.assertRaises(ValueError):
                verify({**e, "peer_credentials_base64": value}, r, args)
        for field, raw in (("response_base64", b"{}\n"), ("claim_base64", b'{"x":0,"x":0}'),
                           ("challenge_base64", b"x" * 4097), ("epoch_base64", b"x" * 32769),
                           ("before_reader_status_base64", b"x" * 16385), ("before_boot_base64", b"x" * 65)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify({**e, field: b64(raw)}, r, args)

    def test_proc_decoding_ignores_mutable_fields_but_joins_raw_identity(self):
        e, r, args = fixture()
        e["after_reader_stat_before_base64"] = b64(proc_stat(101, 12, "new (comm)\nwith ) spaces"))
        e["after_reader_stat_after_base64"] = b64(proc_stat(101, 12, "another"))
        e["after_reader_status_base64"] = b64(proc_status(997, 998).replace(b"Name:\treader", b"Name:\tchanged"))
        self.assertEqual(verify(e, r, args)["reader_status"], "ACK")
        mutations = [
            ("before_reader_stat_before_base64", b"101 (short) S 0\n"),
            ("after_reader_stat_after_base64", proc_stat(101, 13)),
            ("before_reader_stat_before_base64", proc_stat(102, 12)),
            ("before_observer_stat_before_base64", proc_stat(5000, 34)),
            ("after_observer_status_base64", proc_status(501, 503)),
            ("before_reader_status_base64", b"\xff"),
            ("before_reader_status_base64", proc_status(997, 998) + b"Uid: 997 997 997 997\n"),
            ("before_reader_status_base64", proc_status(997, 998).replace(b"CapEff:\t0\n", b"")),
            ("before_reader_status_base64", proc_status(997, 998).replace(b"CapBnd:\t0", b"CapBnd:\t1")),
            ("before_reader_status_base64", proc_status(997, 998).replace(b"CapAmb:\t0", b"CapAmb:\tx")),
            ("before_reader_status_base64", proc_status(997, 998).replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0")),
            ("before_reader_status_base64", proc_status(997, 998).replace(b"997 997 997 997", b"997 0 997 997")),
            ("before_reader_status_base64", proc_status(997, 998).replace(b"997 997 997 997", b"0997 997 997 997")),
            ("before_reader_status_base64", proc_status(2**32, 998)),
        ]
        for field, raw in mutations:
            with self.subTest(field=field, raw=raw), self.assertRaises(ValueError):
                verify({**e, field: b64(raw)}, r, args)
        changed = deepcopy(e)
        changed["before_processes"]["reader"]["uid"] = 0
        with self.assertRaises(ValueError):
            verify(changed, r, args)

    def test_namespace_boot_fdinfo_and_observed_inventory_substitutions_refuse(self):
        e, r, args = fixture()
        for key in ("device", "inode"):
            changed = deepcopy(e)
            for edge in ("before", "after"):
                for role in ("reader", "observer"):
                    changed[edge + "_namespaces"][role][key] += 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify(changed, r, args)
        for field, value in (("before_boot_base64", b64(b"wrong\n")),
                             ("after_pidfd_info_base64", b64(b"Pid:\t102\n")),
                             ("before_pidfd_info_base64", b64(b"Pid: 101\nPid: 101\n")),
                             ("before_pidfd_info_base64", b64(b"NSpid: 101\n")),
                             ("before_pidfd_info_base64", b64(b"Pid: 101\nextra: \xff\n")),
                             ("observed_fields", e["observed_fields"][::-1]),
                             ("supplied_process_fields", e["supplied_process_fields"] + ["sensor_health"])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify({**e, field: value}, r, args)

    def test_claim_challenge_response_and_epoch_tampering_refuse(self):
        e, r, args = fixture()
        for field, key, value in (("claim_base64", "connection_epoch", "d" * 64),
                                  ("claim_readback_base64", "schema", "wrong"),
                                  ("challenge_base64", "nonce", "d" * 64),
                                  ("epoch_base64", "deployment_digest", "sha256:" + "f" * 64),
                                  ("response_base64", "epoch_digest", "sha256:" + "f" * 64),
                                  ("response_base64", "challenge_digest", "sha256:" + "f" * 64),
                                  ("response_base64", "request_digest", "sha256:" + "f" * 64),
                                  ("response_base64", "schema", "other"),
                                  ("response_base64", "sequence_after", 4),
                                  ("response_base64", "sequence_after", True),
                                  ("response_base64", "extra", 0)):
            changed = deepcopy(e)
            embedded_change(changed, field, key, value)
            with self.subTest(field=field, key=key), self.assertRaises(ValueError):
                verify(changed, r, args)
        changed = deepcopy(e)
        for field in ("claim_base64", "claim_readback_base64"):
            embedded_change(changed, field, "connection_epoch", "d" * 64)
        changed["connection_epoch"] = "d" * 64
        with self.assertRaises(ValueError):
            verify(changed, r, args)

    def test_invalid_pinned_epoch_and_challenge_fields_are_still_rejected(self):
        cases = (("process", "sensor_uid", True), ("process", "sensor_pid", 2**31),
                 ("process", "sensor_gid", 2**32), ("process", "reader_start_ticks", 0),
                 ("process", "reader_source_digest", "not-a-pin"), ("process", "extra", 0),
                 ("clock", "clock_id", "CLOCK_REALTIME"), ("clock", "time_namespace_inode", True),
                 ("clock", "boot_id", "different"), ("policy", "timeout_ns", 0),
                 ("policy", "max_age_ns", -1), (None, "deployment_digest", "bad"),
                 (None, "loss_scope", []), (None, "loss_scope", ["sha256:" + "a" * 64] * 2))
        for role, key, value in cases:
            e, r, args = fixture()
            epoch = json.loads(base64.b64decode(e["epoch_base64"]))
            (epoch[role] if role else epoch)[key] = value
            e["epoch_base64"] = b64(encode(epoch))
            reseal_fixture(e, r, args)
            with self.subTest(role=role, key=key), self.assertRaises(ValueError):
                verify(e, r, args)
        for key, value in (("nonce", "bad"), ("issued_ns", True), ("deadline_ns", 2**63),
                           ("deadline_ns", 199), ("sequence_before", -1), ("boundary", "AFTER_CONNECT"),
                           ("request_digest", "sha256:" + "f" * 64), ("extra", 0)):
            e, r, args = fixture()
            embedded_change(e, "challenge_base64", key, value)
            reseal_fixture(e, r, args)
            with self.subTest(challenge=key), self.assertRaises(ValueError):
                verify(e, r, args)

    def test_linux_credential_abi_flags_and_control_inventory(self):
        e, r, args = fixture()
        for raw in (ucred(102), ucred(uid=0), ucred(gid=0), ucred(byteorder="big"), ucred(-1), b"x" * 11):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                verify({**e, "controls": [[1, 2, b64(raw)]]}, r, args)
        for controls in ([], e["controls"] * 2, [[1, 1, b64((99).to_bytes(4, "little"))]],
                         [[1, 4, b64((99).to_bytes(4, "little"))]], [[True, 2, b64(ucred())]], [[1, True, b64(ucred())]]):
            with self.subTest(controls=controls), self.assertRaises(ValueError):
                verify({**e, "controls": controls}, r, args)
        for field, value in (("send_call_flags", 0x4000), ("send_call_flags", True), ("recvmsg_call_flags", 0x40000080),
                             ("receive_flags", 0x20), ("receive_flags", 0x8), ("receive_flags", -1), ("receive_flags", True)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                verify({**e, field: value}, r, args)

    def test_chronology_sequence_and_strict_integer_edges(self):
        e, r, args = fixture()
        for field, value in (("before_started_ns", 99), ("before_finished_ns", 121), ("send_finished_ns", 119),
                             ("send_finished_ns", 200), ("received_ns", 129), ("after_started_ns", 139),
                             ("after_finished_ns", 149), ("accepted_ns", 154), ("accepted_ns", 200),
                             ("send_bytes", e["send_bytes"] - 1), ("received_ns", True), ("accepted_ns", 2**63)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                verify({**e, field: value}, r, args)
        for ack in (119, 141, True, 2**63):
            changed = deepcopy(e)
            embedded_change(changed, "response_base64", "ack_ns", ack)
            with self.subTest(ack=ack), self.assertRaises(ValueError):
                verify(changed, {**r, "ack_ns": ack}, args)
        e, r, args = fixture("TIMEOUT")
        for field, value in (("after_started_ns", 199), ("send_finished_ns", 200), ("accepted_ns", 199)):
            with self.subTest(timeout=field), self.assertRaises(ValueError):
                verify({**e, field: value}, r, args)

    def test_failure_cleanup_and_false_flag_contract(self):
        e, r, args = fixture()
        mutations = [("failure_type", "OSError"), ("cleanup_failure_count", 1), ("cleanup_failure_count", False),
                     ("cleanup_failure_types", ["OSError"]), ("cleanup_failure_types_complete", False),
                     ("claim_attempted", False), ("claim_confirmed", 1), ("send_attempted", False),
                     ("sensor_health_verified", True), ("effect_authorized", True), ("run_qualified", 0),
                     ("descriptor_cleanup", e["descriptor_cleanup"][:2]),
                     ("descriptor_cleanup", [[701, "OWNED", True]] * 3),
                     ("descriptor_cleanup", [[902, "ANCILLARY", True], *e["descriptor_cleanup"][1:]]),
                     ("descriptor_cleanup", [[902, "OWNED", False], *e["descriptor_cleanup"][1:]]),
                     ("descriptor_cleanup", [[True, "OWNED", True], *e["descriptor_cleanup"][1:]])]
        for field, value in mutations:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                verify({**e, field: value}, r, args)

    def test_reader_summary_is_reconstructed_not_trusted(self):
        e, r, args = fixture()
        for field, value in (("peer", None), ("ack_ns", 126), ("received_ns", 141), ("sequence_after", 6),
                             ("process_after", {}), ("clock_before", {}), ("status", "TIMEOUT"), ("extra", 0)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify(e, {**r, field: value}, args)
        for field in r:
            changed = deepcopy(r)
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                verify(e, changed, args)

    def test_independent_consumer_has_only_explicit_standard_library_imports(self):
        tree = ast.parse(inspect.getsource(verifier))
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                roots.add(node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"__import__", "eval", "exec"})
        self.assertEqual(roots, {"base64", "hashlib", "json", "re"})
