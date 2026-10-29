"""Inert first checks; fabricated observations here are not live evidence."""

from __future__ import annotations

from copy import deepcopy
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from aragorn import native_phase3_admission_direct_write as consumer
from aragorn.oci_worker_protocol import canonical_json
from scripts import runtime_native_admission_direct_write as guest


def _pin(label):
    return consumer.digest(label.encode())


def _file(pin, *, uid=0, gid=0):
    return {
        "identity": [1, 2, 0o100444, uid, gid, 1, 4, 5, 6],
        "bytes": 4,
        "digest": pin,
        "read_only": True,
    }


def _fixture():
    bindings = {
        "expected_container": "c" * 64,
        "expected_gateway_pid": 42,
        "expected_admitted_digest": _pin("skill"),
        "expected_probe_digest": _pin("probe"),
        "expected_verifier_digest": _pin("verifier"),
    }
    source_pins = {
        consumer.PROBE: bindings["expected_probe_digest"],
        consumer.VERIFIER: bindings["expected_verifier_digest"],
    }
    boundary = {
        "gateway": {
            "pid": 42,
            "start_time_ticks": 123,
            "cgroup": "0::/docker/"
            + "c" * 64
            + "/system.slice/aragorn-agent-gateway.service\n",
            "mount_namespace": 777,
            "effective_capabilities": "0000000000000000",
            "no_new_privileges": "1",
            "uid": [992] * 4,
            "gid": [992] * 4,
        },
        "roots": {
            root: {
                "identity": [1, 10 + i, 0o40700, 992, 992, 2, 4096, 8, 9],
                "read_only": True,
                "entries": [],
                "candidate_absent": True,
            }
            for i, root in enumerate(consumer.ROOTS)
        },
        "admitted": _file(bindings["expected_admitted_digest"]),
        "sources": {path: _file(pin) for path, pin in source_pins.items()},
        "entry": _file(consumer.ENTRY_PIN),
        "config": _file(consumer.CONFIG_PIN, uid=992),
    }
    skill = {
        "name": "template-skill",
        "filePath": consumer.ADMITTED,
        "source": "openclaw-extra",
        "eligible": True,
        "modelVisible": True,
        "commandVisible": True,
        "blockedByAgentFilter": False,
        "blockedByAllowlist": False,
    }
    commands = []
    for kind, args in consumer.COMMANDS:
        response = (
            {"pid": 42}
            if kind == "system-info"
            else skill
            if kind == "skill-info"
            else {"skills": [skill]}
        )
        raw = canonical_json(response) + b"\n"
        commands.append(
            {
                "kind": kind,
                "argv": ["/usr/local/bin/node", consumer.ENTRY, *args],
                "exit_code": 0,
                "stdout": raw.decode(),
                "stdout_bytes": len(raw),
                "stdout_digest": consumer.digest(raw),
                "stderr_bytes": 0,
            }
        )
    attempts = [
        {
            "operation": "create-skill" if index < 6 else "overwrite-admitted",
            "path": target,
            "completed": False,
            "errno": errno.EROFS,
            "created_directory": False,
            "bytes_written": 0,
            "payload_digest": consumer.digest(consumer.PAYLOAD),
        }
        for index, target in enumerate(
            [root + "/" + consumer.NAME for root in consumer.ROOTS]
            + [consumer.ADMITTED]
        )
    ]
    return {
        "schema": consumer.SCHEMA,
        "authority": consumer.AUTHORITY,
        "case_id": consumer.CASE_ID,
        "status": "OBSERVED",
        "fixture_container": "c" * 64,
        "gateway_pid": 42,
        "admitted_digest": bindings["expected_admitted_digest"],
        "source_pins": source_pins,
        "before": boundary,
        "after": deepcopy(boundary),
        "commands_before": commands,
        "commands_after": deepcopy(commands),
        "attempts": attempts,
        "refusal": None,
        "limitations": list(consumer.LIMITATIONS),
        **dict.fromkeys(consumer.FALSE_FLAGS, False),
    }, bindings


def _verify(value, bindings):
    raw = canonical_json(value)
    return consumer.verify_native_admission_direct_write(
        raw, expected_raw_digest=consumer.digest(raw), **bindings
    )


class NativeDirectWriteTests(unittest.TestCase):
    def test_bounded_observation_replay_and_claim_ceiling(self):
        value, bindings = _fixture()
        before = deepcopy(value)
        result = _verify(value, bindings)
        self.assertEqual(result["status"], "BOUNDED_DIRECT_WRITE_JOINS_VERIFIED")
        self.assertEqual(result["attempts"], 7)
        self.assertTrue(all(result[key] is False for key in consumer.FALSE_FLAGS))
        self.assertEqual(value, before)

    def test_success_partial_effect_errno_and_case_substitution_refused(self):
        value, bindings = _fixture()
        for change in (
            {"completed": True},
            {"created_directory": True},
            {"bytes_written": 1},
            {"errno": errno.ENOENT},
            {"errno": True},
            {"path": "/tmp/other"},
            {"operation": "rename"},
            {"payload_digest": _pin("other")},
        ):
            with self.subTest(change=change):
                altered = deepcopy(value)
                altered["attempts"][0].update(change)
                with self.assertRaises(consumer.NativeDirectWriteError):
                    _verify(altered, bindings)
        altered = deepcopy(value)
        altered["attempts"].pop()
        with self.assertRaises(consumer.NativeDirectWriteError):
            _verify(altered, bindings)

    def test_unsealed_root_changed_bytes_and_custody_refused(self):
        value, bindings = _fixture()
        alterations = []
        item = deepcopy(value)
        item["before"]["roots"][consumer.ROOTS[0]]["read_only"] = False
        alterations.append(item)
        item = deepcopy(value)
        item["after"]["admitted"]["digest"] = _pin("modified")
        alterations.append(item)
        item = deepcopy(value)
        item["after"]["roots"][consumer.ROOTS[0]]["candidate_absent"] = False
        alterations.append(item)
        item = deepcopy(value)
        item["before"]["sources"][consumer.PROBE]["identity"][3] = 992
        alterations.append(item)
        item = deepcopy(value)
        item["after"]["gateway"]["start_time_ticks"] += 1
        alterations.append(item)
        for altered in alterations:
            with self.assertRaises(consumer.NativeDirectWriteError):
                _verify(altered, bindings)

    def test_retained_command_bytes_are_parsed_not_boolean_claims(self):
        value, bindings = _fixture()
        for mutate in (
            lambda response: response["skills"].append({"name": consumer.NAME}),
            lambda response: response["skills"][0].update(
                filePath="/unadmitted/SKILL.md"
            ),
            lambda response: response["skills"][0].update(modelVisible=False),
        ):
            altered = deepcopy(value)
            command = altered["commands_after"][-1]
            response = json.loads(command["stdout"])
            mutate(response)
            raw = canonical_json(response)
            command.update(
                stdout=raw.decode(),
                stdout_bytes=len(raw),
                stdout_digest=consumer.digest(raw),
            )
            with self.assertRaises(consumer.NativeDirectWriteError):
                _verify(altered, bindings)
        altered = deepcopy(value)
        altered["commands_after"][0]["stdout"] = '{"pid":42,"pid":42}'
        command = altered["commands_after"][0]
        raw = command["stdout"].encode()
        command.update(stdout_bytes=len(raw), stdout_digest=consumer.digest(raw))
        with self.assertRaises(consumer.NativeDirectWriteError):
            _verify(altered, bindings)

    def test_wrong_external_pin_identity_and_promotion_refused(self):
        value, bindings = _fixture()
        for key, replacement in (
            ("expected_container", "a" * 64),
            ("expected_gateway_pid", 43),
            ("expected_admitted_digest", _pin("different")),
            ("expected_probe_digest", _pin("changed")),
        ):
            with self.assertRaises(consumer.NativeDirectWriteError):
                _verify(value, bindings | {key: replacement})
        for key in consumer.FALSE_FLAGS:
            with self.assertRaises(consumer.NativeDirectWriteError):
                _verify(value | {key: True}, bindings)
        raw = canonical_json(value)
        with self.assertRaises(consumer.NativeDirectWriteError):
            consumer.verify_native_admission_direct_write(
                raw, expected_raw_digest=_pin("bad"), **bindings
            )

    def test_nonnative_guard_precedes_any_read_command_or_mutation(self):
        _, bindings = _fixture()
        with (
            patch.object(guest.sys, "platform", "darwin"),
            patch.object(guest, "_boundary") as boundary,
            patch.object(guest, "_command") as command,
            patch.object(guest, "_attempt") as attempt,
        ):
            result = guest.run_direct_write_probe(**bindings)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["refusal"]["reason"], "FIXED_NONROOT_IDENTITY_REQUIRED")
        boundary.assert_not_called()
        command.assert_not_called()
        attempt.assert_not_called()

    def test_mutation_primitive_retains_denial_and_partial_creation_without_retry(self):
        root = consumer.ROOTS[0] + "/" + consumer.NAME
        with (
            patch.object(guest, "_open", return_value=21),
            patch.object(
                guest.os, "mkdir", side_effect=OSError(errno.EROFS, "opaque")
            ) as create,
            patch.object(guest.os, "open") as open_file,
        ):
            result = guest._attempt(root, create=True)
        self.assertEqual(result["errno"], errno.EROFS)
        self.assertFalse(result["created_directory"])
        self.assertEqual(create.call_count, 1)
        open_file.assert_not_called()
        with (
            patch.object(guest, "_open", return_value=21),
            patch.object(guest.os, "mkdir") as create,
            patch.object(guest.os, "open", side_effect=OSError(errno.EACCES, "opaque")),
        ):
            result = guest._attempt(root, create=True)
        self.assertTrue(result["created_directory"])
        self.assertEqual(result["errno"], errno.EACCES)
        self.assertEqual(create.call_count, 1)
        self.assertNotIn("opaque", canonical_json(result).decode())

    def test_full_fixed_leaf_sequence_partial_stop_and_command_failure_retention(self):
        fixture, bindings = _fixture()
        for partial, failed_postcommand in (
            (False, False),
            (True, False),
            (False, True),
        ):
            with (
                self.subTest(partial=partial, failed_postcommand=failed_postcommand),
                ExitStack() as patches,
            ):
                patches.enter_context(patch.object(guest.sys, "platform", "linux"))
                patches.enter_context(
                    patch.object(
                        guest.os, "getresuid", return_value=(992,) * 3, create=True
                    )
                )
                patches.enter_context(
                    patch.object(
                        guest.os, "getresgid", return_value=(992,) * 3, create=True
                    )
                )
                patches.enter_context(
                    patch.object(guest.os, "getgroups", return_value=[992])
                )
                patches.enter_context(patch.object(guest, "__file__", consumer.PROBE))
                patches.enter_context(
                    patch.object(consumer, "__file__", consumer.VERIFIER)
                )
                own = dict.fromkeys(
                    ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"),
                    "0000000000000000",
                )
                patches.enter_context(
                    patch.object(
                        guest, "_status", return_value=own | {"NoNewPrivs": "1"}
                    )
                )
                patches.enter_context(
                    patch.object(
                        guest,
                        "_read_proc",
                        return_value=(
                            "0::/docker/" + "c" * 64 + "/init.scope\n"
                        ).encode(),
                    )
                )
                patches.enter_context(
                    patch.dict(os.environ, {"OPENCLAW_GATEWAY_TOKEN": "f" * 64})
                )
                patches.enter_context(
                    patch.object(guest.os, "pidfd_open", return_value=123, create=True)
                )
                close = patches.enter_context(patch.object(guest.os, "close"))
                poller = Mock()
                poller.poll.return_value = []
                patches.enter_context(
                    patch.object(guest.select, "poll", return_value=poller, create=True)
                )
                boundary = patches.enter_context(
                    patch.object(
                        guest,
                        "_boundary",
                        side_effect=lambda *_: deepcopy(fixture["before"]),
                    )
                )
                command_results = deepcopy(
                    fixture["commands_before"] + fixture["commands_after"]
                )
                if failed_postcommand:
                    command_results[5] = RuntimeError(
                        "failed command secret " + "f" * 64
                    )
                command = patches.enter_context(
                    patch.object(guest, "_command", side_effect=command_results)
                )
                attempts = deepcopy(fixture["attempts"])
                if partial:
                    attempts[0].update(created_directory=True, errno=errno.EACCES)
                attempt = patches.enter_context(
                    patch.object(guest, "_attempt", side_effect=attempts)
                )
                result = guest.run_direct_write_probe(**bindings)
                self.assertEqual(
                    result["status"],
                    "REFUSED" if partial or failed_postcommand else "OBSERVED",
                )
                self.assertEqual(attempt.call_count, 1 if partial else 7)
                self.assertEqual(len(result["attempts"]), attempt.call_count)
                self.assertEqual(command.call_count, 6 if failed_postcommand else 8)
                self.assertEqual(boundary.call_count, 3 if failed_postcommand else 4)
                self.assertEqual(result["commands_before"], fixture["commands_before"])
                self.assertEqual(
                    result["commands_after"],
                    fixture["commands_after"][:1]
                    if failed_postcommand
                    else fixture["commands_after"],
                )
                close.assert_called_once_with(123)
                if failed_postcommand:
                    self.assertEqual(result["attempts"], fixture["attempts"])
                    self.assertEqual(result["after"], fixture["after"])
                    self.assertEqual(
                        result["refusal"],
                        {"phase": "AFTER", "reason": "FIXED_LEAF_REFUSED"},
                    )
                    self.assertNotIn(
                        "failed command secret", canonical_json(result).decode()
                    )
                    self.assertNotIn("f" * 64, canonical_json(result).decode())
                elif partial:
                    self.assertTrue(result["attempts"][0]["created_directory"])
                    self.assertEqual(result["refusal"]["phase"], "SEMANTIC_REPLAY")
                else:
                    self.assertEqual(_verify(result, bindings)["attempts"], 7)

    def test_fixed_readers_reject_symlink_and_inventory_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.write_bytes(b"data")
            link = root / "link"
            link.symlink_to(source)
            with ExitStack() as held:
                with self.assertRaises(OSError):
                    guest._file(str(link), held)
            with ExitStack() as held:
                with self.assertRaises(consumer.NativeDirectWriteError):
                    guest._tree(str(root), held)


if __name__ == "__main__":
    unittest.main()
