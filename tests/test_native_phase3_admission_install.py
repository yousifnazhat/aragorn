"""Fabricated native install records only; no install, service or VM execution."""

from copy import deepcopy
import subprocess
import unittest
from unittest.mock import Mock

from aragorn import native_phase3_admission_install as subject
from aragorn.oci_worker_protocol import canonical_json
from test_native_admission_direct_write import _fixture


def fixture():
    value, bindings = _fixture()
    del value["attempts"]
    value.update(
        schema=subject.SCHEMA, authority=subject.AUTHORITY,
        case_id=subject.CASE_ID, branch=subject.BRANCH,
        limitations=list(subject.LIMITATIONS),
        shared_source_pins=value.pop("source_pins"),
    )
    stdout = canonical_json(subject.DENIAL) + b"\n"
    value["install_command"] = {
        "argv": list(subject.ARGV), "exit_code": 1,
        "stdout": stdout.decode(), "stdout_bytes": len(stdout),
        "stdout_digest": subject.shared.digest(stdout), "stderr_bytes": 0,
    }
    bindings["expected_shared_probe_digest"] = bindings.pop("expected_probe_digest")
    bindings["expected_shared_verifier_digest"] = bindings.pop("expected_verifier_digest")
    return value, bindings


def verify(value, bindings):
    raw = canonical_json(value)
    return subject.verify_native_admission_install(
        raw, expected_raw_digest=subject.shared.digest(raw), **bindings,
    )


def set_path(value, path, replacement):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = replacement


class NativeInstallTests(unittest.TestCase):
    def test_fixed_denial_and_proof_ceiling(self):
        value, bindings = fixture()
        original = deepcopy(value)
        result = verify(value, bindings)
        self.assertEqual(result["status"], "BOUNDED_UPLOAD_INSTALL_DENIAL_JOINS_VERIFIED")
        self.assertEqual(value, original)
        self.assertTrue(all(result[key] is False for key in subject.shared.FALSE_FLAGS))
        self.assertFalse(subject.PARAMS["force"])

    def test_contract_identity_and_command_mutations_refuse(self):
        mutations = [
            (("schema",), "other"), (("branch",), "LOCAL_PATH"),
            (("case_id",), "ADM-02/update"), (("status",), "REFUSED"),
            (("refusal",), "FAILED"), (("fixture_container",), "d" * 64),
            (("gateway_pid",), True), (("admitted_digest",), "sha256:" + "e" * 64),
            (("limitations",), []), (("install_command", "argv"), []),
            (("install_command", "exit_code"), True),
            (("install_command", "exit_code"), 0),
            (("install_command", "stderr_bytes"), False),
            (("install_command", "stderr_bytes"), 1),
            (("install_command", "stdout_bytes"), 1),
            (("install_command", "stdout_digest"), "sha256:" + "0" * 64),
            (("after", "gateway", "start_time_ticks"), 124),
            (("after", "admitted", "read_only"), False),
        ] + [((key,), True) for key in subject.shared.FALSE_FLAGS]
        for path, replacement in mutations:
            with self.subTest(path=path, replacement=replacement):
                value, bindings = fixture()
                set_path(value, path, replacement)
                with self.assertRaises(subject.NativeInstallError):
                    verify(value, bindings)

    def test_only_exact_disabled_upload_response_is_accepted(self):
        responses = [
            b'{"ok":true}', b'{"ok":false}', b'[]', b'{"ok":NaN}',
            b'{"ok":false,"ok":false}',
            canonical_json({**subject.DENIAL, "extra": "unexpected"}),
            canonical_json({**subject.DENIAL, "ok": 0}),
            canonical_json({**subject.DENIAL, "error": {
                **subject.DENIAL["error"], "message": "Upload not found",
            }}),
        ]
        for raw in responses:
            with self.subTest(raw=raw):
                value, bindings = fixture()
                value["install_command"].update(
                    stdout=raw.decode(), stdout_bytes=len(raw),
                    stdout_digest=subject.shared.digest(raw),
                )
                with self.assertRaises(subject.NativeInstallError):
                    verify(value, bindings)

    def test_target_residue_even_if_identical_before_and_after_refuses(self):
        value, bindings = fixture()
        entry = {
            "path": subject.NAME, "kind": "directory",
            "identity": [1, 22, 0o40700, 992, 992, 2, 0, 1, 1],
            "bytes": None, "digest": None,
        }
        for side in ("before", "after"):
            value[side]["roots"][subject.shared.ROOTS[0]]["entries"] = [deepcopy(entry)]
        with self.assertRaisesRegex(subject.NativeInstallError, "INSTALL_TARGET_PRESENT"):
            verify(value, bindings)

    def test_catalog_target_even_if_unchanged_refuses(self):
        value, bindings = fixture()
        for side in ("before", "after"):
            command = value["commands_" + side][2]
            response = subject.shared.parse(command["stdout"])
            response["skills"].append({"name": subject.NAME})
            raw = canonical_json(response)
            command.update(stdout=raw.decode(), stdout_bytes=len(raw),
                           stdout_digest=subject.shared.digest(raw))
        with self.assertRaisesRegex(subject.NativeInstallError, "INSTALL_TARGET_DISCOVERED"):
            verify(value, bindings)

    def test_invalid_raw_and_caller_pins_refuse(self):
        value, bindings = fixture()
        raw = canonical_json(value)
        for altered in (raw + b"\n", b"[]", b"{}", b"{", b"x" * (2097152 + 1)):
            with self.subTest(size=len(altered)):
                with self.assertRaises(subject.NativeInstallError):
                    subject.verify_native_admission_install(
                        altered, expected_raw_digest=subject.shared.digest(altered), **bindings,
                    )
        for key in bindings:
            changed = {**bindings, key: None}
            with self.subTest(key=key), self.assertRaises(subject.NativeInstallError):
                verify(value, changed)
        with self.assertRaises(subject.NativeInstallError):
            subject.verify_native_admission_install(
                raw, expected_raw_digest="sha256:" + "0" * 64, **bindings,
            )


class NativeInstallRecordingTests(unittest.TestCase):
    def setUp(self):
        self.value, self.bindings = fixture()
        rows = [*self.value["commands_before"], self.value["install_command"],
                *self.value["commands_after"]]
        self.outputs = [subprocess.CompletedProcess(
            row["argv"], row["exit_code"], row["stdout"].encode(), b"",
        ) for row in rows]
        self.command = Mock(side_effect=self.outputs)
        self.boundary = Mock(side_effect=lambda: deepcopy(self.value["before"]))

    def record(self, **bindings):
        return subject.record_native_admission_install(
            read_boundary=self.boundary, run_command=self.command,
            **(bindings or self.bindings),
        )

    def test_records_actual_bytes_once_and_replays(self):
        result = self.record()
        self.assertEqual(result, self.value)
        verify(result, self.bindings)
        self.assertEqual(self.command.call_count, 9)
        self.assertEqual(self.boundary.call_count, 3)
        self.assertEqual([call.args[0] for call in self.command.call_args_list],
                         [output.args for output in self.outputs])
        self.assertEqual(sum(call.args[0] == list(subject.ARGV)
                             for call in self.command.call_args_list), 1)

    def test_bad_caller_performs_no_reads_or_commands(self):
        result = self.record(**{**self.bindings, "expected_gateway_pid": True})
        self.assertEqual(result["refusal"]["phase"], "PREREQUISITES")
        self.boundary.assert_not_called()
        self.command.assert_not_called()

    def test_unsealed_boundary_never_attempts_install(self):
        self.value["before"]["admitted"]["read_only"] = False
        result = self.record()
        self.assertEqual(result["status"], "REFUSED")
        self.assertIsNone(result["install_command"])
        self.assertEqual(self.command.call_count, 4)

    def test_boundary_change_before_attempt_refuses(self):
        changed = deepcopy(self.value["before"])
        changed["gateway"]["start_time_ticks"] += 1
        self.boundary.side_effect = [self.value["before"], changed]
        result = self.record()
        self.assertIsNone(result["install_command"])
        self.assertEqual(self.command.call_count, 4)

    def test_wrong_denial_retains_metadata_without_diagnostic_or_retry(self):
        raw = b'{"error":"private fixture diagnostic"}'
        self.outputs[4].stdout = raw
        result = self.record()
        self.assertEqual(result["refusal"]["phase"], "INSTALL")
        self.assertIsNone(result["install_command"]["stdout"])
        self.assertEqual(result["install_command"]["stdout_digest"],
                         subject.shared.digest(raw))
        self.assertNotIn(b"private fixture diagnostic", canonical_json(result))
        self.assertIsNotNone(result["after"])
        self.assertEqual(len(result["commands_after"]), 4)
        self.assertEqual(self.command.call_count, 9)
        with self.assertRaises(subject.NativeInstallError):
            verify(result, self.bindings)

    def test_timeout_preserves_unknown_attempt_and_postconditions(self):
        self.outputs[4] = subprocess.TimeoutExpired(list(subject.ARGV), 15)
        self.command.side_effect = self.outputs
        result = self.record()
        self.assertEqual(result["refusal"]["phase"], "INSTALL")
        self.assertIsNone(result["install_command"]["exit_code"])
        self.assertIsNotNone(result["after"])
        self.assertEqual(self.command.call_count, 9)

    def test_postcondition_failure_cannot_become_success(self):
        self.boundary.side_effect = [self.value["before"], self.value["before"],
                                     OSError("private read failure")]
        result = self.record()
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["refusal"]["phase"], "AFTER")
        self.assertEqual(len(result["commands_after"]), 4)
        self.assertNotIn(b"private read failure", canonical_json(result))

    def test_changed_final_boundary_fails_independent_replay(self):
        changed = deepcopy(self.value["before"])
        changed["gateway"]["start_time_ticks"] += 1
        self.boundary.side_effect = [self.value["before"], self.value["before"], changed]
        result = self.record()
        self.assertEqual(result["refusal"]["phase"], "REPLAY")
        self.assertEqual(result["status"], "REFUSED")

    def test_interrupt_preserves_observation_and_propagates_without_retry(self):
        interruption = KeyboardInterrupt()
        self.outputs[4] = interruption
        self.command.side_effect = self.outputs
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.record()
        self.assertIs(caught.exception, interruption)
        result = interruption._native_install_observation
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["refusal"]["phase"], "INSTALL")
        self.assertIsNotNone(result["after"])
        self.assertEqual(self.command.call_count, 9)

    def test_invalid_command_envelopes_refuse_and_never_retry(self):
        for field, replacement in (
            ("returncode", True), ("returncode", 0), ("args", ["other"]),
            ("stdout", "not bytes"), ("stdout", b"x" * (subject.shared.MAX_COMMAND + 1)),
            ("stderr", b"private stderr"),
        ):
            with self.subTest(field=field, replacement_type=type(replacement).__name__):
                self.setUp()
                setattr(self.outputs[4], field, replacement)
                result = self.record()
                self.assertEqual(result["status"], "REFUSED")
                self.assertEqual(self.command.call_count, 9)
                self.assertNotIn(b"private stderr", canonical_json(result))


if __name__ == "__main__":
    unittest.main()
