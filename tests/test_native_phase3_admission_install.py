"""Fabricated native install records only; no install, service or VM execution."""

from copy import deepcopy
import unittest

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


if __name__ == "__main__":
    unittest.main()
