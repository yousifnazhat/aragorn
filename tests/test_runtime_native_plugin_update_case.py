"""Inert fixed guest wire tests; no Linux services, captures, or VM execute."""

import copy
import io
import json
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from aragorn.cas import CAS, CASError
from scripts import runtime_native_plugin_update_case as subject


class RuntimeNativePluginUpdateCaseTests(unittest.TestCase):
    def setUp(self):
        self.container = "a" * 64
        self.static_pin = "sha256:" + "b" * 64
        self.intent = {"static_pin_manifest_digest": self.static_pin}
        self.intent_raw = subject.canonical_json(self.intent)
        self.intent_pin = subject.identity_guest._digest(self.intent_raw)
        source = b"inert caller-held public source\n"
        self.blobs = {
            self.intent_pin: self.intent_raw,
            subject.identity_guest._digest(source): source,
        }
        self.bundle = {
            "schema": subject.BUNDLE_SCHEMA,
            "intent_digest": self.intent_pin,
            "blobs": {pin: raw.decode("utf-8") for pin, raw in self.blobs.items()},
        }
        self.bundle_raw = subject.canonical_json(self.bundle)
        self.bundle_pin = subject.identity_guest._digest(self.bundle_raw)
        self.provisioning = {
            path: subject.canonical_json(
                {"private": "inert-secret-not-for-output", "path": path}
            )
            for path in subject.identity_guest.DYNAMIC_PATHS
        }
        self.request = {
            "schema": subject.case.REQUEST_SCHEMA,
            "intent_digest": self.intent_pin,
            "provisioning_file_digests": {
                path: subject.identity_guest._digest(raw)
                for path, raw in self.provisioning.items()
            },
        }
        self.request_raw = subject.canonical_json(self.request)
        self.request_pin = subject.identity_guest._digest(self.request_raw)
        self.identity_result = {
            "schema": subject.identity_guest.SCHEMA,
            "status": "OBSERVED",
            "activation_count": 1,
            "invocation_count": 1,
            "inert_identity_result": True,
        }

    def run_guest(
        self,
        *,
        closure=None,
        fail_prepare=False,
        fail_request_write=False,
        fail_request_readback=False,
        identity_mode=None,
    ):
        events, retained = [], {}
        bound = {
            "intent": self.intent,
            "input_blobs": self.blobs if closure is None else closure,
        }
        original_put = CAS.put_expected
        original_read = CAS.read
        with TemporaryDirectory() as directory:
            writer = CAS(Path(directory) / "cas")
            reader = CAS(writer.root, read_only=True)

            @contextmanager
            def store():
                yield writer, reader, lambda: events.append("guard")

            def inspect_intent(raw, *, expected_intent_digest, evidence_cas):
                events.append("closure")
                self.assertEqual(raw, self.intent_raw)
                self.assertEqual(expected_intent_digest, self.intent_pin)
                self.assertIs(evidence_cas, reader)
                self.assertTrue(evidence_cas.read_only)
                for pin, value in self.blobs.items():
                    self.assertEqual(evidence_cas.read(pin), value)
                return copy.deepcopy(bound)

            def prepare(
                raw, *, expected_intent_digest, evidence_cas, provisioning_inputs
            ):
                events.append("prepare")
                self.assertEqual(raw, self.intent_raw)
                self.assertEqual(expected_intent_digest, self.intent_pin)
                self.assertIs(evidence_cas, reader)
                self.assertEqual(provisioning_inputs, self.provisioning)
                if fail_prepare:
                    raise subject.case.NativePluginUpdateCaseError(
                        "inert private preparation detail"
                    )
                return {
                    "request": copy.deepcopy(self.request),
                    "request_raw": self.request_raw,
                    "request_digest": self.request_pin,
                }

            def identity_run(container, copied_owner, static_pin, *, before_activation):
                events.append("identity")
                self.assertEqual(
                    (container, copied_owner, static_pin),
                    (self.container, (100, 200), self.static_pin),
                )
                if identity_mode == "skip-hook":
                    return copy.deepcopy(self.identity_result)
                try:
                    before_activation(dict(self.provisioning))
                    self.assertEqual(reader.read(self.request_pin), self.request_raw)
                    events.append("committed-readback")
                    if identity_mode == "repeat-hook":
                        before_activation(dict(self.provisioning))
                except Exception:
                    return {
                        "status": "REFUSED",
                        "activation_count": 0,
                        "invocation_count": 0,
                    }
                events.append("activate")
                value = copy.deepcopy(self.identity_result)
                if identity_mode == "later-refusal":
                    value["status"] = "REFUSED"
                return value

            def put(store, source, *, expected_digest, max_bytes):
                if expected_digest == self.request_pin:
                    events.append("request-put")
                    if fail_request_write:
                        raise CASError("inert private write failure")
                return original_put(
                    store, source, expected_digest=expected_digest, max_bytes=max_bytes
                )

            def read(store, digest, *, max_bytes=None):
                if fail_request_readback and digest == self.request_pin:
                    raise CASError("inert private readback failure")
                return original_read(store, digest, max_bytes=max_bytes)

            with ExitStack() as patches:
                for item in (
                    patch.object(subject, "_environment"),
                    patch.object(subject, "_read_bundle", return_value=self.blobs),
                    patch.object(subject, "_fresh_store", store),
                    patch.object(
                        subject.case,
                        "validate_native_plugin_update_case_intent",
                        side_effect=inspect_intent,
                    ),
                    patch.object(
                        subject.case,
                        "prepare_native_plugin_update_case",
                        side_effect=prepare,
                    ),
                    patch.object(
                        subject.identity_guest, "_run", side_effect=identity_run
                    ),
                    patch.object(CAS, "put_expected", put),
                    patch.object(CAS, "read", read),
                ):
                    patches.enter_context(item)
                result = subject._run(
                    self.container,
                    (100, 200),
                    self.static_pin,
                    self.bundle_pin,
                    self.intent_pin,
                )
            for pin in (*self.blobs, self.request_pin):
                try:
                    retained[pin] = reader.read(pin)
                except CASError:
                    pass
        return result, events, retained

    def test_commits_nonsecret_request_before_single_activation_without_schema_rewrite(
        self,
    ):
        result, events, retained = self.run_guest()
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["identity_observation"], self.identity_result)
        self.assertEqual(retained, {**self.blobs, self.request_pin: self.request_raw})
        self.assertLess(events.index("prepare"), events.index("request-put"))
        self.assertLess(events.index("request-put"), events.index("committed-readback"))
        self.assertLess(events.index("committed-readback"), events.index("activate"))
        self.assertEqual(events.count("activate"), 1)
        prepared = result["prepared_case"]
        self.assertEqual(prepared["request"], self.request)
        self.assertEqual(prepared["request_digest"], self.request_pin)
        self.assertTrue(prepared["local_pre_activation_readback"])
        self.assertFalse(prepared["host_ack_received"])
        self.assertEqual(prepared["authority"], subject.AUTHORITY)
        for document in (result, prepared):
            self.assertTrue(all(document[key] is False for key in subject._FALSE_FLAGS))
        self.assertNotIn("inert-secret-not-for-output", json.dumps(result))
        self.assertNotIn(b"inert-secret-not-for-output", b"".join(retained.values()))

    def test_dangling_or_extra_closure_refuses_before_identity_guest(self):
        changed = dict(self.blobs)
        changed.pop(self.intent_pin)
        for closure in (changed, {**self.blobs, "sha256:" + "c" * 64: b"extra"}):
            with self.subTest(closure=list(closure)):
                result, events, retained = self.run_guest(closure=closure)
                self.assertEqual(result["status"], "REFUSED")
                self.assertEqual(
                    result["refusal"]["reason"], "BUNDLE_INPUT_CLOSURE_CHANGED"
                )
                self.assertNotIn("identity", events)
                self.assertNotIn(self.request_pin, retained)

    def test_commit_failure_or_missing_or_repeated_hook_never_returns_success(self):
        for arguments in (
            {"fail_prepare": True},
            {"fail_request_write": True},
            {"fail_request_readback": True},
            {"identity_mode": "skip-hook"},
            {"identity_mode": "repeat-hook"},
        ):
            with self.subTest(arguments=arguments):
                result, events, _ = self.run_guest(**arguments)
                self.assertEqual(result["status"], "REFUSED")
                self.assertNotIn("activate", events)
                self.assertNotIn("inert private write failure", json.dumps(result))
                self.assertNotIn("inert private readback failure", json.dumps(result))
                self.assertNotIn("inert private preparation detail", json.dumps(result))
                stages = {
                    "fail_prepare": "PREACTIVATION_PREPARATION",
                    "fail_request_write": "PREACTIVATION_PUBLICATION",
                    "fail_request_readback": "PREACTIVATION_READBACK",
                }
                for flag, phase in stages.items():
                    if arguments.get(flag):
                        self.assertEqual(
                            result["refusal"],
                            {"phase": phase, "reason": phase + "_REFUSED"},
                        )

    def test_later_refusal_retains_local_commit_without_qualification(self):
        result, events, retained = self.run_guest(identity_mode="later-refusal")
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["identity_observation"]["status"], "REFUSED")
        self.assertTrue(result["prepared_case"]["local_pre_activation_readback"])
        self.assertEqual(events.count("activate"), 1)
        self.assertEqual(retained[self.request_pin], self.request_raw)

    def test_bundle_requires_exact_canonical_pinned_bounded_utf8_blobs(self):
        self.assertEqual(
            subject._parse_bundle(self.bundle_raw, self.bundle_pin, self.intent_pin),
            self.blobs,
        )
        changed = copy.deepcopy(self.bundle)
        changed["blobs"][self.intent_pin] += "changed"
        missing = copy.deepcopy(self.bundle)
        del missing["blobs"][self.intent_pin]
        wrong_type = copy.deepcopy(self.bundle)
        wrong_type["blobs"][self.intent_pin] = 4
        for raw, pin in (
            (self.bundle_raw, "sha256:" + "0" * 64),
            (self.bundle_raw + b"\n", None),
            (b'{"schema":1,"schema":2}', None),
            (subject.canonical_json(changed), None),
            (subject.canonical_json(missing), None),
            (subject.canonical_json(wrong_type), None),
            (b"x" * (subject._MAX_INPUT + 1), None),
        ):
            with (
                self.subTest(prefix=raw[:35]),
                self.assertRaises(subject.NativePluginUpdateCaseGuestError),
            ):
                subject._parse_bundle(
                    raw, pin or subject.identity_guest._digest(raw), self.intent_pin
                )

    def test_fixed_input_uses_existing_held_nofollow_custody_reader(self):
        with (
            patch.object(subject.os, "open", return_value=123) as opened,
            patch.object(subject.os, "close") as closed,
            patch.object(
                subject.identity_guest.identity,
                "_read_at",
                return_value=(self.bundle_raw, {}),
            ) as read,
        ):
            self.assertEqual(
                subject._read_bundle(self.bundle_pin, self.intent_pin), self.blobs
            )
        opened.assert_called_once_with(
            "/",
            subject.os.O_RDONLY
            | subject.os.O_DIRECTORY
            | subject.os.O_NOFOLLOW
            | subject.os.O_CLOEXEC,
        )
        read.assert_called_once_with(
            123,
            subject.BUNDLE_PATH,
            owner=0,
            owner_gid=0,
            modes={0o444},
            limit=subject._MAX_INPUT,
        )
        closed.assert_called_once_with(123)

    def test_fixed_output_root_must_be_absent_and_has_no_reuse_path(self):
        with (
            patch.object(subject.os, "open", side_effect=[100, 101]) as opened,
            patch.object(subject.os, "close") as closed,
            patch.object(subject, "_directory", return_value=(1, 2, 3)),
            patch.object(subject.os, "mkdir", side_effect=FileExistsError) as mkdir,
            patch.object(subject, "CAS") as cas,
            self.assertRaises(FileExistsError),
            subject._fresh_store(),
        ):
            self.fail("existing output root was reused")
        self.assertEqual(opened.call_count, 2)
        mkdir.assert_called_once_with(
            "aragorn-native-plugin-update-case", 0o700, dir_fd=101
        )
        self.assertEqual(
            [call.args for call in closed.call_args_list], [(101,), (100,)]
        )
        cas.assert_not_called()

    def test_guest_output_directory_custody_requires_root_pair_and_private_mode(self):
        for uid, gid, mode in (
            (1000, 0, 0o700),
            (0, 1000, 0o700),
            (0, 0, 0o770),
            (0, 0, 0o755),
        ):
            metadata = SimpleNamespace(st_mode=0o040000 | mode, st_uid=uid, st_gid=gid)
            with (
                patch.object(subject.os, "fstat", return_value=metadata),
                self.assertRaises(subject.NativePluginUpdateCaseGuestError),
            ):
                subject._directory(123, 0o700)

    def test_held_output_root_replacement_refuses_and_closes_every_descriptor(self):
        def metadata(inode, mode):
            return SimpleNamespace(
                st_dev=1, st_ino=inode, st_mode=0o040000 | mode, st_uid=0, st_gid=0
            )

        held = {
            100: metadata(1, 0o755),
            101: metadata(2, 0o755),
            102: metadata(3, 0o700),
        }
        replacement = False

        def named(component, *, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            if (dir_fd, component) == (100, "."):
                return held[100]
            if (dir_fd, component) == (100, "run"):
                return held[101]
            self.assertEqual(
                (dir_fd, component), (101, "aragorn-native-plugin-update-case")
            )
            return metadata(4, 0o700) if replacement else held[102]

        with (
            patch.object(subject.os, "open", side_effect=[100, 101, 102]),
            patch.object(subject.os, "close") as closed,
            patch.object(subject.os, "fstat", side_effect=held.__getitem__),
            patch.object(subject.os, "stat", side_effect=named),
            patch.object(subject.os, "mkdir") as mkdir,
            patch.object(subject.os, "fsync") as sync,
            patch.object(subject, "CAS", side_effect=[object(), object()]) as cas,
        ):
            with self.assertRaises(subject.NativePluginUpdateCaseGuestError):
                with subject._fresh_store() as (_, _, guard):
                    replacement = True
                    guard()
        mkdir.assert_called_once_with(
            "aragorn-native-plugin-update-case", 0o700, dir_fd=101
        )
        sync.assert_called_once_with(101)
        self.assertEqual(cas.call_count, 2)
        self.assertEqual(
            [call.args for call in closed.call_args_list], [(102,), (101,), (100,)]
        )

    def test_cli_is_fixed_six_arguments_and_structured_refusal(self):
        args = [
            self.container,
            "100",
            "200",
            self.static_pin,
            self.bundle_pin,
            self.intent_pin,
        ]
        output = io.BytesIO()
        refusal = {"status": "REFUSED", "reason": "inert"}
        with (
            patch.object(subject, "_run", return_value=refusal) as run,
            patch.object(subject.sys, "stdout", SimpleNamespace(buffer=output)),
        ):
            self.assertEqual(subject.main(args[:4]), 64)
            run.assert_not_called()
            self.assertEqual(subject.main(args), 126)
            run.assert_called_once_with(
                self.container,
                (100, 200),
                self.static_pin,
                self.bundle_pin,
                self.intent_pin,
            )
        self.assertEqual(output.getvalue(), subject.canonical_json(refusal) + b"\n")


if __name__ == "__main__":
    unittest.main()
