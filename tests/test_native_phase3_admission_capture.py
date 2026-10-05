"""New offline consumer checks only; inert fixtures are never capture evidence.

The public positive tests isolate outer/live/branch readers deliberately. They
exercise the real retained intent, request and input-bundle joins, not a live
successor fixture, admission acceptance or Phase 3 qualification.
"""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aragorn import native_phase3_admission_capture as subject
from aragorn import native_phase3_admission_case as case
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from test_native_phase3_admission_case import builder_arguments, provisioning_inputs
from test_native_phase3_plugin_update_live_binding import _fixture as inert_live_fixture


_CAPTURE_SCHEMA = "aragorn/native-admission-case-capture/v1"
_CAPTURE_AUTHORITY = (
    "OWNED_SUCCESSOR_CASE_CAPTURE_NOT_INDEPENDENT_ROUTE_OR_PHASE3_QUALIFICATION"
)
_GUEST_SCHEMA = "aragorn/native-admission-case-guest/v1"
_GUEST_AUTHORITY = (
    "GUEST_LOCAL_PREACTIVATION_NATIVE_ADMISSION_CASE_NOT_HOST_ACK_OR_QUALIFICATION"
)


class NativeAdmissionCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.store = CAS(self.root / "cas")
        self.readonly = CAS(self.store.root, read_only=True)
        self.arguments = builder_arguments()
        self.flags = dict.fromkeys(case._FALSE_FLAGS, False)
        self.make_case(case.DIRECT_WRITE_CASE)

    def put(self, raw, *, store=None):
        return (self.store if store is None else store).put(
            BytesIO(raw), max_bytes=len(raw)
        )

    def make_case(self, selected):
        self.built = case.build_native_admission_case_intent(
            **(self.arguments | {"case_id": selected})
        )
        for raw in self.built["input_blobs"].values():
            self.put(raw)
        self.intent_pin = self.built["intent_digest"]
        self.intent = json.loads(self.built["intent_raw"])
        self.prepared = case.prepare_native_admission_case(
            self.built["intent_raw"],
            expected_intent_digest=self.intent_pin,
            evidence_cas=self.readonly,
            provisioning_inputs=provisioning_inputs(),
        )
        self.put(self.prepared["request_raw"])
        bundle = canonical_json(
            {
                "schema": "aragorn/native-admission-case-inputs/v1",
                "intent_digest": self.intent_pin,
                "blobs": {
                    pin: raw.decode("utf-8")
                    for pin, raw in self.built["input_blobs"].items()
                },
            }
        )
        self.value = {
            "schema": _CAPTURE_SCHEMA,
            "authority": _CAPTURE_AUTHORITY,
            "status": "OBSERVED",
            "intent_digest": self.intent_pin,
            "case_id": selected,
            "fixture_container": "a" * 64,
            "fixture_creation_attempted": True,
            "plugin_input_bundle": None if selected == case.DIRECT_WRITE_CASE else {},
            "source": json.loads(self.arguments["source_record_raw"]),
            "staged_profile": deepcopy(self.arguments["staged_profile"]),
            "refusal": None,
            "postcondition_failures": [],
            "independent_capture_replay_complete": False,
            "guest": {
                "schema": _GUEST_SCHEMA,
                "authority": _GUEST_AUTHORITY,
                "status": "OBSERVED",
                "fixture_container": "a" * 64,
                "intent_digest": self.intent_pin,
                "case_id": selected,
                "branch": self.intent["branch"],
                "input_bundle_digest": case._digest(bundle),
                "static_pin_manifest_digest": self.intent["static_pin_manifest_digest"],
                "prepared_case": {
                    "request": deepcopy(self.prepared["request"]),
                    "request_digest": self.prepared["request_digest"],
                    "local_pre_activation_readback": True,
                    "host_ack_received": False,
                    "authority": _GUEST_AUTHORITY,
                    **self.flags,
                },
                "live_identity": {
                    "provisioning_file_digests": deepcopy(
                        self.prepared["provisioning_file_digests"]
                    )
                },
                "leaf": {} if selected == case.DIRECT_WRITE_CASE else None,
                "plugin_update": {} if selected == case.UPDATE_CASE else None,
                "refusal": None,
                "postcondition_failures": [],
                **self.flags,
            },
            **self.flags,
        }

    @contextmanager
    def isolated_readers(self):
        """Never confuse these mocked joins with a complete capture replay."""
        with ExitStack() as stack:
            readers = {
                name: stack.enter_context(
                    patch.object(subject, name, return_value={"inert_join": name})
                )
                for name in ("_outer", "_live", "_direct", "_plugin")
            }
            stack.enter_context(
                patch("subprocess.run", side_effect=AssertionError("live effect"))
            )
            yield readers

    def verify(self, value=None, *, raw=None, **changes):
        if raw is None:
            raw = canonical_json(self.value if value is None else value) + b"\n"
        pin = self.put(raw)
        kwargs = {
            "expected_capture_digest": pin,
            "expected_intent_digest": self.intent_pin,
            "evidence_cas": self.readonly,
        }
        kwargs.update(changes)
        with (
            patch.object(CAS, "put", side_effect=AssertionError("consumer wrote CAS")),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("consumer wrote CAS")
            ),
        ):
            return subject.verify_native_admission_capture(raw, **kwargs)

    def test_real_input_request_joins_and_case_dispatch_with_readers_isolated(self):
        for selected in case.CASE_BRANCHES:
            with self.subTest(case_id=selected):
                self.make_case(selected)
                before = deepcopy(self.value)
                with self.isolated_readers() as readers:
                    result = self.verify()
                self.assertEqual(result["status"], "BOUNDED_CAPTURE_REPLAY_VERIFIED")
                self.assertIs(result["independent_capture_replay_complete"], True)
                self.assertTrue(all(result[name] is False for name in self.flags))
                self.assertEqual(self.value, before)
                readers["_outer"].assert_called_once()
                readers["_live"].assert_called_once()
                chosen = "_direct" if selected == case.DIRECT_WRITE_CASE else "_plugin"
                other = "_plugin" if chosen == "_direct" else "_direct"
                readers[chosen].assert_called_once()
                readers[other].assert_not_called()

    def test_caller_pins_readonly_store_and_canonical_bytes_are_required(self):
        changes = (
            {"expected_capture_digest": "sha256:" + "0" * 64},
            {"expected_intent_digest": "sha256:" + "0" * 64},
            {"evidence_cas": self.store},
            {"raw": canonical_json(self.value)},
            {"raw": canonical_json(self.value) + b"\n\n"},
            {"raw": b"{}\n"},
        )
        with self.isolated_readers():
            for change in changes:
                with (
                    self.subTest(change=tuple(change)),
                    self.assertRaises(subject.NativeAdmissionCaptureError),
                ):
                    self.verify(**change)

    def test_capture_must_be_present_in_caller_readonly_store(self):
        raw = canonical_json(self.value) + b"\n"
        with (
            self.isolated_readers(),
            self.assertRaises(subject.NativeAdmissionCaptureError),
        ):
            subject.verify_native_admission_capture(
                raw,
                expected_capture_digest=case._digest(raw),
                expected_intent_digest=self.intent_pin,
                evidence_cas=self.readonly,
            )

    def test_each_proof_ceiling_and_observation_envelope_is_fail_closed(self):
        mutations = []
        for location in ((), ("guest",), ("guest", "prepared_case")):
            for name in self.flags:
                for promoted in (True, 0):
                    mutations.append((location, name, promoted))
        mutations.extend(
            [
                ((), "independent_capture_replay_complete", True),
                ((), "status", "REFUSED"),
                ((), "authority", "QUALIFIED"),
                ((), "schema", "aragorn/runtime-native-plugin-update-capture/v1"),
                (("guest",), "status", "REFUSED"),
                (("guest",), "authority", "QUALIFIED"),
                (("guest",), "case_id", case.UPDATE_CASE),
                (("guest",), "branch", case.UPDATE_BRANCH),
                (("guest",), "fixture_container", "b" * 64),
                (("guest", "prepared_case"), "host_ack_received", True),
                (("guest", "prepared_case"), "local_pre_activation_readback", False),
            ]
        )
        with self.isolated_readers():
            for location, name, replacement in mutations:
                changed = deepcopy(self.value)
                target = changed
                for component in location:
                    target = target[component]
                target[name] = replacement
                with (
                    self.subTest(path=(*location, name), value=replacement),
                    self.assertRaises(subject.NativeAdmissionCaptureError),
                ):
                    self.verify(changed)

    def test_request_bundle_static_and_provisioning_substitution_is_rejected(self):
        changed_values = []
        for name in ("input_bundle_digest", "static_pin_manifest_digest"):
            changed = deepcopy(self.value)
            changed["guest"][name] = "sha256:" + "0" * 64
            changed_values.append((name, changed))
        changed = deepcopy(self.value)
        changed["guest"]["prepared_case"]["request_digest"] = "sha256:" + "0" * 64
        changed_values.append(("request_digest", changed))
        changed = deepcopy(self.value)
        request = changed["guest"]["prepared_case"]["request"]
        request["prepared_before_activation"] = False
        changed["guest"]["prepared_case"]["request_digest"] = self.put(
            canonical_json(request)
        )
        changed_values.append(("retained_but_changed_request", changed))
        changed = deepcopy(self.value)
        hashes = changed["guest"]["live_identity"]["provisioning_file_digests"]
        hashes[next(iter(hashes))] = "sha256:" + "0" * 64
        changed_values.append(("provisioning", changed))
        with self.isolated_readers():
            for name, changed in changed_values:
                with (
                    self.subTest(field=name),
                    self.assertRaises(subject.NativeAdmissionCaptureError),
                ):
                    self.verify(changed)

    def test_missing_retained_source_or_request_never_reaches_branch_reader(self):
        source_pin = next(iter(self.intent["controller_source_digests"].values()))
        for index, omitted in enumerate((source_pin, self.prepared["request_digest"])):
            incomplete = CAS(self.root / f"incomplete-{index}")
            records = self.built["input_blobs"] | {
                self.prepared["request_digest"]: self.prepared["request_raw"]
            }
            for pin, raw in records.items():
                if pin != omitted:
                    self.put(raw, store=incomplete)
            raw = canonical_json(self.value) + b"\n"
            pin = self.put(raw, store=incomplete)
            with self.subTest(omitted=omitted), self.isolated_readers() as readers:
                with self.assertRaises(subject.NativeAdmissionCaptureError):
                    subject.verify_native_admission_capture(
                        raw,
                        expected_capture_digest=pin,
                        expected_intent_digest=self.intent_pin,
                        evidence_cas=CAS(incomplete.root, read_only=True),
                    )
                readers["_direct"].assert_not_called()
                readers["_plugin"].assert_not_called()

    def test_failed_join_stops_once_without_fallback_or_second_branch(self):
        for failed in ("_outer", "_live", "_direct"):
            events = []
            with self.subTest(failed=failed), self.isolated_readers() as readers:
                for name, mocked in readers.items():

                    def observe(*args, name=name):
                        events.append(name)
                        if name == failed:
                            raise subject.NativeAdmissionCaptureError("inert refusal")
                        return {"inert_join": name}

                    mocked.side_effect = observe
                with self.assertRaises(subject.NativeAdmissionCaptureError):
                    self.verify()
                expected = ["_outer", "_live", "_direct"]
                self.assertEqual(events, expected[: expected.index(failed) + 1])
                readers["_plugin"].assert_not_called()

    def plugin_fixture(self):
        """Translate old data only for a branch unit; never relabel it as evidence."""
        baseline = json.loads(self.arguments["baseline_capture_raw"])
        old = baseline["observation"]
        guest = deepcopy(old)
        live_fixture = deepcopy(baseline)
        inert_live_fixture(live_fixture)
        guest["live_identity"] = live_fixture["live_identity"]
        installed = {}
        for source in (
            "scripts/runtime_native_plugin_update_check.py",
            "scripts/runtime_native_plugin_package_check.py",
        ):
            item = baseline["fixture_helpers"][source]
            installed[item["installed_path"]] = {
                key: item[key] for key in ("bytes", "digest")
            }
        plugin = {
            "invocation": deepcopy(old["plugin_update"]),
            "installed_sources": installed,
            "installed_sources_after": deepcopy(installed),
            "staged_input_bundle": {
                path.replace(
                    "/route-input", "/opt/aragorn/native-plugin-update-input", 1
                ): deepcopy(record)
                for path, record in old["input_bundle"].items()
            },
            **{
                key: deepcopy(old[key])
                for key in (
                    "input_bundle",
                    "input_mount",
                    "input_mount_source",
                    "baseline",
                    "input_mount_removed",
                    "inherited_input_restored",
                    "inherited_input_restoration",
                )
            },
        }
        guest["plugin_update"] = plugin
        guest["leaf"] = None
        guest["setup"]["admission_observation"] = {
            "empty_receipt_store_after": deepcopy(old["empty_receipt_store_after"]),
            "protected_effects_unchanged": True,
        }
        guest["post_observation"] = {
            "PLUGIN_UPDATE_SOURCES_AFTER": deepcopy(installed),
            "PLUGIN_INPUT_BUNDLE_AFTER": deepcopy(plugin["input_bundle"]),
            "PLUGIN_STAGED_INPUT_BUNDLE_AFTER": deepcopy(plugin["staged_input_bundle"]),
            "PLUGIN_INPUT_MOUNT_AFTER": deepcopy(plugin["input_mount"]),
            "RECEIPT_STORE_AFTER": deepcopy(old["empty_receipt_store_after"]),
        }
        capture = {
            **deepcopy(baseline),
            "guest": guest,
            "plugin_input_bundle": deepcopy(baseline["input_bundle"]),
        }
        return capture, baseline

    def test_real_plugin_branch_replays_retained_primitives_without_other_joins(self):
        capture, baseline = self.plugin_fixture()
        before = deepcopy(capture)
        result = subject._plugin(capture, baseline)
        self.assertIsInstance(result, dict)
        self.assertEqual(capture, before)

    def test_plugin_branch_rejects_rehashed_semantic_and_cleanup_tampering(self):
        capture, baseline = self.plugin_fixture()
        mutations = (
            (("guest", "leaf"), {}),
            (("guest", "plugin_update", "input_mount_removed"), False),
            (("guest", "plugin_update", "inherited_input_restored"), False),
            (("guest", "plugin_update", "invocation", "execution", "exit_code"), 1),
            (("guest", "plugin_update", "invocation", "document", "status"), "REFUSED"),
            (
                (
                    "guest",
                    "plugin_update",
                    "invocation",
                    "document",
                    "decision",
                    "phase3_exit_eligible",
                ),
                True,
            ),
            (
                (
                    "guest",
                    "plugin_update",
                    "invocation",
                    "document",
                    "explicit_policy_denial_observation",
                    "qualification_eligible",
                ),
                True,
            ),
            (
                (
                    "guest",
                    "plugin_update",
                    "invocation",
                    "document",
                    "action",
                    "state_invariants",
                    "config",
                ),
                False,
            ),
        )
        for path, replacement in mutations:
            changed = deepcopy(capture)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            if "document" in path:
                invocation = changed["guest"]["plugin_update"]["invocation"]
                raw = canonical_json(invocation["document"]) + b"\n"
                invocation["execution"]["stdout_bytes"] = len(raw)
                invocation["execution"]["stdout_digest"] = case._digest(raw)
            with self.subTest(path=path), self.assertRaises(ValueError):
                subject._plugin(changed, baseline)

    def files_fixture(self):
        """Reuse data-only old live shape to isolate the new file-join helper."""
        value = json.loads(self.arguments["baseline_capture_raw"])
        inert_live_fixture(value)
        value["guest"] = deepcopy(value["observation"])
        envelope = value["live_identity"]
        accounts = {
            role: (item["process"]["uid"], item["process"]["gid"])
            for role, item in value["guest"]["processes"].items()
        }
        return value, envelope, accounts

    def test_plugin_copied_helper_records_join_source_and_installed_readback(self):
        capture, baseline = self.plugin_fixture()
        for source in (
            "scripts/runtime_native_plugin_update_check.py",
            "scripts/runtime_native_plugin_package_check.py",
        ):
            for field, replacement in (
                ("digest", "sha256:" + "0" * 64),
                ("installed_path", "/tmp/unbound.py"),
                ("installed_mode", "0755"),
            ):
                changed = deepcopy(capture)
                changed["fixture_helpers"][source][field] = replacement
                with (
                    self.subTest(source=source, field=field),
                    self.assertRaises(subject.NativeAdmissionCaptureError),
                ):
                    subject._plugin(changed, baseline)
            changed = deepcopy(capture)
            next(row for row in changed["source"]["files"] if row["path"] == source)[
                "digest"
            ] = "sha256:" + "0" * 64
            with (
                self.subTest(source=source, field="source_digest"),
                self.assertRaises(subject.NativeAdmissionCaptureError),
            ):
                subject._plugin(changed, baseline)

    def test_plugin_lifecycle_and_staged_mount_identity_must_agree(self):
        capture, baseline = self.plugin_fixture()
        for lifecycle in (False, 1):
            changed = deepcopy(capture)
            changed["guest"]["plugin_update"]["invocation"]["document"][
                "plugin_update_lifecycle_executed"
            ] = lifecycle
            with (
                self.subTest(lifecycle=lifecycle),
                self.assertRaises(subject.NativeAdmissionCaptureError),
            ):
                subject._plugin(changed, baseline)
        changed = deepcopy(capture)
        changed["guest"]["plugin_update"]["staged_input_bundle"][
            "/opt/aragorn/native-plugin-update-input"
        ]["identity"][1] += 1
        with self.assertRaises(subject.NativeAdmissionCaptureError):
            subject._plugin(changed, baseline)

    def test_real_file_joins_from_inert_live_shape_without_outer_acceptance(self):
        capture, envelope, accounts = self.files_fixture()
        before = deepcopy(capture)
        self.assertIsNone(
            subject._files(envelope["before"], envelope, capture, accounts)
        )
        self.assertEqual(capture, before)

    def test_file_joins_reject_loaded_bytes_inventory_and_installed_substitution(self):
        capture, envelope, accounts = self.files_fixture()
        paths = (
            ("live_identity", "before", "files", subject.live._ENTRY, "digest"),
            (
                "live_identity",
                "before",
                "loaded_process_views",
                "gateway",
                "openclaw-config",
                "digest",
            ),
            ("guest", "installed_sources", subject.live._PROFILE_PATHS[0], "digest"),
            ("guest", "setup", "worker_binding", "policy_digest"),
        )
        for path in paths:
            changed = deepcopy(capture)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = "sha256:" + "0" * 64
            changed_envelope = changed["live_identity"]
            with self.subTest(path=path), self.assertRaises(ValueError):
                subject._files(
                    changed_envelope["before"], changed_envelope, changed, accounts
                )
        changed = deepcopy(capture)
        changed_envelope = changed["live_identity"]
        changed_envelope["before"]["files"].pop(subject.live._ENTRY)
        with self.assertRaises(subject.NativeAdmissionCaptureError):
            subject._files(
                changed_envelope["before"], changed_envelope, changed, accounts
            )


if __name__ == "__main__":
    unittest.main()
