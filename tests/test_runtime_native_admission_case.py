"""Inert guest integration checks; no native services, VM or live effects run."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn.cas import CAS
from scripts import runtime_native_admission_case as guest


def pin(raw):
    return guest.direct.digest(raw)


class NativeAdmissionCaseGuestTests(unittest.TestCase):
    def setUp(self):
        self.container = "a" * 64
        self.dynamic = {
            path: guest.canonical_json({"path": path, "private": "inert-never-publish"})
            for path in guest.writer_parent.DYNAMIC_PATHS
        }
        self.static = {
            "schema": guest.writer_parent.STATIC_SCHEMA,
            "file_digests": {
                path: pin(path.encode()) for path in guest.writer_parent.STATIC_PATHS
            },
        }
        self.static_raw = guest.canonical_json(self.static)
        self.profile = {
            "schema": "aragorn/runtime-native-admission-staged-profile/v1",
            "files": [
                {
                    "path": path,
                    "mode": mode,
                    "bytes": size,
                    "digest": pin(path.encode()),
                }
                for path, mode, size in zip(
                    guest._OVERRIDE_PATHS, ("0644", "0755"), (3870, 41965), strict=True
                )
            ]
            + [
                {
                    "path": f"/inert/{index}",
                    "mode": "0644",
                    "bytes": 1,
                    "digest": pin(b"fixed"),
                }
                for index in range(68)
            ],
        }
        self.profile_raw = guest.canonical_json(self.profile)
        self.intent = {
            "case_id": guest.case.DIRECT_WRITE_CASE,
            "branch": guest.case.DIRECT_WRITE_BRANCH,
            "static_pin_manifest_digest": pin(self.static_raw),
            "staged_profile_digest": pin(self.profile_raw),
            "case_source_digests": {
                guest._LEAF_SOURCE: pin(b"leaf"),
                guest._VERIFIER_SOURCE: pin(b"verifier"),
            },
        }
        self.intent_raw = guest.canonical_json(self.intent)
        self.intent_pin = pin(self.intent_raw)
        self.blobs = {
            self.intent_pin: self.intent_raw,
            pin(self.static_raw): self.static_raw,
            pin(self.profile_raw): self.profile_raw,
            pin(b"leaf"): b"leaf",
            pin(b"verifier"): b"verifier",
        }
        self.bundle_raw = guest.canonical_json(
            {
                "schema": guest.BUNDLE_SCHEMA,
                "intent_digest": self.intent_pin,
                "blobs": {key: value.decode() for key, value in self.blobs.items()},
            }
        )
        self.bundle_pin = pin(self.bundle_raw)
        self.bound = {"intent": self.intent, "input_blobs": self.blobs}
        self.request = {
            "schema": guest.case.REQUEST_SCHEMA,
            "intent_digest": self.intent_pin,
            "provisioning_file_digests": {
                path: pin(raw) for path, raw in self.dynamic.items()
            },
        }
        self.request_raw = guest.canonical_json(self.request)
        self.request_pin = pin(self.request_raw)

    def test_bundle_reuses_parser_under_distinct_schema_and_restores_parent(self):
        prior_schema = guest.storage.BUNDLE_SCHEMA
        with (
            patch.object(guest.os, "open", return_value=77),
            patch.object(guest.os, "close"),
            patch.object(
                guest.identity, "_read_at", return_value=(self.bundle_raw, {})
            ) as read,
        ):
            value = guest._read_bundle(self.bundle_pin, self.intent_pin)
        self.assertEqual(value, self.blobs)
        self.assertEqual(guest.storage.BUNDLE_SCHEMA, prior_schema)
        self.assertEqual(read.call_args.args[1], guest.BUNDLE_PATH)
        old = guest.direct.parse(self.bundle_raw)
        old["schema"] = prior_schema
        raw = guest.canonical_json(old)
        with (
            patch.object(guest.os, "open", return_value=77),
            patch.object(guest.os, "close"),
            patch.object(guest.identity, "_read_at", return_value=(raw, {})),
            self.assertRaises(guest.storage.NativePluginUpdateCaseGuestError),
        ):
            guest._read_bundle(pin(raw), self.intent_pin)
        self.assertEqual(guest.storage.BUNDLE_SCHEMA, prior_schema)

    def test_exact_two_source_overrides_and_old_inventory_untouched(self):
        before = deepcopy(self.bound)
        result = guest._overrides(self.bound)
        self.assertEqual(set(result), set(guest._OVERRIDE_PATHS))
        self.assertEqual(result[guest._OVERRIDE_PATHS[0]][2], 0o644)
        self.assertEqual(result[guest._OVERRIDE_PATHS[1]][2], 0o755)
        self.assertEqual(self.bound, before)
        bad = deepcopy(self.bound)
        profile = deepcopy(self.profile)
        profile["files"][0]["mode"] = "0777"
        bad["input_blobs"][bad["intent"]["staged_profile_digest"]] = (
            guest.canonical_json(profile)
        )
        with self.assertRaises(guest.NativeAdmissionCaseGuestError):
            guest._overrides(bad)

    def test_seven_original_writer_hooks_commit_before_single_activation(self):
        for mode in ("success", "callback-refusal", "second-activation"):
            with self.subTest(mode=mode):
                events, detached = [], []
                p37b = SimpleNamespace(
                    _write_document=Mock(),
                    capability=SimpleNamespace(_write_control=Mock()),
                )
                native = SimpleNamespace(
                    provision=SimpleNamespace(_create_document=Mock()),
                    _activate=Mock(side_effect=lambda *_: events.append("activate")),
                )

                def prepare():
                    for path, raw in self.dynamic.items():
                        if path == guest.identity._GENESIS:
                            native.provision._create_document(
                                1, Path(path).name, raw, []
                            )
                        elif path == guest.identity._POLICY:
                            p37b.capability._write_control(
                                Path(path), guest.direct.parse(raw)
                            )
                        else:
                            p37b._write_document(Path(path), guest.direct.parse(raw))
                    native._activate(None, "private-token")
                    if mode == "second-activation":
                        native._activate(None, "private-token")
                    return {"setup": "inert"}

                native._prepare = prepare
                activate = native._activate

                def callback(inputs, state):
                    self.assertEqual(inputs, self.dynamic)
                    self.assertEqual(
                        state["provisioning_file_digests"],
                        {path: pin(raw) for path, raw in self.dynamic.items()},
                    )
                    self.assertTrue(state["pins_frozen_before_activation"])
                    self.assertEqual(state["activation_count"], 0)
                    events.append("commit")
                    detached.append(inputs)
                    if mode == "callback-refusal":
                        raise guest.NativeAdmissionCaseGuestError(
                            "INERT_COMMIT_REFUSED"
                        )

                state = {
                    "activation_count": 0,
                    "pins_frozen_before_activation": False,
                    "provisioning_file_digests": {},
                }
                with patch.object(guest.writer_parent, "_p37b", return_value=p37b):
                    if mode == "success":
                        setup, returned = guest._prepare(native, callback, state=state)
                        self.assertEqual(setup, {"setup": "inert"})
                        self.assertIs(returned, state)
                    else:
                        with self.assertRaises(guest.NativeAdmissionCaseGuestError):
                            guest._prepare(native, callback, state=state)
                self.assertEqual(
                    events,
                    ["commit"]
                    if mode == "callback-refusal"
                    else ["commit", "activate"],
                )
                self.assertEqual(
                    state["activation_count"], 0 if mode == "callback-refusal" else 1
                )
                self.assertEqual(detached, [{}])
                self.assertIs(native._activate, activate)

    def test_unsupported_update_refused_before_store_or_bootstrap(self):
        intent = self.intent | {"case_id": guest.case.UPDATE_CASE}
        raw = guest.canonical_json(intent)
        with (
            patch.object(guest, "_environment"),
            patch.object(guest, "_read_bundle", return_value={pin(raw): raw}),
            patch.object(guest, "_fresh_store") as store,
            patch.object(guest.package, "_native") as native,
        ):
            result = guest._run(self.container, (501, 20), self.bundle_pin, pin(raw))
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(
            result["refusal"]["reason"], "SELECTED_CASE_NOT_EXECUTABLE_BY_THIS_GUEST"
        )
        store.assert_not_called()
        native.assert_not_called()

    def _run_inert(self, mode="success"):
        events, retained = [], {}
        sources = {"inert": {"digest": pin(b"installed")}}
        setup = {
            "skill_digest": pin(b"skill"),
            "provisioning": {"genesis_digest": pin(b"genesis")},
            "empty_store": {"receipts": []},
        }
        native = SimpleNamespace(
            _STARTUP_CODE={"/old": (1, "a" * 64, 0o644)},
            setup_prior=SimpleNamespace(
                _require_fixture=Mock(), _installed=Mock(return_value={"denial": None})
            ),
            _sources=Mock(return_value=sources),
            _checked_startup_budget=Mock(return_value={"budget": 8}),
            _snapshot=Mock(return_value=setup["empty_store"]),
            _fixture_token=Mock(return_value="f" * 64),
            prior=SimpleNamespace(
                _stop_fixture=Mock(return_value={"units_inactive": True})
            ),
        )
        old_code = deepcopy(native._STARTUP_CODE)
        cgroup = SimpleNamespace(observe=Mock(return_value={"status": "READY"}))
        p37b = SimpleNamespace(
            _snapshot_effects=Mock(return_value={"protected": "same"})
        )
        gateway = {
            "pid": 42,
            "start_time_ticks": 17,
            "cgroup": "/docker/" + self.container,
            "mount_namespace": {"device": 4, "inode": 5},
            "uids": [992] * 4,
            "gids": [992] * 4,
        }
        config = {
            "identity": [1, 2, 0o100400, 992, 0, 1, 4, 8, 9],
            "bytes": 4,
            "digest": guest.direct.CONFIG_PIN,
        }
        live = {
            "processes": {"gateway": gateway},
            "loaded_process_views": {"gateway": {"openclaw-config": config}},
        }
        boundary = {
            "gateway": {
                "pid": 42,
                "start_time_ticks": 17,
                "cgroup": "0::" + gateway["cgroup"] + "\n",
                "mount_namespace": 5,
                "uid": [992] * 4,
                "gid": [992] * 4,
            },
            "config": config | {"read_only": True},
        }
        leaf = {
            "document": {
                "status": "OBSERVED",
                "before": boundary,
                "after": deepcopy(boundary),
            },
            "execution": {"inert": True},
            "verification": None,
        }
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as patches:
            writer = CAS(Path(temporary).resolve() / "cas")
            reader = CAS(writer.root, read_only=True)

            @contextmanager
            def store():
                yield writer, reader, lambda: events.append("guard")
                if mode == "store-exit-refusal":
                    raise RuntimeError("private store diagnostic")

            def validate(raw, *, expected_intent_digest, evidence_cas):
                self.assertEqual(raw, self.intent_raw)
                self.assertIs(evidence_cas, reader)
                for digest, value in self.blobs.items():
                    self.assertEqual(reader.read(digest), value)
                return deepcopy(self.bound)

            def prepare_request(
                raw, *, expected_intent_digest, evidence_cas, provisioning_inputs
            ):
                events.append("request")
                self.assertEqual(provisioning_inputs, self.dynamic)
                self.assertIs(evidence_cas, reader)
                if mode == "request-refusal":
                    raise RuntimeError("private callback diagnostic")
                return {
                    "request": self.request,
                    "request_raw": self.request_raw,
                    "request_digest": self.request_pin,
                }

            def prepare_native(native_arg, callback, *, state):
                self.assertIs(native_arg, native)
                self.assertEqual(
                    set(native._STARTUP_CODE), {"/old", *guest._OVERRIDE_PATHS}
                )
                state["pins_frozen_before_activation"] = True
                state["provisioning_file_digests"] = {
                    path: pin(raw) for path, raw in self.dynamic.items()
                }
                callback(dict(self.dynamic), state)
                self.assertEqual(reader.read(self.request_pin), self.request_raw)
                retained["request"] = reader.read(self.request_pin)
                events.append("activate")
                state["activation_count"] += 1
                if mode == "activation-refusal":
                    raise RuntimeError("private activation diagnostic")
                return deepcopy(setup), state

            patches.enter_context(patch.object(guest, "_environment"))
            patches.enter_context(
                patch.object(guest, "_read_bundle", return_value=self.blobs)
            )
            patches.enter_context(patch.object(guest, "_fresh_store", store))
            patches.enter_context(
                patch.object(
                    guest.case,
                    "validate_native_admission_case_intent",
                    side_effect=validate,
                )
            )
            patches.enter_context(
                patch.object(
                    guest.case,
                    "prepare_native_admission_case",
                    side_effect=prepare_request,
                )
            )
            patches.enter_context(
                patch.object(guest.package, "_native", return_value=native)
            )
            pin_sources = patches.enter_context(
                patch.object(guest, "_pin_sources", return_value={"inert_leaf": True})
            )
            patches.enter_context(
                patch.dict(sys.modules, {"runtime_native_cgroup_prerequisite": cgroup})
            )
            patches.enter_context(
                patch.object(guest, "_prepare", side_effect=prepare_native)
            )
            patches.enter_context(
                patch.object(guest.writer_parent, "_p37b", return_value=p37b)
            )
            live_reader = patches.enter_context(
                patch.object(
                    guest.identity, "read_native_live_identity", return_value=live
                )
            )
            patches.enter_context(
                patch.object(
                    guest.identity,
                    "compare_native_live_identity",
                    return_value={"same": True},
                )
            )
            invoke = patches.enter_context(
                patch.object(guest, "_invoke_leaf", return_value=leaf)
            )
            patches.enter_context(
                patch.object(
                    guest.direct,
                    "verify_native_admission_direct_write",
                    return_value={"bounded": True},
                )
            )
            if mode == "leaf-refusal":
                leaf["document"]["status"] = "REFUSED"
            if mode.startswith("leaf-timeout"):
                invoke.side_effect = guest.subprocess.TimeoutExpired("fixed", 150)
                if mode == "leaf-timeout-postread-refusal":
                    live_reader.side_effect = [
                        live,
                        RuntimeError("private postread diagnostic"),
                    ]
                    native._sources.side_effect = [
                        sources,
                        RuntimeError("private source diagnostic"),
                    ]
            if mode == "cleanup-refusal":
                native.prior._stop_fixture.side_effect = RuntimeError(
                    "private cleanup diagnostic"
                )
            result = guest._run(
                self.container, (501, 20), self.bundle_pin, self.intent_pin
            )
            for secret in (
                b"inert-never-publish",
                b"private callback",
                b"private activation",
                b"private cleanup",
                b"private store",
                b"private postread",
                b"private source",
            ):
                self.assertNotIn(secret, guest.canonical_json(result))
            self.assertEqual(native._STARTUP_CODE, old_code)
            native.prior._stop_fixture.assert_called_once_with()
            if mode.startswith("leaf-timeout"):
                self.assertEqual(live_reader.call_count, 2)
                self.assertEqual(native._sources.call_count, 2)
                self.assertEqual(pin_sources.call_count, 2)
                self.assertEqual(native.setup_prior._installed.call_count, 2)
                native._snapshot.assert_called_once()
                self.assertEqual(p37b._snapshot_effects.call_count, 2)
                self.assertEqual(native._checked_startup_budget.call_count, 2)
            return result, events, retained, invoke.call_count

    def test_leaf_timeout_retains_independent_postreadbacks_and_original_failure(self):
        for mode in ("leaf-timeout", "leaf-timeout-postread-refusal"):
            with self.subTest(mode=mode):
                result, _, retained, calls = self._run_inert(mode)
                self.assertEqual(result["status"], "REFUSED")
                self.assertEqual(calls, 1)
                self.assertEqual(
                    result["refusal"],
                    {
                        "phase": "LEAF_INVOCATION",
                        "reason": "FIXED_ADMISSION_GUEST_REFUSED",
                    },
                )
                self.assertEqual(retained["request"], self.request_raw)
                self.assertEqual(
                    result["fixture_stack_cleanup"], {"units_inactive": True}
                )
                self.assertEqual(
                    result["postcondition_failures"],
                    ["LIVE_IDENTITY_AFTER", "INSTALLED_SOURCES_AFTER"]
                    if mode.endswith("postread-refusal")
                    else [],
                )
                for name in (
                    "LEAF_SOURCES_AFTER",
                    "INSTALLED_SKILL_AFTER",
                    "RECEIPT_STORE_AFTER",
                    "PROTECTED_EFFECTS_AFTER",
                    "STARTUP_BUDGET_AFTER",
                ):
                    self.assertIn(name, result["post_observation"])

    def test_completed_direct_write_case_retains_request_before_single_dispatch(self):
        result, events, retained, calls = self._run_inert()
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(calls, 1)
        self.assertLess(events.index("request"), events.index("activate"))
        self.assertEqual(retained["request"], self.request_raw)
        self.assertEqual(result["live_identity"]["activation_count"], 1)
        self.assertEqual(result["live_identity"]["invocation_count"], 1)
        self.assertEqual(result["fixture_stack_cleanup"], {"units_inactive": True})
        self.assertTrue(all(result[key] is False for key in guest._FALSE_FLAGS))

    def test_refusals_preserve_partial_evidence_and_cleanup_without_retry(self):
        for mode in (
            "request-refusal",
            "activation-refusal",
            "leaf-refusal",
            "cleanup-refusal",
            "store-exit-refusal",
        ):
            with self.subTest(mode=mode):
                result, events, retained, calls = self._run_inert(mode)
                self.assertEqual(result["status"], "REFUSED")
                self.assertIsNotNone(result["refusal"])
                self.assertEqual(
                    calls, 0 if mode in {"request-refusal", "activation-refusal"} else 1
                )
                self.assertEqual(
                    result["live_identity"]["activation_count"],
                    0 if mode == "request-refusal" else 1,
                )
                if mode != "request-refusal":
                    self.assertEqual(retained["request"], self.request_raw)
                    self.assertIsNotNone(result["prepared_case"])
                if mode == "leaf-refusal":
                    self.assertEqual(result["leaf"]["document"]["status"], "REFUSED")
                    self.assertIsNotNone(result["live_identity"]["after"])

    def test_leaf_root_live_joins_reject_same_pid_replacement_or_credential_substitution(
        self,
    ):
        result, _, _, _ = self._run_inert()
        leaf, live = result["leaf"]["document"], result["live_identity"]
        for kind in ("start", "cgroup", "namespace", "credential"):
            modified = deepcopy(live)
            if kind == "start":
                modified["after"]["processes"]["gateway"]["start_time_ticks"] += 1
            elif kind == "cgroup":
                modified["after"]["processes"]["gateway"]["cgroup"] += "/substituted"
            elif kind == "namespace":
                modified["after"]["processes"]["gateway"]["mount_namespace"][
                    "inode"
                ] += 1
            else:
                modified["after"]["loaded_process_views"]["gateway"]["openclaw-config"][
                    "identity"
                ][1] += 1
            with (
                self.subTest(kind=kind),
                self.assertRaises(guest.NativeAdmissionCaseGuestError),
            ):
                guest._leaf_live_joins(leaf, modified)

    def test_fixed_leaf_uses_held_namespace_fd_and_accepts_secret_safe_refusal(self):
        gateway = {
            "pid": 42,
            "start_time_ticks": 17,
            "cgroup": "/docker/" + self.container,
            "mount_namespace": {"device": 4, "inode": 5},
        }
        setup = {"skill_digest": pin(b"skill")}
        source_pins = self.intent["case_source_digests"]
        document = {
            "schema": guest.direct.SCHEMA,
            "authority": guest.direct.AUTHORITY,
            "case_id": guest.direct.CASE_ID,
            "fixture_container": self.container,
            "gateway_pid": 42,
            "admitted_digest": setup["skill_digest"],
            "status": "REFUSED",
            "source_pins": {
                guest.direct.PROBE: source_pins[guest._LEAF_SOURCE],
                guest.direct.VERIFIER: source_pins[guest._VERIFIER_SOURCE],
            },
            **dict.fromkeys(guest.direct.FALSE_FLAGS, False),
        }
        raw = guest.canonical_json(document) + b"\n"
        with (
            patch.object(guest.identity, "_open_pidfd", return_value=91),
            patch.object(guest.os, "open", return_value=92),
            patch.object(guest.os, "close"),
            patch.object(
                guest.os, "fstat", return_value=SimpleNamespace(st_dev=4, st_ino=5)
            ),
            patch.object(
                guest.identity.process, "_process_start_time", return_value=17
            ),
            patch.object(
                guest.identity.process,
                "_process_cgroup",
                return_value=gateway["cgroup"],
            ),
            patch.object(guest.identity.process, "require_live_pidfd"),
            patch.object(
                guest.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=126, stdout=raw, stderr=b""),
            ) as run,
        ):
            value = guest._invoke_leaf(
                self.container,
                {"processes": {"gateway": gateway}},
                setup,
                self.bound,
                "f" * 64,
            )
        self.assertEqual(value["document"], document)
        argv = run.call_args.args[0]
        self.assertEqual(
            argv[:3], ["/usr/bin/nsenter", "--mount=/proc/self/fd/92", "--"]
        )
        self.assertIn("--bounding-set=-all", argv)
        self.assertIn("--groups=992", argv)
        self.assertEqual(run.call_args.kwargs["pass_fds"], (92,))
        self.assertEqual(run.call_args.kwargs["timeout"], 150)
        self.assertNotIn("f" * 64, str(value))


if __name__ == "__main__":
    unittest.main()
