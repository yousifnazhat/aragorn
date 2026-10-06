"""Inert common74 writer integration; no services, live fixtures or qualification.

The existing preparation fixture is used only for data construction. Tests do
not inherit or discover historical test methods. Native writers are syscall-free
doubles, while the seven-writer hook, pure preparation and local test CAS are real.
"""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import runtime_native_common_case_setup as subject
from tests import test_native_phase3_common_preparation as data


class NativeCommonCaseSetupTests(unittest.TestCase):
    def setUp(self):
        self.fixture = data.NativeCommonPreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.arguments = {
            key: value
            for key, value in self.fixture.arguments.items()
            if key not in {"container_id", "provisioning_inputs"}
        } | {
            "expected_container_id": data.CONTAINER,
            "expected_setup_digest": subject.preparation.old._digest(
                b"inert setup source"
            ),
        }
        self.events = []
        self.saved_inputs = []
        self.published = []
        self.cleanup = {
            unit: {
                "Id": unit,
                "ActiveState": "inactive",
                "MainPID": "0",
                "ControlPID": "0",
            }
            for unit in subject.measurement._UNITS
        }

    def harness(self, stack, *, writer_failure=False, post_failure=False):
        fake = SimpleNamespace(
            _STARTUP_CODE={"/inherited/source": (7, "a" * 64, 0o644)},
            _activate=Mock(side_effect=AssertionError("activation forbidden")),
            provision=SimpleNamespace(_create_document=Mock()),
            setup_prior=SimpleNamespace(
                _require_fixture=Mock(
                    side_effect=lambda *_: self.events.append("owned")
                )
            ),
            prior=SimpleNamespace(
                _stop_fixture=Mock(
                    side_effect=lambda: (
                        self.events.append("stop") or deepcopy(self.cleanup)
                    )
                )
            ),
        )
        p37b = SimpleNamespace(
            _write_document=Mock(), capability=SimpleNamespace(_write_control=Mock())
        )
        self.original_startup = deepcopy(fake._STARTUP_CODE)
        expected_overrides = subject._overrides(self.fixture.stage)
        source_count = 0

        def sources(**kwargs):
            nonlocal source_count
            source_count += 1
            self.events.append("sources" + str(source_count))
            self.assertEqual(kwargs, {"health": True, "startup_reserve": True})
            self.assertEqual(
                fake._STARTUP_CODE, self.original_startup | expected_overrides
            )
            return {
                "source": "changed"
                if post_failure and source_count == 2
                else "unchanged"
            }

        fake._sources = Mock(side_effect=sources)

        def prepare():
            self.events.append("writers")
            for path, raw in self.fixture.inputs.items():
                if path == subject.predecessor.identity._GENESIS:
                    fake.provision._create_document(1, Path(path).name, raw, [])
                elif path == subject.predecessor.identity._POLICY:
                    p37b.capability._write_control(
                        Path(path), subject.predecessor.direct.parse(raw)
                    )
                else:
                    p37b._write_document(
                        Path(path), subject.predecessor.direct.parse(raw)
                    )
            if writer_failure:
                raise RuntimeError("secret diagnostic must not be returned")
            fake._activate(None, "secret gateway token")
            raise AssertionError("native setup passed activation sentinel")

        fake._prepare = Mock(side_effect=prepare)

        def writer_readback(native, inputs):
            self.assertIs(native, fake)
            self.saved_inputs.append(inputs)
            self.events.append("writer-readback")
            return {
                path: {"digest": subject.preparation.old._digest(raw)}
                for path, raw in inputs.items()
            }

        @contextmanager
        def store():
            self.events.append("fresh-cas")
            yield (
                self.fixture.cas,
                self.fixture.reader,
                lambda: self.events.append("cas-guard"),
            )

        put = self.fixture.cas.put_expected

        def retain(raw, **kwargs):
            self.published.append(kwargs["expected_digest"])
            return put(raw, **kwargs)

        stack.enter_context(
            patch.object(
                subject.predecessor,
                "_environment",
                side_effect=lambda *_: self.events.append("environment"),
            )
        )
        stack.enter_context(
            patch.object(subject.predecessor.package, "_native", return_value=fake)
        )
        stack.enter_context(
            patch.object(subject.predecessor.writer_parent, "_p37b", return_value=p37b)
        )
        stack.enter_context(
            patch.object(
                subject,
                "_implementation_readback",
                side_effect=lambda *_: (
                    self.events.append("implementation") or {"pinned": True}
                ),
            )
        )
        self.unused = stack.enter_context(
            patch.object(
                subject.measurement,
                "require_native_measurement_unused",
                side_effect=lambda: (
                    self.events.append("unused")
                    or {"status": "MEASUREMENT_PATHS_ABSENT"}
                ),
            )
        )
        self.absent = stack.enter_context(
            patch.object(
                subject,
                "_ingress_absent",
                side_effect=lambda: (
                    self.events.append("ingress") or {"status": "ABSENT"}
                ),
            )
        )
        stack.enter_context(patch.object(subject, "_fresh_store", store))
        self.readback = stack.enter_context(
            patch.object(subject, "_writer_readback", side_effect=writer_readback)
        )
        stack.enter_context(
            patch.object(self.fixture.cas, "put_expected", side_effect=retain)
        )
        return fake

    def test_actual_seven_writer_hook_retains_v2_child_first_and_never_activates(self):
        with ExitStack() as stack:
            native = self.harness(stack)
            result = subject.prepare_common_native_setup(**self.arguments)
        self.assertEqual(result["status"], "PREPARED_NOT_ACTIVATED")
        self.assertEqual(
            result["preparation"]["preparation"]["schema"],
            "aragorn/native-common-deployment-preparation/v2",
        )
        self.assertEqual(result["setup_state"]["activation_count"], 0)
        self.assertTrue(result["setup_state"]["pins_frozen_before_activation"])
        self.assertEqual(
            result["setup_state"]["provisioning_file_digests"],
            {
                p: subject.preparation.old._digest(raw)
                for p, raw in self.fixture.inputs.items()
            },
        )
        native._activate.assert_not_called()
        native._prepare.assert_called_once()
        native.prior._stop_fixture.assert_called_once()
        self.assertEqual(native._STARTUP_CODE, self.original_startup)
        self.assertEqual(self.saved_inputs, [{}, {}])
        self.assertLess(self.events.index("unused"), self.events.index("writers"))
        self.assertLess(self.events.index("ingress"), self.events.index("fresh-cas"))
        self.assertEqual(
            self.published[-1], result["preparation"]["preparation_digest"]
        )
        self.assertEqual(
            set(self.published), set(result["preparation"]["retained_blob_digests"])
        )
        for pin in self.published:
            self.assertNotIn(
                self.fixture.reader.read(pin), self.fixture.inputs.values()
            )
        self.assertTrue(all(result[key] is False for key in subject._FALSE))
        self.assertIsNone(result["refusal"])
        self.assertEqual(result["fixture_stack_cleanup"], self.cleanup)

    def test_exact_reviewed_stage_derives_thirteen_overrides_not_old70_or73(self):
        original = deepcopy(self.fixture.stage)
        overrides = subject._overrides(original)
        self.assertEqual(len(overrides), 13)
        for path, (source, mode) in subject._OVERRIDE_SOURCES.items():
            row = next(row for row in original["files"] if row["path"] == path)
            self.assertEqual(
                overrides[path], (row["bytes"], row["digest"][7:], int(mode, 8))
            )
            self.assertEqual(row["source_name"], source)
        self.assertEqual(original, self.fixture.stage)
        for change in ("count", "duplicate", "source", "mode", "bool-size", "digest"):
            stage = deepcopy(original)
            selected = next(
                row
                for row in stage["files"]
                if row["path"] in subject._OVERRIDE_SOURCES
            )
            if change == "count":
                stage["files"].pop()
            elif change == "duplicate":
                stage["files"][-1] = deepcopy(stage["files"][0])
            elif change == "source":
                selected["source_name"] = "unreviewed.py"
            elif change == "mode":
                selected["mode"] = "0666"
            elif change == "bool-size":
                selected["bytes"] = True
            else:
                selected["digest"] = "not-a-pin"
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject._overrides(stage)

    def test_bad_inputs_and_initial_guards_refuse_before_writers_or_cleanup(self):
        for mode in (
            "schema",
            "sources",
            "oversize-source",
            "oversize-record",
            "namespace",
            "unused",
            "ingress",
        ):
            with self.subTest(mode=mode), ExitStack() as stack:
                native = self.harness(stack)
                args = dict(self.arguments)
                if mode == "schema":
                    value = deepcopy(self.fixture.stage)
                    value["schema"] = "aragorn/runtime-phase3-common-staged-profile/v1"
                    args["staged_profile_raw"] = subject.canonical_json(value)
                elif mode == "sources":
                    args["implementation_source_raws"] = {}
                elif mode == "oversize-source":
                    args["implementation_source_raws"] = dict(
                        args["implementation_source_raws"]
                    )
                    args["implementation_source_raws"][
                        next(iter(args["implementation_source_raws"]))
                    ] = b"x" * (subject.preparation.old._MAX_ARTIFACT + 1)
                elif mode == "oversize-record":
                    args["source_record_raw"] = b"x" * (
                        subject.preparation.old._MAX_ARTIFACT + 1
                    )
                elif mode == "namespace":
                    stack.enter_context(
                        patch.object(
                            subject.predecessor,
                            "_environment",
                            side_effect=ValueError("foreign fixture"),
                        )
                    )
                elif mode == "unused":
                    self.unused.side_effect = ValueError("preexisting active service")
                else:
                    self.absent.side_effect = ValueError("preexisting ingress")
                result = subject.prepare_common_native_setup(**args)
                self.assertEqual(result["status"], "REFUSED")
                native._prepare.assert_not_called()
                native._activate.assert_not_called()
                native.prior._stop_fixture.assert_not_called()
                self.assertIsNone(result["fixture_stack_cleanup"])
                self.assertNotIn("fresh-cas", self.events)

    def test_partial_writer_failure_keeps_hashes_runs_postreads_and_cleanup(self):
        with ExitStack() as stack:
            native = self.harness(stack, writer_failure=True)
            result = subject.prepare_common_native_setup(**self.arguments)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["refusal"]["phase"], "SEVEN_WRITER_SETUP")
        self.assertEqual(len(result["setup_state"]["provisioning_file_digests"]), 7)
        self.assertIsNone(result["preparation"])
        self.assertEqual(native._sources.call_count, 2)
        native._activate.assert_not_called()
        native.prior._stop_fixture.assert_called_once()
        self.assertNotIn(b"secret diagnostic", subject.canonical_json(result))

    def test_partial_publication_retains_prior_blob_and_primary_cleanup_failure(self):
        with ExitStack() as stack:
            native = self.harness(stack)
            saved_put = self.fixture.cas.put_expected
            calls = 0

            def second_fails(raw, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("secret partial publication")
                return saved_put(raw, **kwargs)

            stack.enter_context(
                patch.object(self.fixture.cas, "put_expected", side_effect=second_fails)
            )
            native.prior._stop_fixture.side_effect = RuntimeError("secret cleanup")
            result = subject.prepare_common_native_setup(**self.arguments)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["refusal"]["phase"], "RETENTION")
        self.assertEqual(
            result["cleanup_failure"], "OWNED_FOUR_SERVICE_CLEANUP_UNCONFIRMED"
        )
        self.assertEqual(calls, 2)
        self.assertEqual(len(self.published), 1)
        self.assertTrue(self.fixture.reader.read(self.published[0]))
        self.assertNotIn(b"secret", subject.canonical_json(result))
        native._activate.assert_not_called()
        native.prior._stop_fixture.assert_called_once()

    def test_final_source_change_refuses_but_retains_preparation_and_zero_activation(
        self,
    ):
        with ExitStack() as stack:
            native = self.harness(stack, post_failure=True)
            result = subject.prepare_common_native_setup(**self.arguments)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(
            result["refusal"]["reason"], "FINAL_SOURCE_OR_CUSTODY_READBACK_REFUSED"
        )
        self.assertIsNotNone(result["preparation"])
        pin = result["preparation"]["preparation_digest"]
        self.assertEqual(
            self.fixture.reader.read(pin),
            subject.canonical_json(result["preparation"]["preparation"]),
        )
        self.assertEqual(result["setup_state"]["activation_count"], 0)
        native._activate.assert_not_called()
        native.prior._stop_fixture.assert_called_once()

    def test_fixed_ingress_absence_never_writes_or_repairs_and_always_closes(self):
        custody = subject.measurement.custody
        for present in (False, True):
            with (
                self.subTest(present=present),
                patch.object(custody, "_root_directory", return_value=71) as root,
                patch.object(
                    custody,
                    "_absent",
                    side_effect=ValueError("existing") if present else None,
                ) as absent,
                patch.object(custody, "_recheck") as recheck,
                patch.object(custody, "_close") as close,
                patch.object(
                    subject.os,
                    "mkdir",
                    side_effect=AssertionError("no ingress creation"),
                ),
                patch.object(
                    subject.os,
                    "unlink",
                    side_effect=AssertionError("no evidence removal"),
                ),
            ):
                if present:
                    with self.assertRaises(ValueError):
                        subject._ingress_absent()
                    recheck.assert_not_called()
                else:
                    self.assertEqual(subject._ingress_absent()["status"], "ABSENT")
                    recheck.assert_called_once()
                root.assert_called_once_with(Path("/var/lib"), [])
                absent.assert_called_once_with(71, "aragorn-runtime-worker-measurement")
                close.assert_called_once_with([])

    def test_source_and_writer_readbacks_use_fixed_nofollow_reader_without_raw_output(
        self,
    ):
        sources = self.fixture.arguments["implementation_source_raws"]
        installed = {
            path: sources[name] for name, path in subject._IMPLEMENTATION_PATHS.items()
        }
        installed[subject.SETUP_PATH] = b"inert setup source"
        seen = []

        def read(root, path, **kwargs):
            seen.append((path, kwargs))
            raw = installed[path]
            return raw, {"digest": subject.preparation.old._digest(raw)}

        with (
            patch.object(subject.os, "open", return_value=91),
            patch.object(subject.os, "close") as close,
            patch.object(subject.predecessor.identity, "_read_at", side_effect=read),
        ):
            result = subject._implementation_readback(
                sources, self.arguments["expected_setup_digest"]
            )
        close.assert_called_once_with(91)
        self.assertEqual(set(result), set(installed))
        self.assertTrue(
            all(
                kwargs["owner"] == kwargs["owner_gid"] == 0
                and kwargs["modes"] == {0o444}
                for _, kwargs in seen
            )
        )
        self.assertTrue(all(set(value) == {"digest"} for value in result.values()))
        seen.clear()
        installed = dict(self.fixture.inputs)
        native = SimpleNamespace(
            response=SimpleNamespace(
                _identities=lambda: (995, 994, 994, 992, 992, 993, 993)
            )
        )
        with (
            patch.object(subject.os, "open", return_value=92),
            patch.object(subject.os, "close") as close,
            patch.object(subject.predecessor.identity, "_read_at", side_effect=read),
        ):
            result = subject._writer_readback(native, self.fixture.inputs)
        close.assert_called_once_with(92)
        self.assertEqual(
            set(result), set(subject.predecessor.writer_parent.DYNAMIC_PATHS)
        )
        for path, kwargs in seen:
            self.assertEqual(kwargs["modes"], {0o400})
            self.assertEqual(
                (kwargs["owner"], kwargs["owner_gid"]),
                (995, 994) if path == subject.predecessor.identity._POLICY else (0, 0),
            )

    def test_cleanup_errors_preserve_original_source_and_store_failure(self):
        sources = self.fixture.arguments["implementation_source_raws"]
        primary = ValueError("inert primary read error")
        with (
            patch.object(subject.os, "open", return_value=93),
            patch.object(
                subject.os, "close", side_effect=OSError("close refused")
            ) as close,
            patch.object(subject.predecessor.identity, "_read_at", side_effect=primary),
        ):
            with self.assertRaises(ValueError) as raised:
                subject._implementation_readback(
                    sources, self.arguments["expected_setup_digest"]
                )
        self.assertIs(raised.exception, primary)
        self.assertEqual(
            primary._common_cleanup_failures,
            ["IMPLEMENTATION_DESCRIPTOR_CLOSE_REFUSED"],
        )
        close.assert_called_once_with(93)
        primary = ValueError("inert setup error")

        @contextmanager
        def failing_store():
            try:
                yield ("writer", "reader", "guard")
            finally:
                raise OSError("inert descriptor cleanup error")

        old_root = subject.predecessor.storage.CAS_ROOT
        with patch.object(subject.predecessor.storage, "_fresh_store", failing_store):
            with self.assertRaises(ValueError) as raised:
                with subject._fresh_store() as opened:
                    self.assertEqual(opened, ("writer", "reader", "guard"))
                    self.assertEqual(
                        subject.predecessor.storage.CAS_ROOT, subject.CAS_ROOT
                    )
                    raise primary
        self.assertIs(raised.exception, primary)
        self.assertEqual(
            primary._common_cleanup_failures, ["CAS_CONTEXT_CLEANUP_REFUSED"]
        )
        self.assertEqual(subject.predecessor.storage.CAS_ROOT, old_root)
        with patch.object(subject.predecessor.storage, "_fresh_store", failing_store):
            with self.assertRaises(OSError):
                with subject._fresh_store():
                    pass


if __name__ == "__main__":
    unittest.main()
