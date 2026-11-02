"""Ready94 delta checks with inert data and OS boundaries; no live readiness.

Old data builders are reused, never old test methods or capture observations.
The generated modules are composed before import-time inventories are derived.
"""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from aragorn import native_phase3_http_canary_contract as canary
from aragorn import runtime_http_readiness as readiness
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_native_phase3_http_ready_helpers as renderer
from scripts import stage_runtime_phase3_http_ready_profile as stager
from tests import test_native_phase3_http_preparation as data
from tests import test_native_phase3_http_identity as identity_data
from tests import test_native_phase3_http_writer as writer_data

ROOT = Path(__file__).resolve().parents[1]
READINESS_NONCE = "9" * 32


@lru_cache(maxsize=1)
def generated_sources():
    originals = {name: (ROOT / name).read_bytes() for name in renderer.INPUTS}
    return renderer.render(originals)


@lru_cache(maxsize=1)
def runtime_sources():
    original, replacements, _ = stager._verified_payloads()
    return original | replacements


def stage_source(name):
    return runtime_sources()[stager._destination(name)[0]][2]


def ready_modules():
    generated = dict(generated_sources())
    for name in (stager._PLAN, stager._PRIOR, stager._EFFECTIVE):
        generated[name] = stage_source(name)
    prior = data._module(generated[stager._PRIOR], "ready_measurement_verify")
    identity = data._module(
        generated[renderer.identity.IDENTITY],
        "ready_identity",
        {"runtime_broker_decision_measurement_verify": prior},
    )
    validator = data._module(
        generated[renderer.preparation.MEASUREMENT_INPUTS],
        "ready_inputs",
        {"runtime_broker_decision_measurement_verify": prior},
    )
    planner = data._module(generated[stager._PLAN], "ready_measurement_plan")
    subject = data._module(
        generated[renderer.preparation.PREPARATION],
        "ready_preparation",
        {
            "native_phase3_common_identity": identity,
            "runtime_native_measurement_inputs": validator,
        },
    )
    verifier = data._module(
        generated[renderer.identity.VERIFIER],
        "ready_process_verifier",
    )
    return subject, validator, planner, identity, verifier, generated


@lru_cache(maxsize=1)
def _stage_data():
    with tempfile.TemporaryDirectory() as temporary:
        destination = Path(temporary).resolve() / "ready94"
        stage = stager.stage_runtime_phase3_http_ready_profile(destination)
        config = (
            destination / "opt/aragorn/runtime-http-gateway-template.json"
        ).read_bytes()
    baseline = data.BASELINE.read_bytes()
    return stage, baseline, json.loads(baseline), config


class ReadyPreparationFixture:
    """Fresh ready94 data constructor; not a TestCase or acceptance capture."""

    def __init__(self, testcase):
        self.testcase = testcase
        temporary = tempfile.TemporaryDirectory()
        testcase.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cas = CAS(self.root / "retained")
        self.reader = CAS(self.cas.root, read_only=True)
        (
            self.subject,
            self.input_validator,
            self.planner,
            self.identity,
            self.verifier,
            self.generated,
        ) = ready_modules()
        stage, self.baseline_raw, self.baseline, self.config_raw = _stage_data()
        self.stage = deepcopy(stage)
        self.inputs = data.provisioning_inputs(
            self.subject, self.baseline, self.config_raw
        )
        self.fixture_binding = json.loads(self.inputs[self.subject.HTTP_FIXTURE])
        self.inputs[self.subject.HTTP_READINESS] = canonical_json(
            readiness.build_readiness_input(
                fixture_binding=self.fixture_binding,
                readiness_nonce=READINESS_NONCE,
            )
        )
        self.descriptor = data.http.endpoint_descriptor(self.fixture_binding)
        self.payload = canary.canary_request(data.ATTEMPT)
        live = self.subject.old.live
        files = {row["path"]: row for row in self.stage["files"]}
        special = {
            live._ENTRY: stage["required_runtime_not_included"]["entrypoint_digest"],
            live._PYTHON: self.baseline["observation"]["setup"]["runtime_profile"][
                "executable_digest"
            ],
            live._NODE: self.subject.admission._NODE_PIN,
        }
        self.static = {
            "schema": self.subject.STATIC_SCHEMA,
            "file_digests": {
                path: special[path] if path in special else files[path]["digest"]
                for path in self.subject.STATIC_PATHS
            },
        }
        self.arguments = {
            "case_id": self.subject.admission.DIRECT_WRITE_CASE,
            "nonce": "a" * 64,
            "readiness_nonce": READINESS_NONCE,
            "container_id": data.CONTAINER,
            "source_record_raw": canonical_json(
                {"commit": "c" * 40, "test_only": True}
            ),
            "implementation_source_raws": {
                name: self.generated[name]
                if name in self.generated
                else (ROOT / name).read_bytes()
                for name in self.subject.IMPLEMENTATION_SOURCE_PATHS
            },
            "static_pin_manifest_raw": canonical_json(self.static),
            "staged_profile_raw": canonical_json(self.stage),
            "baseline_capture_raw": self.baseline_raw,
            "provisioning_inputs": self.inputs,
        }

    # Reuse data operations, not inherited or invoked TestCase methods.
    build = data.HttpPreparationFixture.build
    retain = data.HttpPreparationFixture.retain
    measurement = data.HttpPreparationFixture.measurement
    request_arguments = data.HttpPreparationFixture.request_arguments
    input_arguments = data.HttpPreparationFixture.input_arguments


class ReadyPreparationTests(unittest.TestCase):
    def setUp(self):
        self.data = ReadyPreparationFixture(self)
        self.subject = self.data.subject
        self.valid = self.data.build()
        self.assertEqual(len(self.valid["provisioning_file_digests"]), 9)

    def test_nine_writer_preparation_request_and_identity_abi_agree(self):
        fixture = self.data
        fixture.retain(self.valid["input_blobs"])
        measured = fixture.measurement(self.valid)
        request = self.subject.prepare_native_common_request(
            **fixture.request_arguments(self.valid, measured)
        )
        raw = {
            path: stage_source("src/aragorn/" + name)
            for name, path in fixture.identity.MEASUREMENT_SOURCES.items()
        } | fixture.inputs
        raw[fixture.identity.MEASUREMENT_BINDING] = canonical_json(measured["binding"])
        accounts = dict(identity_data.ACCOUNTS) | {"broker": (998, 997)}
        joins = fixture.identity._joins(raw, data.BOOT, data.CONTAINER, accounts)
        self.assertEqual(len(self.subject.STATIC_PATHS), 33)
        self.assertEqual(len(fixture.identity.FILE_PATHS), 43)
        self.assertEqual(len(request["expected_file_digests"]), 43)
        self.assertEqual(len(request["provisioning_file_digests"]), 10)
        self.assertEqual(len(measured["binding"]["source_pins"]), 22)
        self.assertEqual(
            joins["measurement_source_pins"], fixture.stage["binding_source_pins"]
        )
        for value in (
            self.valid["preparation"],
            request["request"],
            joins["http_readiness_input"],
        ):
            self.assertEqual(value["readiness_nonce"], READINESS_NONCE)
        self.assertEqual(
            request["expected_file_digests"][self.subject.HTTP_READINESS],
            canonical_digest(joins["http_readiness_input"]),
        )
        self.assertEqual(
            self.valid["preparation"]["schema"],
            "aragorn/native-common-deployment-preparation/v4",
        )
        self.assertEqual(
            request["request"]["schema"],
            "aragorn/native-common-measured-case-request/v4",
        )
        self.assertFalse(request["decision"]["phase3_exit_eligible"])
        self.assertFalse(self.valid["preparation"]["decision"]["phase3_exit_eligible"])
        self.assertLessEqual(len(canonical_json(measured["binding"])), 8192)

    def test_missing_ninth_writer_is_refused_at_inventory(self):
        inputs = dict(self.data.inputs)
        del inputs[self.subject.HTTP_READINESS]
        with self.assertRaisesRegex(ValueError, "common writer inventory"):
            self.data.build(provisioning_inputs=inputs)

    def test_nonce_schema_timeout_and_fixture_join_mutations_refuse(self):
        path = self.subject.HTTP_READINESS
        for update in (
            {"readiness_nonce": "a" * 32},
            {"readiness_nonce": "A" * 32},
            {"readiness_nonce": "a" * 64},
            {"timeout_ms": True},
            {"timeout_ms": 501},
            {"schema": "caller-schema"},
            {"fixture_binding_digest": data.PIN},
            {"extra": "not allowed"},
        ):
            inputs = dict(self.data.inputs)
            inputs[path] = canonical_json(json.loads(inputs[path]) | update)
            with (
                self.subTest(update=update),
                self.assertRaisesRegex(ValueError, "readiness"),
            ):
                self.data.build(provisioning_inputs=inputs)

    def test_explicit_nonce_differs_from_valid_writer_refused(self):
        with self.assertRaisesRegex(ValueError, "requested nonce"):
            self.data.build(readiness_nonce="0" * 32)

    def test_replay_rejects_replaced_ninth_writer(self):
        self.data.retain(self.valid["input_blobs"])
        inputs = dict(self.data.inputs)
        inputs[self.subject.HTTP_READINESS] = canonical_json(
            json.loads(inputs[self.subject.HTTP_READINESS])
            | {"readiness_nonce": "1" * 32}
        )
        with self.assertRaisesRegex(ValueError, "requested nonce"):
            self.subject._inspect(
                self.valid["preparation_raw"],
                self.valid["preparation_digest"],
                self.data.reader,
                inputs,
            )


def _identity_fixture():
    _, _, _, reader, verifier, _ = ready_modules()
    raw = identity_data._documents(reader)
    raw[reader.HTTP_READINESS_BINDING] = canonical_json(
        readiness.build_readiness_input(
            fixture_binding=json.loads(raw[reader.HTTP_FIXTURE_BINDING]),
            readiness_nonce=READINESS_NONCE,
        )
    )
    return reader, verifier, raw


class ReadyIdentityTests(unittest.TestCase):
    def test_broker_only_readiness_view_is_read_twice_and_independently_joined(self):
        reader, verifier, raw = _identity_fixture()
        observed, reads, _, pins = identity_data._inert_read(reader, raw)
        self.assertEqual(len(observed["files"]), 43)
        self.assertEqual(set(observed["http_readiness_views"]), {"broker"})
        rows = [row for row in reads if row[1] == reader.HTTP_READINESS_BINDING]
        self.assertEqual(
            [(row[0], row[2]) for row in rows],
            [("observer", 1), ("broker", 1), ("observer", 2), ("broker", 2)],
        )
        self.assertTrue(
            all(
                row[3]["modes"] == {0o440} and row[3]["owner_gid"] == 997
                for row in rows
            )
        )
        self.assertNotIn(
            reader.HTTP_READINESS_BINDING, reader.CREDENTIALS["broker"].values()
        )
        self.assertEqual(reader.SCHEMA, verifier.IDENTITY_SCHEMA)
        verifier._files(observed, pins, identity_data.ACCOUNTS)
        self.assertEqual(
            reader.compare_native_common_identity(observed, deepcopy(observed))[
                "status"
            ],
            "CALLER_COMMON_MEASUREMENTS_EQUAL",
        )

    def test_readiness_process_view_change_is_refused_on_readback(self):
        reader, _, raw = _identity_fixture()
        reader._joins(
            raw, identity_data.BOOT, identity_data.CONTAINER, identity_data.ACCOUNTS
        )
        with self.assertRaises(ValueError):
            identity_data._inert_read(
                reader,
                raw,
                change=lambda key, count, value: (
                    value + b" "
                    if key == ("broker", reader.HTTP_READINESS_BINDING) and count == 2
                    else value
                ),
            )

    def test_consumer_rejects_nonce_view_mode_and_extra_role_independently(self):
        reader, verifier, raw = _identity_fixture()
        observed, _, _, pins = identity_data._inert_read(reader, raw)
        verifier._files(observed, pins, identity_data.ACCOUNTS)
        for change in (
            lambda value: value["measured_joins"]["http_readiness_input"].update(
                readiness_nonce="f" * 32
            ),
            lambda value: value["http_readiness_views"]["broker"].update(
                digest=data.PIN
            ),
            lambda value: value["http_readiness_views"]["broker"][
                "identity"
            ].__setitem__(2, 0o100444),
            lambda value: value["http_readiness_views"].update(
                worker=value["http_readiness_views"]["broker"]
            ),
        ):
            changed = deepcopy(observed)
            change(changed)
            with self.assertRaises(ValueError):
                verifier._files(changed, pins, identity_data.ACCOUNTS)


class ReadyRenderTests(unittest.TestCase):
    def test_exact_seven_pinned_outputs_compile_and_keep_predecessors(self):
        before = {name: (ROOT / name).read_bytes() for name in renderer.INPUTS}
        result = generated_sources()
        self.assertEqual(set(result), set(before))
        self.assertEqual(len(result), 7)
        for name, raw in result.items():
            compile(raw, name, "exec")
        for original in (
            {},
            before | {"extra.py": b"unexpected"},
            before | {renderer.writer.SOURCE: before[renderer.writer.SOURCE] + b"\n"},
        ):
            with self.assertRaises(renderer.NativeHttpReadyHelpersError):
                renderer.render(original)
        self.assertEqual(before, {name: (ROOT / name).read_bytes() for name in before})

    def test_changed_generated_predecessor_is_refused(self):
        sources = {name: (ROOT / name).read_bytes() for name in renderer.INPUTS}
        with patch.object(
            renderer,
            "PREDECESSOR_OUTPUTS",
            renderer.PREDECESSOR_OUTPUTS | {renderer.setup.SOURCE: (1, "0" * 64)},
        ):
            with self.assertRaisesRegex(
                renderer.NativeHttpReadyHelpersError, "generated predecessor"
            ):
                renderer.render(sources)


def _ready_writer(testcase):
    # Reuse the preexisting data builder, not its test methods or their verdicts.
    ns, args, calls, http, provision, os_api, reader, callback = (
        writer_data.NativeHttpWriterTests.wrapper(testcase)
    )
    request = readiness.build_readiness_input(
        fixture_binding=writer_data.BINDING, readiness_nonce=READINESS_NONCE
    )
    raw = canonical_json(request)
    publication = {
        "path": renderer.READINESS,
        "created": True,
        "bytes_written": len(raw),
        "completed": True,
        "cleanup_failed": False,
    }
    ready = SimpleNamespace(
        CREDENTIAL=Path(renderer.READINESS),
        CLAIM=Path("/inert/readiness-used.json"),
        RESULT=Path("/inert/readiness-result.json"),
        build_readiness_input=readiness.build_readiness_input,
        _read_owned=MagicMock(return_value=(raw, {"identity": [4, 5]})),
        provision_readiness_input=MagicMock(
            side_effect=lambda **_: (
                calls.append("readiness-provision")
                or {
                    "request_digest": canonical_digest(request),
                    "publication": deepcopy(publication),
                    "activation_performed": False,
                    "completed": True,
                }
            )
        ),
    )
    ready_callback = MagicMock(
        side_effect=lambda value: calls.append(("readiness-writer", value))
    )
    ns["_http_ready"] = ready
    writer_data._functions(
        generated_sources()[renderer.writer.SOURCE],
        {"_prepare", "_http_writer_cleanup"},
        ns,
    )
    args.update(
        readiness_nonce=READINESS_NONCE, readiness_binding_writer=ready_callback
    )
    return ns, args, calls, ready, ready_callback, publication, os_api


def _sanitizer():
    ns = {"readiness": readiness}
    writer_data._functions(
        generated_sources()[renderer.setup.SOURCE],
        {"_readiness_partial_observation"},
        ns,
    )
    return ns["_readiness_partial_observation"]


class ReadyWriterTests(unittest.TestCase):
    def test_ninth_intent_precedes_absent_write_and_seven_writer_body(self):
        ns, args, calls, ready, callback, _, os_api = _ready_writer(self)
        with self.assertRaises(writer_data.Prepared):
            ns["_prepare"](**args)
        request = canonical_json(
            readiness.build_readiness_input(
                fixture_binding=writer_data.BINDING, readiness_nonce=READINESS_NONCE
            )
        )
        self.assertLess(
            calls.index(("readiness-writer", request)),
            calls.index("readiness-provision"),
        )
        self.assertLess(calls.index("readiness-provision"), calls.index("body"))
        callback.assert_called_once_with(request)
        ready.provision_readiness_input.assert_called_once()
        os_api.close.assert_called_once_with(9)

    def test_invalid_nonce_refuses_before_any_writer_or_os_open(self):
        ns, args, _, ready, callback, _, os_api = _ready_writer(self)
        args["readiness_nonce"] = "x" * 32
        with self.assertRaises(ValueError):
            ns["_prepare"](**args)
        args["http_binding_writer"].assert_not_called()
        callback.assert_not_called()
        ready.provision_readiness_input.assert_not_called()
        os_api.open.assert_not_called()

    def test_ninth_intent_failure_prevents_publication(self):
        ns, args, _, ready, callback, _, _ = _ready_writer(self)
        callback.side_effect = RuntimeError("inert ninth intent failure")
        with self.assertRaisesRegex(RuntimeError, "ninth intent"):
            ns["_prepare"](**args)
        ready.provision_readiness_input.assert_not_called()
        ns["_prepare_http_inputs"].assert_not_called()

    def test_used_readiness_state_prevents_first_writer(self):
        ns, args, _, ready, callback, _, os_api = _ready_writer(self)
        os_api.path.lexists.side_effect = lambda path: path == ready.CLAIM
        with self.assertRaisesRegex(ValueError, "absent credential"):
            ns["_prepare"](**args)
        args["http_binding_writer"].assert_not_called()
        callback.assert_not_called()

    def test_completed_publication_with_failed_overall_custody_is_refused(self):
        ns, args, _, ready, _, publication, _ = _ready_writer(self)
        ready.provision_readiness_input.side_effect = None
        ready.provision_readiness_input.return_value = {
            "request_digest": canonical_digest(
                readiness.build_readiness_input(
                    fixture_binding=writer_data.BINDING, readiness_nonce=READINESS_NONCE
                )
            ),
            "publication": publication,
            "activation_performed": False,
            "completed": False,
        }
        with self.assertRaisesRegex(ValueError, "readiness credential publication"):
            ns["_prepare"](**args)
        ns["_prepare_http_inputs"].assert_not_called()

    def test_failure_after_readiness_publication_keeps_evidence_across_cleanup(self):
        ns, args, _, ready, _, publication, os_api = _ready_writer(self)
        original = OSError("inert final namespace guard failure")
        original.http_readiness_provisioning = {
            "publication": publication,
            "completed": False,
        }
        ready.provision_readiness_input.side_effect = original
        os_api.close.side_effect = OSError("inert final descriptor close failure")
        with self.assertRaisesRegex(OSError, "descriptor close") as caught:
            ns["_prepare"](**args)
        self.assertEqual(_sanitizer()(caught.exception), publication)
        ns["_prepare_http_inputs"].assert_not_called()

    def test_readiness_mutation_in_final_guard_overrides_prepared_sentinel(self):
        ns, args, _, ready, _, _, _ = _ready_writer(self)

        def body(*_):
            ready._read_owned.return_value = (b"changed", {"identity": [4, 5]})
            raise writer_data.Prepared()

        ns["_prepare_http_inputs"].side_effect = body
        with self.assertRaisesRegex(ValueError, "readiness credential changed"):
            ns["_prepare"](**args)

    def test_partial_publication_export_drops_extra_fields_and_returns_copy(self):
        sanitizer = _sanitizer()
        error = OSError("not exported")
        publication = {
            "path": renderer.READINESS,
            "created": True,
            "bytes_written": None,
            "completed": False,
            "cleanup_failed": True,
        }
        error.http_readiness_provisioning = {
            "publication": publication,
            "secret": "not exported",
        }
        self.assertEqual(sanitizer(error), publication)
        self.assertIsNot(sanitizer(error), publication)
        error.http_readiness_provisioning["publication"] = publication | {
            "secret": "not exported"
        }
        self.assertEqual(
            sanitizer(error),
            {"status": "UNCLASSIFIED_READINESS_PROVISIONING_NOT_EXPORTED"},
        )


class ReadyMeasurementTests(unittest.TestCase):
    def harness(self):
        subject, validator, _, _, _, generated = ready_modules()
        provision = data._module(
            generated[renderer.measurement.SOURCE],
            "ready_measurement_provisioning",
            {"runtime_native_measurement_inputs": validator},
        )
        binding = deepcopy(writer_data.BINDING)
        action = provision.http.action_digests(data.ATTEMPT, binding)
        bound = {
            "binding": {
                "attempt_id": data.ATTEMPT,
                "boot_id": binding["fixture"]["boot_id"],
                "runtime_digest": data.PIN,
                "active_skill_digest": data.PIN,
                **action,
            },
            "path_descriptor": provision.http.endpoint_descriptor(binding),
        }
        raw = canonical_json(
            readiness.build_readiness_input(
                fixture_binding=binding, readiness_nonce=READINESS_NONCE
            )
        )
        fixture_entry = SimpleNamespace(raw=canonical_json(binding), fd=10)
        ready_entry = SimpleNamespace(raw=raw, fd=11)
        policy = {
            "id": "owned-native-receipt-http-canary",
            "default": "BLOCK",
            "allow": [
                {"runtime_digest": data.PIN, "active_skill_digest": data.PIN, **action}
            ],
        }
        identities = (995, 997, 997)
        session = SimpleNamespace(guard=MagicMock())
        return provision, bound, fixture_entry, ready_entry, policy, identities, session

    def test_protected_ninth_input_is_held_and_rechecked_with_endpoint(self):
        p, bound, fixture, ready, policy, identities, session = self.harness()
        entries = {fixture.fd: fixture.raw, ready.fd: ready.raw}
        with (
            patch.object(p.custody, "_root_directory", return_value=3),
            patch.object(p.custody, "_hold_file", side_effect=[fixture, ready]) as hold,
            patch.object(p.custody, "_recheck") as recheck,
            patch.object(p.response, "_identities", return_value=identities),
            patch.object(p.http_provisioning, "_accounts", return_value=(995, 997)),
            patch.object(p, "_boot_id", return_value=bound["binding"]["boot_id"]),
            patch.object(p.os, "lseek"),
            patch.object(p.os, "read", side_effect=lambda fd, size: entries[fd]),
        ):
            endpoint = p._http_endpoint(bound, identities, policy, [], session)
            self.assertIs(endpoint.readiness_credential, ready)
            self.assertEqual(
                hold.call_args_list[-1].args[1:6],
                ("runtime-http-readiness.json", 0, 997, 0o440, 4096),
            )
            self.assertIn(unittest.mock.call([ready]), recheck.call_args_list)
            entries[ready.fd] = b"changed"
            with self.assertRaises(p.NativeMeasurementProvisioningError):
                p._recheck_protected_inputs(bound, endpoint)
        self.assertEqual(len(p._SOURCE_NAMES), 22)
        self.assertIn("runtime_http_readiness.py", p._SOURCE_NAMES)
        self.assertIn("http-readiness-used.json", p._PRIOR_RESULTS)
        self.assertIn("http-readiness-result.json", p._PRIOR_RESULTS)

    def test_wrong_ninth_input_fails_before_endpoint_recheck(self):
        p, bound, fixture, ready, policy, identities, session = self.harness()
        ready.raw = canonical_json(
            json.loads(ready.raw) | {"fixture_binding_digest": data.PIN}
        )
        with (
            patch.object(p.custody, "_root_directory", return_value=3),
            patch.object(p.custody, "_hold_file", side_effect=[fixture, ready]),
            patch.object(p, "_recheck_protected_inputs") as recheck,
        ):
            with self.assertRaises(ValueError):
                p._http_endpoint(bound, identities, policy, [], session)
            recheck.assert_not_called()


if __name__ == "__main__":
    unittest.main()
