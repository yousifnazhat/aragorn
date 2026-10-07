"""HTTP public setup composition and inert controller checks, not live evidence."""

from copy import deepcopy
from functools import lru_cache
import hashlib
from io import BytesIO
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn.oci_worker_protocol import canonical_json
from scripts import capture_native_phase3_http_setup as launcher
from scripts import materialize_native_phase3_http_setup_capture as renderer
from test_native_phase3_http_preparation import (
    HttpPreparationFixture,
    CONTAINER,
    ATTEMPT,
)

ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def _composition():
    originals = {name: (ROOT / name).read_bytes() for name in launcher.source_paths()}
    controller = launcher.build_controller(originals)
    return originals, renderer.compose(originals), controller


def _metadata(raw, digest, *, uid=0, gid=0, mode=0o444):
    return {
        "bytes": len(raw),
        "digest": digest(raw),
        "identity": [1, 100, stat.S_IFREG | mode, uid, gid, 1, len(raw), 1, 1],
    }


def _tree_row(name, raw, digest):
    return {
        "path": name,
        "mode": "100644",
        "bytes": len(raw),
        "digest": digest(raw),
        "blob": hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw
        ).hexdigest(),
    }


class HttpSetupCaptureFixture:
    """Construct real pure preparation, labeling all process/cleanup data inert."""

    def __init__(self, testcase):
        self.data = HttpPreparationFixture(testcase)
        self.original, self.generated, self.host = _composition()
        self.contract = self.host.contract
        subject = self.contract
        self.installed = self.original | self.generated
        self.arguments = {
            key: value
            for key, value in self.data.arguments.items()
            if key not in {"container_id", "provisioning_inputs"}
        }
        self.arguments["implementation_source_raws"] = {
            name: self.installed[name] for name in subject.IMPLEMENTATION_PATHS
        }
        self.arguments.update(
            http_attempt_id=ATTEMPT,
            source_raws=self.original,
            generated_source_raws=self.generated,
            setup_source_raw=self.installed[subject.SETUP_SOURCE],
            wrapper_source_raw=self.installed[subject.WRAPPER_SOURCE],
            host_source_raw=self.installed[subject.HOST_SOURCE],
        )
        self.built = subject.prepare_common_setup_inputs(**self.arguments)
        self.bound = subject.inspect_common_setup_inputs(
            self.built["bundle_raw"], expected_bundle_digest=self.built["bundle_digest"]
        )
        args = {
            key: value
            for key, value in self.bound["setup_arguments"].items()
            if key != "expected_setup_digest"
        }
        self.prepared = subject.preparation.prepare_native_common_deployment(
            **args, container_id=CONTAINER, provisioning_inputs=self.data.inputs
        )
        self.data.retain(self.built["input_blobs"] | self.prepared["input_blobs"])
        ordered = [
            (pin, raw)
            for pin, raw in self.prepared["input_blobs"].items()
            if pin != self.prepared["preparation_digest"]
        ]
        ordered.append(
            (self.prepared["preparation_digest"], self.prepared["preparation_raw"])
        )
        public = [
            {"digest": pin, "bytes": len(raw), "text": raw.decode()}
            for pin, raw in ordered
        ]
        metadata = lambda raw, **kw: _metadata(raw, subject._digest, **kw)
        implementation = {
            target: metadata(self.installed[name])
            for name, target in subject.IMPLEMENTATION_PATHS.items()
        }
        implementation[subject.FIXTURE_HELPERS[subject.SETUP_SOURCE]] = metadata(
            self.installed[subject.SETUP_SOURCE]
        )
        rows = {row["path"]: row for row in self.data.stage["files"]}
        installed = {}
        for name in set(rows) | set(
            self.data.baseline["observation"]["installed_sources"]
        ):
            if name in rows:
                row = rows[name]
                installed[name] = {
                    "bytes": row["bytes"],
                    "digest": row["digest"],
                    "identity": [
                        1,
                        200,
                        stat.S_IFREG | int(row["mode"], 8),
                        0,
                        0,
                        1,
                        row["bytes"],
                        1,
                        1,
                    ],
                }
            else:
                installed[name] = {
                    "bytes": 13884,
                    "digest": "sha256:a34452c8ef7ee1fa9257848759fdb7f3f045b93ac7bc0e59cc5727129b257cbc",
                }
        writers = {}
        for name, raw in self.data.inputs.items():
            is_http = name == subject.preparation.HTTP_FIXTURE
            is_policy = name == subject.live._POLICY
            writers[name] = metadata(
                raw,
                uid=998 if is_policy else 0,
                gid=997 if is_http or is_policy else 0,
                mode=0o440 if is_http else 0o400,
            )
        units = {}
        for unit, (user, group) in subject._UNITS.items():
            path = f"/docker/{CONTAINER}/system.slice/{unit}"
            units[unit] = {
                "unit": {
                    "Id": unit,
                    "LoadState": "loaded",
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "MainPID": "0",
                    "ControlPID": "0",
                    "ControlGroup": "",
                    "User": user,
                    "Group": group,
                    "KillMode": "control-group",
                    "Delegate": "no",
                    "Restart": "no",
                },
                "cgroup": {"path": path, "status": "ABSENT"},
            }
        setup = {
            "schema": self.host.setup.SCHEMA,
            "authority": self.host.setup.AUTHORITY,
            "status": "PREPARED_NOT_ACTIVATED",
            "container_id": CONTAINER,
            "setup_source_digest": subject._digest(
                self.installed[subject.SETUP_SOURCE]
            ),
            "preparation": {
                "preparation": self.prepared["preparation"],
                "preparation_digest": self.prepared["preparation_digest"],
                "retained_blob_digests": sorted(self.prepared["input_blobs"]),
                "local_readback": True,
            },
            "public_blob_attempts": [
                {key: row[key] for key in ("digest", "bytes")} for row in public
            ],
            "installed_sources": installed,
            "installed_sources_after": deepcopy(installed),
            "implementation_sources": implementation,
            "implementation_sources_after": deepcopy(implementation),
            "measurement_unused": {
                "status": "MEASUREMENT_PATHS_ABSENT",
                "units": units,
                "reset_authorized": False,
                "activation_performed": False,
            },
            "ingress_absent": {
                "path": "/var/lib/aragorn-runtime-worker-measurement",
                "status": "ABSENT",
                "created": False,
            },
            "http_writer_intent_digest": subject._digest(
                self.data.inputs[subject.preparation.HTTP_FIXTURE]
            ),
            "http_provisioning_observation": None,
            "writer_readback": writers,
            "writer_readback_after": deepcopy(writers),
            "setup_state": {
                "activation_count": 0,
                "pins_frozen_before_activation": True,
                "provisioning_file_digests": self.prepared["provisioning_file_digests"],
            },
            "fixture_stack_cleanup": {
                unit: {
                    "Id": unit,
                    "ActiveState": "inactive",
                    "MainPID": "0",
                    "ControlPID": "0",
                }
                for unit in subject._UNITS
            },
            "cleanup_failure": None,
            "postcondition_failures": [],
            "refusal": None,
            "limitations": list(subject._SETUP_LIMITATIONS),
            **dict.fromkeys(subject.FALSE_FLAGS, False),
        }
        controllers = {
            name: metadata(self.installed[name])
            for name in (subject.WRAPPER_SOURCE, subject.CONSUMER_SOURCE)
        }
        guest = {
            "schema": subject.GUEST_SCHEMA,
            "authority": subject.GUEST_AUTHORITY,
            "status": "PREPARED_NOT_ACTIVATED",
            "container_id": CONTAINER,
            "input_bundle_digest": self.built["bundle_digest"],
            "setup": setup,
            "http_fixture": self.data.fixture_binding["fixture"],
            "public_blobs": public,
            "export_failures": [],
            "refusal": None,
            "input_bundle_readback": True,
            "controller_sources": controllers,
            "controller_sources_after": deepcopy(controllers),
            "postcondition_failures": [],
            "limitations": list(subject.GUEST_LIMITATIONS),
            **dict.fromkeys(subject.FALSE_FLAGS, False),
        }
        keys = (
            "build_observation",
            "fixture_image",
            "parent_identity",
            "parent_before",
            "parent_after",
            "runtime_before",
            "runtime_after",
            "container_inspect",
            "cleanup",
        )
        capture = {key: deepcopy(self.data.baseline[key]) for key in keys}
        owner = "e" * 64
        name = "aragorn-native-http-setup-" + owner[:16]
        item = capture["container_inspect"]
        item.update(Id=CONTAINER, Name="/" + name)
        item["Config"]["Labels"].update(
            {"dev.aragorn.snapshot-owner": owner, "dev.aragorn.source-commit": "c" * 40}
        )
        cleanup = capture["cleanup"]
        cleanup.update(name=name, owner=owner, removed_id=CONTAINER)
        cleanup["owned_container"] = {
            "id": CONTAINER,
            "image": subject.reported._IMAGE,
            "name": "/" + name,
            "owner": owner,
        }
        listing = ["container", "ls", "--all", "--no-trunc", "--filter"]
        by_name = [*listing, "name=^/" + name + "$", "--format", "{{.ID}}"]
        commands = [
            by_name,
            ["container", "inspect", CONTAINER],
            ["container", "rm", "--force", CONTAINER],
            ["info", "--format", "{{.ServerVersion}}"],
            by_name,
            [*listing, "id=" + CONTAINER, "--format", "{{.ID}}"],
        ]
        for index, command in enumerate(cleanup["commands"]):
            command["argv"] = subject.reported._DOCKER + commands[index]
            command["stdout"] = (
                CONTAINER + "\n"
                if index in (0, 2)
                else json.dumps([item])
                if index == 1
                else ""
                if index in (4, 5)
                else command["stdout"]
            )
        self.source_rows = {
            name: _tree_row(name, raw, subject._digest)
            for name, raw in self.original.items()
        }
        capture.update(
            schema=subject.CAPTURE_SCHEMA,
            authority=subject.CAPTURE_AUTHORITY,
            status="PREPARED_NOT_ACTIVATED",
            input_bundle_digest=self.built["bundle_digest"],
            source=json.loads(self.arguments["source_record_raw"]),
            fixture_container=CONTAINER,
            staged_profile=deepcopy(self.data.stage),
            guest=guest,
            fixture_helpers=subject.helper_records(self.bound, self.source_rows),
            guest_publication={
                "attempted": [row["digest"] for row in public],
                "retained": [row["digest"] for row in public],
                "complete": True,
            },
            cleanup_failure=None,
            refusal=None,
            fixture_creation_attempted=True,
            postcondition_failures=[],
            independent_capture_replay_complete=False,
            **dict.fromkeys(subject.FALSE_FLAGS, False),
        )
        self.capture = capture

    def verify(self, capture=None):
        raw = canonical_json(self.capture if capture is None else capture) + b"\n"
        pin = self.data.cas.put(BytesIO(raw), max_bytes=len(raw))
        return self.contract.verify_native_common_setup_capture(
            raw, expected_capture_digest=pin, store=self.data.reader
        )


class HttpSetupSourceTests(unittest.TestCase):
    def test_exact_render_pins_and_original_sources_remain_distinct(self):
        original, generated, host = _composition()
        self.assertEqual(set(generated), set(renderer.GENERATED_SOURCES))
        self.assertEqual(host._FILES, host.contract.FIXTURE_HELPERS)
        self.assertEqual(set(host._SOURCE_PATHS), set(original))
        for name in renderer.INPUTS:
            with (
                self.subTest(name=name),
                self.assertRaises(renderer.NativeHttpSetupCaptureRenderError),
            ):
                renderer.render(original | {name: original[name] + b"\n"})
            self.assertEqual((ROOT / name).read_bytes(), original[name])

    def test_local_loader_uses_http_dependencies_without_global_module_replacement(
        self,
    ):
        before = {
            name: value
            for name, value in sys.modules.items()
            if name.startswith(
                ("aragorn.native_phase3_common", "scripts.runtime_native_common")
            )
        }
        original, _, _ = _composition()
        host = launcher.build_controller(original)
        for name, value in before.items():
            self.assertIs(sys.modules[name], value)
        self.assertIs(host.setup.preparation, host.preparation)
        self.assertIs(host.contract.preparation, host.preparation)
        self.assertIs(host.guest.setup, host.setup)
        self.assertEqual(len(host.preparation.common_identity.FILE_PATHS), 41)
        self.assertEqual(len(host.preparation.common_identity.MEASUREMENT_SOURCES), 21)

    def test_http_handoff_and_source_guard_bind_outputs_not_original_copy_paths(self):
        _, generated, host = _composition()
        program = host._http_handoff_program()
        self.assertIn("len(directories)!=21", program)
        self.assertNotIn("startswith('/usr/')", program)
        self.assertIn(
            b'raw = bound["installed_source_raws"][path]', generated[renderer.HOST]
        )
        self.assertNotIn(b'"cp", str(_ROOT / path)', generated[renderer.HOST])

    def test_launcher_never_dispatches_when_signed_source_guard_refuses(self):
        with (
            patch.object(launcher, "_verified_sources", side_effect=ValueError),
            patch.object(launcher, "build_controller") as build,
        ):
            with patch("builtins.print"):
                self.assertEqual(launcher.main(["capture"]), 2)
            build.assert_not_called()


class HttpSetupReplayTests(unittest.TestCase):
    def setUp(self):
        self.fixture = HttpSetupCaptureFixture(self)

    def test_real_http_preparation_public_closure_replays_with_false_authority_flags(
        self,
    ):
        result = self.fixture.verify()
        self.assertEqual(result["writer_digest_count"], 8)
        self.assertEqual(result["status"], "BOUNDED_PUBLIC_SETUP_REPLAY_VERIFIED")
        self.assertFalse(result["generated_sources_recomputed"])
        self.assertFalse(result["signature_verified"])
        self.assertTrue(
            all(result[key] is False for key in self.fixture.contract.FALSE_FLAGS)
        )
        self.assertLessEqual(result["public_blob_count"], 32)
        self.assertFalse(
            set(self.fixture.prepared["provisioning_file_digests"].values())
            & set(self.fixture.prepared["input_blobs"])
        )

    def test_old_schema_original_code_and_seven_writer_reports_are_not_relabelled(self):
        self.fixture.verify()
        mutations = (
            lambda x: x.update(schema="aragorn/native-common-setup-capture/v1"),
            lambda x: x["guest"]["setup"].update(
                http_writer_intent_digest="sha256:" + "f" * 64
            ),
            lambda x: x["guest"]["setup"]["writer_readback"].pop(
                self.fixture.contract.preparation.HTTP_FIXTURE
            ),
            lambda x: x["guest"]["http_fixture"].update(container_id="d" * 64),
            lambda x: x["fixture_helpers"][renderer.GUEST].update(
                digest=self.fixture.contract._digest(
                    self.fixture.original[renderer.GUEST]
                )
            ),
            lambda x: x["cleanup"].update(container_name_absent=False),
        )
        for mutate in mutations:
            value = deepcopy(self.fixture.capture)
            mutate(value)
            with self.assertRaises(ValueError):
                self.fixture.verify(value)

    def test_bundle_rejects_wrong_generated_inventory_attempt_and_stage_owned_bytes(
        self,
    ):
        self.fixture.verify()
        args = self.fixture.arguments
        subject = self.fixture.contract
        with self.assertRaises(ValueError):
            subject.prepare_common_setup_inputs(
                **(args | {"http_attempt_id": "p3-lab-a026"})
            )
        for name in (
            renderer.GUEST,
            "src/aragorn/runtime_broker_decision_measurement_verify.py",
        ):
            generated = dict(self.fixture.generated)
            generated.pop(name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                subject.prepare_common_setup_inputs(
                    **(args | {"generated_source_raws": generated})
                )
        generated = dict(self.fixture.generated)
        generated["src/aragorn/runtime_broker_decision_measurement_verify.py"] += b"\n"
        with self.assertRaises(ValueError):
            subject.prepare_common_setup_inputs(
                **(args | {"generated_source_raws": generated})
            )

    def test_host_source_guard_recomposes_before_any_copy_or_creation(self):
        host, data = self.fixture.host, self.fixture
        with (
            patch.object(
                host,
                "_current_source",
                return_value=json.loads(data.arguments["source_record_raw"]),
            ),
            patch.object(
                host._API,
                "_tree_file",
                side_effect=lambda commit, path: data.source_rows[str(path)],
            ),
            patch.object(host.legacy, "_source_bytes"),
        ):
            host._source_guard(data.bound)
            bound = dict(data.bound)
            bound["generated_source_raws"] = dict(data.generated)
            bound["generated_source_raws"][renderer.GUEST] += b"\n"
            with self.assertRaisesRegex(ValueError, "derivation changed"):
                host._source_guard(bound)

    def test_guest_derives_owned_fixture_before_setup_and_uses_installed_code_views(
        self,
    ):
        data, guest = self.fixture, self.fixture.host.guest
        report = data.capture["guest"]["setup"]
        expected = data.data.fixture_binding["fixture"]
        calls = []

        def controller(name, raw):
            self.assertEqual(raw, data.installed[name])
            return _metadata(raw, data.contract._digest)

        def setup(**args):
            calls.append("setup")
            self.assertEqual(args["expected_http_fixture"], expected)
            self.assertEqual(args["http_attempt_id"], ATTEMPT)
            return deepcopy(report)

        with (
            patch.object(guest.setup.predecessor, "_environment"),
            patch.object(
                guest, "_read_bundle", return_value=(data.built["bundle_raw"], {})
            ),
            patch.object(guest, "_read_controller", side_effect=controller),
            patch.object(
                guest,
                "_observe_http_fixture",
                side_effect=lambda container: calls.append("fixture") or expected,
            ),
            patch.object(guest.setup, "prepare_common_native_setup", side_effect=setup),
            patch.object(
                guest,
                "_export_public",
                side_effect=lambda result, rows: result.update(
                    public_blobs=deepcopy(data.capture["guest"]["public_blobs"])
                ),
            ),
        ):
            result = guest._run(CONTAINER, data.built["bundle_digest"])
        self.assertEqual(calls, ["fixture", "setup"])
        self.assertEqual(result["status"], "PREPARED_NOT_ACTIVATED")
        self.assertEqual(result["http_fixture"], expected)
        self.assertTrue(all(result[key] is False for key in guest._FALSE))
