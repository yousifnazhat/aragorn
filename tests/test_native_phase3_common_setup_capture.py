"""Inert public report models, not live captures or acceptance evidence.

The reviewed common74 stager and pure preparation are real. Metadata, source
claims, container operations and cleanup below are explicitly test-only values;
no producer/controller, service, VM, credential writer or historical test runs.
"""

from copy import deepcopy
import hashlib
from io import BytesIO
import json
import stat
import unittest
from unittest.mock import patch

from aragorn import native_phase3_common_setup_capture as subject
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from tests import test_native_phase3_common_preparation as data


def _metadata(raw, *, uid=0, gid=0, mode=0o444, inode=100):
    return {
        "bytes": len(raw),
        "digest": subject._digest(raw),
        "identity": [1, inode, stat.S_IFREG | mode, uid, gid, 1, len(raw), 1, 1],
    }


def _pinned_metadata(row, *, inode=200):
    return {
        "bytes": row["bytes"],
        "digest": row["digest"],
        "identity": [
            1,
            inode,
            stat.S_IFREG | int(row["mode"], 8),
            0,
            0,
            1,
            row["bytes"],
            1,
            1,
        ],
    }


class SetupCaptureData(unittest.TestCase):
    """Reusable data constructor only; never inherit historical test methods."""

    def setUp(self):
        fixture = data.NativeCommonPreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.store, self.reader = fixture.cas, fixture.reader
        sources = {
            path: ("inert test-only source: " + path).encode()
            for path in subject.SOURCE_PATHS
        }
        self.arguments = {
            key: raw
            for key, raw in fixture.arguments.items()
            if key not in {"container_id", "provisioning_inputs"}
        }
        self.arguments["implementation_source_raws"] = {
            path: sources[path] for path in subject.IMPLEMENTATION_PATHS
        }
        self.arguments.update(
            source_raws=sources,
            setup_source_raw=sources[subject.SETUP_SOURCE],
            wrapper_source_raw=sources[subject.WRAPPER_SOURCE],
            host_source_raw=sources[subject.HOST_SOURCE],
        )
        self.bundle = subject.prepare_common_setup_inputs(**self.arguments)
        self.bound = subject.inspect_common_setup_inputs(
            self.bundle["bundle_raw"],
            expected_bundle_digest=self.bundle["bundle_digest"],
        )
        arguments = {
            key: value
            for key, value in self.bound["setup_arguments"].items()
            if key != "expected_setup_digest"
        }
        self.prepared = subject.preparation.prepare_native_common_deployment(
            **arguments, container_id=data.CONTAINER, provisioning_inputs=fixture.inputs
        )
        self.blobs = self.bundle["input_blobs"] | self.prepared["input_blobs"]
        self.retain(self.blobs)
        ordered = [
            (pin, raw)
            for pin, raw in self.prepared["input_blobs"].items()
            if pin != self.prepared["preparation_digest"]
        ] + [(self.prepared["preparation_digest"], self.prepared["preparation_raw"])]
        self.public = [
            {"digest": pin, "bytes": len(raw), "text": raw.decode()}
            for pin, raw in ordered
        ]
        implementation = {
            target: _metadata(sources[path], inode=500 + index)
            for index, (path, target) in enumerate(subject.IMPLEMENTATION_PATHS.items())
        }
        implementation[subject.FIXTURE_HELPERS[subject.SETUP_SOURCE]] = _metadata(
            sources[subject.SETUP_SOURCE], inode=600
        )
        files = {row["path"]: row for row in fixture.stage["files"]}
        installed = {}
        for index, path in enumerate(
            sorted(
                set(fixture.baseline["observation"]["installed_sources"])
                | set(subject._OVERRIDE_PATHS)
            )
        ):
            installed[path] = (
                _pinned_metadata(files[path], inode=700 + index)
                if path in files
                else {
                    "bytes": 13884,
                    "digest": "sha256:a34452c8ef7ee1fa9257848759fdb7f3f045b93ac7bc0e59cc5727129b257cbc",
                }
            )
        writers = {
            path: _metadata(
                raw,
                uid=991 if path == subject.live._POLICY else 0,
                gid=990 if path == subject.live._POLICY else 0,
                mode=0o400,
                inode=900 + index,
            )
            for index, (path, raw) in enumerate(fixture.inputs.items())
        }
        units = {}
        for unit, (user, group) in subject._UNITS.items():
            path = "/docker/" + data.CONTAINER + "/system.slice/" + unit
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
        self.setup = {
            "schema": "aragorn/native-common-case-setup/v1",
            "authority": "OWNED_SEVEN_WRITER_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY",
            "status": "PREPARED_NOT_ACTIVATED",
            "container_id": data.CONTAINER,
            "setup_source_digest": subject._digest(sources[subject.SETUP_SOURCE]),
            "preparation": {
                "preparation": deepcopy(self.prepared["preparation"]),
                "preparation_digest": self.prepared["preparation_digest"],
                "retained_blob_digests": sorted(self.prepared["input_blobs"]),
                "local_readback": True,
            },
            "public_blob_attempts": [
                {key: row[key] for key in ("digest", "bytes")} for row in self.public
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
            path: _metadata(sources[path], inode=1200 + index)
            for index, path in enumerate(
                (subject.WRAPPER_SOURCE, subject.CONSUMER_SOURCE)
            )
        }
        self.guest = {
            "schema": subject.GUEST_SCHEMA,
            "authority": subject.GUEST_AUTHORITY,
            "status": "PREPARED_NOT_ACTIVATED",
            "container_id": data.CONTAINER,
            "input_bundle_digest": self.bundle["bundle_digest"],
            "setup": self.setup,
            "public_blobs": self.public,
            "export_failures": [],
            "refusal": None,
            "input_bundle_readback": True,
            "controller_sources": controllers,
            "controller_sources_after": deepcopy(controllers),
            "postcondition_failures": [],
            "limitations": list(subject.GUEST_LIMITATIONS),
            **dict.fromkeys(subject.FALSE_FLAGS, False),
        }
        baseline = fixture.baseline
        outer_names = (
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
        capture = {name: deepcopy(baseline[name]) for name in outer_names}
        owner = "e" * 64
        name = "aragorn-native-common-setup-" + owner[:16]
        item = capture["container_inspect"]
        item.update(Id=data.CONTAINER, Name="/" + name)
        item["Config"]["Labels"].update(
            {"dev.aragorn.snapshot-owner": owner, "dev.aragorn.source-commit": "c" * 40}
        )
        cleanup = capture["cleanup"]
        cleanup.update(name=name, owner=owner, removed_id=data.CONTAINER)
        cleanup["owned_container"] = {
            "id": data.CONTAINER,
            "image": subject.reported._IMAGE,
            "name": "/" + name,
            "owner": owner,
        }
        listing = ["container", "ls", "--all", "--no-trunc", "--filter"]
        by_name = [*listing, "name=^/" + name + "$", "--format", "{{.ID}}"]
        argv = [
            by_name,
            ["container", "inspect", data.CONTAINER],
            ["container", "rm", "--force", data.CONTAINER],
            ["info", "--format", "{{.ServerVersion}}"],
            by_name,
            [*listing, "id=" + data.CONTAINER, "--format", "{{.ID}}"],
        ]
        for index, command in enumerate(cleanup["commands"]):
            command["argv"] = subject.reported._DOCKER + argv[index]
            command["stdout"] = (
                data.CONTAINER + "\n"
                if index in (0, 2)
                else json.dumps([item])
                if index == 1
                else ""
                if index in (4, 5)
                else command["stdout"]
            )
        capture.update(
            schema=subject.CAPTURE_SCHEMA,
            authority=subject.CAPTURE_AUTHORITY,
            status="PREPARED_NOT_ACTIVATED",
            input_bundle_digest=self.bundle["bundle_digest"],
            source=json.loads(self.arguments["source_record_raw"]),
            fixture_container=data.CONTAINER,
            staged_profile=deepcopy(fixture.stage),
            guest=self.guest,
            fixture_helpers={
                path: {
                    "path": path,
                    "mode": "100644",
                    "blob": hashlib.sha1(
                        b"blob "
                        + str(len(sources[path])).encode("ascii")
                        + b"\0"
                        + sources[path]
                    ).hexdigest(),
                    "bytes": len(sources[path]),
                    "digest": subject._digest(sources[path]),
                    "installed_path": target,
                    "installed_mode": "0444",
                }
                for path, target in subject.FIXTURE_HELPERS.items()
            },
            guest_publication={
                "attempted": [row["digest"] for row in self.public],
                "retained": [row["digest"] for row in self.public],
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

    def retain(self, blobs):
        for pin, raw in blobs.items():
            self.store.put_expected(
                BytesIO(raw), expected_digest=pin, max_bytes=len(raw)
            )

    def capture_bytes(self, value=None):
        raw = canonical_json(self.capture if value is None else value) + b"\n"
        pin = self.store.put(BytesIO(raw), max_bytes=len(raw))
        return raw, pin

    def verify(self, value=None, **changes):
        raw, pin = self.capture_bytes(value)
        return subject.verify_native_common_setup_capture(
            raw, **({"expected_capture_digest": pin, "store": self.reader} | changes)
        )


class NativeCommonSetupCaptureTests(SetupCaptureData):
    def test_real_public_composition_remains_setup_only(self):
        with (
            patch.object(
                CAS, "put", side_effect=AssertionError("read-only replay wrote")
            ),
            patch.object(
                subject.preparation,
                "_inspect",
                side_effect=AssertionError("private writer replay forbidden"),
            ),
        ):
            raw = canonical_json(self.capture) + b"\n"
            pin = subject._digest(raw)
            # Retain before the read-only call using put_expected, not a callback.
            self.retain({pin: raw})
            result = subject.verify_native_common_setup_capture(
                raw, expected_capture_digest=pin, store=self.reader
            )
        self.assertEqual(result["status"], "BOUNDED_PUBLIC_SETUP_REPLAY_VERIFIED")
        self.assertTrue(result["independent_capture_replay_complete"])
        self.assertIs(result["writer_semantics_independently_replayed"], False)
        self.assertIs(result["private_writer_semantics_replayed"], False)
        self.assertTrue(all(result[key] is False for key in subject.FALSE_FLAGS))
        self.assertEqual(result["writer_digest_count"], 7)

    def test_bundle_roundtrip_and_exact_sources(self):
        self.assertEqual(self.bound["bundle_raw"], self.bundle["bundle_raw"])
        self.assertNotIn("expected_container_id", self.bound["setup_arguments"])
        for change in (
            lambda value: value["sources"].pop(subject.CONSUMER_SOURCE),
            lambda value: value["decision"].update(resumable=0),
            lambda value: value.update(extra="not accepted"),
        ):
            value = deepcopy(self.bundle["bundle"])
            change(value)
            raw = canonical_json(value)
            with self.assertRaises(subject.NativeCommonSetupCaptureError):
                subject.inspect_common_setup_inputs(
                    raw, expected_bundle_digest=subject._digest(raw)
                )

    def test_partial_refusal_and_claim_escalation_refuse(self):
        mutations = (
            lambda item: item.update(status="REFUSED"),
            lambda item: item["guest"].update(status="REFUSED"),
            lambda item: item["guest"]["setup"].update(status="REFUSED"),
            lambda item: item.update(independent_capture_replay_complete=True),
            lambda item: item["guest_publication"].update(complete=False),
            lambda item: item["guest"]["setup"]["setup_state"].update(
                activation_count=True
            ),
            lambda item: item.update(measurement_collected=0),
            lambda item: item["guest"]["setup"].update(
                postcondition_failures=["INERT_FAILURE"]
            ),
        )
        for change in mutations:
            value = deepcopy(self.capture)
            change(value)
            with self.assertRaises(subject.NativeCommonSetupCaptureError):
                self.verify(value)

    def test_digest_metadata_and_source_readback_mutations_refuse(self):
        mutations = (
            lambda item: item["fixture_helpers"][subject.WRAPPER_SOURCE].update(
                digest="sha256:" + "f" * 64
            ),
            lambda item: item["fixture_helpers"][subject.WRAPPER_SOURCE].update(
                blob="f" * 40
            ),
            lambda item: item["guest"]["controller_sources_after"][
                subject.CONSUMER_SOURCE
            ]["identity"].__setitem__(1, 9999),
            lambda item: item["guest"]["setup"]["writer_readback_after"][
                subject.live._WORKER
            ].update(bytes=1),
            lambda item: item["guest"]["setup"]["implementation_sources"][
                subject.FIXTURE_HELPERS[subject.SETUP_SOURCE]
            ]["identity"].__setitem__(2, stat.S_IFREG | 0o644),
            lambda item: item["guest"]["setup"]["installed_sources"][
                subject._OVERRIDE_PATHS[0]
            ].update(digest="sha256:" + "e" * 64),
        )
        for change in mutations:
            value = deepcopy(self.capture)
            change(value)
            with self.assertRaises(subject.NativeCommonSetupCaptureError):
                self.verify(value)

    def test_missing_extra_or_reordered_public_exports_refuse(self):
        for change in (
            lambda item: item["guest"]["public_blobs"].pop(),
            lambda item: item["guest"]["public_blobs"].reverse(),
            lambda item: item["guest_publication"]["retained"].pop(),
            lambda item: item["guest"]["setup"]["preparation"][
                "retained_blob_digests"
            ].append("sha256:" + "f" * 64),
        ):
            value = deepcopy(self.capture)
            change(value)
            with self.assertRaises(subject.NativeCommonSetupCaptureError):
                self.verify(value)

    def test_public_artifact_and_preparation_report_must_join(self):
        value = deepcopy(self.capture)
        value["guest"]["setup"]["preparation"]["preparation"]["artifact_digests"][
            "worker"
        ] = "sha256:" + "e" * 64
        with self.assertRaises(subject.NativeCommonSetupCaptureError):
            self.verify(value)
        value = deepcopy(self.capture)
        value["guest"]["public_blobs"][0]["text"] += " "
        with self.assertRaises(subject.NativeCommonSetupCaptureError):
            self.verify(value)

    def test_rehashed_impossible_public_worker_binding_refuses(self):
        for field, replacement in (
            ("runtime_digest", "sha256:" + "e" * 64),
            ("policy_version", 2),
        ):
            with self.subTest(field=field):
                value = deepcopy(self.capture)
                setup = value["guest"]["setup"]
                preparation = setup["preparation"]["preparation"]

                def replace_blob(old_pin, raw):
                    pin = subject._digest(raw)
                    self.retain({pin: raw})
                    for row in value["guest"]["public_blobs"]:
                        if row["digest"] == old_pin:
                            row.update(digest=pin, bytes=len(raw), text=raw.decode())
                    for row in setup["public_blob_attempts"]:
                        if row["digest"] == old_pin:
                            row.update(digest=pin, bytes=len(raw))
                    for key in ("attempted", "retained"):
                        value["guest_publication"][key] = [
                            pin if old == old_pin else old
                            for old in value["guest_publication"][key]
                        ]
                    return pin

                old_worker = preparation["artifact_digests"]["worker"]
                worker = json.loads(self.blobs[old_worker])
                worker["identity"]["binding"][field] = replacement
                worker_raw = canonical_json(worker["identity"]["binding"])
                worker_pin = subject._digest(worker_raw)
                preparation["provisioning_file_digests"][subject.live._WORKER] = (
                    worker_pin
                )
                setup["setup_state"]["provisioning_file_digests"][
                    subject.live._WORKER
                ] = worker_pin
                for side in ("writer_readback", "writer_readback_after"):
                    row = setup[side][subject.live._WORKER]
                    row.update(bytes=len(worker_raw), digest=worker_pin)
                    row["identity"][6] = len(worker_raw)
                preparation["artifact_digests"]["worker"] = replace_blob(
                    old_worker, canonical_json(worker)
                )
                deployment = subject.build_phase3_deployment_identity(
                    preparation["artifact_digests"]
                )
                preparation["deployment_digest"] = replace_blob(
                    preparation["deployment_digest"], canonical_json(deployment)
                )
                setup["preparation"]["preparation_digest"] = replace_blob(
                    setup["preparation"]["preparation_digest"],
                    canonical_json(preparation),
                )
                setup["preparation"]["retained_blob_digests"] = sorted(
                    row["digest"] for row in value["guest"]["public_blobs"]
                )
                with self.assertRaises(subject.NativeCommonSetupCaptureError):
                    self.verify(value)

    def test_isolation_parent_and_cleanup_mutations_refuse(self):
        mutations = (
            lambda item: item["container_inspect"]["HostConfig"].update(
                NetworkMode="host"
            ),
            lambda item: item["parent_after"]["volume_inspect"].update(Name="other"),
            lambda item: item["runtime_after"]["content"].update(
                runtime_tree_after="sha256:" + "e" * 64
            ),
            lambda item: item["cleanup"].update(owner="f" * 64),
            lambda item: item["cleanup"]["commands"][2].update(exit_code=False),
            lambda item: item["guest"]["setup"]["fixture_stack_cleanup"][
                next(iter(subject._UNITS))
            ].update(MainPID="99"),
        )
        for change in mutations:
            value = deepcopy(self.capture)
            change(value)
            with self.assertRaises(subject.NativeCommonSetupCaptureError):
                self.verify(value)

    def test_old_stage_and_v1_preparation_refuse(self):
        arguments = dict(self.arguments)
        stage = deepcopy(self.fixture.stage)
        stage["schema"] = "aragorn/runtime-phase3-common-staged-profile/v1"
        arguments["staged_profile_raw"] = canonical_json(stage)
        with self.assertRaises(subject.NativeCommonSetupCaptureError):
            subject.prepare_common_setup_inputs(**arguments)
        value = deepcopy(self.capture)
        value["guest"]["setup"]["preparation"]["preparation"]["schema"] = (
            "aragorn/native-common-deployment-preparation/v1"
        )
        with self.assertRaises(subject.NativeCommonSetupCaptureError):
            self.verify(value)

    def test_writable_cas_wrong_pin_and_noncanonical_refuse(self):
        with self.assertRaises(subject.NativeCommonSetupCaptureError):
            self.verify(store=self.store)
        with self.assertRaises(subject.NativeCommonSetupCaptureError):
            self.verify(expected_capture_digest="sha256:" + "f" * 64)
        raw = canonical_json(self.capture)
        pin = self.store.put(BytesIO(raw), max_bytes=len(raw))
        with self.assertRaises(subject.NativeCommonSetupCaptureError):
            subject.verify_native_common_setup_capture(
                raw, expected_capture_digest=pin, store=self.reader
            )

    def test_final_public_closure_loss_refuses(self):
        original = CAS.read
        pin = self.prepared["preparation_digest"]
        count = 0

        def read(store, digest, **kwargs):
            nonlocal count
            if digest == pin:
                count += 1
                if count >= 4:
                    raise ValueError("inert final custody loss")
            return original(store, digest, **kwargs)

        with (
            patch.object(CAS, "read", read),
            self.assertRaises(subject.NativeCommonSetupCaptureError),
        ):
            self.verify()
        self.assertGreaterEqual(count, 4)
