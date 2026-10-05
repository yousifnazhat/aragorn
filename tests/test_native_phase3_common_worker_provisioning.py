"""Inert common-worker provenance checks, never live or acceptance evidence."""

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import unittest
from unittest.mock import patch

from aragorn import native_phase3_common_preparation as subject
from aragorn.cas import CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_native_phase3_common_preparation as data


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class NativeCommonWorkerProvisioningTests(unittest.TestCase):
    def setUp(self):
        # Compose only the previous data constructor; never inherit or discover
        # its historical test methods.
        self.fixture = data.NativeCommonPreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.live = subject.old.live
        self.stage = deepcopy(self.fixture.stage)
        self.static = deepcopy(self.fixture.static)
        # Literal data only. This stands for a separately reviewed stage change;
        # it is neither executable worker code nor a replacement live sample.
        raw = b"inert reviewed successor worker provenance fixture\n"
        self.worker_code = {"bytes": len(raw), "digest": _digest(raw)}
        row = next(
            row for row in self.stage["files"] if row["path"] == self.live._WORKER_CODE
        )
        row.update(self.worker_code)
        self.static["file_digests"][self.live._WORKER_CODE] = self.worker_code["digest"]

    @contextmanager
    def reviewed(self, stage=None):
        stage_raw = canonical_json(self.stage if stage is None else stage)
        with (
            patch.object(
                subject, "STAGED_PROFILE_PIN", (len(stage_raw), _digest(stage_raw))
            ),
            patch.object(
                subject.old,
                "_provisioning",
                side_effect=AssertionError(
                    "frozen provisioning must not be delegated to"
                ),
            ) as predecessor,
        ):
            try:
                yield stage_raw
            finally:
                predecessor.assert_not_called()

    def build(self, *, stage=None, static=None, inputs=None):
        with self.reviewed(stage) as stage_raw:
            return subject.prepare_native_common_deployment(
                **{
                    **self.fixture.arguments,
                    "staged_profile_raw": stage_raw,
                    "static_pin_manifest_raw": canonical_json(
                        self.static if static is None else static
                    ),
                    "provisioning_inputs": self.fixture.inputs
                    if inputs is None
                    else inputs,
                }
            )

    def test_reviewed_worker_pair_changes_truthful_artifact_not_writer_hashes(self):
        frozen = subject.old._WORKER_BYTES, subject.old._WORKER_PIN
        # The actual current stage passes with its real, unpatched report pin.
        with patch.object(
            subject.old,
            "_provisioning",
            side_effect=AssertionError("frozen delegation"),
        ) as predecessor:
            original = self.fixture.build()
            predecessor.assert_not_called()
        changed = self.build()
        identity = json.loads(changed["artifacts"]["worker"])["identity"]
        self.assertEqual(
            identity,
            {
                **self.worker_code,
                "binding": json.loads(self.fixture.inputs[self.live._WORKER]),
            },
        )
        self.assertNotEqual(identity["digest"], subject.old._WORKER_PIN)
        self.assertEqual((subject.old._WORKER_BYTES, subject.old._WORKER_PIN), frozen)
        self.assertEqual(
            changed["provisioning_file_digests"], original["provisioning_file_digests"]
        )
        self.assertEqual(
            changed["provisioning_file_digests"],
            {path: _digest(raw) for path, raw in self.fixture.inputs.items()},
        )
        self.assertNotEqual(changed["deployment"], original["deployment"])
        self.assertNotEqual(
            changed["artifacts"]["worker"], original["artifacts"]["worker"]
        )
        for name in (
            "configuration",
            "policy",
            "runtime_commit_or_image",
            "adapter",
            "aragorn_version",
        ):
            self.assertEqual(changed["artifacts"][name], original["artifacts"][name])
        for name, raw in changed["artifacts"].items():
            self.assertEqual(changed["deployment"]["bindings"][name], _digest(raw))
            self.assertEqual(changed["input_blobs"][_digest(raw)], raw)
        self.assertEqual(
            changed["preparation"]["decision"], dict.fromkeys(subject._FALSE, False)
        )
        self.assertNotIn(
            self.fixture.inputs[self.live._CONFIG], changed["input_blobs"].values()
        )

    def test_complete_stage_pin_still_blocks_unreviewed_worker_substitution(self):
        with patch.object(subject.old, "_provisioning") as predecessor:
            with self.assertRaisesRegex(
                subject.NativeCommonPreparationError,
                "reviewed common stage bytes changed",
            ):
                subject.prepare_native_common_deployment(
                    **{
                        **self.fixture.arguments,
                        "staged_profile_raw": canonical_json(self.stage),
                        "static_pin_manifest_raw": canonical_json(self.static),
                    }
                )
            predecessor.assert_not_called()

    def test_worker_stage_row_requires_unique_fixed_source_mode_and_strict_pair(self):
        self.assertEqual(
            subject._worker_code(self.stage, self.static), self.worker_code
        )
        for mode in (
            "duplicate",
            "missing",
            "row-type",
            "files-type",
            "extra",
            "mode",
            "mode-type",
            "source",
            "source-type",
            "bytes-bool",
            "bytes-zero",
            "bytes-large",
            "digest-shape",
            "digest-static",
        ):
            stage = deepcopy(self.stage)
            row = next(
                row for row in stage["files"] if row["path"] == self.live._WORKER_CODE
            )
            if mode == "duplicate":
                stage["files"].append(deepcopy(row))
            elif mode == "missing":
                stage["files"].remove(row)
            elif mode == "row-type":
                stage["files"].append(None)
            elif mode == "files-type":
                stage["files"] = tuple(stage["files"])
            elif mode == "extra":
                row["trusted"] = True
            elif mode == "mode":
                row["mode"] = "0755"
            elif mode == "mode-type":
                row["mode"] = 644
            elif mode == "source":
                row["source_name"] = "inert-other-worker.py"
            elif mode == "source-type":
                row["source_name"] = True
            elif mode == "bytes-bool":
                row["bytes"] = True
            elif mode == "bytes-zero":
                row["bytes"] = 0
            elif mode == "bytes-large":
                row["bytes"] = 2 * 1024 * 1024 + 1
            elif mode == "digest-shape":
                row["digest"] = "sha256:not-a-digest"
            else:
                row["digest"] = data.PIN
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                subject._worker_code(stage, self.static)

    def test_static_and_worker_artifact_must_match_exact_stage_pair(self):
        with self.assertRaises(subject.NativeCommonPreparationError):
            self.build(static=self.fixture.static)
        built = self.build()
        for worker_code, static in (
            (self.worker_code, self.fixture.static),
            ({**self.worker_code, "bytes": True}, self.static),
            ({**self.worker_code, "authority": "TRUSTED"}, self.static),
        ):
            with (
                self.subTest(worker_code=worker_code, static=static),
                self.reviewed(),
                self.assertRaises(subject.NativeCommonPreparationError),
            ):
                subject._provisioning(
                    self.fixture.inputs,
                    {"artifacts": built["artifacts"], "static": static},
                    worker_code,
                )
        for mode in (
            "worker-bytes",
            "worker-digest",
            "worker-binding",
            "configuration",
            "policy",
        ):
            artifacts = dict(built["artifacts"])
            name = "worker" if mode.startswith("worker-") else mode
            document = json.loads(artifacts[name])
            if mode == "worker-bytes":
                document["identity"]["bytes"] += 1
            elif mode == "worker-digest":
                document["identity"]["digest"] = subject.old._WORKER_PIN
            elif mode == "worker-binding":
                document["identity"]["binding"]["policy_digest"] = data.PIN
            else:
                document["identity"][name + "_digest"] = data.PIN
            artifacts[name] = canonical_json(document)
            with (
                self.subTest(mode=mode),
                self.reviewed(),
                self.assertRaises(subject.NativeCommonPreparationError),
            ):
                subject._provisioning(
                    self.fixture.inputs,
                    {"artifacts": artifacts, "static": self.static},
                    self.worker_code,
                )

    def test_successor_retained_closure_rebuilds_and_refuses_drift(self):
        built = self.build()
        self.fixture.retain(built["input_blobs"])
        with self.reviewed():
            rebuilt = subject._inspect(
                built["preparation_raw"],
                built["preparation_digest"],
                self.fixture.reader,
                self.fixture.inputs,
            )
        self.assertEqual(rebuilt, built)
        read = self.fixture.reader.read
        for selected in (
            built["preparation"]["staged_profile_digest"],
            built["preparation"]["static_pin_manifest_digest"],
            built["deployment"]["bindings"]["worker"],
        ):
            for missing in (False, True):
                hits = []

                def drift(pin, *, max_bytes):
                    if pin == selected:
                        hits.append(pin)
                        if missing:
                            raise CASError("inert retained worker closure missing")
                        return b"inert substituted retained worker closure"
                    return read(pin, max_bytes=max_bytes)

                with (
                    self.subTest(pin=selected, missing=missing),
                    self.reviewed(),
                    patch.object(self.fixture.reader, "read", side_effect=drift),
                    self.assertRaises((subject.NativeCommonPreparationError, CASError)),
                ):
                    subject._inspect(
                        built["preparation_raw"],
                        built["preparation_digest"],
                        self.fixture.reader,
                        self.fixture.inputs,
                    )
                self.assertEqual(hits, [selected])

    def test_existing_document_and_cross_writer_rejection_vectors_are_preserved(self):
        vectors = (
            (self.live._CONFIG, "extra", "inert config drift"),
            (self.live._WORKER, "schema", "unreviewed"),
            (self.live._WORKER, "policy_digest", data.PIN),
            (self.live._WORKER, "active_skill_digest", data.PIN),
            (self.live._RUNTIME, "runtime_profile_digest", data.PIN),
            (self.live._OBSERVATION, "schema", "unreviewed"),
            (self.live._POLICY, "default", "ALLOW"),
            (self.live._GRANT, "authority", "EFFECT_AUTHORITY"),
            (self.live._GRANT, "max_actions", True),
            (self.live._GRANT, "max_actions", 2),
            (self.live._GRANT, "expires_at_unix", 1),
            (self.live._GRANT, "source_manifest_digest", data.PIN),
            (self.live._GENESIS, "worker_uid", True),
            (self.live._GENESIS, "policy_version", True),
            (self.live._GENESIS, "stream_id", "invalid"),
        )
        for path, field, value in vectors:
            inputs = dict(self.fixture.inputs)
            document = json.loads(inputs[path])
            document[field] = value
            inputs[path] = canonical_json(document)
            with (
                self.subTest(path=path, field=field, value=value),
                self.assertRaises(subject.NativeCommonPreparationError),
            ):
                self.build(inputs=inputs)

    def test_writer_inventory_canonical_bytes_and_size_limits_remain_required(self):
        for mode in (
            "extra",
            "missing",
            "noncanonical",
            "grant-size",
            "genesis-size",
            "grant-lifetime",
        ):
            inputs = dict(self.fixture.inputs)
            if mode == "extra":
                inputs["/unrequested"] = b"{}"
            elif mode == "missing":
                del inputs[self.live._GRANT]
            elif mode == "noncanonical":
                inputs[self.live._GRANT] += b"\n"
            else:
                path = (
                    self.live._GENESIS if mode == "genesis-size" else self.live._GRANT
                )
                value = json.loads(inputs[path])
                if mode == "grant-lifetime":
                    value["expires_at_unix"] = value["issued_at_unix"] + 301
                else:
                    value["inert_padding"] = "x" * (
                        4096 if mode == "genesis-size" else 65536
                    )
                inputs[path] = canonical_json(value)
            with (
                self.subTest(mode=mode),
                self.assertRaises(subject.NativeCommonPreparationError),
            ):
                self.build(inputs=inputs)

    def test_rehashed_historical_worker_artifact_cannot_replace_reviewed_successor(
        self,
    ):
        built = self.build()
        stale_raw = subject.old._artifact(
            "worker",
            {
                "bytes": subject.old._WORKER_BYTES,
                "digest": subject.old._WORKER_PIN,
                "binding": json.loads(self.fixture.inputs[self.live._WORKER]),
            },
        )
        stale_pin = _digest(stale_raw)
        deployment = subject.build_phase3_deployment_identity(
            {
                **built["preparation"]["artifact_digests"],
                "worker": stale_pin,
            }
        )
        deployment_raw = canonical_json(deployment)
        changed = {
            **built["preparation"],
            "artifact_digests": dict(deployment["bindings"]),
            "deployment_digest": _digest(deployment_raw),
        }
        raw = canonical_json(changed)
        pin = _digest(raw)
        self.fixture.retain(
            {
                **built["input_blobs"],
                stale_pin: stale_raw,
                _digest(deployment_raw): deployment_raw,
                pin: raw,
            }
        )
        with (
            self.reviewed(),
            self.assertRaisesRegex(
                subject.NativeCommonPreparationError,
                "preparation contract or fresh writers changed",
            ),
        ):
            subject._inspect(raw, pin, self.fixture.reader, self.fixture.inputs)

    def test_coherent_profile_sensor_revocation_and_policy_drift_still_refuse(self):
        for mode in (
            "profile-executable",
            "profile-skill",
            "profile-container",
            "sensor",
            "revocation-source",
            "policy-version-bool",
        ):
            documents = {
                path: json.loads(raw) for path, raw in self.fixture.inputs.items()
            }
            profile = documents[self.live._OBSERVATION]["runtime_profile"]
            if mode == "profile-executable":
                profile["executable_digest"] = data.PIN
            elif mode == "profile-skill":
                profile["skill_path"] = "/tmp/inert-unapproved/SKILL.md"
            elif mode == "profile-container":
                profile["cgroup"] = (
                    f"/docker/{'e' * 64}/system.slice/aragorn-runtime-action-worker.service"
                )
            elif mode == "sensor":
                for path in (
                    self.live._OBSERVATION,
                    self.live._POLICY,
                    self.live._GRANT,
                ):
                    documents[path]["sensor_digest"] = data.PIN
            elif mode == "revocation-source":
                documents[self.live._POLICY]["revocation_source_digest"] = data.PIN
            else:
                documents[self.live._POLICY]["version"] = True
                for path in (self.live._WORKER, self.live._GRANT, self.live._GENESIS):
                    documents[path]["policy_version"] = True
            profile_pin = canonical_digest(profile)
            for path in (self.live._RUNTIME, self.live._GRANT):
                documents[path]["runtime_profile_digest"] = profile_pin
            policy_pin = canonical_digest(documents[self.live._POLICY])
            for path in (self.live._WORKER, self.live._GRANT, self.live._GENESIS):
                documents[path]["policy_digest"] = policy_pin
            with (
                self.subTest(mode=mode),
                self.assertRaises(subject.NativeCommonPreparationError),
            ):
                self.build(
                    inputs={
                        path: canonical_json(value) for path, value in documents.items()
                    }
                )


if __name__ == "__main__":
    unittest.main()
