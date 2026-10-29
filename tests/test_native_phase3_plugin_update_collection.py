"""New offline collection seam only; no live captures or old test cases run."""

import hashlib
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import native_phase3_plugin_update_collection as subject
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_json
import test_native_phase3_plugin_update_live_binding as live_fixture

_PATH = (
    Path(__file__).resolve().parents[1]
    / "benchmark/evidence/phase3-native-plugin-update-systemd-development-v2-2026-10-01.json"
)
_CAPTURE_PIN = "sha256:42acdf26c128c4d7ecdfd740ac04b17509e9e17e0b799e7d4a870bf5e82a9e12"


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class NativePluginUpdateCollectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = _PATH.read_bytes()
        if _digest(cls.raw) != _CAPTURE_PIN:
            raise AssertionError("immutable capture changed")
        source = json.loads(cls.raw)["source"]
        cls.pins = {
            "expected_capture_digest": _CAPTURE_PIN,
            "expected_source_digest": _digest(canonical_json(source)),
            "expected_source_commit": source["commit"],
        }
        cls.prepared = subject.prepare_native_plugin_update_collection(
            cls.raw, **cls.pins
        )

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(Path(self.temporary.name) / "cas")
        self.readonly = CAS(self.cas.root, read_only=True)

    def collect(self, **overrides):
        arguments = {
            **self.pins,
            "deployment_raw": self.prepared["deployment_raw"],
            "expected_deployment_digest": self.prepared["deployment_digest"],
            "evidence_cas": self.cas,
        }
        arguments.update(overrides)
        return subject.collect_native_plugin_update_observation(self.raw, **arguments)

    def replay(self, digest, **overrides):
        arguments = {
            **self.pins,
            "expected_collection_digest": digest,
            "expected_deployment_digest": self.prepared["deployment_digest"],
            "evidence_cas": self.readonly,
        }
        arguments.update(overrides)
        return subject.replay_native_plugin_update_collection(**arguments)

    def inventory(self):
        return sorted(
            str(path.relative_to(self.cas.root)) for path in self.cas.root.rglob("*")
        )

    def test_preparation_is_pure_and_projects_the_existing_deployment_contract(self):
        before = self.inventory()
        with patch.object(
            CAS, "put_expected", side_effect=AssertionError("unexpected write")
        ):
            prepared = subject.prepare_native_plugin_update_collection(
                self.raw, **self.pins
            )
        self.assertEqual(prepared, self.prepared)
        self.assertEqual(before, self.inventory())
        deployment = json.loads(prepared["deployment_raw"])
        self.assertEqual(deployment["schema"], "aragorn/phase3-deployment-identity/v1")
        self.assertEqual(len(deployment["bindings"]), 7)
        self.assertFalse(prepared["common_deployment_fully_verified"])

    def test_collection_retains_exact_bytes_and_readonly_replay_without_promotion(self):
        result = self.collect()
        manifest = result["collection"]
        self.assertEqual(
            self.readonly.read(
                manifest["capture"]["digest"], max_bytes=2 * 1024 * 1024
            ),
            self.raw,
        )
        self.assertEqual(
            self.readonly.read(manifest["deployment"]["digest"]),
            self.prepared["deployment_raw"],
        )
        self.assertEqual(
            self.readonly.read(manifest["source"]["digest"]),
            self.prepared["source_raw"],
        )
        for name, reference in manifest["identity_artifacts"].items():
            self.assertEqual(
                self.readonly.read(reference["digest"]),
                self.prepared["identity_artifacts"][name],
            )
        before = self.inventory()
        replayed = self.replay(result["collection_digest"])
        self.assertEqual(replayed, result)
        self.assertEqual(before, self.inventory())
        self.assertEqual(
            result["verification"]["status"], "BOUNDED_OBSERVATION_VERIFIED"
        )
        self.assertTrue(all(manifest[name] is False for name in subject._FALSE_FLAGS))

    def test_identical_collection_deduplicates_without_execution(self):
        first = self.collect()
        before = self.inventory()
        second = self.collect()
        self.assertEqual(first, second)
        self.assertEqual(before, self.inventory())

    def test_caller_pin_mismatches_refuse_before_any_writes(self):
        for overrides in (
            {"expected_capture_digest": "sha256:" + "0" * 64},
            {"expected_source_digest": "sha256:" + "0" * 64},
            {"expected_source_commit": "0" * 40},
            {"deployment_raw": b"{}"},
            {"expected_deployment_digest": "sha256:" + "0" * 64},
            {"evidence_cas": self.readonly},
        ):
            before = self.inventory()
            with (
                self.subTest(overrides=tuple(overrides)),
                self.assertRaises(subject.NativePluginUpdateCollectionError),
            ):
                self.collect(**overrides)
            self.assertEqual(before, self.inventory())

    def test_replay_rejects_wrong_pins_and_writable_views(self):
        result = self.collect()
        for overrides in (
            {"expected_capture_digest": "sha256:" + "0" * 64},
            {"expected_source_digest": "sha256:" + "0" * 64},
            {"expected_source_commit": "0" * 40},
            {"expected_deployment_digest": "sha256:" + "0" * 64},
            {"evidence_cas": self.cas},
        ):
            with (
                self.subTest(overrides=tuple(overrides)),
                self.assertRaises(subject.NativePluginUpdateCollectionError),
            ):
                self.replay(result["collection_digest"], **overrides)

    def test_dangling_children_are_not_complete_collections(self):
        result = self.collect()
        manifest = result["collection"]
        references = [
            manifest[name]
            for name in ("capture", "source", "deployment", "verification")
        ]
        references.extend(manifest["identity_artifacts"].values())
        for omitted in (references[0], references[3], references[-1]):
            with (
                self.subTest(omitted=omitted["digest"]),
                tempfile.TemporaryDirectory() as directory,
            ):
                partial = CAS(Path(directory) / "cas")
                for reference in references:
                    if reference != omitted:
                        raw = self.readonly.read(
                            reference["digest"], max_bytes=2 * 1024 * 1024
                        )
                        partial.put_expected(
                            BytesIO(raw),
                            expected_digest=reference["digest"],
                            max_bytes=len(raw),
                        )
                raw = canonical_json(manifest)
                partial.put_expected(
                    BytesIO(raw),
                    expected_digest=result["collection_digest"],
                    max_bytes=len(raw),
                )
                with self.assertRaises(subject.NativePluginUpdateCollectionError):
                    self.replay(
                        result["collection_digest"],
                        evidence_cas=CAS(partial.root, read_only=True),
                    )

    def test_retained_verifier_verdict_is_recomputed_not_trusted(self):
        result = self.collect()
        manifest = json.loads(canonical_json(result["collection"]))
        forged = {**result["verification"], "route_qualified": True}
        raw = canonical_json(forged)
        manifest["verification"] = {
            "bytes": len(raw),
            "digest": self.cas.put(BytesIO(raw), max_bytes=len(raw)),
        }
        raw = canonical_json(manifest)
        digest = self.cas.put(BytesIO(raw), max_bytes=len(raw))
        with self.assertRaises(subject.NativePluginUpdateCollectionError):
            self.replay(digest)

    def test_missing_limits_and_mixed_references_refuse_even_after_repinning(self):
        result = self.collect()
        for mutate in (
            lambda value: value.update(limitations=[]),
            lambda value: value.update(phase3_eligible=True),
            lambda value: value["identity_artifacts"].pop("policy"),
            lambda value: value["identity_artifacts"].update(
                policy=value["identity_artifacts"]["worker"]
            ),
            lambda value: value["capture"].update(bytes=value["capture"]["bytes"] + 1),
        ):
            value = json.loads(canonical_json(result["collection"]))
            mutate(value)
            raw = canonical_json(value)
            digest = self.cas.put(BytesIO(raw), max_bytes=len(raw))
            with (
                self.subTest(mutation=mutate),
                self.assertRaises(subject.NativePluginUpdateCollectionError),
            ):
                self.replay(digest)

    def test_partial_retention_failure_publishes_no_collection_success(self):
        original = CAS.put_expected

        def fail_verification(store, source, **kwargs):
            document = json.loads(source.getvalue())
            if (
                document.get("schema")
                == "aragorn/native-phase3-plugin-update-binding/v1"
            ):
                raise CASError("inert retention failure")
            return original(store, source, **kwargs)

        with (
            patch.object(CAS, "put_expected", fail_verification),
            self.assertRaises(subject.NativePluginUpdateCollectionError),
        ):
            self.collect()
        for path in (self.cas.root / "blobs" / "sha256").rglob("*"):
            if path.is_file():
                value = json.loads(path.read_bytes())
                self.assertNotEqual(value.get("schema"), subject.SCHEMA)

    def live_inputs(self):
        capture = json.loads(self.raw)
        sources = live_fixture._fixture(capture)
        raw = canonical_json(capture) + b"\n"
        base_pins = {**self.pins, "expected_capture_digest": _digest(raw)}
        prepared = subject.prepare_native_plugin_update_collection(raw, **base_pins)
        static_raw = canonical_json(capture["live_identity"]["static_pin_manifest"])
        pins = {
            **base_pins,
            "expected_deployment_digest": prepared["deployment_digest"],
            "expected_live_identity_digest": _digest(
                canonical_json(capture["live_identity"])
            ),
            "expected_static_pin_manifest_digest": _digest(static_raw),
            "expected_live_source_digests": {
                path: _digest(value) for path, value in sources.items()
            },
        }
        inputs = {
            "deployment_raw": prepared["deployment_raw"],
            "static_pin_manifest_raw": static_raw,
            "live_source_raws": sources,
        }
        return raw, pins, inputs

    def test_live_collection_reuses_original_manifest_and_replays_without_writes(self):
        raw, pins, inputs = self.live_inputs()
        retained = subject.collect_native_plugin_update_live_observation(
            raw, **pins, **inputs, evidence_cas=self.cas
        )
        manifest = retained["collection"]
        self.assertEqual(manifest["schema"], subject.LIVE_SCHEMA)
        self.assertTrue(
            all(manifest[name] is False for name in subject._LIVE_FALSE_FLAGS)
        )
        original = json.loads(
            self.readonly.read(manifest["reported_collection"]["digest"])
        )
        self.assertEqual(original["schema"], subject.SCHEMA)
        self.assertNotIn("live_sources", original)
        self.assertEqual(self.readonly.read(original["capture"]["digest"]), raw)
        before = self.inventory()
        with patch.object(
            CAS, "put_expected", side_effect=AssertionError("live replay wrote")
        ):
            replayed = subject.replay_native_plugin_update_live_collection(
                expected_collection_digest=retained["collection_digest"],
                **pins,
                evidence_cas=self.readonly,
            )
        self.assertEqual(replayed, retained)
        self.assertEqual(before, self.inventory())
        self.assertEqual(
            retained["verification"]["live_deployment_dimensions_verified"], []
        )
        self.assertFalse(retained["verification"]["metrics_eligible"])

    def test_live_wrong_pins_missing_children_and_forged_verdict_refuse(self):
        raw, pins, inputs = self.live_inputs()
        before = self.inventory()
        for override in (
            {"expected_live_identity_digest": "sha256:" + "0" * 64},
            {"expected_static_pin_manifest_digest": "sha256:" + "0" * 64},
            {"expected_live_source_digests": {}},
            {
                "live_source_raws": {
                    **inputs["live_source_raws"],
                    subject.live_binding.SOURCE_PATHS[0]: b"wrong",
                }
            },
        ):
            with (
                self.subTest(override=tuple(override)),
                self.assertRaises(subject.NativePluginUpdateCollectionError),
            ):
                subject.collect_native_plugin_update_live_observation(
                    raw, **{**pins, **inputs, **override}, evidence_cas=self.cas
                )
            self.assertEqual(before, self.inventory())
        retained = subject.collect_native_plugin_update_live_observation(
            raw, **pins, **inputs, evidence_cas=self.cas
        )
        original_read = CAS.read
        references = (
            retained["collection"]["reported_collection"]["digest"],
            retained["collection"]["live_identity"]["digest"],
            pins["expected_static_pin_manifest_digest"],
            *pins["expected_live_source_digests"].values(),
        )
        for missing in references:

            def read(store, digest, *, max_bytes=None):
                if digest == missing:
                    raise CASError("inert missing live child")
                return original_read(store, digest, max_bytes=max_bytes)

            with (
                self.subTest(missing=missing),
                patch.object(CAS, "read", read),
                self.assertRaises(subject.NativePluginUpdateCollectionError),
            ):
                subject.replay_native_plugin_update_live_collection(
                    expected_collection_digest=retained["collection_digest"],
                    **pins,
                    evidence_cas=self.readonly,
                )
        forged = json.loads(canonical_json(retained["collection"]))
        verification_raw = canonical_json(
            {**retained["verification"], "route_qualified": True}
        )
        forged["verification"] = {
            "digest": self.cas.put(
                BytesIO(verification_raw), max_bytes=len(verification_raw)
            ),
            "bytes": len(verification_raw),
        }
        forged_raw = canonical_json(forged)
        forged_pin = self.cas.put(BytesIO(forged_raw), max_bytes=len(forged_raw))
        with self.assertRaises(subject.NativePluginUpdateCollectionError):
            subject.replay_native_plugin_update_live_collection(
                expected_collection_digest=forged_pin,
                **pins,
                evidence_cas=self.readonly,
            )
        with (
            patch.object(
                subject.live_binding,
                "verify_native_plugin_update_live_binding",
                side_effect=ValueError("inert semantic refusal"),
            ),
            self.assertRaises(subject.NativePluginUpdateCollectionError),
        ):
            subject.collect_native_plugin_update_live_observation(
                raw, **pins, **inputs, evidence_cas=self.cas
            )


if __name__ == "__main__":
    unittest.main()
