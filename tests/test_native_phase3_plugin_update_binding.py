"""Only the new read-only F0 seam; never execute a retained capture or old suite."""

import hashlib
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from aragorn import native_phase3_plugin_update_binding as subject
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase3_deployment import build_phase3_deployment_identity

_EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "benchmark/evidence/phase3-native-plugin-update-systemd-development-v2-2026-10-01.json"
)
_CAPTURE_PIN = "sha256:42acdf26c128c4d7ecdfd740ac04b17509e9e17e0b799e7d4a870bf5e82a9e12"


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class NativePluginUpdateBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = _EVIDENCE.read_bytes()
        if _digest(cls.raw) != _CAPTURE_PIN:
            raise AssertionError("immutable plugin-update observation changed")
        cls.capture = json.loads(cls.raw)
        cls.source_pin = _digest(canonical_json(cls.capture["source"]))
        cls.source_commit = cls.capture["source"]["commit"]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(Path(self.temporary.name) / "cas")
        artifacts = subject.native_plugin_update_identity_artifacts(
            self.raw,
            expected_capture_digest=_CAPTURE_PIN,
            expected_source_digest=self.source_pin,
            expected_source_commit=self.source_commit,
        )
        bindings = {
            name: self.cas.put(BytesIO(raw), max_bytes=1024 * 1024)
            for name, raw in artifacts.items()
        }
        self.deployment = build_phase3_deployment_identity(bindings)
        self.deployment_raw = canonical_json(self.deployment)
        self.read_only = CAS(self.cas.root, read_only=True)

    def verify(self, raw=None, **overrides):
        raw = self.raw if raw is None else raw
        kwargs = {
            "expected_capture_digest": _digest(raw),
            "expected_source_digest": self.source_pin,
            "expected_source_commit": self.source_commit,
            "deployment_raw": self.deployment_raw,
            "expected_deployment_digest": _digest(self.deployment_raw),
            "evidence_cas": self.read_only,
        }
        kwargs.update(overrides)
        return subject.verify_native_plugin_update_binding(raw, **kwargs)

    def test_real_retained_observation_joins_seven_dimensions_without_qualification(
        self,
    ):
        before = sorted(
            str(path.relative_to(self.cas.root)) for path in self.cas.root.rglob("*")
        )
        result = self.verify()
        self.assertEqual(result["status"], "BOUNDED_OBSERVATION_VERIFIED")
        self.assertEqual(len(result["reported_deployment_dimensions_verified"]), 7)
        self.assertFalse(result["common_deployment_fully_verified"])
        self.assertFalse(result["route_qualified"])
        self.assertFalse(result["phase3_eligible"])
        self.assertEqual(result["live_deployment_dimensions_verified"], [])
        self.assertEqual(
            before,
            sorted(
                str(path.relative_to(self.cas.root))
                for path in self.cas.root.rglob("*")
            ),
        )

    def test_all_caller_pins_and_read_only_cas_are_required(self):
        for override in (
            {"expected_capture_digest": "sha256:" + "0" * 64},
            {"expected_source_digest": "sha256:" + "0" * 64},
            {"expected_source_commit": "0" * 40},
            {"expected_deployment_digest": "sha256:" + "0" * 64},
            {"evidence_cas": self.cas},
        ):
            with (
                self.subTest(override=tuple(override)),
                self.assertRaises(subject.NativePluginUpdateBindingError),
            ):
                self.verify(**override)

    def test_each_mixed_deployment_dimension_is_rejected(self):
        for dimension in self.deployment["bindings"]:
            changed = json.loads(self.deployment_raw)
            changed["bindings"][dimension] = self.cas.put(
                BytesIO(b"unrelated identity"), max_bytes=64
            )
            raw = canonical_json(changed)
            with (
                self.subTest(dimension=dimension),
                self.assertRaises(subject.NativePluginUpdateBindingError),
            ):
                self.verify(deployment_raw=raw, expected_deployment_digest=_digest(raw))

    def test_mutated_semantics_rejected_even_when_envelope_digests_are_recomputed(self):
        mutations = (
            lambda c: c.update(status="REFUSED"),
            lambda c: c.update(branch="NPM_UPDATE"),
            lambda c: c["observation"]["plugin_update"]["document"]["action"][
                "commands"
            ][4]["argv"].__setitem__(3, "install"),
            lambda c: c["observation"]["plugin_update"]["document"]["action"][
                "commands"
            ][4].update(stdout_excerpt="denied\n"),
            lambda c: c["observation"]["plugin_update"]["document"]["action"][
                "commands"
            ][4].update(exit_code=0),
            lambda c: c["observation"]["plugin_update"]["document"][
                "explicit_policy_denial_observation"
            ]["tracked_records_after"].clear(),
            lambda c: c["observation"]["plugin_update"]["document"]["action"]["after"][
                "boundary"
            ]["config_lock"].update(exists=True),
            lambda c: c["observation"]["plugin_update"]["document"]["action"]["before"][
                "boundary"
            ].pop("state_store"),
            lambda c: c["observation"]["plugin_update"]["document"][
                "explicit_policy_denial_observation"
            ]["sqlite_file_delta"].update(logical_database_unchanged_verified=True),
            lambda c: c["observation"]["plugin_update"]["document"][
                "limitations"
            ].clear(),
            lambda c: c["cleanup"]["commands"][5].update(stdout="leftover\n"),
            lambda c: c["runtime_after"]["content"]["runtime_tree_after"].update(
                tree_digest="sha256:" + "0" * 64
            ),
            lambda c: c["observation"]["plugin_update"]["document"].update(
                implementation_digest="sha256:" + "0" * 64
            ),
        )
        for mutate in mutations:
            changed = json.loads(self.raw)
            mutate(changed)
            document_raw = (
                canonical_json(changed["observation"]["plugin_update"]["document"])
                + b"\n"
            )
            changed["observation"]["plugin_update"]["execution"].update(
                stdout_bytes=len(document_raw), stdout_digest=_digest(document_raw)
            )
            with (
                self.subTest(mutation=mutate),
                self.assertRaises(subject.NativePluginUpdateBindingError),
            ):
                self.verify(canonical_json(changed) + b"\n")

    def test_missing_dangling_or_noncanonical_inputs_refuse(self):
        for raw in (self.raw[:-1], b'{"status":1,"status":2}\n', b'{"x":NaN}\n'):
            with (
                self.subTest(raw=raw[:40]),
                self.assertRaises(subject.NativePluginUpdateBindingError),
            ):
                self.verify(raw)
        changed = json.loads(self.deployment_raw)
        changed["bindings"]["policy"] = "sha256:" + "0" * 64
        raw = canonical_json(changed)
        with self.assertRaises(subject.NativePluginUpdateBindingError):
            self.verify(deployment_raw=raw, expected_deployment_digest=_digest(raw))


if __name__ == "__main__":
    unittest.main()
