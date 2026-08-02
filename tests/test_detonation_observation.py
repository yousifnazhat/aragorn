from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest import mock

from aragorn.behavior_capability_diff import (
    CAPABILITY_KINDS,
    derive_behavior_capability_diff,
)
from aragorn.cas import CAS
from aragorn.detonation_observation import (
    AUTHORITY,
    DIFF_RECEIPT_AUTHORITY,
    DIFF_RECEIPT_SCHEMA,
    MAX_SOURCE_EVENT_BYTES,
    SOURCE_OPERATIONS,
    SOURCE_SCHEMA,
    DetonationObservationError,
    derive_detonation_capability_diff_closure,
    observed_capabilities,
    retain_detonation_capability_diff,
    retain_detonation_observation,
    verify_detonation_capability_diff,
    verify_detonation_observation,
)
from aragorn.oci_worker_protocol import canonical_json

_SUBJECT = "sha256:" + "1" * 64
_MANIFEST = "sha256:" + "2" * 64
_TREE = "sha256:" + "3" * 64
_REQUEST = "sha256:" + "4" * 64
_NORMALIZER = "sha256:" + "5" * 64


def _retain_sources(
    cas: CAS,
) -> tuple[
    tuple[bytes, ...],
    tuple[str, ...],
    tuple[str, ...],
    dict[str, str],
    dict[str, str],
]:
    sources = (
        canonical_json(
            {
                "schema": SOURCE_SCHEMA,
                "operation": "file-open-read",
                "detail": "read /canary/token",
            }
        ),
        canonical_json(
            {
                "schema": SOURCE_SCHEMA,
                "operation": "network-connect",
                "detail": "connect 192.0.2.1:443",
            }
        ),
    )
    source_digests = tuple(
        "sha256:" + hashlib.sha256(source).hexdigest() for source in sources
    )
    common = {
        "subject_digest": _SUBJECT,
        "input_manifest_digest": _MANIFEST,
        "input_tree_digest": _TREE,
        "run_request_digest": _REQUEST,
        "normalizer_implementation_digest": _NORMALIZER,
    }
    observation_digests = tuple(
        retain_detonation_observation(cas, source, **common) for source in sources
    )
    bindings = dict(zip(observation_digests, source_digests, strict=True))
    return sources, source_digests, observation_digests, bindings, common


class DetonationObservationTests(unittest.TestCase):
    def test_retains_replays_and_rejects_source_or_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cas"
            cas = CAS(root)
            sources, source_digests, observation_digests, bindings, common = (
                _retain_sources(cas)
            )

            categories = observed_capabilities(
                cas,
                bindings,
                expected_subject_digest=_SUBJECT,
                expected_input_manifest_digest=_MANIFEST,
                expected_input_tree_digest=_TREE,
                expected_run_request_digest=_REQUEST,
                expected_normalizer_implementation_digest=_NORMALIZER,
            )
            self.assertEqual(categories, ("file-read", "network-connect"))
            mutated_bindings = dict(bindings)
            original_read = cas.read

            def mutate_after_snapshot(*args: object, **kwargs: object) -> bytes:
                mutated_bindings[observation_digests[0]] = "sha256:" + "6" * 64
                return original_read(*args, **kwargs)

            with mock.patch.object(cas, "read", side_effect=mutate_after_snapshot):
                self.assertEqual(
                    observed_capabilities(
                        cas,
                        mutated_bindings,
                        expected_subject_digest=_SUBJECT,
                        expected_input_manifest_digest=_MANIFEST,
                        expected_input_tree_digest=_TREE,
                        expected_run_request_digest=_REQUEST,
                        expected_normalizer_implementation_digest=_NORMALIZER,
                    ),
                    categories,
                )
            capability_diff = derive_behavior_capability_diff(
                subject_digest=_SUBJECT,
                declared_capabilities=["file-read"],
                observed_capabilities=categories,
            )
            self.assertEqual(
                capability_diff["undeclared_observed_capabilities"],
                ["network-connect"],
            )

            verified = verify_detonation_observation(
                cas,
                observation_digests[0],
                expected_subject_digest=_SUBJECT,
                expected_input_manifest_digest=_MANIFEST,
                expected_input_tree_digest=_TREE,
                expected_run_request_digest=_REQUEST,
                expected_normalizer_implementation_digest=_NORMALIZER,
                expected_source_event_digest=source_digests[0],
            )
            self.assertEqual(verified["authority"], AUTHORITY)
            self.assertNotIn("read /canary/token", canonical_json(verified).decode())

            substitutions = {
                "expected_subject_digest": "sha256:" + "6" * 64,
                "expected_input_manifest_digest": "sha256:" + "6" * 64,
                "expected_input_tree_digest": "sha256:" + "6" * 64,
                "expected_run_request_digest": "sha256:" + "6" * 64,
                "expected_normalizer_implementation_digest": "sha256:" + "6" * 64,
                "expected_source_event_digest": "sha256:" + "6" * 64,
            }
            expected = {
                "expected_subject_digest": _SUBJECT,
                "expected_input_manifest_digest": _MANIFEST,
                "expected_input_tree_digest": _TREE,
                "expected_run_request_digest": _REQUEST,
                "expected_normalizer_implementation_digest": _NORMALIZER,
                "expected_source_event_digest": source_digests[0],
            }
            for field, substituted in substitutions.items():
                with (
                    self.subTest(field=field),
                    self.assertRaises(DetonationObservationError),
                ):
                    verify_detonation_observation(
                        cas,
                        observation_digests[0],
                        **(expected | {field: substituted}),
                    )

            original = json.loads(cas.read(observation_digests[0]))
            for label, changed in (
                ("authority", {**original, "authority": "EXECUTION_AUTHORITY"}),
                ("capability", {**original, "capability": "socket-open"}),
                (
                    "supported capability substitution",
                    {**original, "capability": "network-connect"},
                ),
                ("extra field", {**original, "unexpected": True}),
            ):
                forged = cas.put(BytesIO(canonical_json(changed)), max_bytes=16 * 1024)
                with (
                    self.subTest(label=label),
                    self.assertRaises(DetonationObservationError),
                ):
                    verify_detonation_observation(cas, forged, **expected)

            noncanonical = cas.put(
                BytesIO(b" " + cas.read(observation_digests[0])),
                max_bytes=16 * 1024,
            )
            with self.assertRaises(DetonationObservationError):
                verify_detonation_observation(cas, noncanonical, **expected)

            with self.assertRaises(DetonationObservationError):
                retain_detonation_observation(cas, b"", **common)
            with self.assertRaises(DetonationObservationError):
                retain_detonation_observation(
                    cas,
                    b"x" * (MAX_SOURCE_EVENT_BYTES + 1),
                    **common,
                )
            for label, source in (
                (
                    "unknown operation",
                    canonical_json(
                        {
                            "schema": SOURCE_SCHEMA,
                            "operation": "socket-open",
                            "detail": "unknown",
                        }
                    ),
                ),
                ("noncanonical", b" " + sources[0]),
                ("truncated", sources[0][:-1]),
            ):
                with (
                    self.subTest(source=label),
                    self.assertRaises(DetonationObservationError),
                ):
                    retain_detonation_observation(cas, source, **common)
            with self.assertRaises(DetonationObservationError):
                observed_capabilities(
                    cas,
                    {
                        observation_digests[0]: source_digests[0],
                        observation_digests[1]: source_digests[0],
                    },
                    expected_subject_digest=_SUBJECT,
                    expected_input_manifest_digest=_MANIFEST,
                    expected_input_tree_digest=_TREE,
                    expected_run_request_digest=_REQUEST,
                    expected_normalizer_implementation_digest=_NORMALIZER,
                )
            with self.assertRaises(DetonationObservationError):
                observed_capabilities(
                    cas,
                    {observation_digests[0]: 1},
                    expected_subject_digest=_SUBJECT,
                    expected_input_manifest_digest=_MANIFEST,
                    expected_input_tree_digest=_TREE,
                    expected_run_request_digest=_REQUEST,
                    expected_normalizer_implementation_digest=_NORMALIZER,
                )

            source_hex = source_digests[0].removeprefix("sha256:")
            source_blob = root / "blobs" / "sha256" / source_hex[:2] / source_hex[2:]
            source_blob.chmod(0o600)
            source_blob.write_bytes(b"tampered")
            with self.assertRaisesRegex(DetonationObservationError, "digest"):
                verify_detonation_observation(cas, observation_digests[0], **expected)

        schema = json.loads(
            (
                Path(__file__).parents[1]
                / "schema"
                / "detonation-observation-v1.schema.json"
            ).read_text()
        )
        self.assertEqual(
            schema["properties"]["capability"]["enum"],
            sorted(CAPABILITY_KINDS),
        )
        source_schema = json.loads(
            (
                Path(__file__).parents[1]
                / "schema"
                / "detonation-source-event-v1.schema.json"
            ).read_text()
        )
        self.assertEqual(
            source_schema["properties"]["operation"]["enum"],
            sorted(SOURCE_OPERATIONS),
        )
        self.assertEqual(set(SOURCE_OPERATIONS.values()), CAPABILITY_KINDS)

    def test_retains_and_replays_selected_observation_set_diff_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            _, source_digests, observation_digests, bindings, common = _retain_sources(
                cas
            )
            receipt_digest = retain_detonation_capability_diff(
                cas,
                bindings,
                declared_capabilities=["file-read"],
                **common,
            )
            expected = {
                "expected_observations": bindings,
                "expected_subject_digest": _SUBJECT,
                "expected_input_manifest_digest": _MANIFEST,
                "expected_input_tree_digest": _TREE,
                "expected_run_request_digest": _REQUEST,
                "expected_normalizer_implementation_digest": _NORMALIZER,
                "expected_declared_capabilities": ["file-read"],
            }
            receipt = verify_detonation_capability_diff(cas, receipt_digest, **expected)
            self.assertEqual(receipt["schema"], DIFF_RECEIPT_SCHEMA)
            self.assertEqual(receipt["authority"], DIFF_RECEIPT_AUTHORITY)
            capability_diff = json.loads(cas.read(receipt["capability_diff_digest"]))
            self.assertEqual(
                capability_diff["undeclared_observed_capabilities"],
                ["network-connect"],
            )

            reordered = dict(reversed(tuple(bindings.items())))
            self.assertEqual(
                retain_detonation_capability_diff(
                    cas,
                    reordered,
                    declared_capabilities=["file-read"],
                    **common,
                ),
                receipt_digest,
            )
            closure = derive_detonation_capability_diff_closure(
                cas, receipt_digest, **expected
            )
            self.assertEqual(
                set(closure),
                {
                    receipt_digest,
                    receipt["capability_diff_digest"],
                    *observation_digests,
                    *source_digests,
                },
            )
            self.assertTrue(all(size > 0 for size in closure.values()))

            substitutions = {
                "expected_subject_digest": "sha256:" + "6" * 64,
                "expected_input_manifest_digest": "sha256:" + "6" * 64,
                "expected_input_tree_digest": "sha256:" + "6" * 64,
                "expected_run_request_digest": "sha256:" + "6" * 64,
                "expected_normalizer_implementation_digest": ("sha256:" + "6" * 64),
                "expected_declared_capabilities": ["network-connect"],
                "expected_observations": {observation_digests[0]: source_digests[0]},
            }
            for field, substituted in substitutions.items():
                with (
                    self.subTest(field=field),
                    self.assertRaises(DetonationObservationError),
                ):
                    verify_detonation_capability_diff(
                        cas,
                        receipt_digest,
                        **(expected | {field: substituted}),
                    )

            original = json.loads(cas.read(receipt_digest))
            wrong_diff = derive_behavior_capability_diff(
                subject_digest=_SUBJECT,
                declared_capabilities=["file-read"],
                observed_capabilities=["file-read"],
            )
            wrong_diff_digest = cas.put(
                BytesIO(canonical_json(wrong_diff)), max_bytes=16 * 1024
            )
            reversed_bindings = deepcopy(original)
            reversed_bindings["observation_bindings"].reverse()
            duplicate_source = deepcopy(original)
            duplicate_source["observation_bindings"][1]["source_event_digest"] = (
                duplicate_source["observation_bindings"][0]["source_event_digest"]
            )
            for label, changed in (
                (
                    "authority",
                    {**original, "authority": "EXECUTION_AUTHORITY"},
                ),
                ("noncanonical bindings", reversed_bindings),
                ("duplicate source binding", duplicate_source),
                (
                    "substituted diff",
                    {**original, "capability_diff_digest": wrong_diff_digest},
                ),
                ("extra field", {**original, "unexpected": True}),
            ):
                forged = cas.put(
                    BytesIO(canonical_json(changed)), max_bytes=2 * 1024 * 1024
                )
                with (
                    self.subTest(label=label),
                    self.assertRaises(DetonationObservationError),
                ):
                    verify_detonation_capability_diff(cas, forged, **expected)

            noncanonical = cas.put(
                BytesIO(b" " + cas.read(receipt_digest)),
                max_bytes=2 * 1024 * 1024,
            )
            with self.assertRaises(DetonationObservationError):
                verify_detonation_capability_diff(cas, noncanonical, **expected)


if __name__ == "__main__":
    unittest.main()
