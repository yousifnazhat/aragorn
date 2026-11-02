"""Replay fixed retained data, never the inert verifier or its crypto operations."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
NAME = "tetragon-release-signature-crypto-check-v1-2026-09-13"
REFERENCE = f"benchmark/evidence/reference/{NAME}.py.txt"
ARTIFACT_PIN = (
    38078,
    "14caa02dd3ba3ed75dca40eab9ab42627f340ad773ad0c6ffe211af888b54d00",
)
REFERENCE_PIN = (
    14983,
    "139f0d0d13ad397c615251597904c8e2c11b83ef8a6a32374b74d35f10f6a3ff",
)
ENVELOPE_PIN = (
    29942,
    "599c6c4a36197120e1bb2a0a59ff3e36ea9b08a7e0c212ae8ec2c1794d5cf25c",
)
RESULT_PIN = (
    3529,
    "8b94e11b5ada2658a3274ef9c4798d8bc43499f9985c98b1ccb8d8108e6470c0",
)
INPUT_PINS = {
    "index": (685, "deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527"),
    "arm64": (2865, "1bffeee60f1d47e367d237129e576729d14fe8db748440328aded8a6091c4a40"),
    "signature_manifest": (
        9788,
        "86a0fc2a5e68091290b2f9d3c4e0f4deeb6b2f6c64fc07412fef39e00725b3c8",
    ),
    "payload": (
        239,
        "e69040a93af2e2b1934c926afca94f4265a760296de7ae1b7c21021ce25fed58",
    ),
    "trust": (6787, "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"),
    "rekor_entry": (
        7692,
        "646b7cab614c280db46b60974f544142005d1c77a763f210ff969a9cc449bd85",
    ),
}
LIMITS = {
    "tuf_verification",
    "cosign_equivalence",
    "build_reproduction",
    "executed_binary_binding",
    "tool_binary_identity_verified",
    "global_to_shard_offset_independently_verified",
    "global_log_consistency_verified",
    "ct_log_inclusion_beyond_sct_verified",
    "independent_crypto_rerun_by_retention_test",
    "verifier_execution_attested",
    "phase3_eligible",
    "run_conformance_eligible",
    "production_activation_eligible",
    "general_release_qualification",
}


def _need(condition: bool) -> None:
    if not condition:
        raise ValueError("retained signature-check pin, join, or ceiling mismatch")


def _pin(raw: bytes, pin: tuple[int, str]) -> None:
    _need(type(raw) is bytes and len(raw) == pin[0])
    _need(hashlib.sha256(raw).hexdigest() == pin[1])


def _read(path: Path, pin: tuple[int, str]) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(pin[0] + 1)
    _pin(raw, pin)
    return raw


def _load(raw: bytes, reference: bytes) -> dict:
    # Both fixed artifacts are pinned before the first JSON parse.
    _pin(raw, ARTIFACT_PIN)
    _pin(reference, REFERENCE_PIN)
    document = json.loads(raw)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    _need(raw == canonical + b"\n")
    return document


def _embedded(value: dict, pin: tuple[int, str]) -> dict:
    _need(type(value["bytes"]) is int and value["bytes"] == pin[0])
    _need(value["digest"] == "sha256:" + pin[1])
    _need(type(value["raw"]) is str)
    raw = value["raw"].encode()
    _pin(raw, pin)
    return json.loads(raw)


def _replay(document: dict, reference: bytes) -> None:
    _pin(reference, REFERENCE_PIN)
    _need(
        document["schema"]
        == "aragorn/tetragon-release-signature-crypto-check-retention/v1"
    )
    _need(document["status"] == "OBSERVED")
    _need(
        document["authority"]
        == "RETAINED_FIXED_CRYPTO_CHECK_WITH_EXPLICIT_HTTPS_TRUST_NOT_GENERAL_RELEASE_OR_RUN_AUTHORITY"
    )
    _need(set(document["proof_limits"]) == LIMITS)
    _need(all(value is False for value in document["proof_limits"].values()))
    _need(
        document["local_verifier_reference"]
        == {
            "path": REFERENCE,
            "bytes": REFERENCE_PIN[0],
            "digest": "sha256:" + REFERENCE_PIN[1],
            "execution_attested_by_reference": False,
        }
    )
    _need(
        document["local_verifier_reference"]["execution_attested_by_reference"] is False
    )
    inputs = _embedded(document["public_inputs_envelope"], ENVELOPE_PIN)
    result = _embedded(document["observed_result"], RESULT_PIN)
    _need(set(inputs) == set(result["input_pins"]) == set(INPUT_PINS))
    parsed = {}
    for name, pin in INPUT_PINS.items():
        item = inputs[name]
        _need(set(item) == {"url", "raw"})
        _pin(item["raw"].encode(), pin)
        _need(
            result["input_pins"][name]
            == {"bytes": pin[0], "digest": "sha256:" + pin[1], "url": item["url"]}
        )
        parsed[name] = json.loads(item["raw"])

    index_digest = "sha256:" + INPUT_PINS["index"][1]
    arm_digest = "sha256:" + INPUT_PINS["arm64"][1]
    _need(
        result["image_index"] == index_digest and result["arm64_manifest"] == arm_digest
    )
    arm = [
        x
        for x in parsed["index"]["manifests"]
        if x["platform"]["architecture"] == "arm64"
    ]
    _need(len(arm) == 1)
    _need(arm[0]["digest"] == arm_digest and arm[0]["size"] == INPUT_PINS["arm64"][0])
    _need(arm[0]["platform"] == {"architecture": "arm64", "os": "linux"})
    _need(
        parsed["payload"]
        == {
            "critical": {
                "identity": {"docker-reference": "quay.io/cilium/tetragon"},
                "image": {"docker-manifest-digest": index_digest},
                "type": "cosign container image signature",
            },
            "optional": None,
        }
    )
    layers = parsed["signature_manifest"]["layers"]
    _need(len(layers) == 1)
    _need(layers[0]["digest"] == "sha256:" + INPUT_PINS["payload"][1])
    _need(layers[0]["size"] == INPUT_PINS["payload"][0])
    annotations = layers[0]["annotations"]
    bundle = json.loads(annotations["dev.sigstore.cosign/bundle"])
    entries = parsed["rekor_entry"]
    _need(len(entries) == 1)
    entry = next(iter(entries.values()))
    signed = bundle["Payload"]
    _need(
        all(
            entry[key] == signed[key]
            for key in ("body", "integratedTime", "logIndex", "logID")
        )
    )
    record = json.loads(base64.b64decode(signed["body"], validate=True))
    _need(record["kind"] == "hashedrekord" and record["apiVersion"] == "0.0.1")
    _need(
        record["spec"]["data"]["hash"]
        == {"algorithm": "sha256", "value": INPUT_PINS["payload"][1]}
    )
    signature = record["spec"]["signature"]
    _need(signature["content"] == annotations["dev.cosignproject.cosign/signature"])
    _need(
        base64.b64decode(signature["publicKey"]["content"], validate=True).strip()
        == annotations["dev.sigstore.cosign/certificate"].encode().strip()
    )
    proof = entry["verification"]["inclusionProof"]
    _need(
        result["rekor_indices"]
        == {
            "signed_global_log_index": signed["logIndex"],
            "checkpoint_shard_local_leaf_index": proof["logIndex"],
            "global_to_shard_offset_independently_verified": False,
            "binding": "IDENTICAL_BODY_HASH_VERIFIED_IN_SIGNED_SET_AND_CHECKPOINT_TREE",
        }
    )
    _need(signed["logIndex"] == 1401688071 and proof["logIndex"] == 1279783809)
    _need(
        result["rekor_indices"]["global_to_shard_offset_independently_verified"]
        is False
    )
    checkpoint = proof["checkpoint"].splitlines()
    _need(checkpoint[0] == "rekor.sigstore.dev - 1193050959916656506")
    _need(int(checkpoint[1]) == proof["treeSize"] == 2694761933)
    _need(base64.b64decode(checkpoint[2], validate=True).hex() == proof["rootHash"])

    # These are retained reports. This test does not verify signatures or trust.
    _need(
        result["status"]
        == "CRYPTOGRAPHIC_CHECKS_PASSED_WITH_EXPLICIT_HTTPS_TRUST_SNAPSHOT"
    )
    _need(
        all(
            result[key] is True
            for key in (
                "chain",
                "payload_signature",
                "rekor_set",
                "sct",
                "rekor_checkpoint",
                "rekor_inclusion",
            )
        )
    )
    _need(
        all(
            result[key] is False
            for key in (
                "tuf_verification",
                "cosign_equivalence",
                "build_reproduction",
                "executed_binary_binding",
                "run_or_phase3_qualification",
            )
        )
    )
    _need(result["integrated_time"] == signed["integratedTime"] == 1777471230)
    _need(result["oidc_issuer"] == "https://token.actions.githubusercontent.com")
    _need(
        result["signer_identity"]
        == "https://github.com/cilium/tetragon/.github/workflows/build-images-releases.yml@refs/tags/v1.7.0"
    )
    openssl = result["local_openssl"]
    _need(openssl["tool_binary_identity_verified"] is False)
    _need(openssl["version_argv"] == ["/opt/homebrew/bin/openssl", "version"])
    _need(openssl["version_exit_code"] == openssl["verify_exit_code"] == 0)
    _need(openssl["version_stderr"] == openssl["verify_stderr"] == "")
    _need(
        openssl["version_stdout"]
        == "OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)\n"
    )
    pem_root = "/private/tmp/aragorn-tetragon-signature.OvzCHNBk/"
    _need(
        openssl["verify_argv"]
        == [
            "/opt/homebrew/bin/openssl",
            "verify",
            "-x509_strict",
            "-purpose",
            "any",
            "-attime",
            "1777471230",
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
            pem_root + "root.pem",
            "-untrusted",
            pem_root + "intermediate.pem",
            pem_root + "leaf.pem",
        ]
    )
    _need(openssl["verify_stdout"] == pem_root + "leaf.pem: OK\n")
    provenance = document["source_provenance"]
    _need(
        provenance["github_release_source_commit"]
        == "1de2ed8ebea18e56257dc59597aa13bf8f0e471e"
    )
    _need(
        provenance["github_workflow_source"]
        == "https://raw.githubusercontent.com/cilium/tetragon/v1.7.0/.github/workflows/build-images-releases.yml"
    )
    _need(
        provenance["trust_bootstrap"]
        == "OFFICIAL_SIGSTORE_ROOT_SIGNING_COMMIT_FETCHED_OVER_HTTPS_NOT_TUF_UPDATE_VERIFICATION"
    )
    # The older file has its own fixed replay test; this is only its provenance link.
    _need(
        provenance["older_os_smoke"]
        == {
            "path": "benchmark/evidence/tetragon-isolated-exec-exit-smoke-v1-2026-09-13.json",
            "bytes": 189925,
            "digest": "sha256:3f64362ab12391e5d44c7ce781e4963c8b37262707ec89095d83e719d1bf17de",
            "image": "quay.io/cilium/tetragon@" + arm_digest,
            "artifact_modified": False,
            "release_signature_flag_in_older_artifact": False,
        }
    )
    _need(provenance["older_os_smoke"]["artifact_modified"] is False)
    _need(
        provenance["older_os_smoke"]["release_signature_flag_in_older_artifact"]
        is False
    )


class RetainedSignatureCheckTests(unittest.TestCase):
    def test_fixed_replay_and_tampering(self) -> None:
        raw = _read(ROOT / f"benchmark/evidence/{NAME}.json", ARTIFACT_PIN)
        reference = _read(ROOT / REFERENCE, REFERENCE_PIN)
        document = _load(raw, reference)
        _replay(document, reference)
        for label, candidate, source in (
            ("artifact", raw[:-1] + b" ", reference),
            ("reference", raw, reference[:-1] + b" "),
            ("oversized", raw + b" ", reference),
        ):
            with self.subTest(label=label), patch.object(json, "loads") as parser:
                with self.assertRaises(ValueError):
                    _load(candidate, source)
                parser.assert_not_called()
        for flag in LIMITS:
            altered = copy.deepcopy(document)
            altered["proof_limits"][flag] = True
            with self.subTest(limit=flag), self.assertRaises(ValueError):
                _replay(altered, reference)
        for field in ("public_inputs_envelope", "observed_result"):
            altered = copy.deepcopy(document)
            altered[field]["raw"] += " "
            with self.subTest(raw=field), self.assertRaises(ValueError):
                _replay(altered, reference)
        for label, container, key, value in (
            ("smoke-link", "older_os_smoke", "digest", "sha256:" + "0" * 64),
            (
                "old-claim",
                "older_os_smoke",
                "release_signature_flag_in_older_artifact",
                True,
            ),
        ):
            altered = copy.deepcopy(document)
            altered["source_provenance"][container][key] = value
            with self.subTest(label=label), self.assertRaises(ValueError):
                _replay(altered, reference)


if __name__ == "__main__":
    unittest.main()
