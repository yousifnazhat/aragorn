from __future__ import annotations

from copy import deepcopy
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import aragorn.worker_supervisor_v2 as worker_supervisor_v2
from aragorn.benchmark_authenticated_handoff_v2 import (
    collect_signed_worker_output,
    issue_worker_measurement_challenge,
)
from aragorn.benchmark_handoff_v2 import (
    build_worker_input_handoff_manifest,
    export_handoff,
    handoff_manifest_digest,
)
from aragorn.benchmark_semantic_closure_v2 import (
    derive_worker_input_cas_closure,
    derive_worker_output_cas_closure,
)
from aragorn.benchmark_worker_measurement import (
    build_worker_trust_store,
    generate_worker_signing_key,
    write_worker_trust_store,
)
from aragorn.cas import CAS, CASError
from aragorn.oci_worker import WorkerError
from tests import test_benchmark_semantic_closure_v2 as semantic_support


try:
    import cryptography  # noqa: F401
except ImportError:
    HAS_CRYPTOGRAPHY = False
else:
    HAS_CRYPTOGRAPHY = True


@unittest.skipUnless(
    HAS_CRYPTOGRAPHY,
    "locked cryptography worker dependency is not installed",
)
class WorkerSupervisorV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)

        self.evidence = semantic_support.BenchmarkSemanticClosureV2Tests()
        self.evidence.setUp()
        self.addCleanup(self.evidence.doCleanups)
        (
            self.result_digest,
            self.request_digest,
            self.result,
        ) = self.evidence._deep_output()
        self.challenge = "b" * 64
        self.worker_id = "isolated-worker-01"
        self.trust_domain = "phase0.example"

        input_manifest = build_worker_input_handoff_manifest(
            self.evidence.source,
            self.request_digest,
            expected_verifier_challenge=self.challenge,
        )
        self.input_bundle = self.root / "worker-input-bundle"
        self.input_manifest_digest = export_handoff(
            self.evidence.source,
            input_manifest,
            self.input_bundle,
            expected_verifier_challenge=self.challenge,
        )

        self.signing_key = self.root / "worker-signing.key"
        self.key = generate_worker_signing_key(
            self.signing_key,
            worker_id=self.worker_id,
        )
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.lock_path = (
            Path(__file__).resolve().parents[1]
            / "benchmark"
            / "baselines.lock.json"
        )

    def test_supervisor_imports_executes_exports_signs_and_collects(self) -> None:
        paths = self._supervisor_paths("success")
        ledger = self.root / "measurement-ledger"
        issue_worker_measurement_challenge(
            ledger,
            trust_domain=self.trust_domain,
            worker_id=self.worker_id,
            job_id=self.result["job_id"],
            request_digest=self.request_digest,
            verifier_challenge=self.challenge,
        )
        trust_store = build_worker_trust_store(
            trust_domain=self.trust_domain,
            keys=[self.key],
        )
        trust_store_path = self.root / "worker-trust-store.json"
        write_worker_trust_store(trust_store_path, trust_store)

        with mock.patch.object(
            worker_supervisor_v2,
            "run_worker_v2",
            side_effect=self._run_valid_worker,
        ) as runner:
            supervisor_result = worker_supervisor_v2.supervise(**paths)

        runner.assert_called_once()
        self.assertEqual(
            supervisor_result["schema"],
            "aragorn/benchmark-worker-supervisor-result/v1",
        )
        self.assertEqual(supervisor_result["request_digest"], self.request_digest)
        self.assertEqual(supervisor_result["result_digest"], self.result_digest)

        output_manifest = json.loads(
            (paths["output_bundle"] / "manifest.json").read_bytes()
        )
        expected_output = derive_worker_output_cas_closure(
            self.evidence.source,
            self.result_digest,
            expected_request_digest=self.request_digest,
            expected_challenge=self.challenge,
        )
        self.assertEqual(
            {
                item["digest"]: item["size"]
                for item in output_manifest["blobs"]
            },
            expected_output,
        )
        self.assertEqual(
            handoff_manifest_digest(output_manifest),
            supervisor_result["handoff_manifest_digest"],
        )

        envelope = paths["measurement_output"].read_bytes()
        self.assertEqual(
            stat.S_IMODE(paths["measurement_output"].stat().st_mode),
            0o400,
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(envelope).hexdigest(),
            supervisor_result["envelope_digest"],
        )

        destination = CAS(self.root / "control-cas")
        receipt = collect_signed_worker_output(
            paths["output_bundle"],
            destination,
            envelope,
            trust_store_path=trust_store_path,
            ledger_root=ledger,
            verifier_challenge=self.challenge,
        )
        self.assertEqual(receipt["result_digest"], self.result_digest)
        self.assertEqual(
            receipt["handoff_manifest_digest"],
            supervisor_result["handoff_manifest_digest"],
        )
        self.assertEqual(
            receipt["envelope_digest"],
            supervisor_result["envelope_digest"],
        )
        destination.verify(receipt["result_digest"])
        destination.verify(receipt["envelope_digest"])
        destination.verify(receipt["trust_store_digest"])

        signing_key_bytes = self.signing_key.read_bytes()
        signing_key_digest = (
            "sha256:" + hashlib.sha256(signing_key_bytes).hexdigest()
        )
        output_cas = CAS(paths["output_state"], read_only=True)
        with self.assertRaises(CASError):
            output_cas.verify(signing_key_digest)
        self.assertNotIn(signing_key_digest, expected_output)
        self.assertFalse(
            (
                paths["output_bundle"]
                / "blobs"
                / signing_key_digest.removeprefix("sha256:")
            ).exists()
        )
        for item in paths["output_bundle"].rglob("*"):
            if item.is_file():
                self.assertNotEqual(item.read_bytes(), signing_key_bytes)

    def test_overlapping_boundaries_publish_no_measurement_envelope(self) -> None:
        paths = self._supervisor_paths("overlap")
        paths["measurement_output"] = paths["output_state"]

        with mock.patch.object(worker_supervisor_v2, "run_worker_v2") as runner:
            with self.assertRaisesRegex(WorkerError, "boundaries overlap"):
                worker_supervisor_v2.supervise(**paths)

        runner.assert_not_called()
        self.assertFalse(paths["measurement_output"].exists())
        self.assertFalse(paths["output_bundle"].exists())

    def test_nonfresh_worker_path_publishes_no_measurement_envelope(self) -> None:
        paths = self._supervisor_paths("nonfresh")
        paths["output_state"].mkdir(mode=0o700)
        marker = paths["output_state"] / "preexisting"
        marker.write_bytes(b"operator-owned state")

        with mock.patch.object(worker_supervisor_v2, "run_worker_v2") as runner:
            with self.assertRaisesRegex(WorkerError, "must be a fresh path"):
                worker_supervisor_v2.supervise(**paths)

        runner.assert_not_called()
        self.assertFalse(paths["measurement_output"].exists())
        self.assertFalse(paths["output_bundle"].exists())
        self.assertEqual(marker.read_bytes(), b"operator-owned state")

    def _supervisor_paths(self, prefix: str) -> dict[str, object]:
        return {
            "input_bundle": self.input_bundle,
            "input_manifest_digest": self.input_manifest_digest,
            "request_digest": self.request_digest,
            "expected_challenge": self.challenge,
            "input_state": self.root / f"{prefix}-input-state",
            "output_state": self.root / f"{prefix}-output-state",
            "output_bundle": self.root / f"{prefix}-output-bundle",
            "measurement_output": self.root / f"{prefix}-measurement.dsse.json",
            "signing_key": self.signing_key,
            "worker_id": self.worker_id,
            "trust_domain": self.trust_domain,
            "key_id": self.key["key_id"],
            "lock_path": self.lock_path,
            "docker_executable": "docker",
            "workspace_root": self.workspace,
        }

    def _run_valid_worker(self, **arguments: object) -> dict:
        self.assertEqual(arguments["request_digest"], self.request_digest)
        self.assertEqual(arguments["expected_challenge"], self.challenge)
        self.assertEqual(arguments["lock_path"], self.lock_path)
        self.assertEqual(arguments["workspace_root"], self.workspace.resolve())

        imported_input = CAS(arguments["input_state"], read_only=True)
        actual_input = derive_worker_input_cas_closure(
            imported_input,
            self.request_digest,
            expected_challenge=self.challenge,
        )
        expected_input = derive_worker_input_cas_closure(
            self.evidence.source,
            self.request_digest,
            expected_challenge=self.challenge,
        )
        self.assertEqual(actual_input, expected_input)

        exact_output = derive_worker_output_cas_closure(
            self.evidence.source,
            self.result_digest,
            expected_request_digest=self.request_digest,
            expected_challenge=self.challenge,
        )
        output = CAS(arguments["output_state"])
        for digest, size in sorted(exact_output.items()):
            content = self.evidence.source.read(digest, max_bytes=size)
            self.assertEqual(
                output.put(BytesIO(content), max_bytes=size),
                digest,
            )
        return deepcopy(self.result)


if __name__ == "__main__":
    unittest.main()
