from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts.prepare_hidden_suite import _V2_GATE, _V3_GATE, _V4_GATE, _V5_GATE
from scripts.run_hidden_workers import (
    ExecutionError,
    Job,
    _controller_lock,
    _error_record,
    _execute,
    _guest_command,
    _parse_guest_attempts,
    _retain_exact,
    _run_receipt,
    _run_worker,
    _validate_acceptance,
    _validate_run_receipt,
    _vm_preflight,
    _write_outcomes,
)


class HiddenWorkerControllerTests(unittest.TestCase):
    def test_guest_attempt_inventory_is_fail_closed(self) -> None:
        self.assertEqual(_parse_guest_attempts(b"", 7), (None, 1))
        self.assertEqual(
            _parse_guest_attempts(
                b"partial\tjob-000007-attempt-0001\n"
                b"complete\tjob-000007-attempt-0002\n",
                7,
            ),
            ("job-000007-attempt-0002", 3),
        )
        self.assertEqual(
            _parse_guest_attempts(
                b"complete\tjob-000007-attempt-0001\n"
                b"complete\tjob-000007-attempt-0002\n",
                7,
            ),
            ("job-000007-attempt-0001", 3),
        )
        with self.assertRaisesRegex(ExecutionError, "inventory changed"):
            _parse_guest_attempts(
                b"partial\tjob-000008-attempt-0001\n",
                7,
            )

    def test_acceptance_must_match_signed_preparation(self) -> None:
        digest = "sha256:" + "1" * 64
        challenge = "2" * 64
        job = Job(
            ordinal=1,
            job_id="3" * 32,
            request_digest=digest,
            challenge=challenge,
            input_manifest_digest=digest,
            input_bundle=Path("/input"),
        )
        preparation = {
            "worker": {
                "trust_store_digest": digest,
                "key_id": digest,
            }
        }
        receipt = {
            "trust_store_digest": digest,
            "key_id": digest,
            "trust_domain": "phase0.hidden-independent-v1.0.0",
            "worker_id": "isolated-worker-01",
            "job_id": job.job_id,
            "request_digest": job.request_digest,
            "verifier_challenge": challenge,
            "result_digest": digest,
            "handoff_manifest_digest": digest,
            "envelope_digest": digest,
        }
        _validate_acceptance(
            acceptance={"receipt": receipt},
            job=job,
            preparation=preparation,
        )
        changed = dict(receipt)
        changed["worker_id"] = "other-worker"
        with self.assertRaisesRegex(ExecutionError, "preparation binding"):
            _validate_acceptance(
                acceptance={"receipt": changed},
                job=job,
                preparation=preparation,
            )
        receipt["trust_domain"] = _V2_GATE.trust_domain
        _validate_acceptance(
            acceptance={"receipt": receipt},
            job=job,
            preparation=preparation,
            gate=_V2_GATE,
        )

    def test_outcomes_are_exclusive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            path = root / "outcomes.jsonl"
            outcomes = [{"schema": "example/outcome/v1", "value": 1}]
            expected = canonical_json(outcomes[0]) + b"\n"
            self.assertEqual(_write_outcomes(path, outcomes), expected)
            self.assertEqual(_write_outcomes(path, outcomes), expected)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            stage = root / ".outcomes.jsonl.staging"
            os.link(path, stage)
            self.assertEqual(_write_outcomes(path, outcomes), expected)
            self.assertFalse(stage.exists())
            self.assertEqual(path.stat().st_nlink, 1)
            with self.assertRaisesRegex(ExecutionError, "differ"):
                _write_outcomes(
                    path,
                    [{"schema": "example/outcome/v1", "value": 2}],
                )

    def test_controller_lock_is_exclusive_for_run_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            descriptor = _controller_lock(root)
            try:
                with self.assertRaisesRegex(ExecutionError, "another"):
                    _controller_lock(root)
            finally:
                os.close(descriptor)

    def test_worker_run_receipt_is_private_and_idempotent(self) -> None:
        digest = "sha256:" + "1" * 64
        receipt = _run_receipt(
            runner_commit="2" * 40,
            preparation={"state": {"binding_digest": digest}},
            preparation_raw=b"preparation",
            acceptance_set_digest=digest,
            result_set_digest=digest,
            composition_digest=digest,
            outcomes_digest=digest,
            outcomes_file_digest=digest,
        )
        self.assertEqual(
            receipt["schema"],
            "aragorn/benchmark-phase0-hidden-worker-run-receipt/v1",
        )
        raw = canonical_json(receipt)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "worker-run-receipt.json"
            _retain_exact(path, raw, mode=0o400, label="worker run receipt")
            _retain_exact(path, raw, mode=0o400, label="worker run receipt")
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            with self.assertRaisesRegex(ExecutionError, "differs"):
                _retain_exact(
                    path,
                    b"different",
                    mode=0o400,
                    label="worker run receipt",
                )

    def test_calibration_run_receipt_and_worker_command_bind_gate(self) -> None:
        digest = "sha256:" + "1" * 64
        arguments = {
            "runner_commit": "2" * 40,
            "preparation": {"state": {"binding_digest": digest}},
            "preparation_raw": b"preparation",
            "acceptance_set_digest": digest,
            "result_set_digest": digest,
            "composition_digest": digest,
            "outcomes_digest": digest,
            "outcomes_file_digest": digest,
        }
        receipt = _run_receipt(**arguments, gate=_V2_GATE)
        self.assertEqual(
            receipt["schema"],
            "aragorn/benchmark-phase0-hidden-worker-run-receipt/v2",
        )
        self.assertEqual(
            receipt["limitations"]["evaluation_status"],
            "calibration_rerun_on_previously_evaluated_corpus_not_fresh_holdout",
        )
        v3_receipt = _run_receipt(**arguments, gate=_V3_GATE)
        self.assertEqual(v3_receipt["schema"], _V3_GATE.run_receipt_schema)
        self.assertNotIn("evaluation_status", v3_receipt["limitations"])
        v4_receipt = _run_receipt(**arguments, gate=_V4_GATE)
        self.assertEqual(v4_receipt["schema"], _V4_GATE.run_receipt_schema)
        self.assertNotIn("evaluation_status", v4_receipt["limitations"])
        v5_receipt = _run_receipt(**arguments, gate=_V5_GATE)
        self.assertEqual(v5_receipt["schema"], _V5_GATE.run_receipt_schema)
        self.assertNotIn("evaluation_status", v5_receipt["limitations"])
        with self.assertRaisesRegex(ValueError, "registered profile"):
            _run_receipt(
                **arguments,
                gate=replace(_V2_GATE, calibration_only=False),
            )
        synthetic = replace(
            _V2_GATE,
            name="synthetic-v3",
            run_receipt_schema=(
                "aragorn/benchmark-phase0-hidden-worker-run-receipt/v3"
            ),
        )
        with patch.dict(
            "scripts.prepare_hidden_suite._GATES",
            {synthetic.name: synthetic},
        ):
            self.assertEqual(
                _run_receipt(**arguments, gate=synthetic)["schema"],
                synthetic.run_receipt_schema,
            )

        job = Job(
            ordinal=1,
            job_id="3" * 32,
            request_digest=digest,
            challenge="4" * 64,
            input_manifest_digest=digest,
            input_bundle=Path("/input"),
        )
        supervisor = {
            "schema": "aragorn/benchmark-worker-supervisor-result/v1",
            "request_digest": digest,
        }
        with patch(
            "scripts.run_hidden_workers._guest_command",
            return_value=canonical_json(supervisor) + b"\n",
        ) as guest_command:
            self.assertEqual(
                _run_worker(
                    limactl=Path("/limactl"),
                    vm="worker",
                    guest_source="/source",
                    guest_python="/venv/bin/python",
                    guest_signing_key="/key",
                    guest_execution_root="/execution",
                    attempt_name="attempt",
                    job=job,
                    key_id=digest,
                    gate=_V2_GATE,
                ),
                supervisor,
            )
        self.assertEqual(
            guest_command.call_args.args[3][-2:],
            [_V2_GATE.trust_domain, digest],
        )

    def test_worker_run_receipt_semantics_are_replayed(self) -> None:
        digest = "sha256:" + "1" * 64
        result_digest = "sha256:" + "2" * 64
        runner_commit = "3" * 40
        challenge = "4" * 64
        job = Job(
            ordinal=1,
            job_id="5" * 32,
            request_digest=digest,
            challenge=challenge,
            input_manifest_digest=digest,
            input_bundle=Path("/input"),
        )
        acceptance = {"receipt": {"result_digest": result_digest}}
        acceptance_set = {
            "schema": "aragorn/benchmark-acceptance-digest-set/v1",
            "digests": [canonical_digest(acceptance["receipt"])],
        }
        result_set = {
            "schema": "aragorn/benchmark-result-digest-set/v1",
            "digests": [result_digest],
        }
        outcome = {"schema": "example/outcome/v1"}
        composition = {
            "outcomes": [outcome],
            "outcomes_digest": canonical_digest([outcome]),
        }
        preparation = {
            "state": {"binding_digest": digest},
            "preparation": {"dispatch_digest": digest},
        }
        preparation_raw = canonical_json(preparation)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "jobs_root": root / "jobs",
                "challenge_ledger": root / "ledger",
                "control_state": root / "control",
                "outcomes": root / "outcomes.jsonl",
            }
            for directory in (
                paths["jobs_root"],
                paths["challenge_ledger"],
                paths["challenge_ledger"] / "receipts",
                paths["control_state"],
            ):
                directory.mkdir(mode=0o700)
            outcomes_raw = canonical_json(outcome) + b"\n"
            paths["outcomes"].write_bytes(outcomes_raw)
            os.chmod(paths["outcomes"], 0o600)
            receipt = _run_receipt(
                runner_commit=runner_commit,
                preparation=preparation,
                preparation_raw=preparation_raw,
                acceptance_set_digest=canonical_digest(acceptance_set),
                result_set_digest=canonical_digest(result_set),
                composition_digest=canonical_digest(composition),
                outcomes_digest=composition["outcomes_digest"],
                outcomes_file_digest=(
                    "sha256:" + hashlib.sha256(outcomes_raw).hexdigest()
                ),
            )
            receipt["batch"]["accepted_count"] = 1
            receipt["composition"]["outcome_count"] = 1
            documents = {
                canonical_digest(acceptance_set): canonical_json(acceptance_set),
                canonical_digest(result_set): canonical_json(result_set),
                canonical_digest(composition): canonical_json(composition),
            }

            class ReadOnlyControl:
                def read(self, item: str, *, max_bytes: int) -> bytes:
                    del max_bytes
                    return documents[item]

            patches = (
                patch(
                    "scripts.run_hidden_workers._EXPECTED_JOBS",
                    1,
                ),
                patch(
                    "scripts.run_hidden_workers._EXPECTED_OUTCOMES",
                    1,
                ),
                patch(
                    "scripts.run_hidden_workers._runner_commit",
                    return_value=runner_commit,
                ),
                patch(
                    "scripts.run_hidden_workers._load_preparation",
                    return_value=(preparation, preparation_raw, digest),
                ),
                patch(
                    "scripts.run_hidden_workers._state_paths",
                    return_value=paths,
                ),
                patch("scripts.run_hidden_workers._reject_symlink_components"),
                patch(
                    "scripts.run_hidden_workers._load_jobs",
                    return_value=[job],
                ),
                patch(
                    "scripts.run_hidden_workers._directory_names",
                    return_value={f"{challenge}.json"},
                ),
                patch(
                    "scripts.run_hidden_workers.load_verified_worker_output_acceptance",
                    return_value=acceptance,
                ),
                patch("scripts.run_hidden_workers._validate_acceptance"),
                patch(
                    "scripts.run_hidden_workers.CAS",
                    return_value=ReadOnlyControl(),
                ),
                patch(
                    "scripts.run_hidden_workers.compose_candidate_batch",
                    return_value=composition,
                ),
            )
            for active in patches:
                active.start()
            try:
                _validate_run_receipt(
                    receipt,
                    canonical_json(receipt),
                    runner_commit=runner_commit,
                    preparation=preparation,
                    preparation_raw=preparation_raw,
                    run_state_root=root,
                )
                changed = {**receipt, "batch": {**receipt["batch"]}}
                changed["batch"]["result_set_digest"] = digest
                with self.assertRaisesRegex(ExecutionError, "semantic"):
                    _validate_run_receipt(
                        changed,
                        canonical_json(changed),
                        runner_commit=runner_commit,
                        preparation=preparation,
                        preparation_raw=preparation_raw,
                        run_state_root=root,
                    )
            finally:
                for active in reversed(patches):
                    active.stop()

    def test_command_output_is_bounded_while_running(self) -> None:
        with self.assertRaisesRegex(ExecutionError, "failed"):
            _execute(
                Path(sys.executable),
                ["-c", "import sys; sys.stdout.write('x' * 32)"],
                label="bounded command",
                timeout=5,
                maximum=8,
            )

    def test_guest_command_uses_positional_arguments(self) -> None:
        with patch(
            "scripts.run_hidden_workers._limactl",
            return_value=b"ok\n",
        ) as limactl:
            self.assertEqual(
                _guest_command(
                    Path("/limactl"),
                    "worker-vm",
                    "printf '%s\\n' \"$1\"",
                    ["/guest/path"],
                    label="test command",
                ),
                b"ok\n",
            )
        self.assertEqual(
            limactl.call_args.args,
            (
                Path("/limactl"),
                [
                    "shell",
                    "worker-vm",
                    "--",
                    "bash",
                    "-c",
                    "printf '%s\\n' \"$1\"",
                    "aragorn-hidden",
                    "/guest/path",
                ],
            ),
        )

    def test_vm_preflight_uses_only_the_pinned_runtime_python(self) -> None:
        instance = {
            "name": "worker-vm",
            "status": "Running",
            "protected": True,
            "arch": "aarch64",
            "config": {
                "mounts": None,
                "ssh": {
                    "forwardAgent": False,
                    "loadDotSSHPubKeys": False,
                },
            },
        }
        with (
            patch(
                "scripts.run_hidden_workers._limactl",
                return_value=json.dumps(instance).encode(),
            ),
            patch(
                "scripts.run_hidden_workers._guest_command",
                return_value=b"ok\n",
            ) as guest_command,
        ):
            _vm_preflight(
                limactl=Path("/limactl"),
                vm="worker-vm",
                guest_source="/source",
                guest_python="/runtime/venv/bin/python",
                guest_signing_key="/key",
                guest_execution_root="/execution",
                expected_source_digest="sha256:" + "1" * 64,
            )
        script = guest_command.call_args.args[2]
        arguments = guest_command.call_args.args[3]
        self.assertNotIn("/usr/bin/python3", script)
        self.assertNotIn("system_python", script)
        self.assertEqual(script.count('"$python" -I -S -B'), 2)
        self.assertEqual(len(arguments), 14)

    def test_cli_error_record_redacts_private_context(self) -> None:
        record = _error_record(
            OSError("/private/tmp/run/challenge-secret", "sha256:secret")
        )
        self.assertEqual(record["error"], "validation_failed")
        self.assertNotIn("private", str(record))
        self.assertNotIn("sha256", str(record))


if __name__ == "__main__":
    unittest.main()
