from __future__ import annotations

from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from aragorn.analyze import run_analyzer
from aragorn.analyzer_receipt import (
    AnalyzerReceiptError,
    retain_analyzer_run,
    verify_analyzer_run,
)
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase0_candidate import candidate_implementation_digest


_SUBJECT = "sha256:" + "1" * 64


def _put(cas: CAS, raw: bytes) -> str:
    return cas.put(BytesIO(raw), max_bytes=len(raw))


class AnalyzerReceiptTests(unittest.TestCase):
    def test_retained_run_replays_and_rejects_mutated_evidence(self) -> None:
        script = (
            "import json,sys;"
            "r=json.load(sys.stdin);"
            "print(json.dumps({'schema':'aragorn/observation/v1',"
            "'subject_digest':r['subject_digest'],'reason_code':'TEST_FINDING',"
            "'severity':'high'},sort_keys=True,separators=(',',':')))"
        )
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            cas = CAS(root / "state")
            executable = Path(sys.executable).resolve(strict=True)
            with executable.open("rb") as stream:
                executable_digest = cas.put(stream, max_bytes=128 * 1024 * 1024)
            configuration = {
                "name": "test-scanner",
                "version": "1.0",
                "argv": [str(executable), "-c", script],
                "operator_argv0": str(executable),
                "executable_digest": executable_digest,
            }
            config_digest = _put(cas, canonical_json(configuration))
            verifier_digest = candidate_implementation_digest()
            other_invocation = {
                **configuration,
                "argv": [str(executable), "-c", "pass"],
            }
            rejected = run_analyzer(
                (str(executable), "-c", script),
                workspace=workspace,
                name="test-scanner",
                version="1.0",
                config_digest=_put(cas, canonical_json(other_invocation)),
                executable_digest=executable_digest,
                subject_digest=_SUBJECT,
                configuration_bytes=canonical_json(other_invocation),
                timeout_seconds=2,
                output_limit_bytes=4096,
            )
            self.assertEqual(rejected.error_code, "INVALID_CONFIGURATION")
            self.assertIn("argv tail", rejected.error_message or "")

            fake_executable_digest = _put(cas, b"not the launched executable")
            fake_executable_configuration = {
                **configuration,
                "executable_digest": fake_executable_digest,
            }
            rejected = run_analyzer(
                (str(executable), "-c", script),
                workspace=workspace,
                name="test-scanner",
                version="1.0",
                config_digest=_put(cas, canonical_json(fake_executable_configuration)),
                executable_digest=fake_executable_digest,
                subject_digest=_SUBJECT,
                configuration_bytes=canonical_json(fake_executable_configuration),
                timeout_seconds=2,
                output_limit_bytes=4096,
            )
            self.assertEqual(rejected.error_code, "INVALID_CONFIGURATION")
            self.assertIn("executable bytes", rejected.error_message or "")

            result = run_analyzer(
                (str(executable), "-c", script),
                workspace=workspace,
                name="test-scanner",
                version="1.0",
                config_digest=config_digest,
                executable_digest=executable_digest,
                subject_digest=_SUBJECT,
                configuration_bytes=canonical_json(configuration),
                timeout_seconds=2,
                output_limit_bytes=4096,
            )

            receipt_digest = retain_analyzer_run(
                cas,
                result,
                verifier_implementation_digest=verifier_digest,
            )
            verified = verify_analyzer_run(
                cas,
                receipt_digest,
                expected_subject_digest=_SUBJECT,
                expected_verifier_digest=verifier_digest,
            )
            self.assertTrue(verified.ok)
            self.assertEqual(
                [item.reason_code for item in verified.observations],
                ["TEST_FINDING"],
            )
            self.assertEqual(verified.raw_request, result.raw_request)

            receipt = json.loads(cas.read(receipt_digest))
            bad_stdout = deepcopy(receipt)
            bad_stdout["stdout_digest"] = _put(cas, b"")

            other_request = json.loads(result.raw_request)
            other_request["subject_digest"] = "sha256:" + "3" * 64
            bad_subject = deepcopy(receipt)
            bad_subject["request_digest"] = _put(
                cas, canonical_json(other_request) + b"\n"
            )

            missing_executable_request = json.loads(result.raw_request)
            missing_executable_request["analyzer"]["executable_digest"] = (
                "sha256:" + "0" * 64
            )
            bad_executable = deepcopy(receipt)
            bad_executable["request_digest"] = _put(
                cas, canonical_json(missing_executable_request) + b"\n"
            )

            missing_config_request = json.loads(result.raw_request)
            missing_config_request["analyzer"]["config_digest"] = "sha256:" + "0" * 64
            bad_config = deepcopy(receipt)
            bad_config["request_digest"] = _put(
                cas, canonical_json(missing_config_request) + b"\n"
            )

            mismatched_configuration = deepcopy(configuration)
            mismatched_configuration["name"] = "other-scanner"
            mismatched_config_request = json.loads(result.raw_request)
            mismatched_config_request["analyzer"]["config_digest"] = _put(
                cas, canonical_json(mismatched_configuration)
            )
            bad_config_identity = deepcopy(receipt)
            bad_config_identity["request_digest"] = _put(
                cas, canonical_json(mismatched_config_request) + b"\n"
            )

            for label, candidate, message in (
                ("stdout", bad_stdout, "observations do not match stdout"),
                ("subject", bad_subject, "another subject"),
                ("configuration", bad_config, "cannot verify retained analyzer run"),
                (
                    "configuration identity",
                    bad_config_identity,
                    "configuration does not match",
                ),
                ("executable", bad_executable, "cannot verify retained analyzer run"),
            ):
                with self.subTest(label):
                    with self.assertRaisesRegex(AnalyzerReceiptError, message):
                        verify_analyzer_run(
                            cas,
                            _put(cas, canonical_json(candidate)),
                            expected_subject_digest=_SUBJECT,
                            expected_verifier_digest=verifier_digest,
                        )

            with self.assertRaisesRegex(AnalyzerReceiptError, "identity is untrusted"):
                verify_analyzer_run(
                    cas,
                    receipt_digest,
                    expected_subject_digest=_SUBJECT,
                    expected_verifier_digest="sha256:" + "0" * 64,
                )

            error_script = "import sys;sys.stdin.read();sys.exit(7)"
            error_configuration = {
                **configuration,
                "argv": [str(executable), "-c", error_script],
            }
            error_result = run_analyzer(
                (str(executable), "-c", error_script),
                workspace=workspace,
                name="test-scanner",
                version="1.0",
                config_digest=_put(cas, canonical_json(error_configuration)),
                executable_digest=executable_digest,
                subject_digest=_SUBJECT,
                configuration_bytes=canonical_json(error_configuration),
                timeout_seconds=2,
                output_limit_bytes=4096,
            )
            error_receipt = retain_analyzer_run(
                cas,
                error_result,
                verifier_implementation_digest=verifier_digest,
            )
            verified_error = verify_analyzer_run(
                cas,
                error_receipt,
                expected_subject_digest=_SUBJECT,
                expected_verifier_digest=verifier_digest,
            )
            self.assertEqual(
                (
                    verified_error.status,
                    verified_error.error_code,
                    verified_error.error_message,
                    verified_error.returncode,
                ),
                (
                    "error",
                    "NONZERO_EXIT",
                    "analyzer exited with status 7",
                    7,
                ),
            )

    def test_v2_request_binds_a_distinct_analysis_input_manifest(self) -> None:
        script = (
            "import json,sys;"
            "r=json.load(sys.stdin);"
            "assert r['schema']=='aragorn/analyzer-request/v2';"
            "assert set(r['input'])=={'manifest_digest','tree_digest'};"
            "print(json.dumps({'schema':'aragorn/observation/v1',"
            "'subject_digest':r['subject_digest'],'reason_code':'INPUT_SCANNED',"
            "'severity':'info'},sort_keys=True,separators=(',',':')))"
        )
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            cas = CAS(root / "state")
            content = b"analysis-only bytes\n"
            content_digest = _put(cas, content)
            files = [
                {
                    "path": "release/asset.txt",
                    "size": len(content),
                    "digest": content_digest,
                    "executable": False,
                }
            ]
            tree_digest = (
                "sha256:" + hashlib.sha256(canonical_json(files)).hexdigest()
            )
            manifest_digest = _put(
                cas,
                canonical_json(
                    {
                        "schema": "aragorn/manifest/v1",
                        "source": {"kind": "local", "path": str(workspace)},
                        "tree_digest": tree_digest,
                        "files": files,
                        "closure": {"scope": "source_tree", "status": "complete"},
                    }
                ),
            )
            executable = Path(sys.executable).resolve(strict=True)
            with executable.open("rb") as stream:
                executable_digest = cas.put(
                    stream,
                    max_bytes=128 * 1024 * 1024,
                )
            configuration = {
                "name": "test-scanner",
                "version": "1.0",
                "argv": [str(executable), "-c", script],
                "operator_argv0": str(executable),
                "executable_digest": executable_digest,
            }
            config_raw = canonical_json(configuration)
            result = run_analyzer(
                (str(executable), "-c", script),
                workspace=workspace,
                name="test-scanner",
                version="1.0",
                config_digest=_put(cas, config_raw),
                executable_digest=executable_digest,
                subject_digest=_SUBJECT,
                input_manifest_digest=manifest_digest,
                input_tree_digest=tree_digest,
                configuration_bytes=config_raw,
                timeout_seconds=2,
                output_limit_bytes=4096,
            )
            verifier_digest = candidate_implementation_digest()
            receipt_digest = retain_analyzer_run(
                cas,
                result,
                verifier_implementation_digest=verifier_digest,
            )
            verified = verify_analyzer_run(
                cas,
                receipt_digest,
                expected_subject_digest=_SUBJECT,
                expected_input_manifest_digest=manifest_digest,
                expected_input_tree_digest=tree_digest,
                expected_verifier_digest=verifier_digest,
            )
            self.assertTrue(verified.ok)

            with self.assertRaisesRegex(AnalyzerReceiptError, "another input"):
                verify_analyzer_run(
                    cas,
                    receipt_digest,
                    expected_subject_digest=_SUBJECT,
                    expected_input_manifest_digest="sha256:" + "0" * 64,
                    expected_input_tree_digest=tree_digest,
                    expected_verifier_digest=verifier_digest,
                )

            receipt = json.loads(cas.read(receipt_digest))
            request = json.loads(result.raw_request)
            request["input"]["tree_digest"] = "sha256:" + "2" * 64
            receipt["request_digest"] = _put(
                cas,
                canonical_json(request) + b"\n",
            )
            with self.assertRaisesRegex(AnalyzerReceiptError, "tree digest"):
                verify_analyzer_run(
                    cas,
                    _put(cas, canonical_json(receipt)),
                    expected_subject_digest=_SUBJECT,
                    expected_verifier_digest=verifier_digest,
                )


if __name__ == "__main__":
    unittest.main()
