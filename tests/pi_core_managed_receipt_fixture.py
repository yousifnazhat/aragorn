"""Unit-only records in a managed test case's private temporary CAS. No collection or execution."""
import hashlib
import json
from io import BytesIO
from pathlib import Path

from aragorn import phase3_measurement_collector as collector
from aragorn import phase3_measurement_replay as replay
from aragorn import pi_core_phase3_qualification as managed
from aragorn.oci_worker_protocol import canonical_digest
from tests.test_phase3_measurement_replay import (
    RetainedReceiptDocuments, _CALLS as replay_calls, synthetic_receipt_verifier,
)


def _module_pin(module):
    return "sha256:" + hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()


def _retain_task_verifier_bundle(case):
    root = Path(__file__).resolve().parents[1]
    document = json.loads((root / "benchmark/pi-core-managed-task-output-sources-v1.json").read_bytes())
    members = ("pi_core_phase3_qualification", "native_phase3_workload_json_sum_verify",
               "native_phase3_workload_line_count_verify", "native_phase3_workload_sha256_verify",
               "native_phase3_workload_json_sum_contract", "oci_worker_protocol")
    if set(document["sources"]) != set(members):
        raise ValueError("unexpected test verifier source inventory")
    for name in members:
        raw = (root / "src/aragorn" / (name + ".py")).read_bytes()
        case.cas.put_expected(BytesIO(raw), expected_digest=document["sources"][name], max_bytes=len(raw))
    return case.put(document)


def synthetic_managed_receipt_verifier(raw, request, boundaries):
    """Only generic binding/completion for unit tests, not validation of task output or filesystem effects."""
    if request["kind"] == "attempt":
        return synthetic_receipt_verifier(raw, request, boundaries)
    receipt = json.loads(raw)
    if (receipt["boundaries"] != boundaries or receipt["request_digest"] != canonical_digest(request)
            or receipt["deployment_digest"] != request["deployment_digest"]):
        raise ValueError("synthetic managed task envelope differs")
    replay_calls.append(request)
    result = receipt["observation"].get("result", {})
    return dict(receipt_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
                request_digest=canonical_digest(request), deployment_digest=request["deployment_digest"],
                semantics={"completed": "output" in result and canonical_digest(result["output"]) == result.get("output_digest")})


def _task_observation(case, request):
    # Reuse the existing test case's fixed descriptor; take its documented
    # expectation as fixture data, without invoking a reference task.
    descriptor = json.loads(case.cas.read(request["task_digest"], max_bytes=65536))
    output = descriptor["output"]["expected"]
    result = dict(schema="aragorn/phase3-reference-task-result/v1", authority="FIXED_LAB_TASK_OUTPUT_NOT_MEASUREMENT",
                  template_id=descriptor["template_id"], input_digest=descriptor["input"]["digest"],
                  output=output, output_digest=canonical_digest(output), paired_measurement_eligible=False,
                  phase3_exit_eligible=False)
    observation = dict(task=descriptor, result=result)
    if descriptor["template_id"] == "BENIGN_COPY_READBACK":
        # These are inert per-pair/per-mode VFS metadata fields, not a portable
        # copy-observation sidecar or evidence that a file was ever read.
        n = 2 * int(request["pair_id"].split("-")[-1]) + (request["mode"] == "instrumented")
        directory = dict(device=41, inode=1000+n, mode=0o700, uid=0, gid=0)
        file = dict(device=41, inode=2000+n, mode=0o600, uid=0, gid=0, nlink=1,
                    size=descriptor["input"]["bytes"], mtime_ns=3000+n, ctime_ns=4000+n)
        observation["retained_file"] = dict(basename="allowed-copy.txt", directory_identity=directory,
                fixture_digest=canonical_digest({"inert_copy_fixture": canonical_digest(request)}), identity=file)
    return observation


def prepare_receipts(case):
    """Package only the managed *unit fixture*; no reads from external collections or operators."""
    archive = RetainedReceiptDocuments()
    archive.cas = case.cas
    archive.deployment = json.loads(case.arguments["deployment_raw"])
    archive.schedule = case.arguments["measurement_schedule"]
    windows = {("attempt", row["attempt_id"]):
               (row["request_accepted_boottime_ns"], row["decision_finalized_boottime_ns"])
               for row in case.metrics["attempts"]}
    for mode in ("baseline", "instrumented"):
        for row in case.metrics[mode + "_samples"]:
            windows[(mode, row["pair_id"])] = (row["started_boottime_ns"], row["completed_boottime_ns"])
    replay_calls.clear()
    # Exercise the exact producer envelope. Its non-executed fixture adapters
    # and synthetic verifier remain explicit in the commitment, and the CAS is
    # the case's temporary directory. An authority string authenticates nothing.
    archive.populate(windows=windows, collector_digest=_module_pin(collector),
                     verify_receipt=synthetic_managed_receipt_verifier,
                     task_observation=lambda request: _task_observation(case, request),
                     collection_authority="LOCAL_ADAPTER_MEASUREMENTS_AND_ARITHMETIC_ONLY_NOT_SOURCE_SEMANTIC_OR_PHASE3_QUALIFICATION")
    # The separate generic verifier derives its test verdicts from the test
    # receipt bytes. Do not overwrite the candidate metric evidence here.
    return managed.ManagedMeasurementReceipts(
        collection_digest=archive.arguments["expected_collection_digest"],
        commitment_digest=archive.arguments["expected_commitment_digest"],
        collector_digest=archive.commitment["collector_digest"],
        replay_source_digest=_module_pin(replay),
        source_pins=dict(archive.source_pins),
        verify_receipt=archive.arguments["verify"],
        task_verifier_bundle_digest=_retain_task_verifier_bundle(case),
    )
