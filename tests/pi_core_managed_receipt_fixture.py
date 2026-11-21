"""Unit-only records in a managed test case's private temporary CAS. No collection or execution."""
import hashlib
import json
from pathlib import Path

from aragorn import phase3_measurement_collector as collector
from aragorn import phase3_measurement_replay as replay
from aragorn import pi_core_phase3_qualification as managed
from tests.test_phase3_measurement_replay import RetainedReceiptDocuments, _CALLS as replay_calls


def _module_pin(module):
    return "sha256:" + hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()


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
    )
