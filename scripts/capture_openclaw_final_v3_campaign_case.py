"""Execute one supported V3 development case and retain cleanup-checked evidence."""

from __future__ import annotations

import argparse
import io
import os
import re
import signal
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn.cas import CAS, CASError
from scripts import capture_openclaw_final_v3_det01_campaign as det01
from scripts import openclaw_final_v3_config_entry_case as config_entry
from scripts import openclaw_final_v3_core_updater_case as core
from scripts import openclaw_final_v3_curator_restore_case as curator
from scripts import openclaw_final_v3_plugin_enable_case as plugin_enable
from scripts import openclaw_final_v3_workshop_invalidation_case as workshop
from scripts import openclaw_final_v3_workshop_proposal_apply_case as proposal

CaptureError = det01.CaptureError
_canonical = campaign._canonical
_digest = campaign._digest
_DOCKER = det01.acquisition._DOCKER
_CORE_CASE = "ADM-02/update/core-updater-plugin-replacement"
_WORKSHOP_CASE = "ADM-02/reload/workshop-invalidation"
_BACKENDS = {
    _CORE_CASE: (core, "core-updater-plugin-replacement"),
    _WORKSHOP_CASE: (workshop, "workshop-invalidation"),
    "ADM-02/update/workshop-proposal-apply": (proposal, "workshop-proposal-apply"),
    "ADM-02/update/curator-restore-activation": (curator, "curator-restore"),
    "ADM-02/update/config-entry-activation": (config_entry, "config-entry-activation"),
    "ADM-02/update/plugin-enable-activation": (plugin_enable, "plugin-enable"),
}
_SUPPORTED = ("DET-01", *_BACKENDS)
_RECIPE = "scripts/capture_runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd.sh"
_ROLE = "final-combined-v3-core-updater-plugin-replacement-route-input"
_PREFIX = "aragorn-phase3-final-combined-v3-core-updater-plugin-replacement"
_MAX_BYTES = 2 * 1024 * 1024


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise CaptureError("V3 case executor " + message)


def _read_output(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        _expect(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= _MAX_BYTES,
            "output file changed",
        )
        raw = stream.read(_MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    _expect(
        len(raw) == before.st_size
        and all(getattr(before, key) == getattr(after, key) for key in fields),
        "output bytes changed during read",
    )
    return raw


def _source_identity() -> dict[str, Any]:
    # Reuse the existing signed checkout/dependency capture. Add the non-Python
    # recipe inputs explicitly; imported repository modules are already covered.
    source = det01._source_identity()
    git = det01.acquisition.shared._git
    files = {item["path"]: item for item in source["files"]}
    inputs = {
        path for backend, _ in _BACKENDS.values() for path in backend.SOURCE_PATHS
    }
    for path in sorted(inputs - files.keys()):
        entry = git(["ls-tree", "-z", source["commit"], "--", path])
        metadata, separator, name = entry.partition(b"\t")
        fields = metadata.split()
        _expect(
            separator == b"\t"
            and name == path.encode() + b"\0"
            and len(fields) == 3
            and fields[0] in {b"100644", b"100755"}
            and fields[1] == b"blob",
            "source tree entry changed",
        )
        raw = git(["cat-file", "blob", fields[2].decode()])
        _expect(_read_output(_ROOT / path) == raw, "working source changed: " + path)
        files[path] = {
            "path": path,
            "bytes": len(raw),
            "digest": _digest(raw),
            "mode": fields[0].decode(),
            "blob": fields[2].decode(),
        }
    source["files"] = [files[path] for path in sorted(files)]
    return source


def _namespace_state(*, case_id: str = _CORE_CASE) -> dict[str, Any]:
    _, stem = _BACKENDS[case_id]
    prefix = "aragorn-phase3-final-combined-v3-" + stem
    role = "final-combined-v3-" + stem + "-route-input"
    commands = {
        "containers": [
            *_DOCKER,
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            "name=^/" + prefix + "-[0-9]+$",
        ],
        "volumes": [
            *_DOCKER,
            "volume",
            "ls",
            "--format",
            "{{.Name}}",
            "--filter",
            "label=dev.aragorn.role=" + role,
        ],
    }
    state = {
        key: det01.acquisition._run(argv).decode().splitlines()
        for key, argv in commands.items()
    }
    _expect(
        not any(state.values()),
        stem + " resources remain or another capture is active",
    )
    return {"commands": commands, **state}


def _invoke(output: Path, *, case_id: str = _CORE_CASE) -> dict[str, Any]:
    backend, _ = _BACKENDS[case_id]
    argv = ["/bin/sh", str(_ROOT / backend._RECIPE), str(output)]
    started = det01._now()
    with (
        TemporaryDirectory(prefix="aragorn-v3-case-logs-") as temporary,
        (Path(temporary) / "stdout").open("w+b") as stdout,
        (Path(temporary) / "stderr").open("w+b") as stderr,
    ):
        process = subprocess.Popen(
            argv,
            cwd=_ROOT,
            stdout=stdout,
            stderr=stderr,
            env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
            start_new_session=True,
        )
        try:
            process.wait(timeout=240)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
            raise
        completed = det01._now()
        stdout.seek(0)
        stderr.seek(0)
        out, err = stdout.read(_MAX_BYTES + 1), stderr.read(_MAX_BYTES + 1)
    _expect(
        len(out) <= _MAX_BYTES and len(err) <= _MAX_BYTES, "capture logs exceeded bound"
    )
    _expect(
        process.returncode == 0,
        f"recipe failed ({process.returncode}): {err[-2048:].decode('utf-8', 'replace')}",
    )
    return {
        "argv": argv,
        "started_at": started,
        "completed_at": completed,
        "exit_code": process.returncode,
        "stdout": det01.collector._raw(out),
        "stderr": det01.collector._raw(err),
    }


def _verify_cleanup(
    harness: dict[str, Any], *, case_id: str = _CORE_CASE
) -> dict[str, Any]:
    state = _namespace_state(case_id=case_id)
    _, stem = _BACKENDS[case_id]
    prefix = "aragorn-phase3-final-combined-v3-" + stem
    container = harness["container_id"]
    volume = harness["route_input_volume_identity"]["name"]
    _expect(
        type(container) is str
        and re.fullmatch(r"[0-9a-f]{64}", container) is not None
        and type(volume) is str
        and re.fullmatch(re.escape(prefix) + r"-route-input-[1-9][0-9]*", volume)
        is not None,
        "capture cleanup identity changed",
    )
    commands = {
        "container": [
            *_DOCKER,
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            "id=" + container,
        ],
        "volumes": [*_DOCKER, "volume", "ls", "--format", "{{.Name}}"],
        "daemon": [*_DOCKER, "info", "--format", "{{.ServerVersion}}"],
    }
    outputs = {
        key: det01.acquisition._run(argv).decode() for key, argv in commands.items()
    }
    _expect(
        not outputs["container"].strip()
        and volume not in outputs["volumes"].splitlines()
        and bool(outputs["daemon"].strip()),
        "capture resources remain or daemon unavailable",
    )
    return {
        "authority": "LOCAL_DOCKER_OBSERVATION_NOT_EXTERNAL_ATTESTATION",
        "checked_at": det01._now(),
        "namespace": state,
        "container_id": container,
        "volume_name": volume,
        "container_absent": True,
        "volume_absent": True,
        "commands": [
            {"argv": commands[key], "stdout": outputs[key], "exit_code": 0}
            for key in commands
        ],
    }


def capture_case(
    contract: dict[str, Any], case_id: str, *, evidence_cas: CAS
) -> dict[str, Any]:
    """Run one supported case; unsupported cases fail before any execution."""
    contract = campaign.validate_openclaw_final_v3_campaign_contract(contract)
    _expect(
        type(case_id) is str and case_id in _SUPPORTED, "case has no executable backend"
    )
    request = campaign.build_openclaw_final_v3_subfixture_request(contract, case_id)
    if case_id == "DET-01":
        return det01.capture_det01(contract, request, evidence_cas=evidence_cas)
    backend, _ = _BACKENDS[case_id]
    source = _source_identity()
    with TemporaryDirectory(prefix="aragorn-v3-native-case-") as temporary:
        directory = Path(temporary).resolve()
        prepared = backend.prepare_case(contract, request, directory=directory)
        parent = contract["frozen_parent"]["identity"]
        before = det01.snapshot.snapshot_parent(parent)
        namespace_before = _namespace_state(case_id=case_id)
        try:
            output = directory / "native.json"
            invocation = _invoke(output, case_id=case_id)
            raw = _read_output(output)
            verified = backend.verify_capture(
                raw, prepared, source=source, invocation=invocation
            )
            cleanup = _verify_cleanup(verified["harness"], case_id=case_id)
        finally:
            _namespace_state(case_id=case_id)
        after = det01.snapshot.snapshot_parent(parent)
        _expect(
            before["image_inspect"] == after["image_inspect"]
            and before["volume_inspect"] == after["volume_inspect"]
            and before["content"]["runtime_tree_before"]
            == after["content"]["runtime_tree_after"]
            and {
                key: item["content_base64"]
                for key, item in before["content"]["contract_files"].items()
            }
            == {
                key: item["content_base64"]
                for key, item in after["content"]["contract_files"].items()
            },
            "frozen parent changed during capture",
        )
        _expect(_source_identity() == source, "capture source changed during execution")
        document = {
            "schema": "aragorn/openclaw-final-v3-campaign-case-observation/v1",
            "authority": "ONE_DEVELOPMENT_CASE_OBSERVATION_NOT_FINAL_CAMPAIGN_OR_QUALIFICATION_AUTHORITY",
            "recorded_at": det01._now(),
            "request": request,
            "source": source,
            "request_binding": prepared,
            "invocation": invocation,
            "native_capture": det01.collector._raw(raw),
            "capture_checks": verified["proof"],
            "parent_before": before,
            "parent_after": after,
            "namespace_before": namespace_before,
            "cleanup": cleanup,
            "decision": {
                "status": "WRAPPER_BOUND_OBSERVED_NOT_QUALIFIED",
                **{key: False for key in campaign._ELIGIBILITY_KEYS},
            },
            "limitations": [
                "ONE_FRESH_DEVELOPMENT_CASE_NOT_FINAL_COMMON_DEPLOYMENT_CAMPAIGN",
                "CAMPAIGN_NONCE_HOST_ASSOCIATED_NOT_NATIVE_COLLECTOR_ECHOED",
                "EXPLICIT_LEGACY_NATIVE_PATH_MAPPING_NOT_LITERAL_DISPATCH_ARGV_EXECUTION",
                "PARENT_SNAPSHOTS_NOT_EXCLUSIVE_LEASE_AND_LOCAL_CLEANUP_NOT_EXTERNAL_ATTESTATION",
                "CAPTURE_SIDE_SEMANTIC_CHECKS_NOT_INDEPENDENT_QUALIFICATION",
                "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
            ],
        }
    # ponytail: single checked case per call, not an automatic campaign/resume
    # scheduler. Final composition waits for implemented and frozen RUN coverage.
    raw = _canonical(document) + b"\n"
    _expect(len(raw) <= _MAX_BYTES, "case evidence exceeded bound")
    digest = evidence_cas.put_expected(
        io.BytesIO(raw), expected_digest=_digest(raw), max_bytes=_MAX_BYTES
    )
    _expect(
        evidence_cas.read(digest, max_bytes=_MAX_BYTES) == raw, "CAS readback changed"
    )
    return {
        "document": document,
        "result": {
            "case_id": case_id,
            "fixture_id": request["case"]["fixture_id"],
            "parent_identity_digest": request["frozen_parent"]["digest"],
            "fresh": True,
            "destroyed": True,
            "outcome": "OBSERVED",
            "evidence_refs": [digest],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", choices=_SUPPORTED, required=True)
    parser.add_argument("--campaign-nonce", required=True)
    parser.add_argument("--cas-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        _expect(
            args.output.is_absolute() and not os.path.lexists(args.output),
            "output must be absent and absolute",
        )
        contract = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce=args.campaign_nonce
        )
        result = capture_case(contract, args.case_id, evidence_cas=CAS(args.cas_root))
        raw = _canonical(result["document"]) + b"\n"
        det01.acquisition._write_output(args.output, raw)
        print(
            _canonical(
                {
                    "path": str(args.output),
                    "bytes": len(raw),
                    "digest": _digest(raw),
                    "result": result["result"],
                }
            ).decode()
        )
    except (
        CaptureError,
        CASError,
        campaign.CampaignContractError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"V3 case capture failed closed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
