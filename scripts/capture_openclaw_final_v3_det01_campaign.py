"""Capture one wrapper-bound DET-01 case; never qualify a campaign."""

from __future__ import annotations

import argparse
import io
import os
import re
import signal
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import admission_openclaw_final_v3_det01_binding as binding
from aragorn import admission_openclaw_final_v3_det01_qualification as checks
from aragorn.cas import CAS, CASError
from scripts import capture_openclaw_final_v3_core_updater_modules as acquisition
from scripts import materialize_openclaw_final_v3_det01 as materializer
from scripts import openclaw_final_v3_parent_snapshot as snapshot
from scripts import (
    runtime_action_worker_final_combined_v3_det01_systemd_probe as collector,
)

CaptureError = acquisition.CaptureError
_canonical = campaign._canonical
_digest = campaign._digest
_RECIPE = "scripts/capture_runtime_action_worker_final_combined_v3_det01_systemd.sh"
_INHERITED = "scripts/capture_runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd.sh"
_DOCKERFILE = (
    "benchmark/runtime-action-worker-final-combined-v3-det01-systemd/Dockerfile"
)
_HISTORICAL_SOURCE = checks._SOURCE["commit"]
_MAX_BYTES = 2 * 1024 * 1024


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise CaptureError("DET-01 campaign " + message)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _source_identity() -> dict[str, Any]:
    git = acquisition.shared._git
    _expect(
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve() == _ROOT
        and git(["rev-parse", "--show-object-format"]).strip() == b"sha1"
        and not git(["status", "--porcelain=v1", "--untracked-files=all"]),
        "requires the exact clean signed repository",
    )
    commit = git(["rev-parse", "HEAD"]).decode().strip()
    acquisition.shared._verify_signature(commit)
    acquisition.shared._verify_signature(_HISTORICAL_SOURCE)
    git(["merge-base", "--is-ancestor", _HISTORICAL_SOURCE, commit])
    historical = {
        _RECIPE,
        _INHERITED,
        _DOCKERFILE,
        str(Path(collector.__file__).relative_to(_ROOT)),
        *[path.removeprefix("/src/") for path in collector._SOURCE_PINS],
    }
    paths = {
        str(Path(__file__).relative_to(_ROOT)),
        *historical,
        str(acquisition._HELPER_PATH),
    }
    # Record the imported repository dependency closure, including verification
    # helpers. This does not claim that these host modules execute in the child.
    for module in tuple(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if filename and Path(filename).is_relative_to(_ROOT):
            paths.add(str(Path(filename).relative_to(_ROOT)))
    files = []
    for path in sorted(paths):
        entry = git(["ls-tree", "-z", commit, "--", path])
        _expect(
            entry.endswith(b"\0") and entry.count(b"\0") == 1,
            "source tree entry changed",
        )
        metadata, name = entry[:-1].split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        _expect(
            name.decode() == path and kind == "blob" and mode in {"100644", "100755"},
            "source tree mode changed",
        )
        raw = git(["cat-file", "blob", blob])
        _expect(
            (_ROOT / path).read_bytes() == raw, "working dependency changed: " + path
        )
        if path in historical:
            _expect(
                git(["show", f"{_HISTORICAL_SOURCE}:{path}"]) == raw,
                "historical capture bytes changed: " + path,
            )
        files.append(
            {
                "path": path,
                "bytes": len(raw),
                "digest": _digest(raw),
                "mode": mode,
                "blob": blob,
            }
        )
    return {
        "commit": commit,
        "tree": git(["rev-parse", "HEAD^{tree}"]).decode().strip(),
        "parent": git(["rev-parse", "HEAD^"]).decode().strip(),
        "files": files,
        "signature": {
            "key": acquisition.shared._SIGNING_KEY,
            "status": "GOOD_LOCAL_VERIFICATION",
        },
    }


def _namespace_state() -> dict[str, Any]:
    commands = {
        "containers": [
            *acquisition._DOCKER,
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            "name=^/aragorn-phase3-final-combined-v3-det01-[0-9]+$",
        ],
        "volumes": [
            *acquisition._DOCKER,
            "volume",
            "ls",
            "--format",
            "{{.Name}}",
            "--filter",
            "label=dev.aragorn.role=final-combined-v3-det01-subfixture",
        ],
    }
    state = {
        name: acquisition._run(argv).decode().splitlines()
        for name, argv in commands.items()
    }
    _expect(
        not any(state.values()),
        "capture resources remain or another DET-01 capture is active",
    )
    return {"commands": commands, **state}


def _invoke(output: Path) -> dict[str, Any]:
    argv = ["/bin/sh", str(_ROOT / _RECIPE), str(output)]
    # The pinned recipe owns its resources and has signal/EXIT cleanup traps.
    # Give those traps time to finish if the bounded invocation times out.
    started = _now()
    with (
        TemporaryDirectory(prefix="aragorn-det01-logs-") as directory,
        (Path(directory) / "stdout").open("w+b") as stdout,
        (Path(directory) / "stderr").open("w+b") as stderr,
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
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            raise
        completed = _now()
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
        "stdout": collector._raw(out),
        "stderr": collector._raw(err),
    }


def _verify_capture(
    raw: bytes,
    source: dict[str, Any],
    bound: dict[str, Any],
    invocation: dict[str, Any],
    directory: Path,
) -> dict[str, Any]:
    evidence = checks.semantic._load_canonical(raw, "fresh DET-01 capture")
    checks._verify_scalar_types(evidence)
    _expect(
        set(evidence)
        == {
            "schema",
            "authority",
            "case_id",
            "recorded_at",
            "harness",
            "source_artifacts",
            "subfixture",
            "decision",
            "limitations",
        }
        and evidence["schema"] == collector._SCHEMA
        and evidence["authority"] == collector._AUTHORITY
        and evidence["case_id"] == "DET-01"
        and evidence["decision"] == collector._decision("OBSERVED")
        and evidence["limitations"] == collector._LIMITATIONS,
        "observation envelope changed",
    )
    stamp = checks._timestamp(evidence["recorded_at"])
    _expect(
        checks._timestamp(invocation["started_at"])
        < stamp
        < checks._timestamp(invocation["completed_at"]),
        "capture does not belong to this invocation interval",
    )
    harness = evidence["harness"]["document"]
    harness_path = directory / "harness.json"
    harness_path.write_bytes(_canonical(harness))
    _expect(collector._harness(harness_path) == evidence["harness"], "harness changed")
    _expect(
        harness["source_commit"] == source["commit"]
        and harness["parent_image_id"]
        == bound["request"]["frozen_parent"]["identity"]["image_id"]
        and checks._decode(harness["source_commit_verification"]["commit_object"])
        == acquisition.shared._git(["cat-file", "commit", source["commit"]]),
        "source or parent changed",
    )
    artifacts = evidence["source_artifacts"]
    _expect(
        set(artifacts)
        == {"capture_recipe", "collector", "dockerfile", "pinned_sources"},
        "capture source inventory changed",
    )
    records = [
        artifacts[key] for key in ("capture_recipe", "collector", "dockerfile")
    ] + artifacts["pinned_sources"]
    expected_paths = {
        _RECIPE,
        _DOCKERFILE,
        str(Path(collector.__file__).relative_to(_ROOT)),
        *[path.removeprefix("/src/") for path in collector._SOURCE_PINS],
    }
    _expect(
        len(records) == len(expected_paths)
        and {item["path"].removeprefix("/src/") for item in records} == expected_paths,
        "capture source paths changed",
    )
    source_files = {item["path"]: item for item in source["files"]}
    signed = {}
    for record in records:
        path = record["path"].removeprefix("/src/")
        identity = source_files[path]
        expected_mode = "0555" if identity["mode"] == "100755" else "0444"
        _expect(
            record["path"] == "/src/" + path
            and record["bytes"] == identity["bytes"]
            and record["digest"] == identity["digest"]
            and record["stat"]["mode"] == expected_mode
            and record["stat"]["uid"] == record["stat"]["gid"] == 0
            and record["stat"]["nlink"] == 1
            and record["stat"]["type"] == "file"
            and record["stat"]["size"] == identity["bytes"],
            "capture source bytes or custody changed",
        )
        signed[path] = (_ROOT / path).read_bytes()
    # This helper checks the captured replay/lifecycle only. The historical
    # dedicated-PASS entry point is deliberately not called for fresh evidence.
    checks._verify_subfixture(evidence["subfixture"], evidence["recorded_at"], signed)
    subfixture = evidence["subfixture"]
    descriptor = bound["descriptor"]
    _expect(
        subfixture["materializer"]["command"]["argv"]
        == descriptor["materializer"]["argv"]
        and subfixture["replay"]["command"]["argv"] == descriptor["argv"],
        "actual argv differs from bound request",
    )
    expected_bundle = [
        {key: item[key] for key in ("name", "bytes", "digest", "role")}
        | {"mode": "0444"}
        for item in bound["bindings"]["bundle_files"]
    ]
    _expect(
        subfixture["bundle"] == expected_bundle,
        "executed bundle differs from request binding",
    )
    return evidence


def _verify_cleanup(evidence: dict[str, Any]) -> dict[str, Any]:
    state = _namespace_state()
    harness = evidence["harness"]["document"]
    container = harness["container_id"]
    volume = harness["subfixture_volume_identity"]["name"]
    _expect(
        re.fullmatch(r"[0-9a-f]{64}", container) is not None,
        "cleanup container id changed",
    )
    command = [
        *acquisition._DOCKER,
        "ps",
        "-aq",
        "--no-trunc",
        "--filter",
        "id=" + container,
    ]
    _expect(not acquisition._run(command).strip(), "captured container remains")
    volume_command = [*acquisition._DOCKER, "volume", "ls", "--format", "{{.Name}}"]
    _expect(
        volume not in acquisition._run(volume_command).decode().splitlines(),
        "captured volume remains",
    )
    return {
        "checked_at": _now(),
        "namespace": state,
        "container_id": container,
        "volume_name": volume,
        "container_query": command,
        "volume_query": volume_command,
        "container_absent": True,
        "volume_absent": True,
        "authority": "LOCAL_DOCKER_DAEMON_OBSERVATION_NOT_EXTERNAL_ATTESTATION",
    }


def capture_det01(
    contract: dict[str, Any], request: dict[str, Any], *, evidence_cas: CAS
) -> dict[str, Any]:
    contract = campaign.validate_openclaw_final_v3_campaign_contract(contract)
    expected = campaign.build_openclaw_final_v3_subfixture_request(contract, "DET-01")
    _expect(
        type(request) is dict and _canonical(request) == _canonical(expected),
        "request changed",
    )
    source = _source_identity()
    with TemporaryDirectory(prefix="aragorn-det01-campaign-") as temporary:
        directory = Path(temporary).resolve()
        bundle = directory / "bundle"
        materializer.materialize_openclaw_final_v3_det01(bundle)
        bound = binding.bind_openclaw_final_v3_det01_request(
            contract, expected, bundle_root=bundle
        )
        before = snapshot.snapshot_parent(contract["frozen_parent"]["identity"])
        namespace_before = _namespace_state()
        output = directory / "native.json"
        try:
            invocation = _invoke(output)
            fd = os.open(output, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                _expect(
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_nlink == 1
                    and 0 < metadata.st_size <= _MAX_BYTES,
                    "native output file changed",
                )
                raw = stream.read(_MAX_BYTES + 1)
                _expect(len(raw) == metadata.st_size, "native output size changed")
            evidence = _verify_capture(raw, source, bound, invocation, directory)
            cleanup = _verify_cleanup(evidence)
        finally:
            _namespace_state()  # Check residue even when parsing or verification fails.
        after = snapshot.snapshot_parent(contract["frozen_parent"]["identity"])
        _expect(
            before["image_inspect"] == after["image_inspect"]
            and before["volume_inspect"] == after["volume_inspect"]
            and before["content"]["runtime_tree_before"]
            == after["content"]["runtime_tree_after"]
            and {
                name: item["content_base64"]
                for name, item in before["content"]["contract_files"].items()
            }
            == {
                name: item["content_base64"]
                for name, item in after["content"]["contract_files"].items()
            },
            "frozen parent changed during invocation",
        )
        _expect(
            _source_identity() == source, "signed wrapper source changed during capture"
        )
        document = {
            "schema": "aragorn/openclaw-final-v3-det01-campaign-observation/v1",
            "authority": "WRAPPER_BOUND_FRESH_DET01_OBSERVATION_NOT_CAMPAIGN_QUALIFICATION_AUTHORITY",
            "recorded_at": _now(),
            "request_binding": bound,
            "source": source,
            "invocation": invocation,
            "native_capture": collector._raw(raw),
            "parent_before": before,
            "parent_after": after,
            "namespace_before": namespace_before,
            "cleanup": cleanup,
            "campaign_binding": {
                "nonce": expected["campaign_nonce"],
                "fixture_id": expected["case"]["fixture_id"],
                "association": "HOST_WRAPPER_INVOCATION_NOT_COLLECTOR_NONCE_OBSERVATION",
            },
            "decision": {
                **{
                    key: False
                    for key in checks.semantic._FALSE_DECISION
                    if key.endswith("_eligible")
                },
                "status": "DET01_WRAPPER_BOUND_OBSERVED_NOT_QUALIFIED",
            },
            "limitations": [
                "ONE_CASE_ONLY_NOT_31_CASE_CAMPAIGN_EXECUTION_OR_RESUME",
                "CAMPAIGN_NONCE_BOUND_BY_WRAPPER_NOT_ECHOED_BY_NATIVE_COLLECTOR",
                "PARENT_SNAPSHOTS_DO_NOT_ESTABLISH_AN_EXCLUSIVE_RUNTIME_VOLUME_LEASE",
                "EXISTING_LOCAL_PRIVILEGED_SYSTEMD_RECIPE_NETWORK_NONE",
                "NO_INDEPENDENT_CAMPAIGN_QUALIFICATION_ADMISSION_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
            ],
        }
    # Publish only after native resources AND private wrapper staging are gone.
    raw = _canonical(document) + b"\n"
    _expect(len(raw) <= _MAX_BYTES, "campaign observation exceeded bound")
    digest = evidence_cas.put_expected(
        io.BytesIO(raw), expected_digest=_digest(raw), max_bytes=_MAX_BYTES
    )
    _expect(
        evidence_cas.read(digest, max_bytes=_MAX_BYTES) == raw, "CAS readback changed"
    )
    return {
        "document": document,
        "result": {
            "case_id": "DET-01",
            "fixture_id": expected["case"]["fixture_id"],
            "parent_identity_digest": expected["frozen_parent"]["digest"],
            "fresh": True,
            "destroyed": True,
            "outcome": "OBSERVED",
            "evidence_refs": [digest],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-nonce", required=True)
    parser.add_argument("--cas-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        contract = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce=args.campaign_nonce
        )
        request = campaign.build_openclaw_final_v3_subfixture_request(
            contract, "DET-01"
        )
        _expect(
            args.output.is_absolute() and not os.path.lexists(args.output),
            "output must be absent and absolute",
        )
        os.chdir(_ROOT)
        result = capture_det01(contract, request, evidence_cas=CAS(args.cas_root))
        raw = _canonical(result["document"]) + b"\n"
        acquisition._write_output(args.output, raw)
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
        print(f"DET-01 campaign capture failed closed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
