"""Qualify the exact signed standalone V3 DET-01 capture, not a campaign."""

from __future__ import annotations

import base64
import binascii
import hashlib
import runpy
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from . import admission_openclaw_final_v3_det01 as semantic
from . import admission_openclaw_final_v3_workshop_invalidation_subfixture as custody
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[2]
_SOURCE = {
    "commit": "b2c6c84f61e2182286a9d99d0e3cfba748c451cb",
    "parent": "63b36792758ed9e7d0c0adfbb0b50fd44ccf77f7",
    "tree": "fb4596d7eb4f23409168a4407a423290c85d94fb",
}
_RETENTION = {
    "commit": "b20c4937aef02aa6dcefb87b3bdf1c93b1c186e7",
    "parent": _SOURCE["commit"],
    "tree": "7c751af36a3e450be875dfe5d38322d661649c2a",
}
_EVIDENCE = {
    "bytes": 60_060,
    "digest": "sha256:9da723b2812f7fb9fbee02ae64dcdf6a5ef212628c5d87e5a6d352411c2a23d1",
    "path": "benchmark/evidence/runtime-action-worker-final-combined-v3-det01-systemd-p3-final-2026-09-03.json",
}
_BLOB = "3e9141d93523a3911f356552fa9d131e672b957f"
_IMAGE = "sha256:fb0d604f9ef6d1a8a015638bebf9c249484fd81fa6e1f6a304d3d9263304e64f"
_CASE_ROOT = "/campaign/cases/00-det-01"
_PYTHON = "/usr/local/bin/python3.12"
_MATERIALIZER = "scripts/materialize_openclaw_final_v3_det01.py"
_COLLECTOR = "scripts/runtime_action_worker_final_combined_v3_det01_systemd_probe.py"
_INHERITED_RECIPE = "scripts/capture_runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd.sh"
_ENVIRONMENT = {
    "LANG": "C", "LC_ALL": "C", "PATH": "/usr/local/bin:/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0", "TZ": "UTC",
}


def qualify_openclaw_final_v3_det01_subfixture(*, evidence_cas: CAS) -> dict[str, Any]:
    """Return one retained DET-01 case PASS with every profile gate still false."""
    try:
        custody._verify_dependencies()
        base = custody.parent.v3_contract.config.base
        git = base.legacy._git
        _expect(
            Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve() == _ROOT
            and git(["rev-parse", "--show-object-format"]).strip() == b"sha1",
            "qualification repository changed",
        )
        base._verify_commit(_SOURCE)
        base._verify_commit(_RETENTION)
        _expect(
            git(["diff-tree", "--no-commit-id", "--name-status", "-r", "--no-renames",
                 _SOURCE["commit"], _RETENTION["commit"]])
            == f"A\t{_EVIDENCE['path']}\n".encode(),
            "retention is not evidence-only",
        )
        retained = custody._read_signed_blob(
            git, commit=_RETENTION["commit"], mode="100644", blob=_BLOB,
            bytes_=_EVIDENCE["bytes"], digest=_EVIDENCE["digest"], path=_EVIDENCE["path"],
        )
        raw = custody.parent.v3_contract.contract._read_blob(evidence_cas, _EVIDENCE, "DET-01")
        _expect(raw == retained, "CAS differs from signed retention")
        evidence = semantic._load_canonical(raw, "retained DET-01 capture")
        _expect(
            set(evidence) == {"schema", "authority", "case_id", "recorded_at", "harness",
                              "source_artifacts", "subfixture", "decision", "limitations"}
            and evidence["case_id"] == "DET-01"
            and evidence["recorded_at"] == "2026-09-03T18:27:29.006910Z",
            "capture envelope changed",
        )
        _verify_scalar_types(evidence)
        custody.parent.v3_contract.config._verify_no_positive_eligibility(evidence)
        signed = _verify_sources(evidence["source_artifacts"], git)
        collector = runpy.run_path(str(_ROOT / _COLLECTOR))
        _expect(
            evidence["schema"] == collector["_SCHEMA"]
            and evidence["authority"] == collector["_AUTHORITY"]
            and evidence["decision"] == collector["_decision"]("OBSERVED")
            and evidence["limitations"] == collector["_LIMITATIONS"],
            "capture authority or decision changed",
        )
        _verify_harness(evidence["harness"], collector, git)
        result = _verify_subfixture(evidence["subfixture"], evidence["recorded_at"], signed)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, binascii.Error, CASError, KeyError, OSError,
            IndexError, TypeError, ValueError, RuntimeError) as exc:
        raise AdmissionEvidenceError(f"invalid dedicated V3 DET-01 evidence: {exc}") from exc

    return {
        "schema": "aragorn/openclaw-final-admission-v3-det01-dedicated-qualification/v1",
        "assurance": "ONE_EXACT_SIGNED_PRIVATE_V3_DET01_REPLAY_CASE_ONLY",
        "case": {"id": "DET-01", "status": "PASS"},
        "decision": {
            **{key: False for key in semantic._FALSE_DECISION if key.endswith("_eligible")},
            "status": "DEDICATED_DET01_CASE_PASS_NOT_PROFILE_OR_CAMPAIGN_QUALIFICATION",
        },
        "bindings": {
            "observation": dict(_EVIDENCE),
            "source": dict(_SOURCE),
            "retention": dict(_RETENTION),
            "signing_key": custody.parent.v3_contract.contract._SIGNATURE["key"],
            "image": _IMAGE,
            "harness_digest": evidence["harness"]["digest"],
            "replay_semantics_canonical_digest": canonical_digest(result),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "capture": {
            "dedicated_container_and_volume": True,
            "fresh_path_and_destruction_protocol_verified": True,
            "independent_host_destruction_attestation": False,
        },
        "replay": {"cases": ["allow", "deny", "error", "review"], "seeds": ["1", "2", "3"]},
        "limitations": [
            "ONE_EXACT_RETAINED_DET01_REPLAY_CASE_ONLY",
            "NOT_FINAL_CAMPAIGN_SUBFIXTURE_EVIDENCE",
            "PINNED_CAPTURE_RECIPE_CLEANUP_NOT_INDEPENDENT_HOST_ATTESTATION",
            "EXECUTION_ENVIRONMENT_BOUND_TO_CAPTURE_NOT_INDEPENDENTLY_ATTESTED",
            "SOURCE_ANALYZER_RESULTS_ARE_FIXED_RETAINED_VECTORS",
            "DECISION_ONLY_NOT_RUNTIME_ACTIVATION_OR_INSTALLER_AUTHORITY",
            "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_SUBFIXTURE_PUBLIC_NETWORK_DENIED",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "source_recorded_at": evidence["recorded_at"],
    }


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(f"V3 DET-01 {message}")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_scalar_types(value: Any) -> None:
    boolean_keys = {"privileged", "readonly_rootfs", "rw", "fresh_path_observed",
                    "destroyed_before_capture_return"}
    if type(value) is dict:
        for key, item in value.items():
            _expect((key in boolean_keys or key.endswith("_eligible")) == (type(item) is bool),
                    "boolean field type changed")
            _verify_scalar_types(item)
    elif type(value) is list:
        for item in value:
            _expect(type(item) is not bool, "boolean list item changed")
            _verify_scalar_types(item)
    else:
        _expect(type(value) in (str, int, bool, type(None)), "scalar type changed")


def _verify_sources(artifacts: dict[str, Any], git: Any) -> dict[str, bytes]:
    # The exact signed observation pins these records; resolve each back into
    # the signed source tree before loading any capture or materializer code.
    _expect(set(artifacts) == {"capture_recipe", "collector", "dockerfile", "pinned_sources"},
            "source inventory changed")
    records = [artifacts[key] for key in ("capture_recipe", "collector", "dockerfile")]
    records += artifacts["pinned_sources"]
    expected_paths = {
        "scripts/capture_runtime_action_worker_final_combined_v3_det01_systemd.sh",
        _COLLECTOR, _MATERIALIZER,
        "benchmark/runtime-action-worker-final-combined-v3-det01-systemd/Dockerfile",
        "scripts/run_admission_authority_replay.py",
        "benchmark/admission/openclaw-v2026.7.1/deterministic-authority-vectors-v1.json",
        *["src/" + name for name in semantic._FILES if name.startswith("aragorn/")],
    }
    _expect(len(records) == len(expected_paths)
            and {item["path"].removeprefix("/src/") for item in records} == expected_paths,
            "source paths changed")
    signed = {}
    for item in records:
        path = item["path"].removeprefix("/src/")
        raw = git(["show", f"{_SOURCE['commit']}:{path}"], maximum=item["bytes"] + 1)
        blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False).hexdigest()
        mode = "100755" if path.endswith(".sh") or path in {_COLLECTOR, _MATERIALIZER} else "100644"
        custody._read_signed_blob(git, commit=_SOURCE["commit"], mode=mode, blob=blob,
                                 bytes_=item["bytes"], digest=item["digest"], path=path)
        metadata = item["stat"]
        _expect(item["path"] == "/src/" + path
                and metadata["uid"] == metadata["gid"] == 0
                and metadata["nlink"] == 1 and metadata["type"] == "file"
                and metadata["size"] == len(raw)
                and metadata["mode"] == ("0555" if mode == "100755" else "0444"),
                "source custody changed")
        _expect((_ROOT / path).read_bytes() == raw, f"working source dependency changed: {path}")
        signed[path] = raw
    # Also bind the inherited cleanup recipe and independent semantic verifier.
    for path in (_INHERITED_RECIPE, "src/aragorn/admission_openclaw_final_v3_det01.py",
                 "src/aragorn/admission_evidence.py", "src/aragorn/oci_worker_protocol.py"):
        raw = git(["show", f"{_SOURCE['commit']}:{path}"], maximum=262_144)
        _expect((_ROOT / path).read_bytes() == raw, f"verification dependency changed: {path}")
    return signed


def _decode(record: dict[str, Any]) -> bytes:
    _expect(set(record) == {"base64", "bytes", "digest"}
            and type(record["bytes"]) is int and 0 <= record["bytes"] <= 1_048_576
            and type(record["base64"]) is str and len(record["base64"]) <= 1_398_104,
            "raw record shape changed")
    raw = base64.b64decode(record["base64"], validate=True)
    _expect(len(raw) == record["bytes"] and _digest(raw) == record["digest"]
            and base64.b64encode(raw).decode() == record["base64"], "raw record identity changed")
    return raw


def _verify_harness(envelope: dict[str, Any], collector: dict[str, Any], git: Any) -> None:
    document = envelope["document"]
    _expect(set(envelope) == {"digest", "document"}
            and envelope["digest"] == canonical_digest(document)
            and document["source_commit"] == _SOURCE["commit"]
            and document["image_id"] == _IMAGE,
            "harness binding changed")
    # Reuse the pinned collector's complete host/mount/lineage shape checks;
    # its recorded source signature is independently joined to signed Git below.
    with TemporaryDirectory(prefix="aragorn-det01-harness-") as temporary:
        path = Path(temporary) / "harness.json"
        path.write_bytes(canonical_json(document))
        _expect(collector["_harness"](path) == envelope, "harness recomputation changed")
    verification = document["source_commit_verification"]
    _expect(_decode(verification["commit_object"])
            == git(["cat-file", "commit", _SOURCE["commit"]]), "recorded commit object changed")
    _decode(verification["stdout"])
    _decode(verification["stderr"])


def _verify_command(command: dict[str, Any], *, argv: list[str], cwd: str) -> bytes:
    _expect(set(command) == {"argv", "cwd", "environment", "exit_code", "started_at",
                             "completed_at", "stdout", "stderr"}
            and command["argv"] == argv and command["cwd"] == cwd
            and command["environment"] == _ENVIRONMENT
            and type(command["exit_code"]) is int and command["exit_code"] == 0
            and _decode(command["stderr"]) == b"", "command changed")
    _expect(_timestamp(command["started_at"]) < _timestamp(command["completed_at"]),
            "command chronology changed")
    return _decode(command["stdout"])


def _timestamp(value: str) -> datetime:
    _expect(type(value) is str and value.endswith("Z"), "timestamp changed")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _verify_subfixture(subfixture: dict[str, Any], recorded_at: str,
                       signed: dict[str, bytes]) -> dict[str, Any]:
    _expect(set(subfixture) == {"bundle", "lifecycle", "materializer", "replay", "vector_set"},
            "subfixture inventory changed")
    lifecycle = subfixture["lifecycle"]
    before, during, after = [lifecycle[key] for key in
                            ("before_materialization", "during_execution", "after_destruction")]
    _expect(set(lifecycle) == {"before_materialization", "during_execution", "after_destruction",
                              "root", "destroyed_before_capture_return", "fresh_path_observed"}
            and lifecycle["root"] == _CASE_ROOT
            and lifecycle["fresh_path_observed"] is True
            and lifecycle["destroyed_before_capture_return"] is True
            and before == after and before["entries"] == []
            and during["entries"] == sorted(["cases", "cases/00-det-01", "cases/00-det-01/aragorn",
                                              *["cases/00-det-01/" + n for n in semantic._FILES]]),
            "freshness or destruction changed")
    for snapshot in (before, during, after):
        stat = snapshot["root"]
        _expect(set(snapshot) == {"entries", "root"} and stat["type"] == "directory"
                and stat["uid"] == stat["gid"] == 0 and stat["mode"] == "0755"
                and (stat["device"], stat["inode"]) == (before["root"]["device"], before["root"]["inode"]),
                "volume custody changed")
    materializer, replay = subfixture["materializer"], subfixture["replay"]
    _expect(set(materializer) == {"command", "manifest"}
            and set(replay) == {"command", "document"}, "execution envelope changed")
    manifest_raw = _verify_command(materializer["command"],
                                  argv=[_PYTHON, "/src/" + _MATERIALIZER, _CASE_ROOT], cwd="/src")
    replay_raw = _verify_command(replay["command"],
                                argv=[_PYTHON, _CASE_ROOT + "/run_admission_authority_replay.py"], cwd=_CASE_ROOT)
    _expect(manifest_raw == canonical_json(materializer["manifest"]) + b"\n"
            and replay_raw == canonical_json(replay["document"]) + b"\n"
            and _timestamp(materializer["command"]["completed_at"])
            < _timestamp(replay["command"]["started_at"])
            < _timestamp(replay["document"]["recorded_at"])
            <= _timestamp(replay["command"]["completed_at"]) < _timestamp(recorded_at),
            "output or chronology join changed")
    profile = replay["document"]["environment"]["profile"]
    _expect(profile["argv"] == [_PYTHON, "-m", "aragorn.admission_decision"]
            and profile["cwd"] == _CASE_ROOT and profile["python_implementation"] == "CPython"
            and profile["python_version"] == "3.12.13"
            and profile["executable_digest"] == "sha256:7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57"
            and profile["system"] == "Linux-6.8.0-117-generic-aarch64-with-glibc2.36",
            "captured replay environment changed")
    _expect((_ROOT / _MATERIALIZER).read_bytes() == signed[_MATERIALIZER], "materializer changed")
    module = runpy.run_path(str(_ROOT / _MATERIALIZER))
    with TemporaryDirectory(prefix="aragorn-det01-qualify-") as temporary:
        bundle = Path(temporary) / "bundle"
        manifest = module["materialize_openclaw_final_v3_det01"](bundle)
        _expect(materializer["manifest"] == manifest, "materialized manifest changed")
        expected = [{**item, "mode": "0444", "role": "probe" if item["name"].endswith(".py")
                     and not item["name"].startswith("aragorn/") else "vector"
                     if item["name"].endswith(".json") else "probe-dependency"} for item in manifest["files"]]
        _expect(subfixture["bundle"] == expected, "bundle role or inventory changed")
        _expect(_decode(subfixture["vector_set"])
                == (bundle / "deterministic-authority-vectors-v1.json").read_bytes(), "retained vectors changed")
        return semantic.verify_openclaw_final_v3_det01_observation(replay_raw, bundle_root=bundle)
