"""Offline qualification of one exact retained wrapper-associated DET-01 replay."""

from __future__ import annotations

import binascii
import hashlib
import importlib
import os
import re
import stat
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from . import admission_openclaw_final_v3_det01_qualification as checks
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[2]
_SOURCE = {
    "commit": "a37fc94d2a0fbf0ee7ad43b1be61969d8231ebb5",
    "parent": "7a06ebb97f53665b5d8a5102a4e6bae4d73d47cd",
    "tree": "8712b4e22faea00ed642b0ee4d510b72b60c7458",
}
_RETENTION = {
    "commit": "38bbd344dbce513c89b08b0d27448f7136eaa185",
    "parent": _SOURCE["commit"],
    "tree": "b0ef13202a4ddec53d05ce0379866058606123c4",
}
_EVIDENCE = {
    "bytes": 283_422,
    "digest": "sha256:106bf0d438b8a0ec054d104de62aa955eec80fc79b9a1a128cd918ae90ccd484",
    "path": "benchmark/evidence/openclaw-final-v3-det01-campaign-observation-2026-09-08.json",
}
_BLOB = "4dd888b56931f0e68f87e2ecb282d0bd00e86432"
_SOURCE_DIGEST = (
    "sha256:f2feed057131b25d71ca6bf9dbd91c595498206624ea6fd6ade015bc92d4e73f"
)
_NONCE = "3ba71141b94dbd2372a9bf60e671ac7b290db77bfaf8330497ed96ba473b49b2"
_RECIPE = "scripts/capture_runtime_action_worker_final_combined_v3_det01_systemd.sh"
_OUTPUT = "/private/var/folders/c_/s8td4jhd5275m1dmzrb2lnb00000gn/T/aragorn-det01-campaign-iqeymcsf/native.json"
_DOCKER = ["docker", "--context", "colima-aragorn-bakeoff"]
_ASSOCIATION = "HOST_WRAPPER_INVOCATION_NOT_COLLECTOR_NONCE_OBSERVATION"
_OBSERVATION_LIMITATIONS = [
    "ONE_CASE_ONLY_NOT_31_CASE_CAMPAIGN_EXECUTION_OR_RESUME",
    "CAMPAIGN_NONCE_BOUND_BY_WRAPPER_NOT_ECHOED_BY_NATIVE_COLLECTOR",
    "PARENT_SNAPSHOTS_DO_NOT_ESTABLISH_AN_EXCLUSIVE_RUNTIME_VOLUME_LEASE",
    "EXISTING_LOCAL_PRIVILEGED_SYSTEMD_RECIPE_NETWORK_NONE",
    "NO_INDEPENDENT_CAMPAIGN_QUALIFICATION_ADMISSION_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]
_LIMITATIONS = [
    "ONE_EXACT_RETAINED_WRAPPER_ASSOCIATED_DET01_REPLAY_ONLY",
    "CAMPAIGN_NONCE_BOUND_BY_WRAPPER_NOT_ECHOED_BY_NATIVE_COLLECTOR",
    "LOCAL_DOCKER_DAEMON_OBSERVATION_NOT_EXTERNAL_ATTESTATION",
    "PARENT_SNAPSHOTS_DO_NOT_ESTABLISH_AN_EXCLUSIVE_RUNTIME_VOLUME_LEASE",
    "SNAPSHOT_ORDER_FROM_SIGNED_WRAPPER_NOT_INDEPENDENT_TIMESTAMPS",
    "RECORDED_RUNTIME_TREE_IDENTITY_NOT_CONSUMER_REHASH_OF_RUNTIME_FILE_BYTES",
    "FRESH_AT_RETAINED_INVOCATION_NOT_CURRENT_FRESHNESS_OR_REUSE_AUTHORITY",
    "SOURCE_ANALYZER_RESULTS_ARE_FIXED_RETAINED_VECTORS",
    "DECISION_ONLY_NOT_RUNTIME_ACTIVATION_OR_INSTALLER_AUTHORITY",
    "NO_CAMPAIGN_EXECUTION_RESUME_ANTI_REPLAY_OR_AGGREGATE_PASS",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError("V3 wrapper DET-01 " + message)


def _same(left: Any, right: Any) -> bool:
    return canonical_json(left) == canonical_json(right)


def _false_decision(status: str) -> dict[str, Any]:
    return {
        **{
            key: False
            for key in checks.semantic._FALSE_DECISION
            if key.endswith("_eligible")
        },
        "status": status,
    }


def _verify_scalar_types(value: Any) -> None:
    boolean_keys = {
        "container_absent",
        "container_name_absent",
        "daemon_reachable",
        "destroy_before_next",
        "entries_truncated",
        "exists",
        "explicit",
        "fresh",
        "native_execution_enabled",
        "read_only",
        "ready",
        "reuse",
        "runtime_tree_function_unchanged",
        "volume_absent",
    }
    if type(value) is dict:
        for key, item in value.items():
            _expect(
                type(key) is str
                and (
                    (key in boolean_keys or key.endswith("_eligible"))
                    == (type(item) is bool)
                ),
                "boolean field type changed",
            )
            _verify_scalar_types(item)
    elif type(value) is list:
        for item in value:
            _expect(type(item) is not bool, "boolean list item changed")
            _verify_scalar_types(item)
    else:
        _expect(type(value) in (str, int, bool, type(None)), "scalar type changed")


def _verify_bootstrap() -> None:
    # These exact source-closure members are checked without calling their
    # verification functions. The complete signed closure is checked below.
    for module, filename, size, digest in (
        (
            checks,
            "admission_openclaw_final_v3_det01_qualification.py",
            16818,
            "a69aa5639c7036fc080ef58f188eedc48e53ee965fa7b84d7c1ed8189fd0356c",
        ),
        (
            checks.custody,
            "admission_openclaw_final_v3_workshop_invalidation_subfixture.py",
            59335,
            "7d120dd2d925b1e2ea3bf0cde46edb977627c809af111e5c861df1ee93162a5c",
        ),
        (
            checks.semantic,
            "admission_openclaw_final_v3_det01.py",
            13116,
            "26909c694e9e2468d4fb75d46b22c73c8f1efd3cd0a1db5798f024982ada31b9",
        ),
    ):
        path = _ROOT / "src/aragorn" / filename
        _expect(
            Path(module.__file__).resolve() == path
            and not any(p.is_symlink() for p in (path, *path.parents)),
            "bootstrap module path changed",
        )
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            _expect(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and before.st_size == size,
                "bootstrap module file changed",
            )
            raw = stream.read(size + 1)
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
            all(getattr(before, key) == getattr(after, key) for key in fields)
            and len(raw) == size
            and hashlib.sha256(raw).hexdigest() == digest,
            "bootstrap module bytes changed",
        )


def qualify_openclaw_final_v3_det01_campaign_observation(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Qualify this retained replay only; never produce a campaign case result."""
    # ponytail: one exact signed capture. A new capture requires reviewed pins;
    # this consumer does not generalize acquisition or campaign execution.
    try:
        _verify_bootstrap()
        checks.custody._verify_dependencies()
        base = checks.custody.parent.v3_contract.config.base
        git = base.legacy._git
        _expect(
            Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve()
            == _ROOT
            and git(["rev-parse", "--show-object-format"]).strip() == b"sha1",
            "repository changed",
        )
        base._verify_commit(_SOURCE)
        base._verify_commit(_RETENTION)
        _expect(
            git(
                [
                    "diff-tree",
                    "--no-commit-id",
                    "--name-status",
                    "-r",
                    "--no-renames",
                    _SOURCE["commit"],
                    _RETENTION["commit"],
                ]
            )
            == f"A\t{_EVIDENCE['path']}\n".encode(),
            "retention is not immediate evidence-only retention",
        )
        retained = checks.custody._read_signed_blob(
            git,
            commit=_RETENTION["commit"],
            mode="100644",
            blob=_BLOB,
            bytes_=_EVIDENCE["bytes"],
            digest=_EVIDENCE["digest"],
            path=_EVIDENCE["path"],
        )
        raw = checks.custody.parent.v3_contract.contract._read_blob(
            evidence_cas, _EVIDENCE, "wrapper DET-01"
        )
        _expect(raw == retained, "CAS differs from signed retention")
        document = checks.semantic._load_canonical(raw, "wrapper DET-01 observation")
        proof = _verify_observation(document)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        binascii.Error,
        CASError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
    ) as exc:
        raise AdmissionEvidenceError(f"invalid wrapper DET-01 evidence: {exc}") from exc
    return {
        "schema": "aragorn/openclaw-final-admission-v3-det01-wrapper-qualification/v1",
        "authority": "ONE_EXACT_WRAPPER_ASSOCIATED_REPLAY_NOT_CAMPAIGN_QUALIFICATION_AUTHORITY",
        "evidence": dict(_EVIDENCE),
        "source": dict(_SOURCE),
        "retention": dict(_RETENTION),
        "case": {"id": "DET-01", "status": "PASS"},
        "decision": _false_decision(
            "EXACT_WRAPPER_ASSOCIATED_REPLAY_PASS_NOT_CAMPAIGN_QUALIFICATION"
        ),
        "bindings": proof,
        "verifier": {
            "implementation_digest": checks._digest(Path(__file__).read_bytes())
        },
        "limitations": list(_LIMITATIONS),
    }


def _verify_sources(source: dict[str, Any]) -> dict[str, bytes]:
    # The signed observation pins the complete 37-file closure, including the
    # host wrapper. Check bytes before importing any acquisition helper code.
    _expect(
        set(source) == {"commit", "parent", "tree", "signature", "files"}
        and {key: source[key] for key in _SOURCE} == _SOURCE
        and canonical_digest(source) == _SOURCE_DIGEST
        and type(source["files"]) is list
        and len(source["files"]) == 37,
        "recorded source closure changed",
    )
    git = checks.custody.parent.v3_contract.config.base.legacy._git
    signed = {}
    for item in source["files"]:
        _expect(
            set(item) == {"path", "bytes", "digest", "mode", "blob"}
            and type(item["bytes"]) is int
            and 0 < item["bytes"] <= 1_048_576
            and item["mode"] in {"100644", "100755"},
            "source record changed",
        )
        path = item["path"]
        _expect(
            type(path) is str
            and not Path(path).is_absolute()
            and ".." not in Path(path).parts
            and path not in signed,
            "source path changed",
        )
        raw = checks.custody._read_signed_blob(
            git,
            commit=_SOURCE["commit"],
            mode=item["mode"],
            blob=item["blob"],
            bytes_=item["bytes"],
            digest=item["digest"],
            path=path,
        )
        current = _ROOT / path
        _expect(
            not any(parent.is_symlink() for parent in (current, *current.parents)),
            "working source symlink changed",
        )
        fd = os.open(current, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            _expect(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and before.st_size == item["bytes"],
                "working source file changed: " + path,
            )
            working = stream.read(item["bytes"] + 1)
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
                working == raw
                and all(getattr(before, key) == getattr(after, key) for key in fields),
                "working source changed: " + path,
            )
        signed[path] = raw
    return signed


def _load_helpers() -> dict[str, Any]:
    # Imports execute only byte-verified modules; none of the acquisition entry
    # points are called. The materializer writes only a private temporary bundle.
    added = str(_ROOT) not in sys.path
    if added:
        sys.path.insert(0, str(_ROOT))
    try:
        modules = {}
        for name, path in {
            "campaign": "aragorn.admission_openclaw_final_v3_campaign",
            "binding": "aragorn.admission_openclaw_final_v3_det01_binding",
            "materializer": "scripts.materialize_openclaw_final_v3_det01",
            "collector": "scripts.runtime_action_worker_final_combined_v3_det01_systemd_probe",
            "snapshot": "scripts.openclaw_final_v3_parent_snapshot",
            "acquisition": "scripts.capture_openclaw_final_v3_core_updater_modules",
        }.items():
            module = importlib.import_module(path)
            expected = (
                _ROOT
                / ("src" if path.startswith("aragorn.") else "")
                / (path.replace(".", "/") + ".py")
            )
            _expect(
                Path(module.__file__).resolve() == expected,
                "loaded helper module origin changed",
            )
            modules[name] = module
        return modules
    finally:
        if added:
            sys.path.remove(str(_ROOT))


def _namespace() -> dict[str, Any]:
    return {
        "commands": {
            "containers": [
                *_DOCKER,
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                "name=^/aragorn-phase3-final-combined-v3-det01-[0-9]+$",
            ],
            "volumes": [
                *_DOCKER,
                "volume",
                "ls",
                "--format",
                "{{.Name}}",
                "--filter",
                "label=dev.aragorn.role=final-combined-v3-det01-subfixture",
            ],
        },
        "containers": [],
        "volumes": [],
    }


def _verify_parent(
    snapshot: dict[str, Any], parent: dict[str, Any], helpers: dict[str, Any]
) -> None:
    _expect(
        set(snapshot)
        == {
            "schema",
            "authority",
            "parent",
            "image_inspect",
            "volume_inspect",
            "command",
            "cleanup",
            "stdout",
            "content",
            "running_users_command",
            "running_users_before",
            "running_users_after",
            "limitations",
        }
        and snapshot["schema"] == "aragorn/openclaw-final-v3-parent-snapshot/v1"
        and snapshot["authority"]
        == "POINT_IN_TIME_LOCAL_READ_ONLY_SNAPSHOT_NOT_CAMPAIGN_OR_QUALIFICATION_AUTHORITY"
        and _same(snapshot["parent"], parent)
        and snapshot["limitations"]
        == [
            "LOCAL_DOCKER_STATE_NOT_INDEPENDENTLY_ATTESTED",
            "POINT_IN_TIME_SNAPSHOT_NOT_EXCLUSIVE_RUNTIME_VOLUME_LEASE",
            "NO_NATIVE_MODULE_EXECUTION_OR_CAMPAIGN_QUALIFICATION",
        ],
        "parent envelope changed",
    )
    raw = checks._decode(snapshot["stdout"])
    content = helpers["acquisition"]._load_json(raw, "retained parent stdout")
    _expect(_same(content, snapshot["content"]), "parent stdout/content join changed")
    helpers["snapshot"]._validate_content(content, parent)
    image, volume = snapshot["image_inspect"], snapshot["volume_inspect"]
    _expect(
        image["Id"] == parent["image_id"]
        and image["RootFS"]["Type"] == "layers"
        and type(image["RootFS"]["Layers"]) is list
        and bool(image["RootFS"]["Layers"])
        and _same(
            {key: volume.get(key) for key in helpers["acquisition"]._EXPECTED_VOLUME},
            helpers["acquisition"]._EXPECTED_VOLUME,
        ),
        "parent image or volume changed",
    )
    _expect(
        _same(snapshot["running_users_before"], [])
        and _same(snapshot["running_users_after"], [])
        and snapshot["running_users_command"]
        == [
            *_DOCKER,
            "ps",
            "--filter",
            "volume=" + parent["runtime_volume"],
            "--format",
            "{{.ID}}",
        ],
        "parent user inventory changed",
    )
    cleanup = snapshot["cleanup"]
    _expect(
        set(cleanup)
        == {
            "name",
            "owner",
            "image",
            "owned_container",
            "removed_id",
            "daemon_reachable",
            "container_name_absent",
            "removed_id_absent",
            "commands",
        }
        and type(cleanup["owner"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", cleanup["owner"])
        and cleanup["name"] == "aragorn-v3-parent-snapshot-" + cleanup["owner"][:32]
        and cleanup["image"] == parent["image_id"]
        and cleanup["owned_container"]
        is cleanup["removed_id"]
        is cleanup["removed_id_absent"]
        is None
        and cleanup["daemon_reachable"] is True
        and cleanup["container_name_absent"] is True,
        "snapshot cleanup identity changed",
    )
    _expect(
        snapshot["command"]
        == helpers["snapshot"]._command(
            parent, container_name=cleanup["name"], owner=cleanup["owner"]
        ),
        "snapshot readonly command changed",
    )
    listing = [
        *_DOCKER,
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        "name=^/" + cleanup["name"] + "$",
        "--format",
        "{{.ID}}",
    ]
    _expect(
        _same(
            cleanup["commands"],
            [
                {"argv": listing, "stdout": "", "exit_code": 0},
                {
                    "argv": [*_DOCKER, "info", "--format", "{{.ServerVersion}}"],
                    "stdout": "29.5.2\n",
                    "exit_code": 0,
                },
                {"argv": listing, "stdout": "", "exit_code": 0},
            ],
        ),
        "snapshot cleanup command/output changed",
    )


def _verify_native(
    native: dict[str, Any],
    source: dict[str, Any],
    bound: dict[str, Any],
    invocation: dict[str, Any],
    signed: dict[str, bytes],
    helpers: dict[str, Any],
) -> dict[str, Any]:
    collector = helpers["collector"]
    checks._verify_scalar_types(native)
    _expect(
        set(native)
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
        and native["schema"] == collector._SCHEMA
        and native["authority"] == collector._AUTHORITY
        and native["case_id"] == "DET-01"
        and _same(native["decision"], collector._decision("OBSERVED"))
        and native["limitations"] == collector._LIMITATIONS,
        "native envelope changed",
    )
    harness = native["harness"]["document"]
    with TemporaryDirectory(prefix="aragorn-wrapper-harness-") as temporary:
        path = Path(temporary) / "harness.json"
        path.write_bytes(canonical_json(harness))
        _expect(
            _same(collector._harness(path), native["harness"]), "native harness changed"
        )
    git = checks.custody.parent.v3_contract.config.base.legacy._git
    _expect(
        harness["source_commit"] == source["commit"]
        and harness["parent_image_id"]
        == bound["request"]["frozen_parent"]["identity"]["image_id"]
        and harness["image_id"] == checks._IMAGE
        and checks._decode(harness["source_commit_verification"]["commit_object"])
        == git(["cat-file", "commit", _SOURCE["commit"]]),
        "native signed source or image changed",
    )
    artifacts = native["source_artifacts"]
    _expect(
        set(artifacts)
        == {"capture_recipe", "collector", "dockerfile", "pinned_sources"},
        "native source inventory changed",
    )
    records = [
        artifacts[key] for key in ("capture_recipe", "collector", "dockerfile")
    ] + artifacts["pinned_sources"]
    expected = {
        _RECIPE,
        checks._COLLECTOR,
        "benchmark/runtime-action-worker-final-combined-v3-det01-systemd/Dockerfile",
        *[path.removeprefix("/src/") for path in collector._SOURCE_PINS],
    }
    _expect(
        len(records) == len(expected)
        and {item["path"].removeprefix("/src/") for item in records} == expected,
        "native source paths changed",
    )
    identities = {item["path"]: item for item in source["files"]}
    for item in records:
        path = item["path"].removeprefix("/src/")
        identity, metadata = identities[path], item["stat"]
        _expect(
            set(item) == {"path", "bytes", "digest", "stat"}
            and item["path"] == "/src/" + path
            and item["bytes"] == identity["bytes"]
            and item["digest"] == checks._digest(signed[path]) == identity["digest"]
            and metadata["uid"] == metadata["gid"] == 0
            and metadata["nlink"] == 1
            and metadata["type"] == "file"
            and metadata["size"] == identity["bytes"]
            and metadata["mode"]
            == ("0555" if identity["mode"] == "100755" else "0444"),
            "native source bytes or custody changed",
        )
    subfixture = native["subfixture"]
    result = checks._verify_subfixture(subfixture, native["recorded_at"], signed)
    _expect(
        subfixture["materializer"]["command"]["argv"]
        == bound["descriptor"]["materializer"]["argv"]
        and subfixture["replay"]["command"]["argv"] == bound["descriptor"]["argv"]
        and _same(
            subfixture["bundle"],
            [
                {key: item[key] for key in ("name", "bytes", "digest", "role")}
                | {"mode": "0444"}
                for item in bound["bindings"]["bundle_files"]
            ],
        ),
        "executed request/bundle join changed",
    )
    _expect(
        checks._timestamp(invocation["started_at"])
        < checks._timestamp(subfixture["materializer"]["command"]["started_at"])
        < checks._timestamp(native["recorded_at"])
        < checks._timestamp(invocation["completed_at"]),
        "native invocation chronology changed",
    )
    return result


def _verify_observation(document: dict[str, Any]) -> dict[str, Any]:
    """Recompute internal joins; the public API additionally requires signed CAS bytes."""
    try:
        _verify_bootstrap()
        _verify_scalar_types(document)
        _expect(
            set(document)
            == {
                "schema",
                "authority",
                "recorded_at",
                "request_binding",
                "source",
                "invocation",
                "native_capture",
                "parent_before",
                "parent_after",
                "namespace_before",
                "cleanup",
                "campaign_binding",
                "decision",
                "limitations",
            }
            and document["schema"]
            == "aragorn/openclaw-final-v3-det01-campaign-observation/v1"
            and document["authority"]
            == "WRAPPER_BOUND_FRESH_DET01_OBSERVATION_NOT_CAMPAIGN_QUALIFICATION_AUTHORITY"
            and document["recorded_at"] == "2026-09-08T17:16:54.644229Z"
            and _same(
                document["decision"],
                _false_decision("DET01_WRAPPER_BOUND_OBSERVED_NOT_QUALIFIED"),
            )
            and document["limitations"] == _OBSERVATION_LIMITATIONS,
            "observation envelope changed",
        )
        checks.custody.parent.v3_contract.config._verify_no_positive_eligibility(
            document
        )
        signed = _verify_sources(document["source"])
        helpers = _load_helpers()
        campaign = helpers["campaign"]
        contract = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce=_NONCE
        )
        request = campaign.build_openclaw_final_v3_subfixture_request(
            contract, "DET-01"
        )
        _expect(
            _same(
                document["campaign_binding"],
                {
                    "nonce": _NONCE,
                    "fixture_id": request["case"]["fixture_id"],
                    "association": _ASSOCIATION,
                },
            ),
            "exact retained campaign association changed",
        )
        with TemporaryDirectory(prefix="aragorn-wrapper-binding-") as temporary:
            bundle = Path(temporary).resolve() / "bundle"
            helpers["materializer"].materialize_openclaw_final_v3_det01(bundle)
            bound = helpers["binding"].bind_openclaw_final_v3_det01_request(
                contract, request, bundle_root=bundle
            )
        _expect(
            _same(bound, document["request_binding"]),
            "request binding recomputation changed",
        )
        invocation = document["invocation"]
        _expect(
            set(invocation)
            == {"argv", "started_at", "completed_at", "exit_code", "stdout", "stderr"}
            and invocation["argv"] == ["/bin/sh", str(_ROOT / _RECIPE), _OUTPUT]
            and type(invocation["exit_code"]) is int
            and invocation["exit_code"] == 0,
            "wrapper invocation changed",
        )
        checks._decode(invocation["stdout"])
        checks._decode(invocation["stderr"])
        native_raw = checks._decode(document["native_capture"])
        native = checks.semantic._load_canonical(native_raw, "retained native DET-01")
        replay = _verify_native(
            native, document["source"], bound, invocation, signed, helpers
        )
        parent = contract["frozen_parent"]["identity"]
        before, after = document["parent_before"], document["parent_after"]
        for snapshot in (before, after):
            _verify_parent(snapshot, parent, helpers)
        for key in ("image_inspect", "volume_inspect", "content"):
            _expect(
                _same(before[key], after[key]),
                "parent changed across recorded snapshots",
            )
        _expect(
            before["cleanup"]["owner"] != after["cleanup"]["owner"],
            "snapshot identity reused",
        )
        harness = native["harness"]["document"]
        _expect(
            harness["image_lineage"]["parent"]["layers"]
            == before["image_inspect"]["RootFS"]["Layers"],
            "native parent image layers differ from snapshot",
        )
        cleanup = document["cleanup"]
        _expect(
            _same(document["namespace_before"], _namespace())
            and _same(
                cleanup,
                {
                    "authority": "LOCAL_DOCKER_DAEMON_OBSERVATION_NOT_EXTERNAL_ATTESTATION",
                    "checked_at": cleanup["checked_at"],
                    "namespace": _namespace(),
                    "container_id": harness["container_id"],
                    "volume_name": harness["subfixture_volume_identity"]["name"],
                    "container_query": [
                        *_DOCKER,
                        "ps",
                        "-aq",
                        "--no-trunc",
                        "--filter",
                        "id=" + harness["container_id"],
                    ],
                    "volume_query": [*_DOCKER, "volume", "ls", "--format", "{{.Name}}"],
                    "container_absent": True,
                    "volume_absent": True,
                },
            ),
            "capture cleanup identity, query, or absence changed",
        )
        _expect(
            checks._timestamp(invocation["completed_at"])
            < checks._timestamp(cleanup["checked_at"])
            < checks._timestamp(document["recorded_at"]),
            "cleanup chronology changed",
        )
        return {
            "campaign_nonce": _NONCE,
            "fixture_id": request["case"]["fixture_id"],
            "nonce_association": _ASSOCIATION,
            "request_binding_digest": canonical_digest(bound),
            "native_capture_digest": checks._digest(native_raw),
            "replay_semantics_canonical_digest": canonical_digest(replay),
            "parent_snapshot_digests": [
                canonical_digest(before),
                canonical_digest(after),
            ],
            "cleanup_digest": canonical_digest(cleanup),
            "source_closure_digest": _SOURCE_DIGEST,
            "source_file_count": len(signed),
            "signing_key": checks.custody.parent.v3_contract.contract._SIGNATURE["key"],
            "recorded_at": document["recorded_at"],
        }
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        binascii.Error,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
    ) as exc:
        raise AdmissionEvidenceError(f"invalid wrapper DET-01 joins: {exc}") from exc
