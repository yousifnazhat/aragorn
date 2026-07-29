"""Verify one live broker-to-OpenClaw shared-filesystem update slice."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest

_SCHEMA = "aragorn/openclaw-shared-filesystem-update-evidence/v1"
_AUTHORITY = "EVIDENCE_ONLY_NOT_ADM_02_ROUTE_CONFORMANCE"
_EVIDENCE_DIGEST = (
    "sha256:232024cd11cb6ffd830234e609ab793dcfd6144b98b3e73c02fe2033c9c4afca"
)
_LIMITATIONS = [
    "SINGLE_SHARED_FILESYSTEM_UPDATE_SLICE_ONLY",
    "NO_ADM_02_ROUTE_ADAPTER_CONFORMANCE",
    "DOCKER_CONTROL_PLANE_NOT_INDEPENDENTLY_ATTESTED",
    "NO_INSTALLER_AUTHORITY_OR_PHASE1_EXIT",
]
_IMAGE_DIGEST = (
    "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
)
_CONTAINER_ID = "dd9d0ad8022e37cfb30254f6fb0789ff222d9eb02aaca055c7216cd27f3a27a2"
_OLD = {
    "commit": "9ccce3bf07a40e45259004a330409ba00970eff7",
    "context_id": (
        "sha256:63d144746fa590be2cadc72675f4392882ea12253a8131a881911de6b6059e21"
    ),
    "manifest_digest": (
        "sha256:cad11dc0f88305a2b565213580016bed78c93dc2095d3f1f8f2c592af5b1a4e6"
    ),
    "skill_digest": (
        "sha256:a5ff68586ccf62d1803cedeb71d60fd96ec05591d29c8d123196117eefd34cd0"
    ),
}
_NEW = {
    "commit": "f57638a74759376871509ccf080e606f62052f1b",
    "context_id": (
        "sha256:c2a257f537720e667fe1284da5154ebf836cc9776117d8740a1087ae04453832"
    ),
    "manifest_digest": (
        "sha256:2627b902af63875e2d5606c3e3ebcfbaef7db7e479d476ce5119d850d17798ca"
    ),
    "skill_digest": (
        "sha256:1c9e975642c859c407bc4bbc9c06a171bf9ff88267300def1e02f46047ca5ad9"
    ),
    "tree_digest": (
        "sha256:c3e6b4db9b149d219cd714ecabd94806c41c5a4811fdac9299f339e0bfca5d34"
    ),
}
_ROOT_STAT = {
    "device": 64769,
    "gid": 982,
    "inode": 524931,
    "mode": "0750",
    "uid": 0,
}
_SOURCE_REQUEST = {
    "commit": _NEW["commit"],
    "owner": "obra",
    "repository": "superpowers",
    "schema": "aragorn/github-gateway-request/v1",
    "skill_path": "skills/requesting-code-review",
}


def verify_openclaw_shared_filesystem_update_evidence(
    document: Mapping[str, Any],
) -> None:
    """Verify the retained slice without granting route or installer authority."""

    try:
        _expect(
            canonical_digest(document) == _EVIDENCE_DIGEST,
            "retained evidence digest changed",
        )
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["assurance"] == _AUTHORITY, "assurance changed")
        _expect(document["limitations"] == _LIMITATIONS, "limitations changed")
        _expect(document["slice_status"] == "PASS", "slice status changed")
        _expect(
            document["decision"]
            == {
                "adm_02_route_conformance_eligible": False,
                "authority": _AUTHORITY,
                "installer_work_eligible": False,
                "phase1_exit_eligible": False,
                "status": "EVIDENCE_ONLY",
            },
            "authority boundary changed",
        )
        _time(document["recorded_at"])
        payload = document["payload"]
        _verify_composition(payload["composition"])
        _verify_update(payload["broker_update"])
        _verify_activation(payload["activation"])
        _verify_gateway(payload["gateway"])
        _verify_os_invariant(payload["os_invariant"])
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, AdmissionEvidenceError):
            raise
        raise AdmissionEvidenceError(
            f"invalid shared-filesystem update evidence: {exc}"
        ) from exc


def _verify_composition(composition: Mapping[str, Any]) -> None:
    _expect(
        composition["container"]
        == {
            "cap_drop": ["ALL"],
            "id": _CONTAINER_ID,
            "image_digest": _IMAGE_DIGEST,
            "network": "none",
            "no_new_privileges": True,
            "read_only_rootfs": True,
            "runtime_version": "2026.7.1",
            "started_at": "2026-07-29T22:45:48.039228238Z",
        },
        "runtime container identity or isolation changed",
    )
    mount = composition["mount"]
    expected_snapshot = {"container": _ROOT_STAT, "host": _ROOT_STAT}
    _expect(
        mount["host_path"] == "/var/lib/aragorn-protected/skills"
        and mount["container_path"] == "/profile/state/skills"
        and mount["read_only"] is True,
        "runtime bind mount changed",
    )
    _expect(
        mount["before"] == expected_snapshot and mount["after"] == expected_snapshot,
        "shared filesystem identity changed across update",
    )


def _verify_update(update: Mapping[str, Any]) -> None:
    old_version = _version_path(_OLD)
    new_version = _version_path(_NEW)
    _expect(
        update["before"] == {**_OLD, "version_path": old_version},
        "prior broker state changed",
    )
    _expect(
        update["after"] == {**_NEW, "version_path": new_version},
        "updated broker state changed",
    )
    _expect(
        update["before"]["skill_digest"] != update["after"]["skill_digest"],
        "installed skill byte identity did not change",
    )
    _expect(
        update["coordinator_state_after"]
        == {
            "expected_active": {
                "commit": _NEW["commit"],
                "context_id": _NEW["context_id"],
                "manifest_digest": _NEW["manifest_digest"],
                "source_request": _SOURCE_REQUEST,
            },
            "path": "/var/lib/aragorn-protected/coordinator-active.json",
            "tree_digest": _NEW["tree_digest"],
            "version_path": new_version,
        },
        "coordinator state is not bound to the updated broker result",
    )
    _expect(
        update["active_link"]
        == {
            "path": "/var/lib/aragorn-protected/skills/aragorn-admitted",
            "resolved_skill_path": (
                f"/var/lib/aragorn-protected/skills/{new_version}/SKILL.md"
            ),
            "resolved_target_path": (
                f"/var/lib/aragorn-protected/skills/{new_version}"
            ),
            "target": new_version,
            "type": "symlink",
        },
        "active link is not bound to the updated immutable version",
    )


def _verify_activation(activation: Mapping[str, Any]) -> None:
    version = _version_path(_NEW)
    base = f"/profile/state/skills/{version}"
    _expect(
        activation["skills_status_after"]
        == {
            "base_dir": base,
            "eligible": True,
            "file_path": f"{base}/SKILL.md",
            "model_visible": True,
        },
        "OpenClaw did not resolve the updated immutable version",
    )


def _verify_gateway(gateway: Mapping[str, Any]) -> None:
    process = {"pid": 1, "start_time_ticks": "686560"}
    _expect(
        gateway["process"] == {"after": process, "before": process},
        "OpenClaw PID 1 changed across update",
    )
    _expect(
        gateway["log"] == {"ready_count": 1, "restart_count": 0},
        "Gateway restarted during update",
    )


def _verify_os_invariant(invariant: Mapping[str, Any]) -> None:
    _expect(
        invariant["all_blocked"] is True
        and invariant["attempts"]
        == [
            {
                "blocked": True,
                "code": "EROFS",
                "operation": "create-in-root",
            },
            {
                "blocked": True,
                "code": "EROFS",
                "operation": "rename-active-link",
            },
            {
                "blocked": True,
                "code": "EACCES",
                "operation": "open-active-file-rw",
            },
        ],
        "runtime read-only invariant changed",
    )


def _version_path(value: Mapping[str, str]) -> str:
    context = value["context_id"].removeprefix("sha256:")
    manifest = value["manifest_digest"].removeprefix("sha256:")
    return f".aragorn-versions/aragorn-admitted/{context}-{manifest}"


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(
            f"invalid shared-filesystem update evidence: {message}"
        )
