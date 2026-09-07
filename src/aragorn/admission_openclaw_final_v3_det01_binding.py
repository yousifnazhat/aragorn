"""Bind a DET-01 campaign request to local bytes without executing a fixture."""

from __future__ import annotations

import ast
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from . import admission_openclaw_final_v3_campaign as campaign
from . import admission_openclaw_final_v3_det01 as semantic
from .admission_openclaw_final_v3_campaign_dispatch import (
    dispatch_openclaw_final_v3_campaign_case,
)

_ROOT = Path(__file__).resolve().parents[2]


def bind_openclaw_final_v3_det01_request(
    contract: dict[str, Any], request: dict[str, Any], *, bundle_root: Path
) -> dict[str, Any]:
    """Verify a point-in-time byte binding, not live custody or qualification."""

    try:
        bound = campaign.validate_openclaw_final_v3_campaign_contract(contract)
        expected = campaign.build_openclaw_final_v3_subfixture_request(bound, "DET-01")
        if type(request) is not dict or campaign._canonical(
            request
        ) != campaign._canonical(expected):
            raise campaign.CampaignContractError("DET-01 campaign request changed")
        dispatch = dispatch_openclaw_final_v3_campaign_case("DET-01")
        descriptor = dispatch["descriptor"]
        materializer = descriptor["materializer"]["source"]
        materializer_path = materializer["path"].removeprefix("/src/")
        raw = _read_source(
            materializer_path, materializer["bytes"], materializer["digest"]
        )
        # Inspect only literals from the already pinned bytes; never import or
        # execute the materializer while verifying a request.
        assignments = [
            node.value
            for node in ast.parse(raw).body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "_SOURCES"
                for target in node.targets
            )
        ]
        if len(assignments) != 1:
            raise campaign.CampaignContractError("DET-01 source table changed")
        sources = ast.literal_eval(assignments[0])
        if not isinstance(bundle_root, Path) or any(
            path.is_symlink() for path in (bundle_root, *bundle_root.parents)
        ):
            raise campaign.CampaignContractError(
                "DET-01 bundle path is symlinked or invalid"
            )
        files = _verify_bundle(bundle_root)
        if type(sources) is not dict or list(sources) != [
            item["name"] for item in files
        ]:
            raise campaign.CampaignContractError("DET-01 source inventory changed")
        source_files = []
        bundle_files = []
        staging_root = PurePosixPath(descriptor["argv"][1]).parent
        for item, declared in zip(files, descriptor["bundle"], strict=True):
            source = sources[item["name"]]
            if type(source) is not tuple or len(source) != 5:
                raise campaign.CampaignContractError("DET-01 source record changed")
            path, size, digest, output_size, output_digest = source
            if (output_size, output_digest) != (item["bytes"], item["digest"]):
                raise campaign.CampaignContractError(
                    "DET-01 source-to-bundle binding changed"
                )
            if declared["path"] != str(staging_root / item["name"]):
                raise campaign.CampaignContractError(
                    "DET-01 dispatch bundle path changed"
                )
            _read_source(path, size, digest)
            source_files.append({"path": path, "bytes": size, "digest": digest})
            bundle_files.append({**item, **declared})
    except campaign.CampaignContractError:
        raise
    except (
        semantic.Det01ObservationError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        SyntaxError,
        RecursionError,
    ) as exc:
        raise campaign.CampaignContractError(
            f"invalid DET-01 request binding: {exc}"
        ) from exc

    return {
        "schema": "aragorn/openclaw-final-admission-v3-det01-request-binding/v1",
        "authority": "POINT_IN_TIME_REQUEST_AND_LOCAL_BYTES_ONLY_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY",
        "request": expected,
        "descriptor": descriptor,
        "bindings": {
            "contract_digest": campaign._digest(campaign._canonical(bound)),
            "request_digest": campaign._digest(campaign._canonical(expected)),
            "dispatch_digest": campaign._digest(campaign._canonical(dispatch)),
            "materializer_source": dict(materializer),
            "source_files": source_files,
            "source_files_digest": campaign._digest(campaign._canonical(source_files)),
            "bundle_files": bundle_files,
            "bundle_files_digest": campaign._digest(campaign._canonical(bundle_files)),
        },
        "decision": {
            **{
                key: False
                for key in semantic._FALSE_DECISION
                if key.endswith("_eligible")
            },
            "status": "REQUEST_AND_LOCAL_BYTES_BOUND_NOT_EXECUTED",
        },
        "native_execution_enabled": False,
        "limitations": [
            "FROZEN_PARENT_IDENTITIES_ARE_DECLARATIONS_NOT_LIVE_IMAGE_RUNTIME_OR_CONFIGURATION_CUSTODY",
            "LOCAL_STAGING_BUNDLE_CHECK_IS_NOT_EXECUTION_PATH_OR_INTERPRETER_VERIFICATION",
            "POINT_IN_TIME_BYTES_MUST_BE_REVERIFIED_BY_THE_EXECUTION_BACKEND",
            "NO_SIGNED_CAPTURE_SOURCE_FRESHNESS_CLEANUP_REPLAY_OR_QUALIFICATION_VERIFIED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _read_source(path: str, size: int, digest: str) -> bytes:
    relative = PurePosixPath(path)
    if (
        type(path) is not str
        or relative.is_absolute()
        or ".." in relative.parts
        or str(relative) != path
        or type(size) is not int
        or not 0 < size <= 1_048_576
    ):
        raise campaign.CampaignContractError("DET-01 source path or size changed")
    source = _ROOT / path
    if any(parent.is_symlink() for parent in (source, *source.parents)):
        raise campaign.CampaignContractError("DET-01 source path is symlinked")
    return _read_file(source, size, digest)


def _verify_bundle(root: Path) -> list[dict[str, Any]]:
    # Keep the historical semantic verifier byte-pinned. This binding reads
    # caller-provided staging files with bounds before trusting their contents.
    for directory, names in (
        (root, {name.split("/")[0] for name in semantic._FILES}),
        (
            root / "aragorn",
            {name.split("/")[1] for name in semantic._FILES if "/" in name},
        ),
    ):
        metadata = directory.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o555
        ):
            raise campaign.CampaignContractError("DET-01 bundle directory changed")
        observed = set()
        for entry in directory.iterdir():
            if entry.name not in names:
                raise campaign.CampaignContractError("DET-01 bundle inventory changed")
            observed.add(entry.name)
        if observed != names:
            raise campaign.CampaignContractError("DET-01 bundle inventory changed")
    files = []
    for name, (size, digest) in semantic._FILES.items():
        _read_file(root / name, size, digest, mode=0o444)
        files.append({"name": name, "bytes": size, "digest": digest, "mode": "444"})
    return files


def _read_file(path: Path, size: int, digest: str, *, mode: int | None = None) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != size
            or (mode is not None and stat.S_IMODE(before.st_mode) != mode)
        ):
            raise campaign.CampaignContractError(
                "DET-01 file type, links, size, or mode changed"
            )
        raw = stream.read(size + 1)
        after = os.fstat(stream.fileno())
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        any(getattr(before, field) != getattr(after, field) for field in stable_fields)
        or len(raw) != size
        or campaign._digest(raw) != digest
    ):
        raise campaign.CampaignContractError(f"DET-01 file bytes changed: {path}")
    return raw
