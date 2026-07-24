"""Strict normalization of Docker daemon self-reported identity."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import posixpath
import unicodedata
from typing import Any
from urllib.parse import urlsplit


DOCKER_CONTEXT_TEMPLATE = (
    '{"Name":{{json .Name}},"DockerEndpoint":{'
    '"Host":{{json (index .Endpoints "docker").Host}},'
    '"SkipTLSVerify":{{json (index .Endpoints "docker").SkipTLSVerify}},'
    '"TLSMaterialCount":{{len (index .TLSMaterial "docker")}}}}'
)
DOCKER_VERSION_TEMPLATE = (
    '{"PlatformName":{{json .Server.Platform.Name}},'
    '"Version":{{json .Server.Version}},'
    '"APIVersion":{{json .Server.APIVersion}},'
    '"MinAPIVersion":{{json .Server.MinAPIVersion}},'
    '"GitCommit":{{json .Server.GitCommit}},'
    '"GoVersion":{{json .Server.GoVersion}},'
    '"Os":{{json .Server.Os}},'
    '"Arch":{{json .Server.Arch}},'
    '"KernelVersion":{{json .Server.KernelVersion}},'
    '"BuildTime":{{json .Server.BuildTime}},'
    '"Components":{{json .Server.Components}}}'
)
DOCKER_INFO_TEMPLATE = (
    '{"ID":{{json .ID}},"Name":{{json .Name}},'
    '"ServerVersion":{{json .ServerVersion}},'
    '"OperatingSystem":{{json .OperatingSystem}},'
    '"OSType":{{json .OSType}},'
    '"Architecture":{{json .Architecture}},'
    '"KernelVersion":{{json .KernelVersion}},'
    '"SecurityOptions":{{json .SecurityOptions}},'
    '"CgroupVersion":{{json .CgroupVersion}},'
    '"DefaultRuntime":{{json .DefaultRuntime}},'
    '"Driver":{{json .Driver}}}'
)

_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_STRING_BYTES = 4096
_MAX_COMPONENTS = 32
_MAX_DETAILS = 64
_MAX_SECURITY_OPTIONS = 64
_ARCHITECTURES = {
    "aarch64": "arm64",
    "amd64": "amd64",
    "arm64": "arm64",
    "x86_64": "amd64",
}
_REQUIRED_COMPONENTS = frozenset({"Engine", "containerd", "runc"})
_UNREPORTED_COMPONENT_DETAILS_PREFIX = "unreported-details-sha256:"
_CONTEXT_KEYS = frozenset({"Name", "DockerEndpoint"})
_ENDPOINT_KEYS = frozenset({"Host", "SkipTLSVerify", "TLSMaterialCount"})
_VERSION_KEYS = frozenset(
    {
        "PlatformName",
        "Version",
        "APIVersion",
        "MinAPIVersion",
        "GitCommit",
        "GoVersion",
        "Os",
        "Arch",
        "KernelVersion",
        "BuildTime",
        "Components",
    }
)
_COMPONENT_KEYS = frozenset({"Name", "Version", "Details"})
_INFO_KEYS = frozenset(
    {
        "ID",
        "Name",
        "ServerVersion",
        "OperatingSystem",
        "OSType",
        "Architecture",
        "KernelVersion",
        "SecurityOptions",
        "CgroupVersion",
        "DefaultRuntime",
        "Driver",
    }
)


class DockerIdentityError(ValueError):
    """Docker runtime identity evidence is malformed or inconsistent."""


@dataclass(frozen=True, slots=True)
class DockerIdentityReceipt:
    """Raw Docker evidence plus its deterministic normalized identity."""

    raw_context: bytes
    raw_version: bytes
    raw_info: bytes
    document_json: bytes
    endpoint: str


def parse_docker_context(raw_context: bytes) -> tuple[dict[str, Any], str]:
    """Validate targeted ``docker context inspect`` JSON."""

    document = _load(raw_context, "Docker context")
    context = _exact_object(document, _CONTEXT_KEYS, "Docker context")
    endpoint_document = _exact_object(
        context["DockerEndpoint"],
        _ENDPOINT_KEYS,
        "Docker context endpoint",
    )
    name = _canonical_string(context["Name"], "Docker context Name")
    endpoint = _canonical_unix_endpoint(endpoint_document["Host"])
    if endpoint_document["SkipTLSVerify"] is not False:
        raise DockerIdentityError("Docker context must not skip TLS verification")
    tls_material_count = endpoint_document["TLSMaterialCount"]
    if (
        isinstance(tls_material_count, bool)
        or not isinstance(tls_material_count, int)
        or tls_material_count != 0
    ):
        raise DockerIdentityError("Docker context must not contain TLS material")
    return (
        {
            "name": name,
            "endpoint": endpoint,
            "skip_tls_verify": False,
            "tls_material_count": 0,
        },
        endpoint,
    )


def normalize_docker_identity(
    raw_context: bytes,
    raw_version: bytes,
    raw_info: bytes,
) -> DockerIdentityReceipt:
    """Return a deterministic identity from three targeted Docker responses."""

    context, endpoint = parse_docker_context(raw_context)
    version = _exact_object(
        _load(raw_version, "Docker version"),
        _VERSION_KEYS,
        "Docker version",
    )
    info = _exact_object(
        _load(raw_info, "Docker info"),
        _INFO_KEYS,
        "Docker info",
    )

    engine_architecture = _architecture(
        version["Arch"], "Docker version Arch"
    )
    worker_architecture = _architecture(
        info["Architecture"], "Docker info Architecture"
    )
    version_os = _canonical_string(version["Os"], "Docker version Os")
    info_os = _canonical_string(info["OSType"], "Docker info OSType")
    if version_os != "linux" or info_os != "linux":
        raise DockerIdentityError("Docker daemon OS must be exactly linux")

    version_value = _canonical_string(
        version["Version"], "Docker version Version"
    )
    info_version = _canonical_string(
        info["ServerVersion"], "Docker info ServerVersion"
    )
    version_commit = _canonical_string(
        version["GitCommit"], "Docker version GitCommit"
    )
    version_kernel = _canonical_string(
        version["KernelVersion"], "Docker version KernelVersion"
    )
    info_kernel = _canonical_string(
        info["KernelVersion"], "Docker info KernelVersion"
    )
    if version_value != info_version:
        raise DockerIdentityError("Docker version and info server versions differ")
    if engine_architecture != worker_architecture:
        raise DockerIdentityError("Docker version and info architectures differ")
    if version_kernel != info_kernel:
        raise DockerIdentityError("Docker version and info kernels differ")

    components, engine_component = _normalize_components(version["Components"])
    if engine_component["version"] != version_value:
        raise DockerIdentityError(
            "Docker Engine component version differs from server version"
        )
    if engine_component["git_commit"] != version_commit:
        raise DockerIdentityError(
            "Docker Engine component GitCommit differs from server GitCommit"
        )

    security_options = _security_options(info["SecurityOptions"])
    document = {
        "assurance": "docker_daemon_self_report_not_attested",
        "context": context,
        "engine": {
            "platform_name": _canonical_string(
                version["PlatformName"], "Docker version PlatformName"
            ),
            "version": version_value,
            "api_version": _canonical_string(
                version["APIVersion"], "Docker version APIVersion"
            ),
            "minimum_api_version": _canonical_string(
                version["MinAPIVersion"], "Docker version MinAPIVersion"
            ),
            "git_commit": version_commit,
            "go_version": _canonical_string(
                version["GoVersion"], "Docker version GoVersion"
            ),
            "os": "linux",
            "architecture": engine_architecture,
            "kernel_version": version_kernel,
            "build_time": _canonical_string(
                version["BuildTime"], "Docker version BuildTime"
            ),
            "components": components,
        },
        "worker_claim": {
            "daemon_id": _canonical_string(info["ID"], "Docker info ID"),
            "daemon_name": _canonical_string(info["Name"], "Docker info Name"),
            "server_version": info_version,
            "operating_system": _canonical_string(
                info["OperatingSystem"], "Docker info OperatingSystem"
            ),
            "os": "linux",
            "architecture": worker_architecture,
            "kernel_version": info_kernel,
            "security_options": security_options,
            "cgroup_version": _canonical_string(
                info["CgroupVersion"], "Docker info CgroupVersion"
            ),
            "default_runtime": _canonical_string(
                info["DefaultRuntime"], "Docker info DefaultRuntime"
            ),
            "storage_driver": _canonical_string(
                info["Driver"], "Docker info Driver"
            ),
        },
    }
    document_json = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return DockerIdentityReceipt(
        raw_context=raw_context,
        raw_version=raw_version,
        raw_info=raw_info,
        document_json=document_json,
        endpoint=endpoint,
    )


canonicalize_docker_identity = normalize_docker_identity


def _normalize_components(
    value: Any,
) -> tuple[list[dict[str, str]], dict[str, str]]:
    if not isinstance(value, list):
        raise DockerIdentityError("Docker version Components must be an array")
    if not 0 < len(value) <= _MAX_COMPONENTS:
        raise DockerIdentityError("Docker version Components count is invalid")

    components: list[dict[str, str]] = []
    names: set[str] = set()
    engine: dict[str, str] | None = None
    for index, raw_component in enumerate(value):
        label = f"Docker version Components[{index}]"
        component = _exact_object(raw_component, _COMPONENT_KEYS, label)
        name = _canonical_string(component["Name"], f"{label}.Name")
        collision_key = name.casefold()
        if collision_key in names:
            raise DockerIdentityError(f"duplicate Docker component: {name}")
        names.add(collision_key)
        version = _canonical_string(component["Version"], f"{label}.Version")
        details = component["Details"]
        if not isinstance(details, dict) or len(details) > _MAX_DETAILS:
            raise DockerIdentityError(f"{label}.Details must be a bounded object")
        git_commit = _component_git_identity(name, details, label)
        normalized = {
            "name": name,
            "version": version,
            "git_commit": git_commit,
        }
        components.append(normalized)
        if name == "Engine":
            engine = normalized

    missing = _REQUIRED_COMPONENTS - {item["name"] for item in components}
    if missing:
        raise DockerIdentityError(
            "Docker version Components missing required components: "
            + ", ".join(sorted(missing))
        )
    if engine is None:
        raise DockerIdentityError("Docker version Components has no Engine")
    components.sort(key=lambda item: item["name"])
    return components, engine


def _component_git_identity(
    name: str,
    details: dict[Any, Any],
    label: str,
) -> str:
    if "GitCommit" in details:
        return _canonical_string(
            details["GitCommit"],
            f"{label}.Details.GitCommit",
        )
    if name in _REQUIRED_COMPONENTS:
        raise DockerIdentityError(f"{label}.Details has no GitCommit")
    if not details:
        raise DockerIdentityError(
            f"{label}.Details has no identity-bearing fields"
        )
    normalized: dict[str, str] = {}
    for raw_key, raw_value in details.items():
        key = _canonical_string(raw_key, f"{label}.Details key")
        if key in normalized:
            raise DockerIdentityError(f"{label}.Details repeats a key")
        normalized[key] = _canonical_string(
            raw_value,
            f"{label}.Details.{key}",
        )
    raw = json.dumps(
        normalized,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return (
        _UNREPORTED_COMPONENT_DETAILS_PREFIX
        + hashlib.sha256(raw).hexdigest()
    )


def _security_options(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_SECURITY_OPTIONS:
        raise DockerIdentityError(
            "Docker info SecurityOptions must be a bounded array"
        )
    options = [
        _canonical_string(item, f"Docker info SecurityOptions[{index}]")
        for index, item in enumerate(value)
    ]
    if len(set(options)) != len(options):
        raise DockerIdentityError("Docker info SecurityOptions must be unique")
    return sorted(options)


def _architecture(value: Any, label: str) -> str:
    architecture = _canonical_string(value, label)
    try:
        return _ARCHITECTURES[architecture]
    except KeyError as exc:
        raise DockerIdentityError(f"{label} is unsupported: {architecture}") from exc


def _canonical_unix_endpoint(value: Any) -> str:
    endpoint = _canonical_string(value, "Docker context endpoint Host")
    if "%" in endpoint or "\\" in endpoint:
        raise DockerIdentityError("Docker context endpoint is not canonical")
    try:
        parsed = urlsplit(endpoint)
    except ValueError as exc:
        raise DockerIdentityError("Docker context endpoint is invalid") from exc
    path = parsed.path
    if (
        parsed.scheme != "unix"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not path.startswith("/")
        or path == "/"
        or "//" in path
        or posixpath.normpath(path) != path
        or any(part in {".", ".."} for part in path.split("/"))
        or endpoint != f"unix://{path}"
    ):
        raise DockerIdentityError(
            "Docker context endpoint must be a canonical absolute unix:/// path"
        )
    return endpoint


def _canonical_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DockerIdentityError(f"{label} must be a non-empty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DockerIdentityError(f"{label} must be valid Unicode") from exc
    if (
        len(encoded) > _MAX_STRING_BYTES
        or value != value.strip()
        or value != unicodedata.normalize("NFC", value)
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise DockerIdentityError(f"{label} is not a canonical bounded string")
    return value


def _load(raw: bytes, label: str) -> Any:
    if not isinstance(raw, bytes):
        raise DockerIdentityError(f"{label} must be bytes")
    if not raw or len(raw) > _MAX_DOCUMENT_BYTES:
        raise DockerIdentityError(f"{label} exceeds its byte bound")
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                DockerIdentityError(f"non-finite JSON value: {constant}")
            ),
        )
        _finite(document)
        return document
    except DockerIdentityError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise DockerIdentityError(f"invalid {label} JSON: {exc}") from exc


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DockerIdentityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise DockerIdentityError("non-finite JSON number")
    if isinstance(value, list):
        for item in value:
            _finite(item)
    elif isinstance(value, dict):
        for item in value.values():
            _finite(item)


def _exact_object(
    value: Any,
    expected_keys: frozenset[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DockerIdentityError(f"{label} must be an object")
    actual_keys = set(value)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        unexpected = sorted(actual_keys - expected_keys)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise DockerIdentityError(f"{label} has " + "; ".join(details))
    return value


__all__ = [
    "DOCKER_CONTEXT_TEMPLATE",
    "DOCKER_INFO_TEMPLATE",
    "DOCKER_VERSION_TEMPLATE",
    "DockerIdentityError",
    "DockerIdentityReceipt",
    "canonicalize_docker_identity",
    "normalize_docker_identity",
    "parse_docker_context",
]
