"""Local conformance producer for Aragorn's private protected-install primitive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import time
from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

_REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPOSITORY / "src"))

import aragorn.admission_artifact_graph as artifact_graph_module
import aragorn.analyzer_receipt as analyzer_receipt_module
from aragorn.acquire import ingest_local
from aragorn.admission_artifact_graph import (
    retain_admission_artifact_graph,
)
from aragorn.analyze import run_analyzer
from aragorn.analyzer_receipt import retain_analyzer_run
from aragorn.artifact_closure import (
    load_verified_retained_manifest,
)
from aragorn.cas import CAS
from aragorn.decision_receipt import (
    retain_decision_v3,
    verify_decision_v3,
)
from aragorn.github_gateway import build_gateway_request
from aragorn.github_quarantine_receipt import (
    verify_github_quarantine_receipt,
)
from aragorn.manifest_diff import diff_verified_manifests_between
from aragorn.materialization import (
    _freeze_materialized_source_tree,
    verify_materialized_source_tree,
)
from aragorn.oci_worker_protocol import (
    canonical_digest,
    canonical_json,
)
from aragorn.phase0_candidate import (
    candidate_implementation_digest,
)
from aragorn.protected_install import (
    _ACTIVE_RUNTIME_AUTHORITY,
    _ACTIVE_RUNTIME_RECORD,
    _ACTIVE_RUNTIME_SCHEMA,
    ProtectedInstallTransactionError,
    _materialize_verified_manifest,
    _publish_protected_install_transaction,
)

_SCHEMA = "aragorn/openclaw-protected-install-broker-producer-receipt/v1"
_GITHUB_SCHEMA = "aragorn/openclaw-github-protected-install-broker-evidence/v1"
_ASSURANCE = "LOCAL_BROKER_CONFORMANCE_ONLY_NOT_INSTALLER_AUTHORITY"
_GITHUB_ASSURANCE = (
    "LIVE_GITHUB_CUSTODY_TO_PROTECTED_INSTALL_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
)
_TARGET = "aragorn-admitted"
_SCANNER = "aragorn-inert-fixture-scanner"
_GITHUB_SCANNER = "aragorn-agent-skill-threats"
_GITHUB_ANALYZER_VERSION = "0.1.0-phase0-v7"
_SERVICE_ANALYZER_USER = "aragorn-analyze"
_SERVICE_ANALYZER_GROUP = "aragorn-analyze"
_PASSWD_PATH = Path("/etc/passwd")
_GROUP_PATH = Path("/etc/group")
_SERVICE_REQUEST_SCHEMA = "aragorn/protected-install-broker-request/v1"
_SERVICE_REQUEST_SCHEMA_V2 = "aragorn/protected-install-broker-request/v2"
_MAX_SERVICE_REQUEST_BYTES = 64 * 1024
_SERVICE_REQUEST_DIGEST_FIELDS = (
    "target_runtime_digest",
    "runtime_conformance_digest",
    "manifest_digest",
    "quarantine_receipt_digest",
    "gateway_profile_digest",
    "context_id",
    "expected_producer_implementation_digest",
    "expected_analyzer_implementation_digest",
    "expected_analyzer_executable_digest",
    "expected_analyzer_configuration_digest",
    "expected_policy_digest",
    "expected_analyzer_verifier_digest",
    "expected_artifact_graph_verifier_digest",
)
_SERVICE_REQUEST_FIELDS = {
    "schema",
    "expires_at_unix",
    "source_request",
    *_SERVICE_REQUEST_DIGEST_FIELDS,
}
_SERVICE_REQUEST_V2_FIELDS = _SERVICE_REQUEST_FIELDS | {
    "operation",
    "expected_active",
    "expected_manifest_diff_digest",
}
_SERVICE_DYNAMIC_ARGUMENTS = (
    "now_unix",
    "expires_at_unix",
    "target_runtime_digest",
    "runtime_conformance_digest",
    "manifest_digest",
    "quarantine_receipt_digest",
    "gateway_profile_digest",
    "context_id",
    "expected_owner",
    "expected_repository",
    "expected_commit",
    "expected_skill_path",
    "expected_producer_implementation_digest",
    "expected_analyzer_implementation_digest",
    "expected_analyzer_executable_digest",
    "expected_analyzer_configuration_digest",
    "expected_policy_digest",
    "expected_analyzer_verifier_digest",
    "expected_artifact_graph_verifier_digest",
)
_LIMITATIONS = [
    "LOCAL_INERT_FIXTURE_NOT_LIVE_GITHUB_ACQUISITION_CUSTODY",
    "BROKER_DERIVED_CANONICAL_DIGEST_NOT_INDEPENDENT_SIGNATURE",
    "EVALUATOR_CONTROLLED_ANALYZER_NOT_PRODUCTION_ANALYSIS",
    "PRODUCER_RECEIPT_NOT_OPENCLAW_ROUTE_OR_RUNTIME_CONFORMANCE_EVIDENCE",
    "OPENCLAW_RUNTIME_COMPOSITION_MUST_PIN_AGENTS_DEFAULTS_SANDBOX_MODE_OFF",
    "SELF_FED_CONTEXT_AND_RUNTIME_DIGESTS_NOT_INDEPENDENT_TRUST_ANCHORS",
    "CLAIM_TIME_REUSES_PRE_STAGING_CLOCK_NOT_EXPIRY_OR_REVOCATION_FRESHNESS",
    "BOUNDED_TREE_SNAPSHOT_EXCLUDES_CTIME_FLAGS_XATTRS_AND_ACLS",
    "CONTEXT_IDS_ARE_DETERMINISTIC_FIXTURE_IDS_NOT_EXTERNAL_AUTHORSHIP_NONCES",
    "NO_INSTALLER_AUTHORITY",
]
_GITHUB_LIMITATIONS = [
    "PHASE0_FIRST_PARTY_ANALYZER_NOT_PRODUCTION_ANALYSIS",
    "ANALYZER_EXECUTES_AS_ROOT_WITHOUT_OS_SANDBOX_OR_UID_DROP",
    "PYTHON_STDLIB_AND_DYNAMIC_RUNTIME_CLOSURE_NOT_PINNED",
    "CALLER_SUPPLIED_RUNTIME_DIGESTS_NOT_SEMANTICALLY_VERIFIED",
    "HOST_SYSTEM_CLOCK_AND_REVOCATION_INPUT_NOT_EXTERNALLY_ATTESTED",
    "CALLER_SUPPLIED_CONTEXT_ID_NOT_EXTERNALLY_ATTESTED",
    "SELF_DERIVED_CONTEXT_DIGEST_NOT_INDEPENDENT_AUTHORIZATION",
    "ARTIFACT_CLOSURE_LIMITED_TO_SELF_CONTAINED_GITHUB_MARKDOWN_V1",
    "PRODUCER_RECEIPT_NOT_OPENCLAW_ROUTE_OR_ADM02_CONFORMANCE_EVIDENCE",
    "PROTECTED_TRANSACTION_EXECUTION_NOT_INSTALLER_AUTHORITY",
    "NO_INSTALLER_AUTHORITY",
]
_UNPRIVILEGED_ANALYZER_LIMITATIONS = [
    limitation
    for limitation in _GITHUB_LIMITATIONS
    if limitation != "ANALYZER_EXECUTES_AS_ROOT_WITHOUT_OS_SANDBOX_OR_UID_DROP"
]
_FIXTURE_BYTES = {
    "v1": (
        b"---\n"
        b"name: aragorn-admitted\n"
        b"description: Inert Aragorn broker fixture aragorn-broker-v1.\n"
        b"---\n"
        b"# Aragorn broker fixture v1\n\n"
        b"This fixture is inert and performs no actions.\n"
    ),
    "v2": (
        b"---\n"
        b"name: aragorn-admitted\n"
        b"description: Inert Aragorn broker fixture aragorn-broker-v2.\n"
        b"---\n"
        b"# Aragorn broker fixture v2\n\n"
        b"This fixture is inert and performs no actions.\n"
    ),
}
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class BrokerConformanceError(ValueError):
    """The local producer could not prove its bounded conformance claim."""


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _require_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise BrokerConformanceError(f"{label} is invalid")
    return value


def _resolve_analyzer_execution_identity(
    args: argparse.Namespace,
) -> dict[str, Any] | None:
    user = getattr(args, "analyzer_user", None)
    group = getattr(args, "analyzer_group", None)
    if user is None and group is None:
        return None
    if (user, group) != (
        _SERVICE_ANALYZER_USER,
        _SERVICE_ANALYZER_GROUP,
    ):
        raise BrokerConformanceError(
            "analyzer identity must be the fixed service worker"
        )
    try:
        passwd_records = [
            line.split(":")
            for line in _PASSWD_PATH.read_text(encoding="utf-8").splitlines()
            if line.split(":", 1)[0] == user
        ]
        group_records = [
            line.split(":")
            for line in _GROUP_PATH.read_text(encoding="utf-8").splitlines()
            if line.split(":", 1)[0] == group
        ]
        if (
            len(passwd_records) != 1
            or len(passwd_records[0]) != 7
            or len(group_records) != 1
            or len(group_records[0]) != 4
        ):
            raise ValueError
        user_record = passwd_records[0]
        group_record = group_records[0]
        user_uid = int(user_record[2])
        user_gid = int(user_record[3])
        group_gid = int(group_record[2])
    except (OSError, UnicodeError, ValueError) as exc:
        raise BrokerConformanceError(
            "fixed analyzer service identity is not provisioned"
        ) from exc
    if (
        user_record[0] != user
        or group_record[0] != group
        or user_uid <= 0
        or group_gid <= 0
        or user_gid != group_gid
        or user_record[5] != "/nonexistent"
        or user_record[6] != "/usr/sbin/nologin"
    ):
        raise BrokerConformanceError(
            "fixed analyzer service identity is not exact"
        )
    return {
        "user": user,
        "group": group,
        "uid": user_uid,
        "gid": group_gid,
        "supplementary_groups": [],
    }


def _github_analyzer_script(
    expected_implementation_digest: str,
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> str:
    if (expected_uid is None) != (expected_gid is None):
        raise BrokerConformanceError(
            "analyzer UID and GID must be bound together"
        )
    source_root = str(_REPOSITORY / "src")
    identity_check = ""
    if expected_uid is not None:
        identity_check = (
            "import os\n"
            f"if os.geteuid()!={expected_uid!r}:\n"
            " raise RuntimeError('analyzer effective UID changed')\n"
            f"if os.getegid()!={expected_gid!r}:\n"
            " raise RuntimeError('analyzer effective GID changed')\n"
            "if os.getgroups():\n"
            " raise RuntimeError('analyzer supplementary groups are not empty')\n"
            "with open('/proc/self/status',encoding='ascii') as status_stream:\n"
            " status=dict(line.rstrip().split(':',1) "
            "for line in status_stream if ':' in line)\n"
            "for capability_field in ('CapEff','CapPrm','CapAmb'):\n"
            " if int(status.get(capability_field,'-1').strip(),16)!=0:\n"
            "  raise RuntimeError('analyzer process retained capabilities')\n"
        )
    return (
        "import json,sys,tempfile\n"
        f"{identity_check}"
        "from pathlib import Path\n"
        f"sys.path.insert(0,{source_root!r})\n"
        "from aragorn.acquire import ingest_local\n"
        "from aragorn.cas import CAS\n"
        "from aragorn.phase0_candidate import "
        "candidate_implementation_digest,detect_first_party_observations\n"
        f"expected={expected_implementation_digest!r}\n"
        "if candidate_implementation_digest()!=expected:\n"
        " raise RuntimeError('analyzer implementation identity changed')\n"
        "request=json.load(sys.stdin)\n"
        "with tempfile.TemporaryDirectory("
        "prefix='aragorn-analyzer-state-',dir='/tmp') as state:\n"
        " cas=CAS(Path(state))\n"
        " manifest=ingest_local(Path(request['workspace']),cas)\n"
        " if manifest['tree_digest']!=request['subject_digest']:\n"
        "  raise RuntimeError('analyzer workspace identity changed')\n"
        " for observation in detect_first_party_observations(manifest,cas):\n"
        "  sys.stdout.write(observation.document_json+'\\n')\n"
    )


def _module_digest(module: Any) -> str:
    return _digest_bytes(Path(module.__file__).resolve(strict=True).read_bytes())


def _retain_document(cas: CAS, document: object) -> str:
    raw = canonical_json(document)
    return cas.put(BytesIO(raw), max_bytes=len(raw))


def _context_id(label: str) -> str:
    return _digest_bytes(f"aragorn-local-broker:{label}".encode())


def _require_root(path: Path, expected_uid: int) -> os.stat_result:
    try:
        state = path.lstat()
    except OSError as exc:
        raise BrokerConformanceError(f"cannot inspect protected root: {exc}") from exc
    mode = stat.S_IMODE(state.st_mode)
    if (
        not stat.S_ISDIR(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or state.st_uid != expected_uid
        or mode & 0o022
        or mode & 0o300 != 0o300
    ):
        raise BrokerConformanceError(
            "protected root must be broker-owned, writable, and protected"
        )
    return state


def _require_initial_protected_root(
    path: Path,
    expected_uid: int,
    *,
    allow_empty_control_layout: bool,
) -> None:
    entries = sorted(child.name for child in path.iterdir())
    if not entries:
        return
    if not allow_empty_control_layout or entries != [
        ".aragorn-install-claims",
        ".aragorn-versions",
    ]:
        raise BrokerConformanceError(
            "protected root must start empty or contain empty broker controls"
        )
    controls = (
        (path / ".aragorn-install-claims", 0o700, ()),
        (path / ".aragorn-versions", 0o755, (_TARGET,)),
    )
    for control, expected_mode, allowed_names in controls:
        state = _require_root(control, expected_uid)
        names = sorted(child.name for child in control.iterdir())
        if stat.S_IMODE(state.st_mode) != expected_mode or (
            names and tuple(names) != allowed_names
        ):
            raise BrokerConformanceError(
                "protected broker control layout is not empty and exact"
            )
    target_versions = path / ".aragorn-versions" / _TARGET
    if os.path.lexists(target_versions):
        state = _require_root(target_versions, expected_uid)
        if stat.S_IMODE(state.st_mode) != 0o755 or list(
            target_versions.iterdir()
        ):
            raise BrokerConformanceError(
                "protected target versions control is not empty and exact"
            )


def _require_update_protected_root(path: Path, expected_uid: int) -> None:
    entries = sorted(child.name for child in path.iterdir())
    legacy_entries = [
        ".aragorn-install-claims",
        ".aragorn-versions",
        _TARGET,
    ]
    published_entries = sorted([_ACTIVE_RUNTIME_RECORD, *legacy_entries])
    if entries not in (legacy_entries, published_entries):
        raise BrokerConformanceError(
            "protected update root namespace is not exact"
        )
    controls = (
        (path / ".aragorn-install-claims", 0o700),
        (path / ".aragorn-versions", 0o755),
        (path / ".aragorn-versions" / _TARGET, 0o755),
    )
    for control, expected_mode in controls:
        state = _require_root(control, expected_uid)
        if stat.S_IMODE(state.st_mode) != expected_mode:
            raise BrokerConformanceError(
                "protected update control layout is not exact"
            )
    if _ACTIVE_RUNTIME_RECORD in entries:
        _require_active_runtime_record(path, expected_uid)
    active = (path / _TARGET).lstat()
    if (
        not stat.S_ISLNK(active.st_mode)
        or active.st_uid != expected_uid
        or active.st_nlink != 1
    ):
        raise BrokerConformanceError(
            "protected update target must be one broker-owned symlink"
        )


def _require_active_runtime_record(
    path: Path,
    expected_uid: int,
    expected_transaction: dict[str, Any] | None = None,
) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path / _ACTIVE_RUNTIME_RECORD, flags)
    except OSError as exc:
        raise BrokerConformanceError(
            "protected active-runtime record is not exact"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o444
        ):
            raise BrokerConformanceError(
                "protected active-runtime record is not exact"
            )
        if expected_transaction is None:
            return
        expected = canonical_json(
            {
                "schema": _ACTIVE_RUNTIME_SCHEMA,
                "authority": _ACTIVE_RUNTIME_AUTHORITY,
                "transaction": expected_transaction,
            }
        )
        raw = bytearray()
        while chunk := os.read(descriptor, len(expected) + 1 - len(raw)):
            raw.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        _service_request_metadata(before) != _service_request_metadata(after)
        or len(raw) != after.st_size
        or bytes(raw) != expected
    ):
        raise BrokerConformanceError(
            "protected active-runtime record is not exact"
        )


def _require_published_protected_root(
    path: Path,
    expected_uid: int,
    expected_transaction: dict[str, Any],
) -> None:
    if sorted(child.name for child in path.iterdir()) != [
        _ACTIVE_RUNTIME_RECORD,
        ".aragorn-install-claims",
        ".aragorn-versions",
        _TARGET,
    ]:
        raise BrokerConformanceError("protected root namespace contains residue")
    _require_update_protected_root(path, expected_uid)
    _require_active_runtime_record(path, expected_uid, expected_transaction)


def _build_fixture_evidence(
    cas: CAS,
    sources: Path,
    *,
    policy_digest: str,
    executable: Path,
    executable_digest: str,
    analyzer_verifier_digest: str,
    graph_verifier_digest: str,
) -> dict[str, dict[str, Any]]:
    script = "import json,sys;json.load(sys.stdin)"
    configuration = {
        "name": _SCANNER,
        "version": "1",
        "argv": [str(executable), "-c", script],
        "operator_argv0": str(executable),
        "executable_digest": executable_digest,
    }
    configuration_raw = canonical_json(configuration)
    configuration_digest = cas.put(
        BytesIO(configuration_raw),
        max_bytes=len(configuration_raw),
    )
    fixtures: dict[str, dict[str, Any]] = {}
    for version in ("v1", "v2"):
        source = sources / version
        source.mkdir(mode=0o700)
        (source / "SKILL.md").write_bytes(_FIXTURE_BYTES[version])
        manifest = ingest_local(source, cas)
        manifest_digest = _retain_document(cas, manifest)
        graph_digest = retain_admission_artifact_graph(
            cas,
            manifest_digest,
            verifier_implementation_digest=graph_verifier_digest,
        )
        result = run_analyzer(
            (str(executable), "-c", script),
            workspace=source,
            name=_SCANNER,
            version="1",
            config_digest=configuration_digest,
            executable_digest=executable_digest,
            subject_digest=manifest["tree_digest"],
            configuration_bytes=configuration_raw,
            timeout_seconds=2,
            output_limit_bytes=4096,
        )
        if not result.ok:
            raise BrokerConformanceError(
                f"inert fixture analyzer failed closed: {result.error_code}"
            )
        run_receipt_digest = retain_analyzer_run(
            cas,
            result,
            verifier_implementation_digest=analyzer_verifier_digest,
        )
        decision_digest = retain_decision_v3(
            cas,
            manifest_digest=manifest_digest,
            artifact_graph_digest=graph_digest,
            policy_digest=policy_digest,
            analyzer_run_receipt_digests=[run_receipt_digest],
            analyzer_verifier_digest=analyzer_verifier_digest,
            artifact_graph_verifier_digest=graph_verifier_digest,
        )
        decision = verify_decision_v3(
            cas,
            decision_digest,
            expected_manifest_digest=manifest_digest,
            expected_artifact_graph_digest=graph_digest,
            expected_policy_digest=policy_digest,
            expected_analyzer_run_receipt_digests=[run_receipt_digest],
            expected_analyzer_verifier_digest=analyzer_verifier_digest,
            expected_artifact_graph_verifier_digest=graph_verifier_digest,
        )
        if decision["verdict"] != "ALLOW":
            raise BrokerConformanceError("inert fixture decision is not ALLOW")
        fixtures[version] = {
            "artifact_graph_digest": graph_digest,
            "decision_digest": decision_digest,
            "manifest_digest": manifest_digest,
            "tree_digest": manifest["tree_digest"],
            "analyzer_run_receipt_digests": [run_receipt_digest],
            "skill_file_bytes": len(_FIXTURE_BYTES[version]),
            "skill_file_digest": _digest_bytes(_FIXTURE_BYTES[version]),
            "marker": f"aragorn-broker-{version}",
        }
    return fixtures


def _make_context(
    fixture: dict[str, Any],
    *,
    label: str,
    operation: str,
    expected_active: dict[str, str] | None,
    expires_at_unix: int,
    root_state: os.stat_result,
    target_runtime_digest: str,
    runtime_conformance_digest: str,
    policy_digest: str,
    analyzer_verifier_digest: str,
    graph_verifier_digest: str,
) -> dict[str, Any]:
    return {
        "schema": "aragorn/protected-install-context/v2",
        "authority": "BROKER_CONTEXT_ONLY_NOT_INSTALLER_AUTHORITY",
        "context_id": _context_id(label),
        "status": "active",
        "expires_at_unix": expires_at_unix,
        "operation": operation,
        "expected_active": expected_active,
        "decision_digest": fixture["decision_digest"],
        "manifest_digest": fixture["manifest_digest"],
        "artifact_graph_digest": fixture["artifact_graph_digest"],
        "policy_digest": policy_digest,
        "analyzer_run_receipt_digests": fixture["analyzer_run_receipt_digests"],
        "analyzer_verifier_digest": analyzer_verifier_digest,
        "artifact_graph_verifier_digest": graph_verifier_digest,
        "target_runtime_digest": target_runtime_digest,
        "runtime_conformance_digest": runtime_conformance_digest,
        "destination": {
            "root_device": root_state.st_dev,
            "root_inode": root_state.st_ino,
            "target_name": _TARGET,
        },
    }


def _publish(
    cas: CAS,
    root_fd: int,
    context: dict[str, Any],
    *,
    now_unix: int,
    claim_now_unix: int | None = None,
    runtime_conformance_digest: str,
    target_runtime_digest: str,
    revoked_context_ids: tuple[str, ...] = (),
    expected_active_cas: CAS | None = None,
    claim_state_provider: Callable[[], tuple[int, tuple[str, ...]]] | None = None,
) -> dict[str, Any]:
    return _publish_protected_install_transaction(
        cas,
        context,
        root_fd,
        now_unix=now_unix,
        claim_now_unix=now_unix if claim_now_unix is None else claim_now_unix,
        expected_context_digest=canonical_digest(context),
        expected_target_name=_TARGET,
        expected_runtime_conformance_digest=runtime_conformance_digest,
        measured_target_runtime_digest=target_runtime_digest,
        revoked_context_ids=revoked_context_ids,
        expected_active_cas=expected_active_cas,
        claim_state_provider=claim_state_provider,
    )


def _metadata(state: os.stat_result) -> dict[str, int]:
    return {
        "device": state.st_dev,
        "gid": state.st_gid,
        "inode": state.st_ino,
        "links": state.st_nlink,
        "mode": stat.S_IMODE(state.st_mode),
        "mtime_ns": state.st_mtime_ns,
        "size": state.st_size,
        "uid": state.st_uid,
    }


def _service_request_metadata(state: os.stat_result) -> dict[str, int]:
    return {**_metadata(state), "ctime_ns": state.st_ctime_ns}


def _require_owner_protected_ancestry(
    path: Path,
    expected_uid: int,
    *,
    include_path: bool,
) -> None:
    current = path if include_path else path.parent
    while True:
        try:
            state = current.lstat()
        except OSError as exc:
            raise BrokerConformanceError(
                f"cannot inspect protected ancestry: {exc}"
            ) from exc
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or state.st_uid not in {0, expected_uid}
            or stat.S_IMODE(state.st_mode) & 0o022
        ):
            raise BrokerConformanceError(
                "protected ancestry must be owner-protected"
            )
        if current == Path(current.anchor):
            return
        current = current.parent


def _canonical_service_directory(
    path_value: str,
    expected_uid: int,
    label: str,
) -> Path:
    supplied = Path(path_value)
    try:
        resolved = supplied.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BrokerConformanceError(f"cannot resolve {label}: {exc}") from exc
    if not supplied.is_absolute() or supplied != resolved:
        raise BrokerConformanceError(
            f"{label} must be an absolute canonical path"
        )
    _require_owner_protected_ancestry(
        resolved,
        expected_uid,
        include_path=True,
    )
    return resolved


def _load_revocation_snapshot(
    path_value: str,
    expected_uid: int,
) -> tuple[tuple[str, ...], dict[str, Any]]:
    path = Path(path_value)
    if not path.is_absolute():
        raise BrokerConformanceError("revocation file path must be absolute")
    parent = path.parent.resolve(strict=True)
    _require_root(parent, expected_uid)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or mode & 0o022
            or before.st_size > 64 * 1024
        ):
            raise BrokerConformanceError(
                "revocation file must be a bounded broker-owned regular file"
            )
        raw = bytearray()
        while chunk := os.read(descriptor, min(8192, 64 * 1024 + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > 64 * 1024:
                raise BrokerConformanceError("revocation file exceeds 64 KiB")
        after = os.fstat(descriptor)
        if _metadata(before) != _metadata(after) or len(raw) != after.st_size:
            raise BrokerConformanceError("revocation file changed while read")
    finally:
        os.close(descriptor)
    try:
        document = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise BrokerConformanceError(f"revocation file is invalid: {exc}") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "context_ids"}
        or document["schema"] != "aragorn/protected-install-revocations/v1"
        or canonical_json(document) != bytes(raw)
    ):
        raise BrokerConformanceError(
            "revocation file must be one canonical revocation object"
        )
    values = document["context_ids"]
    if not isinstance(values, list):
        raise BrokerConformanceError("revocation context ids must be a list")
    context_ids = tuple(
        _require_digest(value, "revoked context id") for value in values
    )
    if list(context_ids) != sorted(set(context_ids)):
        raise BrokerConformanceError(
            "revoked context ids must be sorted and unique"
        )
    return context_ids, {
        "schema": document["schema"],
        "path": str(path.resolve(strict=True)),
        "digest": _digest_bytes(bytes(raw)),
        "device": after.st_dev,
        "inode": after.st_ino,
        "owner_uid": after.st_uid,
        "mode": stat.S_IMODE(after.st_mode),
        "context_ids": list(context_ids),
    }


def _canonical_source_request(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise BrokerConformanceError(f"{label} is invalid")
    try:
        verified = build_gateway_request(
            value.get("owner"),
            value.get("repository"),
            value.get("commit"),
            value.get("skill_path"),
        )
    except (TypeError, ValueError) as exc:
        raise BrokerConformanceError(f"{label} is invalid: {exc}") from exc
    if value != verified:
        raise BrokerConformanceError(f"{label} is not canonical")
    return verified


def _service_transition(document: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    if document["schema"] == _SERVICE_REQUEST_SCHEMA:
        return "install", None
    operation = document["operation"]
    expected_active = document["expected_active"]
    expected_diff_digest = document["expected_manifest_diff_digest"]
    if operation == "install":
        if expected_active is not None or expected_diff_digest is not None:
            raise BrokerConformanceError(
                "service install request must not bind an active predecessor"
            )
        return operation, None
    if operation != "update" or not isinstance(expected_active, dict):
        raise BrokerConformanceError("service request operation is invalid")
    if set(expected_active) != {
        "context_id",
        "manifest_digest",
        "source_request",
        "quarantine_receipt_digest",
        "gateway_profile_digest",
    }:
        raise BrokerConformanceError(
            "service update predecessor must be one exact object"
        )
    for field in (
        "context_id",
        "manifest_digest",
        "quarantine_receipt_digest",
        "gateway_profile_digest",
    ):
        _require_digest(expected_active[field], f"expected active {field}")
    _canonical_source_request(
        expected_active["source_request"],
        "expected active source request",
    )
    _require_digest(expected_diff_digest, "expected manifest diff digest")
    if expected_active["manifest_digest"] == document["manifest_digest"]:
        raise BrokerConformanceError(
            "service update manifest must differ from its predecessor"
        )
    if expected_active["source_request"] == document["source_request"]:
        raise BrokerConformanceError(
            "service update source request must differ from its predecessor"
        )
    for field in ("owner", "repository", "skill_path"):
        if (
            expected_active["source_request"][field]
            != document["source_request"][field]
        ):
            raise BrokerConformanceError(
                "service update source lineage must not change"
            )
    return operation, expected_active


def _load_service_request(
    path_value: str,
    expected_uid: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    path = Path(path_value)
    if not path.is_absolute():
        raise BrokerConformanceError("service request path must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BrokerConformanceError(
            f"cannot resolve service request: {exc}"
        ) from exc
    if resolved != path:
        raise BrokerConformanceError(
            "service request path must be canonical and contain no symlinks"
        )
    _require_owner_protected_ancestry(
        resolved,
        expected_uid,
        include_path=False,
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise BrokerConformanceError(
            f"cannot open service request: {exc}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size > _MAX_SERVICE_REQUEST_BYTES
        ):
            raise BrokerConformanceError(
                "service request must be a bounded broker-owned 0400 regular file"
            )
        raw = bytearray()
        while chunk := os.read(
            descriptor,
            min(8192, _MAX_SERVICE_REQUEST_BYTES + 1 - len(raw)),
        ):
            raw.extend(chunk)
            if len(raw) > _MAX_SERVICE_REQUEST_BYTES:
                raise BrokerConformanceError(
                    "service request exceeds 64 KiB"
                )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        _service_request_metadata(before)
        != _service_request_metadata(after)
        or len(raw) != after.st_size
    ):
        raise BrokerConformanceError("service request changed while read")
    try:
        document = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise BrokerConformanceError(
            f"service request is invalid: {exc}"
        ) from exc
    schema = document.get("schema") if isinstance(document, dict) else None
    fields = {
        _SERVICE_REQUEST_SCHEMA: _SERVICE_REQUEST_FIELDS,
        _SERVICE_REQUEST_SCHEMA_V2: _SERVICE_REQUEST_V2_FIELDS,
    }.get(schema)
    if (
        not isinstance(document, dict)
        or fields is None
        or set(document) != fields
        or canonical_json(document) != bytes(raw)
    ):
        raise BrokerConformanceError(
            "service request must be one exact canonical request object"
        )
    expiry = document["expires_at_unix"]
    if isinstance(expiry, bool) or not isinstance(expiry, int) or expiry < 0:
        raise BrokerConformanceError("service request expiry is invalid")
    for field in _SERVICE_REQUEST_DIGEST_FIELDS:
        _require_digest(document[field], field.replace("_", " "))
    _canonical_source_request(
        document["source_request"],
        "service source request",
    )
    _service_transition(document)
    request_digest = _digest_bytes(bytes(raw))
    return document, {
        "authority": "PROTECTED_CANONICAL_REQUEST_CREDENTIAL",
        "request_digest": request_digest,
        "request_schema": document["schema"],
        "credential": {
            "path": str(resolved),
            **_service_request_metadata(after),
        },
    }


def _resolve_service_request(
    args: argparse.Namespace,
) -> tuple[argparse.Namespace, dict[str, Any] | None]:
    if args.service_request is None:
        return args, None
    if not args.github_live:
        raise BrokerConformanceError(
            "service request requires --github-live"
        )
    if args.expected_broker_uid != 0 or os.geteuid() != 0:
        raise BrokerConformanceError(
            "service request requires the fixed root broker"
        )
    if any(getattr(args, field) is not None for field in _SERVICE_DYNAMIC_ARGUMENTS):
        raise BrokerConformanceError(
            "service request cannot be combined with dynamic CLI trust inputs"
        )
    request, authority = _load_service_request(
        args.service_request,
        args.expected_broker_uid,
    )
    resolved = argparse.Namespace(**vars(args))
    resolved.now_unix = int(time.time())
    for field in (
        "expires_at_unix",
        *_SERVICE_REQUEST_DIGEST_FIELDS,
    ):
        setattr(resolved, field, request[field])
    operation, expected_active = _service_transition(request)
    resolved.operation = operation
    resolved.expected_active = expected_active
    resolved.expected_manifest_diff_digest = request.get(
        "expected_manifest_diff_digest"
    )
    source = request["source_request"]
    resolved.expected_owner = source["owner"]
    resolved.expected_repository = source["repository"]
    resolved.expected_commit = source["commit"]
    resolved.expected_skill_path = source["skill_path"]
    cas_parent = Path(resolved.cas_root)
    resolved.cas_base_root = str(cas_parent)
    resolved.cas_root = str(
        cas_parent / canonical_digest(source)[7:]
    )
    resolved.expected_active_cas_root = (
        None
        if expected_active is None
        else str(
            cas_parent
            / canonical_digest(expected_active["source_request"])[7:]
        )
    )
    return resolved, authority


def _bounded_tree_snapshot_digest(root: Path) -> str:
    records: list[dict[str, Any]] = []
    entries_seen = 0
    bytes_seen = 0

    def visit(directory: Path, relative: str) -> None:
        nonlocal entries_seen, bytes_seen
        before = directory.lstat()
        records.append(
            {"path": relative or ".", "type": "directory", **_metadata(before)}
        )
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
        for entry in entries:
            entries_seen += 1
            if entries_seen > 256:
                raise BrokerConformanceError("protected snapshot entry limit exceeded")
            path = directory / entry.name
            child = f"{relative}/{entry.name}" if relative else entry.name
            state = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(state.st_mode):
                visit(path, child)
            elif stat.S_ISREG(state.st_mode):
                bytes_seen += state.st_size
                if bytes_seen > 1024 * 1024:
                    raise BrokerConformanceError(
                        "protected snapshot byte limit exceeded"
                    )
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(path, flags)
                try:
                    opened = os.fstat(descriptor)
                    if (opened.st_dev, opened.st_ino) != (
                        state.st_dev,
                        state.st_ino,
                    ):
                        raise BrokerConformanceError(
                            "protected snapshot file identity changed"
                        )
                    digest = hashlib.sha256()
                    while chunk := os.read(descriptor, 64 * 1024):
                        digest.update(chunk)
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                if _metadata(opened) != _metadata(after):
                    raise BrokerConformanceError(
                        "protected snapshot file changed while read"
                    )
                records.append(
                    {
                        "path": child,
                        "type": "file",
                        "digest": f"sha256:{digest.hexdigest()}",
                        **_metadata(after),
                    }
                )
            elif stat.S_ISLNK(state.st_mode):
                target = os.readlink(path)
                after = path.lstat()
                if _metadata(state) != _metadata(after):
                    raise BrokerConformanceError(
                        "protected snapshot link changed while read"
                    )
                records.append(
                    {
                        "path": child,
                        "type": "symlink",
                        "target": target,
                        **_metadata(after),
                    }
                )
            else:
                raise BrokerConformanceError(
                    "protected snapshot contains a special file"
                )
        after = directory.lstat()
        if _metadata(before) != _metadata(after):
            raise BrokerConformanceError(
                "protected snapshot directory changed while read"
            )

    visit(root, "")
    return canonical_digest(records)


def _require_active(
    protected_root: Path,
    fixture: dict[str, Any],
    transaction: dict[str, Any],
) -> dict[str, Any]:
    active = protected_root / _TARGET
    state = active.lstat()
    if (
        not stat.S_ISLNK(state.st_mode)
        or os.readlink(active) != transaction["version_path"]
    ):
        raise BrokerConformanceError("active protected link is not exact")
    skill = active / "SKILL.md"
    raw = skill.read_bytes()
    skill_state = skill.stat()
    version = protected_root / transaction["version_path"]
    version_state = version.stat()
    if (
        raw != _FIXTURE_BYTES["v1"]
        and raw != _FIXTURE_BYTES["v2"]
        or _digest_bytes(raw) != fixture["skill_file_digest"]
        or stat.S_IMODE(skill_state.st_mode) != 0o444
        or stat.S_IMODE(version_state.st_mode) != 0o555
    ):
        raise BrokerConformanceError("active protected bytes are not exact")
    return {
        "link_target": transaction["version_path"],
        "skill_file_bytes": len(raw),
        "skill_file_digest": _digest_bytes(raw),
    }


def _prepare_github_transition(
    args: argparse.Namespace,
    cas: CAS,
    previous_cas: CAS | None,
) -> tuple[dict[str, str] | None, dict[str, Any]]:
    operation = getattr(args, "operation", "install")
    expected_active = getattr(args, "expected_active", None)
    expected_diff_digest = getattr(
        args,
        "expected_manifest_diff_digest",
        None,
    )
    if operation == "install":
        if expected_active is not None or expected_diff_digest is not None:
            raise BrokerConformanceError(
                "GitHub install must not bind an active predecessor"
            )
        return None, {
            "operation": "install",
            "expected_active": None,
            "manifest_diff": None,
        }
    if operation != "update" or not isinstance(expected_active, dict):
        raise BrokerConformanceError("GitHub transition is invalid")
    if previous_cas is None:
        raise BrokerConformanceError("GitHub update predecessor CAS is absent")
    previous_receipt = verify_github_quarantine_receipt(
        previous_cas,
        expected_active["quarantine_receipt_digest"],
        expected_manifest_digest=expected_active["manifest_digest"],
        expected_gateway_profile_digest=expected_active[
            "gateway_profile_digest"
        ],
    )
    if previous_receipt["request"] != expected_active["source_request"]:
        raise BrokerConformanceError(
            "active predecessor quarantine source is not request-authorized"
        )
    manifest_diff = diff_verified_manifests_between(
        previous_cas,
        expected_active["manifest_digest"],
        cas,
        args.manifest_digest,
    )
    retained_diff_digest = _retain_document(cas, manifest_diff)
    if retained_diff_digest != expected_diff_digest:
        raise BrokerConformanceError(
            "manifest update diff does not match the service request"
        )
    context_expected_active = {
        "context_id": expected_active["context_id"],
        "manifest_digest": expected_active["manifest_digest"],
    }
    return context_expected_active, {
        "operation": "update",
        "expected_active": context_expected_active,
        "previous_source": {
            "request": expected_active["source_request"],
            "manifest_digest": expected_active["manifest_digest"],
            "quarantine_receipt_digest": expected_active[
                "quarantine_receipt_digest"
            ],
            "gateway_profile_digest": expected_active[
                "gateway_profile_digest"
            ],
            "source_closure_digest": previous_receipt[
                "source_closure_digest"
            ],
        },
        "manifest_diff": {
            "digest": retained_diff_digest,
            "document": manifest_diff,
        },
    }


def _reverify_github_transition(
    args: argparse.Namespace,
    cas: CAS,
    previous_cas: CAS | None,
    current_receipt: dict[str, Any],
    expected_request: dict[str, str],
    transition: dict[str, Any],
) -> None:
    replayed_current = verify_github_quarantine_receipt(
        cas,
        args.quarantine_receipt_digest,
        expected_manifest_digest=args.manifest_digest,
        expected_gateway_profile_digest=args.gateway_profile_digest,
    )
    if replayed_current != current_receipt or replayed_current[
        "request"
    ] != expected_request:
        raise BrokerConformanceError(
            "current quarantine custody changed before publication"
        )
    if transition["operation"] == "install":
        return
    if previous_cas is None:
        raise BrokerConformanceError("update predecessor CAS is absent")
    expected_active = args.expected_active
    replayed_previous = verify_github_quarantine_receipt(
        previous_cas,
        expected_active["quarantine_receipt_digest"],
        expected_manifest_digest=expected_active["manifest_digest"],
        expected_gateway_profile_digest=expected_active[
            "gateway_profile_digest"
        ],
    )
    if replayed_previous["request"] != expected_active["source_request"]:
        raise BrokerConformanceError(
            "active predecessor custody changed before publication"
        )
    manifest_diff = diff_verified_manifests_between(
        previous_cas,
        expected_active["manifest_digest"],
        cas,
        args.manifest_digest,
    )
    retained_diff_digest = _retain_document(cas, manifest_diff)
    if (
        manifest_diff != transition["manifest_diff"]["document"]
        or retained_diff_digest
        != transition["manifest_diff"]["digest"]
    ):
        raise BrokerConformanceError(
            "manifest update diff changed before publication"
        )


def _run_github_live(
    args: argparse.Namespace,
    *,
    cas: CAS,
    previous_cas: CAS | None,
    protected_root: Path,
    root_state: os.stat_result,
    analyzer_verifier_digest: str,
    graph_verifier_digest: str,
) -> dict[str, Any]:
    analyzer_execution_identity = _resolve_analyzer_execution_identity(args)
    github_limitations = (
        _UNPRIVILEGED_ANALYZER_LIMITATIONS
        if analyzer_execution_identity is not None
        else _GITHUB_LIMITATIONS
    )
    manifest_digest = _require_digest(args.manifest_digest, "manifest digest")
    quarantine_receipt_digest = _require_digest(
        args.quarantine_receipt_digest,
        "quarantine receipt digest",
    )
    gateway_profile_digest = _require_digest(
        args.gateway_profile_digest,
        "gateway profile digest",
    )
    context_id = _require_digest(args.context_id, "context id")
    expected_producer_digest = _require_digest(
        args.expected_producer_implementation_digest,
        "expected producer implementation digest",
    )
    expected_analyzer_implementation_digest = _require_digest(
        args.expected_analyzer_implementation_digest,
        "expected analyzer implementation digest",
    )
    expected_executable_digest = _require_digest(
        args.expected_analyzer_executable_digest,
        "expected analyzer executable digest",
    )
    expected_configuration_digest = _require_digest(
        args.expected_analyzer_configuration_digest,
        "expected analyzer configuration digest",
    )
    expected_policy_digest = _require_digest(
        args.expected_policy_digest,
        "expected policy digest",
    )
    expected_analyzer_verifier_digest = _require_digest(
        args.expected_analyzer_verifier_digest,
        "expected analyzer verifier digest",
    )
    expected_graph_verifier_digest = _require_digest(
        args.expected_artifact_graph_verifier_digest,
        "expected artifact graph verifier digest",
    )
    producer_implementation_digest = _digest_bytes(
        Path(__file__).resolve(strict=True).read_bytes()
    )
    analyzer_implementation_digest = candidate_implementation_digest()
    if producer_implementation_digest != expected_producer_digest:
        raise BrokerConformanceError("producer implementation identity changed")
    if analyzer_implementation_digest != expected_analyzer_implementation_digest:
        raise BrokerConformanceError("analyzer implementation identity changed")
    if analyzer_verifier_digest != expected_analyzer_verifier_digest:
        raise BrokerConformanceError("analyzer verifier identity changed")
    if graph_verifier_digest != expected_graph_verifier_digest:
        raise BrokerConformanceError("artifact graph verifier identity changed")

    executable = Path(sys.executable).resolve(strict=True)
    executable_digest = _digest_bytes(executable.read_bytes())
    if executable_digest != expected_executable_digest:
        raise BrokerConformanceError("analyzer executable identity changed")
    script = _github_analyzer_script(
        analyzer_implementation_digest,
        expected_uid=(
            None
            if analyzer_execution_identity is None
            else analyzer_execution_identity["uid"]
        ),
        expected_gid=(
            None
            if analyzer_execution_identity is None
            else analyzer_execution_identity["gid"]
        ),
    )
    configuration = {
        "name": _GITHUB_SCANNER,
        "version": _GITHUB_ANALYZER_VERSION,
        "argv": [str(executable), "-B", "-c", script],
        "operator_argv0": str(executable),
        "executable_digest": executable_digest,
    }
    configuration_raw = canonical_json(configuration)
    configuration_digest = _digest_bytes(configuration_raw)
    if configuration_digest != expected_configuration_digest:
        raise BrokerConformanceError("analyzer configuration identity changed")
    policy = {
        "schema": "aragorn/policy/v2",
        "id": "openclaw-live-github-broker-evidence",
        "version": 1,
        "required_analyzers": [_GITHUB_SCANNER],
        "hard_deny_reason_codes": [],
        "review_severities": ["critical", "high", "medium"],
        "allowed_artifact_graph_profiles": [
            "self-contained-github-markdown/v1"
        ],
    }
    policy_digest = canonical_digest(policy)
    if policy_digest != expected_policy_digest:
        raise BrokerConformanceError("policy identity changed")
    (
        initial_revoked_context_ids,
        initial_revocation_snapshot,
    ) = _load_revocation_snapshot(
        args.revocation_file,
        args.expected_broker_uid,
    )
    if context_id in initial_revoked_context_ids:
        raise BrokerConformanceError("protected install context is revoked")

    quarantine_receipt = verify_github_quarantine_receipt(
        cas,
        quarantine_receipt_digest,
        expected_manifest_digest=manifest_digest,
        expected_gateway_profile_digest=gateway_profile_digest,
    )
    expected_request = {
        "schema": "aragorn/github-gateway-request/v1",
        "owner": args.expected_owner,
        "repository": args.expected_repository,
        "commit": args.expected_commit,
        "skill_path": args.expected_skill_path,
    }
    if quarantine_receipt["request"] != expected_request:
        raise BrokerConformanceError(
            "quarantine receipt source request is not caller-authorized"
        )
    context_expected_active, transition_record = _prepare_github_transition(
        args,
        cas,
        previous_cas,
    )
    if transition_record["operation"] == "update":
        # Legacy roots enter only after their predecessor CAS was verified above.
        _require_update_protected_root(protected_root, args.expected_broker_uid)
    graph_digest = artifact_graph_module.retain_github_admission_artifact_graph_v2(
        cas,
        manifest_digest,
        expected_quarantine_receipt_digest=quarantine_receipt_digest,
        expected_gateway_profile_digest=gateway_profile_digest,
        verifier_implementation_digest=graph_verifier_digest,
    )
    graph = artifact_graph_module.verify_github_admission_artifact_graph_v2(
        cas,
        graph_digest,
        expected_manifest_digest=manifest_digest,
        expected_quarantine_receipt_digest=quarantine_receipt_digest,
        expected_gateway_profile_digest=gateway_profile_digest,
        expected_verifier_digest=graph_verifier_digest,
    )
    if graph["closure"]["status"] != "complete":
        raise BrokerConformanceError(
            "GitHub artifact closure is incomplete; protected install is blocked"
        )

    manifest = load_verified_retained_manifest(cas, manifest_digest)
    if not any(item["path"] == "SKILL.md" for item in manifest["files"]):
        raise BrokerConformanceError(
            "GitHub source is not an Agent Skill root; SKILL.md is missing"
        )
    with executable.open("rb") as stream:
        retained_executable_digest = cas.put(
            stream,
            max_bytes=128 * 1024 * 1024,
        )
    if retained_executable_digest != executable_digest:
        raise BrokerConformanceError("retained analyzer executable identity changed")
    retained_configuration_digest = cas.put(
        BytesIO(configuration_raw),
        max_bytes=len(configuration_raw),
    )
    if retained_configuration_digest != configuration_digest:
        raise BrokerConformanceError("retained analyzer configuration identity changed")
    retained_policy_digest = _retain_document(cas, policy)
    if retained_policy_digest != policy_digest:
        raise BrokerConformanceError("retained policy identity changed")
    with TemporaryDirectory(prefix="aragorn-github-analyzer-") as temporary:
        staging = Path(temporary)
        staging_fd = os.open(staging, _DIRECTORY_FLAGS)
        try:
            _materialize_verified_manifest(cas, manifest, staging_fd)
            _freeze_materialized_source_tree(staging_fd, manifest)
            if analyzer_execution_identity is not None:
                os.fchmod(staging_fd, 0o555)
                os.fsync(staging_fd)
            staged_tree_digest = verify_materialized_source_tree(
                cas,
                manifest_digest,
                staging_fd,
            )
            analyzer_result = run_analyzer(
                (str(executable), "-B", "-c", script),
                workspace=staging,
                name=_GITHUB_SCANNER,
                version=_GITHUB_ANALYZER_VERSION,
                config_digest=configuration_digest,
                executable_digest=executable_digest,
                subject_digest=graph["tree_digest"],
                configuration_bytes=configuration_raw,
                timeout_seconds=2,
                output_limit_bytes=4096,
                run_as_uid=(
                    None
                    if analyzer_execution_identity is None
                    else analyzer_execution_identity["uid"]
                ),
                run_as_gid=(
                    None
                    if analyzer_execution_identity is None
                    else analyzer_execution_identity["gid"]
                ),
            )
            if not analyzer_result.ok:
                raise BrokerConformanceError(
                    "evidence analyzer failed closed: "
                    f"{analyzer_result.error_code}"
                )
            if (
                verify_materialized_source_tree(cas, manifest_digest, staging_fd)
                != staged_tree_digest
            ):
                raise BrokerConformanceError(
                    "materialized GitHub source changed during analysis"
                )
        finally:
            os.close(staging_fd)
    analyzer_run_receipt_digest = retain_analyzer_run(
        cas,
        analyzer_result,
        verifier_implementation_digest=analyzer_verifier_digest,
    )
    decision_digest = retain_decision_v3(
        cas,
        manifest_digest=manifest_digest,
        artifact_graph_digest=graph_digest,
        policy_digest=policy_digest,
        analyzer_run_receipt_digests=[analyzer_run_receipt_digest],
        analyzer_verifier_digest=analyzer_verifier_digest,
        artifact_graph_verifier_digest=graph_verifier_digest,
        expected_quarantine_receipt_digest=quarantine_receipt_digest,
        expected_gateway_profile_digest=gateway_profile_digest,
    )
    decision = verify_decision_v3(
        cas,
        decision_digest,
        expected_manifest_digest=manifest_digest,
        expected_artifact_graph_digest=graph_digest,
        expected_policy_digest=policy_digest,
        expected_analyzer_run_receipt_digests=[analyzer_run_receipt_digest],
        expected_analyzer_verifier_digest=analyzer_verifier_digest,
        expected_artifact_graph_verifier_digest=graph_verifier_digest,
        expected_quarantine_receipt_digest=quarantine_receipt_digest,
        expected_gateway_profile_digest=gateway_profile_digest,
    )
    if decision["verdict"] != "ALLOW":
        raise BrokerConformanceError(
            f"GitHub evidence decision is not ALLOW: {decision['verdict']}"
        )

    context = {
        "schema": "aragorn/protected-install-context/v2",
        "authority": "BROKER_CONTEXT_ONLY_NOT_INSTALLER_AUTHORITY",
        "context_id": context_id,
        "status": "active",
        "expires_at_unix": args.expires_at_unix,
        "operation": transition_record["operation"],
        "expected_active": context_expected_active,
        "decision_digest": decision_digest,
        "manifest_digest": manifest_digest,
        "artifact_graph_digest": graph_digest,
        "policy_digest": policy_digest,
        "analyzer_run_receipt_digests": [analyzer_run_receipt_digest],
        "analyzer_verifier_digest": analyzer_verifier_digest,
        "artifact_graph_verifier_digest": graph_verifier_digest,
        "quarantine_receipt_digest": quarantine_receipt_digest,
        "gateway_profile_digest": gateway_profile_digest,
        "target_runtime_digest": args.target_runtime_digest,
        "runtime_conformance_digest": args.runtime_conformance_digest,
        "destination": {
            "root_device": root_state.st_dev,
            "root_inode": root_state.st_ino,
            "target_name": _TARGET,
        },
    }
    source_record = {
        "request": expected_request,
        "manifest_digest": manifest_digest,
        "tree_digest": graph["tree_digest"],
        "source_proof_digest": graph["source_proof_digest"],
        "source_closure_digest": quarantine_receipt["source_closure_digest"],
        "quarantine_receipt_digest": quarantine_receipt_digest,
        "gateway_profile_digest": gateway_profile_digest,
        "containment_profile": quarantine_receipt["containment_profile"],
        "gateway": quarantine_receipt["gateway"],
        "quarantine_protected_cas": quarantine_receipt["protected_cas"],
        "artifact_graph_digest": graph_digest,
        "artifact_graph_profile": graph["profile"],
        "artifact_graph_verifier_implementation_digest": graph_verifier_digest,
        "artifact_count": len(graph["artifacts"]),
        "closure": graph["closure"],
    }
    analyzer_record = {
        "name": _GITHUB_SCANNER,
        "version": _GITHUB_ANALYZER_VERSION,
        "implementation_digest": analyzer_implementation_digest,
        "configuration_digest": configuration_digest,
        "executable_digest": executable_digest,
        "run_receipt_digest": analyzer_run_receipt_digest,
        "verifier_implementation_digest": analyzer_verifier_digest,
    }
    if analyzer_execution_identity is not None:
        analyzer_record["execution_identity"] = analyzer_execution_identity
    decision_record = {
        "digest": decision_digest,
        "verdict": decision["verdict"],
        "policy_digest": policy_digest,
        "installer_work_eligible": False,
    }
    context_record = {
        "context_id": context_id,
        "digest": canonical_digest(context),
        "operation": transition_record["operation"],
        "expected_active": context_expected_active,
        "target_runtime_digest": args.target_runtime_digest,
        "runtime_conformance_digest": args.runtime_conformance_digest,
        "destination": context["destination"],
    }
    claim_state: dict[str, Any] = {}

    def fresh_claim_state() -> tuple[int, tuple[str, ...]]:
        context_ids, snapshot = _load_revocation_snapshot(
            args.revocation_file,
            args.expected_broker_uid,
        )
        claim_now_unix = int(time.time())
        claim_state.update(
            {
                "claim_now_unix": claim_now_unix,
                "revocation_snapshot": snapshot,
            }
        )
        return claim_now_unix, context_ids

    def recovery_result(
        transaction_record: dict[str, Any],
        error: Exception,
    ) -> dict[str, Any]:
        return {
            "schema": _GITHUB_SCHEMA,
            "assurance": _GITHUB_ASSURANCE,
            "slice_status": "ERROR",
            "mode": "github-live",
            "producer_implementation_digest": producer_implementation_digest,
            "source": source_record,
            "analyzer": analyzer_record,
            "decision": decision_record,
            "context": context_record,
            "transition": transition_record,
            "transaction": transaction_record,
            "claim": {
                "initial_revocation_snapshot": initial_revocation_snapshot,
                "fresh": claim_state,
            },
            "error": {
                "type": "POST_COMMIT_RECOVERY_REQUIRED",
                "message": str(error),
            },
            "recovery": {
                "active_target": _TARGET,
                "claim_consumed": True,
                "version_path": transaction_record["version_path"],
            },
            "limitations": github_limitations,
        }

    _reverify_github_transition(
        args,
        cas,
        previous_cas,
        quarantine_receipt,
        expected_request,
        transition_record,
    )
    if transition_record["operation"] == "update":
        _require_update_protected_root(protected_root, args.expected_broker_uid)
    root_fd = os.open(protected_root, _DIRECTORY_FLAGS)
    try:
        try:
            transaction = _publish(
                cas,
                root_fd,
                context,
                now_unix=args.now_unix,
                claim_now_unix=args.now_unix,
                runtime_conformance_digest=args.runtime_conformance_digest,
                target_runtime_digest=args.target_runtime_digest,
                revoked_context_ids=initial_revoked_context_ids,
                expected_active_cas=previous_cas,
                claim_state_provider=fresh_claim_state,
            )
        except ProtectedInstallTransactionError as exc:
            if exc.recovery is None:
                raise
            return recovery_result(exc.recovery, exc)
    finally:
        os.close(root_fd)
    try:
        active_link = protected_root / _TARGET
        if (
            not active_link.is_symlink()
            or os.readlink(active_link) != transaction["version_path"]
        ):
            raise BrokerConformanceError(
                "active GitHub protected link is not exact"
            )
        version_fd = os.open(
            protected_root / transaction["version_path"],
            _DIRECTORY_FLAGS,
        )
        try:
            active_tree_digest = verify_materialized_source_tree(
                cas,
                manifest_digest,
                version_fd,
            )
        finally:
            os.close(version_fd)
        if (
            active_tree_digest != graph["tree_digest"]
            or transaction["tree_digest"] != graph["tree_digest"]
        ):
            raise BrokerConformanceError("installed GitHub tree digest is not exact")
        _require_published_protected_root(
            protected_root,
            args.expected_broker_uid,
            transaction,
        )
    except Exception as exc:  # noqa: BLE001 - retain committed recovery identity
        return recovery_result(transaction, exc)

    return {
        "schema": _GITHUB_SCHEMA,
        "assurance": _GITHUB_ASSURANCE,
        "slice_status": "PASS",
        "mode": "github-live",
        "producer_implementation_digest": producer_implementation_digest,
        "source": source_record,
        "analyzer": analyzer_record,
        "decision": decision_record,
        "context": context_record,
        "transition": transition_record,
        "claim": {
            "initial_revocation_snapshot": initial_revocation_snapshot,
            "fresh": claim_state,
        },
        "transaction": transaction,
        "active": {
            "link_target": transaction["version_path"],
            "tree_digest": active_tree_digest,
        },
        "verified_sequence": [
            "quarantine-custody",
            "self-contained-github-markdown-v1-closure",
            "exact-source-materialization",
            "digest-bound-first-party-analyzer-run",
            "decision-v3-replay",
            "protected-install-context-v2",
            *(
                ["manifest-update-diff-v1"]
                if transition_record["operation"] == "update"
                else []
            ),
            "protected-install-transaction",
            "active-tree-reverification",
        ],
        "limitations": github_limitations,
    }


def _run(args: argparse.Namespace) -> dict[str, Any]:
    if os.name != "posix":
        raise BrokerConformanceError("protected install conformance requires POSIX")
    if args.expected_broker_uid != os.geteuid():
        raise BrokerConformanceError("effective UID is not the expected broker UID")
    if (
        args.now_unix is None
        or args.expires_at_unix is None
        or args.now_unix < 0
        or args.expires_at_unix <= args.now_unix
    ):
        raise BrokerConformanceError("trusted time window is invalid")
    _require_digest(args.target_runtime_digest, "target runtime digest")
    _require_digest(
        args.runtime_conformance_digest,
        "runtime conformance digest",
    )
    github_arguments = (
        args.manifest_digest,
        args.quarantine_receipt_digest,
        args.gateway_profile_digest,
        args.context_id,
        args.expected_owner,
        args.expected_repository,
        args.expected_commit,
        args.expected_skill_path,
        args.expected_producer_implementation_digest,
        args.expected_analyzer_implementation_digest,
        args.expected_analyzer_executable_digest,
        args.expected_analyzer_configuration_digest,
        args.expected_policy_digest,
        args.expected_analyzer_verifier_digest,
        args.expected_artifact_graph_verifier_digest,
        args.revocation_file,
    )
    if args.github_live and any(value is None for value in github_arguments):
        raise BrokerConformanceError(
            "GitHub live mode requires manifest, quarantine receipt, "
            "gateway profile, context, and source request inputs"
        )
    if not args.github_live and any(value is not None for value in github_arguments):
        raise BrokerConformanceError(
            "GitHub trust inputs require --github-live"
        )

    protected_root = Path(args.protected_root).resolve(strict=True)
    operation = getattr(args, "operation", "install")
    service_request = getattr(args, "service_request", None)
    previous_cas: CAS | None = None
    if service_request is None:
        if operation != "install":
            raise BrokerConformanceError(
                "GitHub updates require a protected service request"
            )
        cas_root = Path(args.cas_root).resolve(strict=args.github_live)
        cas_roots = (cas_root,)
    else:
        cas_root = _canonical_service_directory(
            args.cas_root,
            args.expected_broker_uid,
            "service CAS namespace",
        )
        cas_base_root = _canonical_service_directory(
            args.cas_base_root,
            args.expected_broker_uid,
            "service quarantine base",
        )
        current_request = build_gateway_request(
            args.expected_owner,
            args.expected_repository,
            args.expected_commit,
            args.expected_skill_path,
        )
        if cas_root != cas_base_root / canonical_digest(current_request)[7:]:
            raise BrokerConformanceError(
                "service CAS namespace is not derived from its source request"
            )
        previous_root_value = getattr(args, "expected_active_cas_root", None)
        if operation == "update":
            if previous_root_value is None:
                raise BrokerConformanceError(
                    "service update predecessor CAS namespace is absent"
                )
            previous_root = _canonical_service_directory(
                previous_root_value,
                args.expected_broker_uid,
                "service predecessor CAS namespace",
            )
            expected_active = args.expected_active
            if previous_root != cas_base_root / canonical_digest(
                expected_active["source_request"]
            )[7:]:
                raise BrokerConformanceError(
                    "service predecessor CAS namespace is not derived "
                    "from its source request"
                )
            if previous_root == cas_root:
                raise BrokerConformanceError(
                    "service update CAS namespaces must be distinct"
                )
            previous_cas = CAS(previous_root, read_only=True)
            cas_roots = (cas_base_root, cas_root, previous_root)
        elif operation == "install":
            if previous_root_value is not None:
                raise BrokerConformanceError(
                    "service install must not select a predecessor CAS"
                )
            cas_roots = (cas_base_root, cas_root)
        else:
            raise BrokerConformanceError("service operation is invalid")
    for checked_root in cas_roots:
        common = Path(os.path.commonpath((protected_root, checked_root)))
        if common in {protected_root, checked_root}:
            raise BrokerConformanceError(
                "CAS and protected roots must be disjoint"
            )
    root_state = _require_root(protected_root, args.expected_broker_uid)
    if operation != "update":
        _require_initial_protected_root(
            protected_root,
            args.expected_broker_uid,
            allow_empty_control_layout=args.github_live,
        )
    cas = CAS(cas_root)
    analyzer_verifier_digest = _module_digest(analyzer_receipt_module)
    graph_verifier_digest = _module_digest(artifact_graph_module)
    if args.github_live:
        return _run_github_live(
            args,
            cas=cas,
            previous_cas=previous_cas,
            protected_root=protected_root,
            root_state=root_state,
            analyzer_verifier_digest=analyzer_verifier_digest,
            graph_verifier_digest=graph_verifier_digest,
        )
    executable = Path(sys.executable).resolve(strict=True)
    with executable.open("rb") as stream:
        executable_digest = cas.put(stream, max_bytes=128 * 1024 * 1024)
    policy = {
        "schema": "aragorn/policy/v2",
        "id": "openclaw-local-broker-conformance",
        "version": 1,
        "required_analyzers": [_SCANNER],
        "hard_deny_reason_codes": [],
        "review_severities": ["critical", "high", "medium"],
        "allowed_artifact_graph_profiles": ["self-contained-local-markdown/v1"],
    }
    policy_digest = _retain_document(cas, policy)
    with TemporaryDirectory(prefix="aragorn-protected-install-") as temporary:
        fixtures = _build_fixture_evidence(
            cas,
            Path(temporary),
            policy_digest=policy_digest,
            executable=executable,
            executable_digest=executable_digest,
            analyzer_verifier_digest=analyzer_verifier_digest,
            graph_verifier_digest=graph_verifier_digest,
        )

    install_id = _context_id("install-v1")
    update_id = _context_id("update-v2")
    rollback_id = _context_id("rollback-v1")
    install = _make_context(
        fixtures["v1"],
        label="install-v1",
        operation="install",
        expected_active=None,
        expires_at_unix=args.expires_at_unix,
        root_state=root_state,
        target_runtime_digest=args.target_runtime_digest,
        runtime_conformance_digest=args.runtime_conformance_digest,
        policy_digest=policy_digest,
        analyzer_verifier_digest=analyzer_verifier_digest,
        graph_verifier_digest=graph_verifier_digest,
    )
    update = _make_context(
        fixtures["v2"],
        label="update-v2",
        operation="update",
        expected_active={
            "context_id": install_id,
            "manifest_digest": fixtures["v1"]["manifest_digest"],
        },
        expires_at_unix=args.expires_at_unix,
        root_state=root_state,
        target_runtime_digest=args.target_runtime_digest,
        runtime_conformance_digest=args.runtime_conformance_digest,
        policy_digest=policy_digest,
        analyzer_verifier_digest=analyzer_verifier_digest,
        graph_verifier_digest=graph_verifier_digest,
    )
    rollback = _make_context(
        fixtures["v1"],
        label="rollback-v1",
        operation="rollback",
        expected_active={
            "context_id": update_id,
            "manifest_digest": fixtures["v2"]["manifest_digest"],
        },
        expires_at_unix=args.expires_at_unix,
        root_state=root_state,
        target_runtime_digest=args.target_runtime_digest,
        runtime_conformance_digest=args.runtime_conformance_digest,
        policy_digest=policy_digest,
        analyzer_verifier_digest=analyzer_verifier_digest,
        graph_verifier_digest=graph_verifier_digest,
    )
    stale = _make_context(
        fixtures["v2"],
        label="stale-update-v2",
        operation="update",
        expected_active={
            "context_id": install_id,
            "manifest_digest": fixtures["v1"]["manifest_digest"],
        },
        expires_at_unix=args.expires_at_unix,
        root_state=root_state,
        target_runtime_digest=args.target_runtime_digest,
        runtime_conformance_digest=args.runtime_conformance_digest,
        policy_digest=policy_digest,
        analyzer_verifier_digest=analyzer_verifier_digest,
        graph_verifier_digest=graph_verifier_digest,
    )
    revoked = _make_context(
        fixtures["v2"],
        label="revoked-update-v2",
        operation="update",
        expected_active={
            "context_id": rollback_id,
            "manifest_digest": fixtures["v1"]["manifest_digest"],
        },
        expires_at_unix=args.expires_at_unix,
        root_state=root_state,
        target_runtime_digest=args.target_runtime_digest,
        runtime_conformance_digest=args.runtime_conformance_digest,
        policy_digest=policy_digest,
        analyzer_verifier_digest=analyzer_verifier_digest,
        graph_verifier_digest=graph_verifier_digest,
    )

    root_fd = os.open(protected_root, _DIRECTORY_FLAGS)
    try:
        transactions = [
            _publish(
                cas,
                root_fd,
                context,
                now_unix=args.now_unix,
                runtime_conformance_digest=args.runtime_conformance_digest,
                target_runtime_digest=args.target_runtime_digest,
                expected_active_cas=(
                    cas if context["expected_active"] is not None else None
                ),
            )
            for context in (install, update, rollback)
        ]
        active = _require_active(protected_root, fixtures["v1"], transactions[-1])
        negative_attempts = []
        attempts = (
            ("replay", rollback, (), "context is consumed"),
            ("stale", stale, (), "active link does not match"),
            (
                "revoked",
                revoked,
                (revoked["context_id"],),
                "context is revoked",
            ),
        )
        for name, context, revoked_ids, expected_error in attempts:
            before = _bounded_tree_snapshot_digest(protected_root)
            try:
                _publish(
                    cas,
                    root_fd,
                    context,
                    now_unix=args.now_unix,
                    runtime_conformance_digest=args.runtime_conformance_digest,
                    target_runtime_digest=args.target_runtime_digest,
                    revoked_context_ids=revoked_ids,
                    expected_active_cas=(
                        cas if context["expected_active"] is not None else None
                    ),
                )
            except ProtectedInstallTransactionError as exc:
                message = str(exc)
            else:
                raise BrokerConformanceError(f"{name} attempt unexpectedly published")
            after = _bounded_tree_snapshot_digest(protected_root)
            if expected_error not in message or before != after:
                raise BrokerConformanceError(
                    f"{name} attempt did not fail closed without mutation"
                )
            negative_attempts.append(
                {
                    "attempt": name,
                    "context_digest": canonical_digest(context),
                    "error_contains": expected_error,
                    "bounded_tree_snapshot_digest_before": before,
                    "bounded_tree_snapshot_digest_after": after,
                    "bounded_tree_snapshot_unchanged": True,
                    "status": "BLOCKED",
                }
            )
    finally:
        os.close(root_fd)

    if transactions[0]["version_path"] == transactions[2]["version_path"]:
        raise BrokerConformanceError("rollback did not use a distinct context version")
    _require_published_protected_root(
        protected_root,
        args.expected_broker_uid,
        transactions[-1],
    )
    return {
        "schema": _SCHEMA,
        "assurance": _ASSURANCE,
        "slice_status": "PASS",
        "decision": {
            "installer_work_eligible": False,
            "status": "NOT_TESTED",
        },
        "context_binding": ("SELF_DERIVED_FIXTURE_SHA256_WITH_REAL_DECISION_V3_REPLAY"),
        "target_name": _TARGET,
        "active": active,
        "fixtures": fixtures,
        "transactions": transactions,
        "negative_attempts": negative_attempts,
        "limitations": _LIMITATIONS,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-live", action="store_true")
    parser.add_argument("--service-request")
    parser.add_argument("--analyzer-user")
    parser.add_argument("--analyzer-group")
    parser.add_argument("--cas-root", required=True)
    parser.add_argument("--protected-root", required=True)
    parser.add_argument("--expected-broker-uid", required=True, type=int)
    parser.add_argument("--now-unix", type=int)
    parser.add_argument("--expires-at-unix", type=int)
    parser.add_argument("--target-runtime-digest")
    parser.add_argument("--runtime-conformance-digest")
    parser.add_argument("--manifest-digest")
    parser.add_argument("--quarantine-receipt-digest")
    parser.add_argument("--gateway-profile-digest")
    parser.add_argument("--context-id")
    parser.add_argument("--expected-owner")
    parser.add_argument("--expected-repository")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-skill-path")
    parser.add_argument("--expected-producer-implementation-digest")
    parser.add_argument("--expected-analyzer-implementation-digest")
    parser.add_argument("--expected-analyzer-executable-digest")
    parser.add_argument("--expected-analyzer-configuration-digest")
    parser.add_argument("--expected-policy-digest")
    parser.add_argument("--expected-analyzer-verifier-digest")
    parser.add_argument("--expected-artifact-graph-verifier-digest")
    parser.add_argument("--revocation-file")
    return parser


def main() -> int:
    args = _parser().parse_args()
    schema = _GITHUB_SCHEMA if args.github_live else _SCHEMA
    assurance = _GITHUB_ASSURANCE if args.github_live else _ASSURANCE
    limitations = _GITHUB_LIMITATIONS if args.github_live else _LIMITATIONS
    request_authority = None
    try:
        args, request_authority = _resolve_service_request(args)
        receipt = _run(args)
    except Exception as exc:  # noqa: BLE001 - emit one canonical fail-closed receipt
        receipt = {
            "schema": schema,
            "assurance": assurance,
            "slice_status": "ERROR",
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "limitations": limitations,
        }
    if request_authority is not None:
        receipt["request_authority"] = request_authority
    sys.stdout.buffer.write(canonical_json(receipt) + b"\n")
    return 0 if receipt["slice_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
