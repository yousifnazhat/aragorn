"""Local conformance producer for Aragorn's private protected-install primitive."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

_REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPOSITORY / "src"))

import aragorn.admission_artifact_graph as artifact_graph_module  # noqa: E402
import aragorn.analyzer_receipt as analyzer_receipt_module  # noqa: E402
from aragorn.acquire import ingest_local  # noqa: E402
from aragorn.admission_artifact_graph import (  # noqa: E402
    retain_admission_artifact_graph,
)
from aragorn.analyze import run_analyzer  # noqa: E402
from aragorn.analyzer_receipt import retain_analyzer_run  # noqa: E402
from aragorn.cas import CAS  # noqa: E402
from aragorn.decision_receipt import (  # noqa: E402
    retain_decision_v3,
    verify_decision_v3,
)
from aragorn.oci_worker_protocol import (  # noqa: E402
    canonical_digest,
    canonical_json,
)
from aragorn.protected_install import (  # noqa: E402
    ProtectedInstallTransactionError,
    _publish_protected_install_transaction,
)

_SCHEMA = "aragorn/openclaw-protected-install-broker-producer-receipt/v1"
_ASSURANCE = "LOCAL_BROKER_CONFORMANCE_ONLY_NOT_INSTALLER_AUTHORITY"
_TARGET = "aragorn-admitted"
_SCANNER = "aragorn-inert-fixture-scanner"
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
    runtime_conformance_digest: str,
    target_runtime_digest: str,
    revoked_context_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    return _publish_protected_install_transaction(
        cas,
        context,
        root_fd,
        now_unix=now_unix,
        claim_now_unix=now_unix,
        expected_context_digest=canonical_digest(context),
        expected_target_name=_TARGET,
        expected_runtime_conformance_digest=runtime_conformance_digest,
        measured_target_runtime_digest=target_runtime_digest,
        revoked_context_ids=revoked_context_ids,
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


def _run(args: argparse.Namespace) -> dict[str, Any]:
    if os.name != "posix":
        raise BrokerConformanceError("protected install conformance requires POSIX")
    if args.expected_broker_uid != os.geteuid():
        raise BrokerConformanceError("effective UID is not the expected broker UID")
    if args.now_unix < 0 or args.expires_at_unix <= args.now_unix:
        raise BrokerConformanceError("trusted time window is invalid")
    for value in (
        args.target_runtime_digest,
        args.runtime_conformance_digest,
    ):
        if (
            not value.startswith("sha256:")
            or len(value) != 71
            or any(character not in "0123456789abcdef" for character in value[7:])
        ):
            raise BrokerConformanceError("runtime digest is invalid")

    protected_root = Path(args.protected_root).resolve(strict=True)
    cas_root = Path(args.cas_root).resolve(strict=False)
    common = Path(os.path.commonpath((protected_root, cas_root)))
    if common in {protected_root, cas_root}:
        raise BrokerConformanceError("CAS and protected roots must be disjoint")
    root_state = _require_root(protected_root, args.expected_broker_uid)
    if list(protected_root.iterdir()):
        raise BrokerConformanceError("protected root must start empty")
    cas = CAS(cas_root)
    analyzer_verifier_digest = _module_digest(analyzer_receipt_module)
    graph_verifier_digest = _module_digest(artifact_graph_module)
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
    if sorted(path.name for path in protected_root.iterdir()) != [
        ".aragorn-install-claims",
        ".aragorn-versions",
        _TARGET,
    ]:
        raise BrokerConformanceError("protected root namespace contains residue")
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
    parser.add_argument("--cas-root", required=True)
    parser.add_argument("--protected-root", required=True)
    parser.add_argument("--expected-broker-uid", required=True, type=int)
    parser.add_argument("--now-unix", required=True, type=int)
    parser.add_argument("--expires-at-unix", required=True, type=int)
    parser.add_argument("--target-runtime-digest", required=True)
    parser.add_argument("--runtime-conformance-digest", required=True)
    return parser


def main() -> int:
    try:
        receipt = _run(_parser().parse_args())
    except Exception as exc:  # noqa: BLE001 - emit one canonical fail-closed receipt
        receipt = {
            "schema": _SCHEMA,
            "assurance": _ASSURANCE,
            "slice_status": "ERROR",
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "limitations": _LIMITATIONS,
        }
        sys.stdout.buffer.write(canonical_json(receipt) + b"\n")
        return 1
    sys.stdout.buffer.write(canonical_json(receipt) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
