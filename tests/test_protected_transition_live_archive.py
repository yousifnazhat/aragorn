from __future__ import annotations

import gzip
import hashlib
import tarfile
import tempfile
import unittest
from io import BytesIO
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from aragorn.artifact_closure import (
    canonical_json,
    load_verified_retained_manifest,
)
from aragorn.cas import CAS
from aragorn.github_gateway import QUARANTINE_AUTHORITY, build_gateway_request
from aragorn.manifest_diff import diff_verified_manifests_between
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.protected_install_transition_replay import _Phase
from aragorn.protected_transition_live_archive import (
    CAPTURE_AUTHORITY,
    CAPTURE_SCHEMA,
    ProtectedTransitionLiveArchiveError,
    verify_protected_transition_live_archive,
)

_LIVE_ARCHIVE = (
    Path(__file__).parents[1]
    / "benchmark"
    / "evidence"
    / (
        "phase1-protected-transition-obra-superpowers-"
        "requesting-code-review-2026-07-29.tar.gz"
    )
)
_LIVE_ARCHIVE_DIGEST = (
    "sha256:3754f7ae4787ced43351ec0d2c696062f563e60543c381f769b86339823a5ac7"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _manifest(content: bytes, label: str) -> tuple[dict, dict[str, bytes]]:
    content_digest = _digest(content)
    files = [
        {
            "path": "SKILL.md",
            "size": len(content),
            "digest": content_digest,
            "executable": False,
        }
    ]
    manifest = {
        "schema": "aragorn/manifest/v1",
        "source": {"kind": "local", "path": f"/synthetic/{label}"},
        "tree_digest": _digest(canonical_json(files)),
        "files": files,
        "closure": {"scope": "source_tree", "status": "complete"},
    }
    raw = canonical_json(manifest)
    return manifest, {content_digest: content, _digest(raw): raw}


def _request(
    label: str,
    source: dict,
    manifest_digest: str,
    context_id: str,
    pins: dict[str, str],
    *,
    expected_active: dict | None,
    diff_digest: str | None,
) -> dict:
    return {
        "schema": "aragorn/protected-install-broker-request/v2",
        "expires_at_unix": 1000,
        "operation": label,
        "expected_active": expected_active,
        "expected_manifest_diff_digest": diff_digest,
        "manifest_digest": manifest_digest,
        "quarantine_receipt_digest": _digest(f"{label}-receipt".encode()),
        "gateway_profile_digest": _digest(b"gateway"),
        "context_id": context_id,
        "source_request": source,
        **pins,
    }


def _claim(label: str, request: dict, tree_digest: str) -> dict:
    version = (
        f".aragorn-versions/aragorn-admitted/{request['context_id'][7:]}-"
        f"{request['manifest_digest'][7:]}"
    )
    return {
        "schema": "aragorn/protected-install-transaction/v1",
        "authority": "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "context_digest": _digest(f"{label}-context".encode()),
        "context_id": request["context_id"],
        "operation": label,
        "expected_active": (
            None
            if label == "install"
            else {
                "context_id": request["expected_active"]["context_id"],
                "manifest_digest": request["expected_active"]["manifest_digest"],
            }
        ),
        "manifest_digest": request["manifest_digest"],
        "tree_digest": tree_digest,
        "destination": {
            "root_device": 1,
            "root_inode": 2,
            "target_name": "aragorn-admitted",
        },
        "version_path": version,
    }


def _tar(files: dict[str, tuple[int, bytes]]) -> bytes:
    directories = {
        "/".join(PurePosixPath(path).parts[:depth])
        for path in files
        for depth in range(1, len(PurePosixPath(path).parts))
    }
    tar_raw = BytesIO()
    with tarfile.open(fileobj=tar_raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(directories | set(files)):
            member = tarfile.TarInfo(name)
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ""
            if name in directories:
                member.type = tarfile.DIRTYPE
                member.mode = (
                    0o555
                    if name.startswith(
                        (
                            "protected/versions/install",
                            "protected/versions/update",
                        )
                    )
                    else 0o700
                )
                tar.addfile(member)
            else:
                member.mode, content = files[name]
                member.size = len(content)
                tar.addfile(member, BytesIO(content))
    compressed = BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=0) as stream:
        stream.write(tar_raw.getvalue())
    return compressed.getvalue()


class ProtectedTransitionLiveArchiveTests(unittest.TestCase):
    def test_replays_live_byte_changing_two_file_transition(self) -> None:
        result = verify_protected_transition_live_archive(
            _LIVE_ARCHIVE,
            expected_archive_digest=_LIVE_ARCHIVE_DIGEST,
        )

        self.assertEqual(result["install"]["installed_file_count"], 2)
        self.assertEqual(result["update"]["installed_file_count"], 2)
        self.assertEqual(result["transition"]["changed_paths"], ["SKILL.md"])
        self.assertEqual(result["transition"]["tree_mismatches"], 0)
        self.assertTrue(result["transition"]["byte_changing"])

    def test_replays_full_trees_and_rejects_extra_or_tampered_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifests = {}
            cas_bytes = {}
            for label, content in (("install", b"old\n"), ("update", b"new\n")):
                manifests[label], cas_bytes[label] = _manifest(content, label)
            manifest_digests = {
                label: next(
                    digest
                    for digest, raw in cas_bytes[label].items()
                    if raw == canonical_json(manifests[label])
                )
                for label in ("install", "update")
            }
            stores = {label: CAS(root / f"build-{label}") for label in manifests}
            for label, store in stores.items():
                for digest, raw in cas_bytes[label].items():
                    store.put_expected(
                        BytesIO(raw),
                        expected_digest=digest,
                        max_bytes=len(raw),
                    )
            diff = diff_verified_manifests_between(
                stores["install"],
                manifest_digests["install"],
                stores["update"],
                manifest_digests["update"],
            )
            diff_raw = canonical_json(diff)
            diff_digest = canonical_digest(diff)
            stores["update"].put_expected(
                BytesIO(diff_raw),
                expected_digest=diff_digest,
                max_bytes=len(diff_raw),
            )
            cas_bytes["update"][diff_digest] = diff_raw

            source_install = build_gateway_request(
                "example", "skills", "1" * 40, "demo"
            )
            source_update = build_gateway_request("example", "skills", "2" * 40, "demo")
            pins = {
                "target_runtime_digest": _digest(b"runtime"),
                "runtime_conformance_digest": _digest(b"conformance"),
                "expected_producer_implementation_digest": _digest(b"broker"),
                "expected_analyzer_implementation_digest": _digest(b"analyzer"),
                "expected_analyzer_executable_digest": _digest(b"python"),
                "expected_analyzer_configuration_digest": _digest(b"config"),
                "expected_policy_digest": _digest(b"policy"),
                "expected_analyzer_verifier_digest": _digest(b"analyzer-verifier"),
                "expected_artifact_graph_verifier_digest": _digest(b"graph-verifier"),
            }
            install = _request(
                "install",
                source_install,
                manifest_digests["install"],
                _digest(b"install-context"),
                pins,
                expected_active=None,
                diff_digest=None,
            )
            expected_active = {
                "context_id": install["context_id"],
                "manifest_digest": install["manifest_digest"],
                "source_request": install["source_request"],
                "quarantine_receipt_digest": install["quarantine_receipt_digest"],
                "gateway_profile_digest": install["gateway_profile_digest"],
            }
            update = _request(
                "update",
                source_update,
                manifest_digests["update"],
                _digest(b"update-context"),
                pins,
                expected_active=expected_active,
                diff_digest=diff_digest,
            )
            requests = {"install": install, "update": update}
            claims = {
                label: _claim(label, requests[label], manifests[label]["tree_digest"])
                for label in requests
            }
            broker = {
                label: {
                    "schema": (
                        "aragorn/openclaw-github-protected-install-broker-evidence/v1"
                    ),
                    "assurance": (
                        "LIVE_GITHUB_CUSTODY_TO_PROTECTED_INSTALL_EVIDENCE_ONLY_"
                        "NOT_INSTALLER_AUTHORITY"
                    ),
                    "slice_status": "PASS",
                    "mode": "github-live",
                    "request_authority": {},
                    "analyzer": {
                        "execution_identity": {
                            "uid": 983,
                            "user": "aragorn-analyze",
                            "gid": 983,
                            "group": "aragorn-analyze",
                            "supplementary_groups": [],
                        }
                    },
                    "decision": {
                        "verdict": "ALLOW",
                        "installer_work_eligible": False,
                    },
                    "context": {
                        "operation": label,
                        "expected_active": (
                            None
                            if label == "install"
                            else {
                                "context_id": install["context_id"],
                                "manifest_digest": install["manifest_digest"],
                            }
                        ),
                    },
                    "transition": (
                        {
                            "operation": "install",
                            "expected_active": None,
                            "manifest_diff": None,
                        }
                        if label == "install"
                        else {"operation": "update"}
                    ),
                }
                for label in requests
            }
            coordinator = {
                label: {
                    "schema": "aragorn/protected-install-coordinator-result/v1",
                    "assurance": (
                        "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
                    ),
                    "operation": label,
                    "source_request": requests[label]["source_request"],
                    "manifest_digest": requests[label]["manifest_digest"],
                    "quarantine_receipt_digest": requests[label][
                        "quarantine_receipt_digest"
                    ],
                    "gateway_profile_digest": requests[label]["gateway_profile_digest"],
                    "context_id": requests[label]["context_id"],
                    "service_request_digest": _digest(canonical_json(requests[label])),
                    "installer_work_eligible": False,
                    "runtime_conformance_qualified": False,
                    "quarantine_authority": QUARANTINE_AUTHORITY,
                    "status": "COMPLETED_NOT_INSTALLER_AUTHORITY",
                }
                for label in requests
            }
            state = {
                "schema": "aragorn/protected-install-coordinator-state/v1",
                "assurance": (
                    "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
                ),
                "expected_active": {
                    "context_id": update["context_id"],
                    "manifest_digest": update["manifest_digest"],
                    "source_request": update["source_request"],
                    "quarantine_receipt_digest": update["quarantine_receipt_digest"],
                    "gateway_profile_digest": update["gateway_profile_digest"],
                },
                "tree_digest": manifests["update"]["tree_digest"],
                "version_path": claims["update"]["version_path"],
                "service_request_digest": _digest(canonical_json(update)),
            }
            revocations = {
                "schema": "aragorn/protected-install-revocations/v1",
                "context_ids": [],
            }
            release = {
                "schema": "aragorn/protected-broker-launch-identity/v1",
                "broker": {
                    "digest": pins["expected_producer_implementation_digest"],
                    "path": "broker.py",
                },
                "launcher": {"digest": _digest(b"launcher"), "path": "launcher.py"},
                "package": {"root": "/opt/aragorn", "tree_digest": _digest(b"package")},
                "python": {
                    "digest": pins["expected_analyzer_executable_digest"],
                    "path": "/usr/bin/python",
                },
            }
            raw = {
                "requests/install.json": canonical_json(install),
                "requests/update.json": canonical_json(update),
                "evidence/install-broker.json": canonical_json(broker["install"]),
                "evidence/update-broker.json": canonical_json(broker["update"]),
                "evidence/install-coordinator.json": canonical_json(
                    coordinator["install"]
                ),
                "evidence/update-coordinator.json": canonical_json(
                    coordinator["update"]
                ),
                "protected/claims/install.json": canonical_json(claims["install"]),
                "protected/claims/update.json": canonical_json(claims["update"]),
                "protected/coordinator-state.json": canonical_json(state),
                "config/revocations.json": canonical_json(revocations),
                "config/release.json": canonical_json(release),
            }
            runtime = {
                "release_digest": _digest(raw["config/release.json"]),
                "producer_implementation_digest": pins[
                    "expected_producer_implementation_digest"
                ],
                "analyzer_implementation_digest": pins[
                    "expected_analyzer_implementation_digest"
                ],
                "analyzer_executable_digest": pins[
                    "expected_analyzer_executable_digest"
                ],
                "analyzer_configuration_digest": pins[
                    "expected_analyzer_configuration_digest"
                ],
                "policy_digest": pins["expected_policy_digest"],
                "analyzer_verifier_digest": pins["expected_analyzer_verifier_digest"],
                "artifact_graph_verifier_digest": pins[
                    "expected_artifact_graph_verifier_digest"
                ],
                "target_runtime_digest": pins["target_runtime_digest"],
                "runtime_conformance_digest": pins["runtime_conformance_digest"],
                "launcher_digest": release["launcher"]["digest"],
                "package_tree_digest": release["package"]["tree_digest"],
            }
            capture = {
                "schema": CAPTURE_SCHEMA,
                "authority": CAPTURE_AUTHORITY,
                "phases": {
                    label: {
                        "source_request": requests[label]["source_request"],
                        "context_id": requests[label]["context_id"],
                        "manifest_digest": requests[label]["manifest_digest"],
                        "tree_digest": manifests[label]["tree_digest"],
                        "version_path": claims[label]["version_path"],
                        "members": {
                            "request_digest": _digest(raw[f"requests/{label}.json"]),
                            "broker_evidence_digest": _digest(
                                raw[f"evidence/{label}-broker.json"]
                            ),
                            "coordinator_evidence_digest": _digest(
                                raw[f"evidence/{label}-coordinator.json"]
                            ),
                            "claim_digest": _digest(
                                raw[f"protected/claims/{label}.json"]
                            ),
                        },
                    }
                    for label in requests
                },
                "active": {
                    "context_id": update["context_id"],
                    "manifest_digest": update["manifest_digest"],
                    "tree_digest": manifests["update"]["tree_digest"],
                    "link_target": claims["update"]["version_path"],
                },
                "control_members": {
                    "coordinator_state_digest": _digest(
                        raw["protected/coordinator-state.json"]
                    ),
                    "revocations_digest": _digest(raw["config/revocations.json"]),
                },
                "runtime_provenance": runtime,
            }
            raw["capture.json"] = canonical_json(capture)

            modes = {
                name: (
                    0o400
                    if name.startswith(("requests/", "protected/claims/"))
                    or name
                    in {
                        "protected/coordinator-state.json",
                        "config/revocations.json",
                        "config/release.json",
                    }
                    else 0o444
                )
                for name in raw
            }
            files = {name: (modes[name], content) for name, content in raw.items()}
            for label, content in (("install", b"old\n"), ("update", b"new\n")):
                files[f"protected/versions/{label}/SKILL.md"] = (0o444, content)
                for digest, blob in cas_bytes[label].items():
                    value = digest[7:]
                    files[f"cas/{label}/blobs/sha256/{value[:2]}/{value[2:]}"] = (
                        0o444,
                        blob,
                    )

            def replay_phase(
                cas,
                request,
                evidence,
                *,
                operation,
                revocation_digest,
                previous=None,
            ):
                del revocation_digest, previous
                manifest = load_verified_retained_manifest(
                    cas, request["manifest_digest"]
                )
                return _Phase(
                    cas,
                    request,
                    evidence,
                    manifest,
                    {},
                    {
                        "context_id": request["context_id"],
                        "manifest_digest": request["manifest_digest"],
                    },
                    claims[operation],
                    set(cas_bytes[operation]),
                )

            with (
                patch(
                    "aragorn.protected_transition_live_archive._phase",
                    side_effect=replay_phase,
                ),
                patch("aragorn.protected_transition_live_archive._request_authority"),
            ):
                archive = _tar(files)
                archive_path = root / "valid.tar.gz"
                archive_path.write_bytes(archive)
                result = verify_protected_transition_live_archive(
                    archive_path,
                    expected_archive_digest=_digest(archive),
                )
                self.assertEqual(result["install"]["installed_file_count"], 1)
                self.assertEqual(result["update"]["verdict"], "ALLOW")
                self.assertEqual(result["transition"]["tree_mismatches"], 0)

                mutations = {
                    "extra": {
                        **files,
                        "unexpected.txt": (0o444, b"extra"),
                    },
                    "tree-content": {
                        **files,
                        "protected/versions/update/SKILL.md": (0o444, b"bad\n"),
                    },
                }
                for name, changed in mutations.items():
                    with self.subTest(name=name):
                        forged = _tar(changed)
                        forged_path = root / f"{name}.tar.gz"
                        forged_path.write_bytes(forged)
                        with self.assertRaises(ProtectedTransitionLiveArchiveError):
                            verify_protected_transition_live_archive(
                                forged_path,
                                expected_archive_digest=_digest(forged),
                            )


if __name__ == "__main__":
    unittest.main()
