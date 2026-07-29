from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
import zipfile
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest import mock

from aragorn.acquire import ingest_local
from aragorn.admission_artifact_graph import verify_admission_artifact_graph
from aragorn.artifact_closure import canonical_json, load_verified_retained_manifest
from aragorn.benchmark_handoff_v2 import build_handoff_manifest
from aragorn.cas import CAS
from aragorn.github_expansion_proof import retain_github_expansion_proof
from aragorn.github_quarantine_receipt import (
    LINUX_CONTAINMENT_PROFILE,
    github_gateway_profile_digest,
    retain_github_quarantine_receipt,
)
from aragorn.github_recursive_artifact_graph import (
    retain_expanded_github_manifest,
    retain_recursive_github_artifact_graph,
)
from aragorn.github_recursive_artifact_graph_v4 import (
    GitHubRecursiveArtifactGraphError,
    discover_recursive_github_release_asset_urls,
)
from aragorn.github_recursive_artifact_graph_v4 import (
    retain_recursive_github_artifact_graph as retain_recursive_github_artifact_graph_v4,
)
from aragorn.github_recursive_artifact_graph_v6 import (
    _validate_combined_analysis_files,
    retain_vendored_release_manifest,
)
from aragorn.github_recursive_artifact_graph_v6 import (
    retain_recursive_github_artifact_graph as retain_recursive_github_artifact_graph_v6,
)
from aragorn.github_source_proof import retain_github_source_proof
from aragorn.policy import Policy, evaluate_policy
from aragorn.zip_inventory import retain_zip_inventory

_VERIFIER_DIGEST = "sha256:" + "1" * 64
_PYTHON_DIGEST = "sha256:" + "2" * 64
_PACKAGE_DIGEST = "sha256:" + "3" * 64


def _oid(kind: str, payload: bytes) -> str:
    header = f"{kind} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _tree(entries: list[tuple[str, str, bytes]]) -> tuple[str, bytes]:
    raw = b"".join(
        mode.encode("ascii") + b" " + name + b"\0" + bytes.fromhex(oid)
        for mode, oid, name in entries
    )
    return _oid("tree", raw), raw


def _commit(tree: str, message: bytes) -> tuple[str, bytes]:
    raw = (
        f"tree {tree}\n".encode("ascii")
        + b"author Fixture <fixture@example.test> 1 +0000\n"
        + b"committer Fixture <fixture@example.test> 1 +0000\n\n"
        + message
        + b"\n"
    )
    return _oid("commit", raw), raw


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _release_result(
    cas: CAS,
    *,
    url: str,
    name: str,
    content: bytes,
    asset_id: int,
    github_digest: bool,
    inventory_digest: str | None = None,
) -> tuple[str, str]:
    asset_digest = cas.put(BytesIO(content), max_bytes=len(content))
    document = {
        "schema": (
            "aragorn/github-release-asset/v2"
            if inventory_digest is not None
            else "aragorn/github-release-asset/v1"
        ),
        "source": {
            "kind": "github_release_asset",
            "host": "github.com",
            "owner": "example",
            "repository": "skills",
            "tag": "0.12.0",
            "url": url,
        },
        "asset": {
            "release_id": 361308705,
            "asset_id": asset_id,
            "name": name,
            "size": len(content),
            "digest": asset_digest,
            "github_digest": asset_digest if github_digest else None,
            "content_type": "application/octet-stream",
        },
        "transport": {
            "api_version": "2026-03-10",
            "redirected": True,
            "final_host": "release-assets.githubusercontent.com",
        },
        "closure": {"scope": "release_asset", "status": "complete"},
    }
    if inventory_digest is not None:
        document["inventory_digest"] = inventory_digest
    raw = canonical_json(document)
    return cas.put(BytesIO(raw), max_bytes=len(raw)), asset_digest


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return output.getvalue()


class GitHubRecursiveArtifactGraphTests(unittest.TestCase):
    def test_runtime_vendoring_requires_digest_backed_inventory_archive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cas = CAS(root / "state")
            source = root / "source"
            source.mkdir()
            (source / "SKILL.md").write_text("# retained source\n")
            source_manifest = ingest_local(source, cas)
            source_raw = canonical_json(source_manifest)
            source_digest = cas.put(
                BytesIO(source_raw),
                max_bytes=len(source_raw),
            )

            archive = _zip_bytes({"agent/main.py": b"print('exact')\n"})
            archive_digest = cas.put(
                BytesIO(archive),
                max_bytes=len(archive),
            )
            inventory_digest = retain_zip_inventory(
                cas,
                archive_digest,
                archive_name="bundle.pyz",
            )
            digest_backed_result, _ = _release_result(
                cas,
                url=(
                    "https://github.com/example/skills/releases/"
                    "download/0.12.0/bundle.pyz"
                ),
                name="bundle.pyz",
                content=archive,
                asset_id=10,
                github_digest=True,
                inventory_digest=inventory_digest,
            )
            vendored_digest = retain_vendored_release_manifest(
                cas,
                source_digest,
                (digest_backed_result,),
            )
            vendored = load_verified_retained_manifest(cas, vendored_digest)
            vendored_path = (
                "__aragorn_release_assets__/361308705/10/raw/bundle.pyz"
            )
            self.assertEqual(
                {entry["path"]: entry for entry in vendored["files"]}[
                    vendored_path
                ]["digest"],
                archive_digest,
            )
            self.assertEqual(cas.read(archive_digest), archive)

            reserved_source = root / "reserved-source"
            reserved_source.mkdir()
            (reserved_source / "SKILL.md").write_text("# reserved source\n")
            reserved_path = (
                reserved_source
                / "__aragorn_release_assets__"
                / "untrusted.txt"
            )
            reserved_path.parent.mkdir()
            reserved_path.write_text("untrusted\n")
            reserved_manifest = ingest_local(reserved_source, cas)
            reserved_raw = canonical_json(reserved_manifest)
            reserved_digest = cas.put(
                BytesIO(reserved_raw),
                max_bytes=len(reserved_raw),
            )
            with self.assertRaisesRegex(
                GitHubRecursiveArtifactGraphError,
                "reserved release namespace",
            ):
                retain_vendored_release_manifest(
                    cas,
                    reserved_digest,
                    (digest_backed_result,),
                )

            duplicate_inventory = retain_zip_inventory(
                cas,
                archive_digest,
                archive_name="duplicate.pyz",
            )
            duplicate_identity_result, _ = _release_result(
                cas,
                url=(
                    "https://github.com/example/skills/releases/"
                    "download/0.12.0/duplicate.pyz"
                ),
                name="duplicate.pyz",
                content=archive,
                asset_id=10,
                github_digest=True,
                inventory_digest=duplicate_inventory,
            )
            with self.assertRaisesRegex(
                GitHubRecursiveArtifactGraphError,
                "repeat a GitHub identity",
            ):
                retain_vendored_release_manifest(
                    cas,
                    source_digest,
                    (digest_backed_result, duplicate_identity_result),
                )

            unsigned_result, _ = _release_result(
                cas,
                url=(
                    "https://github.com/example/skills/releases/"
                    "download/0.12.0/unsigned.pyz"
                ),
                name="unsigned.pyz",
                content=archive,
                asset_id=11,
                github_digest=False,
                inventory_digest=retain_zip_inventory(
                    cas,
                    archive_digest,
                    archive_name="unsigned.pyz",
                ),
            )
            nonarchive_result, _ = _release_result(
                cas,
                url=(
                    "https://github.com/example/skills/releases/"
                    "download/0.12.0/checksums.txt"
                ),
                name="checksums.txt",
                content=b"retained checksum\n",
                asset_id=12,
                github_digest=True,
            )
            for result_digest in (unsigned_result, nonarchive_result):
                with self.subTest(result_digest=result_digest):
                    self.assertEqual(
                        retain_vendored_release_manifest(
                            cas,
                            source_digest,
                            (result_digest,),
                        ),
                        source_digest,
                    )

    def test_analysis_manifest_bounds_and_collisions_fail_closed(self) -> None:
        def entry(path: str, size: int = 0) -> dict[str, object]:
            return {
                "path": path,
                "size": size,
                "digest": _VERIFIER_DIGEST,
                "executable": False,
            }

        for files in (
            [entry("Release.bin"), entry("release.bin")],
            [entry("__aragorn_release_assets__"), entry(
                "__aragorn_release_assets__/1/2/raw/asset.bin"
            )],
            [entry("/".join(["nested"] * 10))],
            [entry(f"file-{index}") for index in range(10_001)],
            [entry(f"file-{index}", 16 * 1024 * 1024) for index in range(9)],
        ):
            with (
                self.subTest(files=len(files)),
                self.assertRaises(GitHubRecursiveArtifactGraphError),
            ):
                _validate_combined_analysis_files(files)

    def test_cross_commit_markdown_closes_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            target_content = b"# target\n"
            target_blob = _oid("blob", target_content)
            payload_tree, payload_tree_raw = _tree(
                [("100644", target_blob, b"target.md")]
            )
            target_root, target_root_raw = _tree(
                [("40000", payload_tree, b"payloads")]
            )
            target_commit, target_commit_raw = _commit(target_root, b"target")

            root_content = (
                f"[target](https://raw.githubusercontent.com/example/skills/"
                f"{target_commit}/payloads/target.md)\n"
            ).encode("ascii")
            root_blob = _oid("blob", root_content)
            skill_tree, skill_tree_raw = _tree(
                [("100644", root_blob, b"SKILL.md")]
            )
            root_tree, root_tree_raw = _tree(
                [("40000", skill_tree, b"demo")]
            )
            root_commit, root_commit_raw = _commit(root_tree, b"root")

            root_blob_digest = cas.put(
                BytesIO(root_content),
                max_bytes=len(root_content),
            )
            target_digest = cas.put(
                BytesIO(target_content),
                max_bytes=len(target_content),
            )
            root_file = {
                "path": "SKILL.md",
                "size": len(root_content),
                "digest": root_blob_digest,
                "git_blob_sha1": root_blob,
                "executable": False,
            }
            root_manifest = {
                "schema": "aragorn/github-manifest/v1",
                "source": {
                    "kind": "github_commit",
                    "host": "github.com",
                    "owner": "example",
                    "repository": "skills",
                    "commit": root_commit,
                    "repository_hash_algorithm": "sha1",
                    "commit_tree": root_tree,
                    "skill_path": "demo",
                    "skill_tree": skill_tree,
                    "api_version": "2026-03-10",
                },
                "tree_digest": _sha256(
                    canonical_json(
                        [
                            {
                                key: root_file[key]
                                for key in (
                                    "path",
                                    "size",
                                    "digest",
                                    "executable",
                                )
                            }
                        ]
                    )
                ),
                "files": [root_file],
                "closure": {"scope": "source_tree", "status": "complete"},
            }
            root_raw = canonical_json(root_manifest)
            root_manifest_digest = cas.put(
                BytesIO(root_raw),
                max_bytes=len(root_raw),
            )
            source_proof_digest = retain_github_source_proof(
                cas,
                root_manifest,
                {
                    ("commit", root_commit): root_commit_raw,
                    ("tree", root_tree): root_tree_raw,
                    ("tree", skill_tree): skill_tree_raw,
                },
            )
            handoff_blobs = {
                root_manifest_digest: len(root_raw),
                root_blob_digest: len(root_content),
                source_proof_digest: len(cas.read(source_proof_digest)),
                _sha256(root_commit_raw): len(root_commit_raw),
                _sha256(root_tree_raw): len(root_tree_raw),
                _sha256(skill_tree_raw): len(skill_tree_raw),
            }
            handoff = build_handoff_manifest(
                kind="github_source",
                root_digest=root_manifest_digest,
                blobs=handoff_blobs,
            )
            handoff_raw = canonical_json(handoff)
            handoff_digest = cas.put(
                BytesIO(handoff_raw),
                max_bytes=len(handoff_raw),
            )
            request = {
                "schema": "aragorn/github-gateway-request/v1",
                "owner": "example",
                "repository": "skills",
                "commit": root_commit,
                "skill_path": "demo",
            }
            gateway_profile = github_gateway_profile_digest(
                containment_profile=LINUX_CONTAINMENT_PROFILE,
                gateway_package_tree_digest=_PACKAGE_DIGEST,
                python_executable_digest=_PYTHON_DIGEST,
            )
            with mock.patch(
                "aragorn.github_quarantine_receipt.sys.platform",
                "linux",
            ):
                receipt_digest = retain_github_quarantine_receipt(
                    cas,
                    request=request,
                    manifest_digest=root_manifest_digest,
                    source_proof_digest=source_proof_digest,
                    handoff_manifest_digest=handoff_digest,
                    containment_profile=LINUX_CONTAINMENT_PROFILE,
                    gateway_package_tree_digest=_PACKAGE_DIGEST,
                    python_executable_digest=_PYTHON_DIGEST,
                )

            materialized = (
                f"__aragorn_expanded__/{target_commit}/payloads/target.md"
            )
            expansion_object = {
                "commit": target_commit,
                "commit_tree": target_root,
                "repository_path": "payloads/target.md",
                "materialized_path": materialized,
                "depth": 1,
                "size": len(target_content),
                "digest": target_digest,
                "git_blob_sha1": target_blob,
                "executable": False,
                "references": [],
            }
            expansion = {
                "schema": "aragorn/github-expansion/v1",
                "profile": "phase0-exact-github-blob-expansion/v1",
                "assurance": (
                    "evaluation_only_github_api_membership_asserted_"
                    "blob_identity_reverified"
                ),
                "source": {
                    key: root_manifest["source"][key]
                    for key in (
                        "host",
                        "owner",
                        "repository",
                        "commit",
                        "commit_tree",
                        "skill_path",
                        "api_version",
                    )
                },
                "root_manifest_digest": root_manifest_digest,
                "root_tree_digest": root_manifest["tree_digest"],
                "comparator_subject_manifest_digest": None,
                "comparator_subject_tree_digest": None,
                "references": [],
                "objects": [expansion_object],
                "accounting": {},
                "closure": {
                    "scope": "phase0_exact_github_blob_expansion",
                    "status": "complete",
                    "unresolved": [],
                },
            }
            expansion_raw = canonical_json(expansion)
            expansion_digest = cas.put(
                BytesIO(expansion_raw),
                max_bytes=len(expansion_raw),
            )
            expansion_proof_digest = retain_github_expansion_proof(
                cas,
                expansion_digest,
                root_manifest_digest,
                {
                    ("commit", target_commit): target_commit_raw,
                    ("tree", target_root): target_root_raw,
                    ("tree", payload_tree): payload_tree_raw,
                },
            )
            manifest_digest = retain_expanded_github_manifest(
                cas,
                expansion_digest,
            )

            with (
                mock.patch(
                    "aragorn.github_quarantine_receipt.sys.platform",
                    "linux",
                ),
                mock.patch(
                    "aragorn.github_recursive_artifact_graph._REQUIRED_BROKER_UID",
                    os.geteuid(),
                ),
            ):
                graph_digest = retain_recursive_github_artifact_graph(
                    cas,
                    manifest_digest,
                    root_manifest_digest=root_manifest_digest,
                    expansion_digest=expansion_digest,
                    expansion_proof_digest=expansion_proof_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile,
                    verifier_implementation_digest=_VERIFIER_DIGEST,
                )
                graph = verify_admission_artifact_graph(
                    cas,
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile,
                    expected_verifier_digest=_VERIFIER_DIGEST,
                )

            self.assertEqual(graph["profile"], "recursive-github-markdown/v1")
            self.assertEqual(
                graph["coverage"]["statically_resolvable"],
                {"captured": 1, "total": 1},
            )
            self.assertEqual(graph["closure"]["status"], "complete")
            self.assertEqual(
                graph["edges"][0]["target"],
                {"path": materialized, "digest": target_digest},
            )
            decision = evaluate_policy(
                Policy(),
                closure=graph["closure"],
                results=[],
            )
            self.assertNotEqual(decision.verdict, "ERROR")

            release_base = (
                "https://github.com/example/skills/releases/download/0.12.0"
            )
            archive_url = f"{release_base}/agent-bundle.tar.gz"
            checksums_url = f"{release_base}/checksums.txt"
            unsigned_url = f"{release_base}/release-notes.txt"
            zip_carrier_url = f"{release_base}/agent-bundle.bin"
            release_reference = (
                f"[archive]({archive_url})\n"
                f"[checksums]({checksums_url})\n"
                f"[notes]({unsigned_url})\n"
                f"[ZIP carrier]({zip_carrier_url})\n"
            ).encode("ascii")
            release_blob = _oid("blob", release_reference)
            release_tree, release_tree_raw = _tree(
                [("100644", release_blob, b"archive.md")]
            )
            release_commit, release_commit_raw = _commit(
                release_tree,
                b"release reference",
            )
            release_reference_digest = cas.put(
                BytesIO(release_reference),
                max_bytes=len(release_reference),
            )
            release_expansion = deepcopy(expansion)
            release_expansion["closure"] = {
                "scope": "phase0_exact_github_blob_expansion",
                "status": "incomplete",
                "unresolved": [
                    {
                        "reason_code": "GITHUB_RELEASE_ASSET_NOT_RETAINED",
                        "subject": "archive.md",
                    }
                ],
            }
            release_expansion["objects"].append(
                {
                    "commit": release_commit,
                    "commit_tree": release_tree,
                    "repository_path": "archive.md",
                    "materialized_path": (
                        f"__aragorn_expanded__/{release_commit}/archive.md"
                    ),
                    "depth": 1,
                    "size": len(release_reference),
                    "digest": release_reference_digest,
                    "git_blob_sha1": release_blob,
                    "executable": False,
                    "references": [],
                }
            )
            release_expansion_raw = canonical_json(release_expansion)
            release_expansion_digest = cas.put(
                BytesIO(release_expansion_raw),
                max_bytes=len(release_expansion_raw),
            )
            release_expansion_proof_digest = retain_github_expansion_proof(
                cas,
                release_expansion_digest,
                root_manifest_digest,
                {
                    ("commit", target_commit): target_commit_raw,
                    ("tree", target_root): target_root_raw,
                    ("tree", payload_tree): payload_tree_raw,
                    ("commit", release_commit): release_commit_raw,
                    ("tree", release_tree): release_tree_raw,
                },
            )
            release_manifest_digest = retain_expanded_github_manifest(
                cas,
                release_expansion_digest,
            )
            self.assertEqual(
                discover_recursive_github_release_asset_urls(
                    cas,
                    release_expansion_digest,
                ),
                tuple(
                    sorted(
                        (
                            archive_url,
                            checksums_url,
                            unsigned_url,
                            zip_carrier_url,
                        )
                    )
                ),
            )

            archive_result_digest, archive_digest = _release_result(
                cas,
                url=archive_url,
                name="agent-bundle.tar.gz",
                content=b"opaque archive fixture",
                asset_id=493071343,
                github_digest=True,
            )
            checksums_result_digest, checksums_digest = _release_result(
                cas,
                url=checksums_url,
                name="checksums.txt",
                content=b"sha256 fixture",
                asset_id=493071344,
                github_digest=True,
            )
            unsigned_result_digest, unsigned_digest = _release_result(
                cas,
                url=unsigned_url,
                name="release-notes.txt",
                content=b"unsigned fixture",
                asset_id=493071345,
                github_digest=False,
            )
            carrier_v1_result_digest, carrier_v1_digest = _release_result(
                cas,
                url=zip_carrier_url,
                name="agent-bundle.bin",
                content=b"opaque binary fixture",
                asset_id=493071346,
                github_digest=True,
            )
            release_result_digests = (
                archive_result_digest,
                checksums_result_digest,
                unsigned_result_digest,
                carrier_v1_result_digest,
            )
            with (
                mock.patch(
                    "aragorn.github_quarantine_receipt.sys.platform",
                    "linux",
                ),
                mock.patch(
                    "aragorn.github_recursive_artifact_graph_v4._REQUIRED_BROKER_UID",
                    os.geteuid(),
                ),
            ):
                release_graph_digest = retain_recursive_github_artifact_graph_v4(
                    cas,
                    release_manifest_digest,
                    root_manifest_digest=root_manifest_digest,
                    expansion_digest=release_expansion_digest,
                    expansion_proof_digest=release_expansion_proof_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile,
                    verifier_implementation_digest=_VERIFIER_DIGEST,
                    release_asset_result_digests=release_result_digests,
                )
                release_graph = verify_admission_artifact_graph(
                    cas,
                    release_graph_digest,
                    expected_manifest_digest=release_manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile,
                    expected_verifier_digest=_VERIFIER_DIGEST,
                    expected_release_asset_result_digests=release_result_digests,
                )
                self.assertEqual(
                    retain_recursive_github_artifact_graph_v6(
                        cas,
                        release_manifest_digest,
                        root_manifest_digest=root_manifest_digest,
                        expansion_digest=release_expansion_digest,
                        expansion_proof_digest=release_expansion_proof_digest,
                        expected_quarantine_receipt_digest=receipt_digest,
                        expected_gateway_profile_digest=gateway_profile,
                        verifier_implementation_digest=_VERIFIER_DIGEST,
                        release_asset_result_digests=release_result_digests,
                    ),
                    release_graph_digest,
                )
                with self.assertRaises(GitHubRecursiveArtifactGraphError):
                    verify_admission_artifact_graph(
                        cas,
                        release_graph_digest,
                        expected_manifest_digest=release_manifest_digest,
                        expected_quarantine_receipt_digest=receipt_digest,
                        expected_gateway_profile_digest=gateway_profile,
                        expected_verifier_digest=_VERIFIER_DIGEST,
                    )

            release_edges = {
                edge["literal"]: edge
                for edge in release_graph["edges"]
                if edge["reference_kind"] == "github_release_asset"
            }
            archive_edge = release_edges[archive_url]
            self.assertEqual(
                archive_edge["target"],
                {
                    "kind": "github_release_asset",
                    "url": archive_url,
                    "release_id": 361308705,
                    "asset_id": 493071343,
                    "digest": archive_digest,
                    "github_digest": archive_digest,
                    "result_digest": archive_result_digest,
                },
            )
            self.assertEqual(
                archive_edge["reason_code"],
                "ARCHIVE_INVENTORY_UNSUPPORTED",
            )
            self.assertEqual(archive_edge["status"], "unresolved")
            self.assertEqual(
                checksums_digest,
                release_edges[checksums_url]["target"]["digest"],
            )
            self.assertEqual(release_edges[checksums_url]["status"], "unresolved")
            self.assertEqual(
                release_edges[checksums_url]["reason_code"],
                "GITHUB_RELEASE_ASSET_NOT_ANALYZED",
            )
            self.assertEqual(
                unsigned_digest,
                release_edges[unsigned_url]["target"]["digest"],
            )
            self.assertIsNone(
                release_edges[unsigned_url]["target"]["github_digest"]
            )
            self.assertEqual(release_edges[unsigned_url]["status"], "unresolved")
            self.assertEqual(
                release_edges[unsigned_url]["reason_code"],
                "GITHUB_RELEASE_ASSET_DIGEST_UNAVAILABLE",
            )
            self.assertEqual(
                release_graph["schema"],
                "aragorn/admission-artifact-graph/v4",
            )
            self.assertEqual(release_graph["closure"]["status"], "incomplete")
            self.assertTrue(
                any(
                    reason.startswith("ARCHIVE_INVENTORY_UNSUPPORTED:")
                    for reason in release_graph["closure"]["unresolved"]
                )
            )
            self.assertTrue(
                any(
                    reason.startswith("GITHUB_RELEASE_ASSET_NOT_ANALYZED:")
                    for reason in release_graph["closure"]["unresolved"]
                )
            )
            self.assertFalse(
                any(
                    reason.startswith(
                        "EXPANSION_GITHUB_RELEASE_ASSET_NOT_RETAINED:"
                    )
                    for reason in release_graph["closure"]["unresolved"]
                )
            )
            retained_artifact_digests = {
                artifact["digest"] for artifact in release_graph["artifacts"]
            }
            for digest in (
                archive_digest,
                checksums_digest,
                unsigned_digest,
                carrier_v1_digest,
                *release_result_digests,
            ):
                self.assertNotIn(digest, retained_artifact_digests)
            self.assertEqual(
                release_graph["coverage"]["statically_resolvable"],
                {"captured": 5, "total": 5},
            )
            self.assertEqual(
                evaluate_policy(
                    Policy(),
                    closure=release_graph["closure"],
                    results=[],
                ).verdict,
                "ERROR",
            )

            zip_content = _zip_bytes(
                {
                    "agent/main.py": b"print('retained')\n",
                    "prompts/system.txt": b"analyze me\n",
                }
            )
            zip_digest = cas.put(BytesIO(zip_content), max_bytes=len(zip_content))
            inventory_digest = retain_zip_inventory(
                cas,
                zip_digest,
                archive_name="agent-bundle.bin",
            )
            carrier_v2_result_digest, carrier_v2_digest = _release_result(
                cas,
                url=zip_carrier_url,
                name="agent-bundle.bin",
                content=zip_content,
                asset_id=493071346,
                github_digest=True,
                inventory_digest=inventory_digest,
            )
            self.assertEqual(carrier_v2_digest, zip_digest)
            analysis_result_digests = (
                archive_result_digest,
                checksums_result_digest,
                unsigned_result_digest,
                carrier_v2_result_digest,
            )
            runtime_manifest_digest = retain_vendored_release_manifest(
                cas,
                release_manifest_digest,
                analysis_result_digests,
            )
            with (
                mock.patch(
                    "aragorn.github_quarantine_receipt.sys.platform",
                    "linux",
                ),
                mock.patch(
                    "aragorn.github_recursive_artifact_graph_v4._REQUIRED_BROKER_UID",
                    os.geteuid(),
                ),
            ):
                analysis_graph_digest = retain_recursive_github_artifact_graph_v6(
                    cas,
                    release_manifest_digest,
                    root_manifest_digest=root_manifest_digest,
                    expansion_digest=release_expansion_digest,
                    expansion_proof_digest=release_expansion_proof_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile,
                    verifier_implementation_digest=_VERIFIER_DIGEST,
                    release_asset_result_digests=analysis_result_digests,
                )
                analysis_graph = verify_admission_artifact_graph(
                    cas,
                    analysis_graph_digest,
                    expected_manifest_digest=release_manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile,
                    expected_verifier_digest=_VERIFIER_DIGEST,
                    expected_release_asset_result_digests=analysis_result_digests,
                )

            self.assertEqual(
                analysis_graph["schema"],
                "aragorn/admission-artifact-graph/v6",
            )
            self.assertEqual(
                analysis_graph["profile"],
                "recursive-github-markdown/v3",
            )
            self.assertEqual(
                analysis_graph["closure"]["status"],
                "incomplete",
            )
            self.assertTrue(
                any(
                    reason.startswith(
                        "GITHUB_RELEASE_ASSET_RUNTIME_CONSUMER_UNPROVEN:"
                    )
                    for reason in analysis_graph["closure"]["unresolved"]
                )
            )
            self.assertEqual(
                analysis_graph["root_manifest_digest"],
                release_graph["root_manifest_digest"],
            )
            self.assertEqual(
                analysis_graph["tree_digest"],
                release_graph["tree_digest"],
            )
            self.assertEqual(
                analysis_graph["artifacts"],
                release_graph["artifacts"],
            )
            self.assertEqual(
                analysis_graph["runtime_candidate_manifest_digest"],
                runtime_manifest_digest,
            )
            runtime_manifest = load_verified_retained_manifest(
                cas,
                runtime_manifest_digest,
            )
            self.assertEqual(
                analysis_graph["runtime_candidate_tree_digest"],
                runtime_manifest["tree_digest"],
            )
            runtime_paths = {
                artifact["path"]: artifact
                for artifact in analysis_graph["runtime_candidate_artifacts"]
            }
            runtime_path = (
                "__aragorn_release_assets__/361308705/"
                "493071346/raw/agent-bundle.bin"
            )
            self.assertEqual(
                runtime_paths[runtime_path]["digest"],
                zip_digest,
            )
            self.assertFalse(
                any("/members/" in path for path in runtime_paths)
            )
            analysis_manifest = load_verified_retained_manifest(
                cas,
                analysis_graph["analysis_manifest_digest"],
            )
            self.assertEqual(
                analysis_manifest["tree_digest"],
                analysis_graph["analysis_tree_digest"],
            )
            self.assertNotEqual(
                analysis_graph["analysis_tree_digest"],
                analysis_graph["runtime_candidate_tree_digest"],
            )
            analysis_paths = {
                artifact["path"]: artifact for artifact in analysis_manifest["files"]
            }
            release_prefix = (
                "__aragorn_release_assets__/361308705/493071346"
            )
            self.assertNotIn(
                f"{release_prefix}/raw/agent-bundle.bin",
                analysis_paths,
            )
            self.assertIn(
                f"{release_prefix}/members/agent/main.py",
                analysis_paths,
            )
            self.assertIn(
                f"{release_prefix}/members/prompts/system.txt",
                analysis_paths,
            )
            self.assertEqual(
                analysis_paths[
                    "__aragorn_release_assets__/361308705/"
                    "493071344/raw/checksums.txt"
                ]["digest"],
                checksums_digest,
            )
            self.assertFalse(
                any("493071343" in path for path in analysis_paths)
            )
            self.assertFalse(
                any("493071345" in path for path in analysis_paths)
            )

            analysis_edges = {
                edge["literal"]: edge
                for edge in analysis_graph["edges"]
                if edge["reference_kind"] == "github_release_asset"
            }
            self.assertEqual(
                analysis_edges[zip_carrier_url]["status"],
                "unresolved",
            )
            self.assertEqual(
                analysis_edges[zip_carrier_url]["reason_code"],
                "GITHUB_RELEASE_ASSET_RUNTIME_CONSUMER_UNPROVEN",
            )
            self.assertEqual(
                analysis_edges[zip_carrier_url]["target"]["inventory_digest"],
                inventory_digest,
            )
            self.assertEqual(
                analysis_edges[zip_carrier_url]["target"]["runtime_path"],
                runtime_path,
            )
            self.assertEqual(
                analysis_edges[checksums_url]["status"],
                "unresolved",
            )
            self.assertEqual(
                analysis_edges[checksums_url]["reason_code"],
                "GITHUB_RELEASE_ASSET_RUNTIME_BINDING_UNPROVEN",
            )
            self.assertIsNone(
                analysis_edges[checksums_url]["target"]["inventory_digest"],
            )
            self.assertIsNone(
                analysis_edges[checksums_url]["target"]["runtime_path"],
            )
            self.assertEqual(analysis_edges[archive_url]["status"], "unresolved")
            self.assertEqual(
                analysis_edges[archive_url]["reason_code"],
                "ARCHIVE_INVENTORY_UNSUPPORTED",
            )
            self.assertEqual(analysis_edges[unsigned_url]["status"], "unresolved")
            self.assertEqual(
                analysis_edges[unsigned_url]["reason_code"],
                "GITHUB_RELEASE_ASSET_DIGEST_UNAVAILABLE",
            )

            unsigned_archive_inventory_digest = retain_zip_inventory(
                cas,
                zip_digest,
                archive_name="agent-bundle.tar.gz",
            )
            unsigned_v2_result_digest, _ = _release_result(
                cas,
                url=archive_url,
                name="agent-bundle.tar.gz",
                content=zip_content,
                asset_id=493071343,
                github_digest=False,
                inventory_digest=unsigned_archive_inventory_digest,
            )
            unsigned_analysis_digests = (
                unsigned_v2_result_digest,
                checksums_result_digest,
                unsigned_result_digest,
                carrier_v2_result_digest,
            )
            with (
                mock.patch(
                    "aragorn.github_quarantine_receipt.sys.platform",
                    "linux",
                ),
                mock.patch(
                    "aragorn.github_recursive_artifact_graph_v4._REQUIRED_BROKER_UID",
                    os.geteuid(),
                ),
            ):
                unsigned_graph_digest = (
                    retain_recursive_github_artifact_graph_v6(
                        cas,
                        release_manifest_digest,
                        root_manifest_digest=root_manifest_digest,
                        expansion_digest=release_expansion_digest,
                        expansion_proof_digest=release_expansion_proof_digest,
                        expected_quarantine_receipt_digest=receipt_digest,
                        expected_gateway_profile_digest=gateway_profile,
                        verifier_implementation_digest=_VERIFIER_DIGEST,
                        release_asset_result_digests=unsigned_analysis_digests,
                    )
                )
            with (
                mock.patch(
                    "aragorn.github_quarantine_receipt.sys.platform",
                    "linux",
                ),
                mock.patch(
                    "aragorn.github_recursive_artifact_graph_v4._REQUIRED_BROKER_UID",
                    os.geteuid(),
                ),
            ):
                unsigned_graph = verify_admission_artifact_graph(
                    cas,
                    unsigned_graph_digest,
                    expected_manifest_digest=release_manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile,
                    expected_verifier_digest=_VERIFIER_DIGEST,
                    expected_release_asset_result_digests=(
                        unsigned_analysis_digests
                    ),
                )
            unsigned_manifest = load_verified_retained_manifest(
                cas,
                unsigned_graph["analysis_manifest_digest"],
            )
            self.assertFalse(
                any(
                    "493071343" in entry["path"]
                    for entry in unsigned_manifest["files"]
                )
            )
            unsigned_edges = {
                edge["literal"]: edge for edge in unsigned_graph["edges"]
            }
            self.assertEqual(
                unsigned_edges[archive_url]["reason_code"],
                "GITHUB_RELEASE_ASSET_DIGEST_UNAVAILABLE",
            )

            def vendored_edge(document: dict) -> dict:
                return next(
                    edge
                    for edge in document["edges"]
                    if edge["literal"] == zip_carrier_url
                )

            def vendored_artifact(document: dict) -> dict:
                return next(
                    artifact
                    for artifact in document["runtime_candidate_artifacts"]
                    if artifact["path"] == runtime_path
                )

            mutations = {
                "analysis tree": lambda document: document.update(
                    analysis_tree_digest="sha256:" + "f" * 64
                ),
                "runtime path": lambda document: vendored_edge(document)[
                    "target"
                ].update(runtime_path="untrusted/path"),
                "edge status": lambda document: vendored_edge(document).update(
                    status="resolved"
                ),
                "target URL": lambda document: vendored_edge(document)[
                    "target"
                ].update(url=checksums_url),
                "asset digest": lambda document: vendored_edge(document)[
                    "target"
                ].update(digest="sha256:" + "a" * 64),
                "GitHub digest": lambda document: vendored_edge(document)[
                    "target"
                ].update(github_digest="sha256:" + "b" * 64),
                "result digest": lambda document: vendored_edge(document)[
                    "target"
                ].update(result_digest="sha256:" + "c" * 64),
                "inventory digest": lambda document: vendored_edge(document)[
                    "target"
                ].update(inventory_digest="sha256:" + "d" * 64),
                "runtime artifact path": lambda document: vendored_artifact(
                    document
                ).update(path="untrusted/path"),
                "runtime artifact digest": lambda document: vendored_artifact(
                    document
                ).update(digest="sha256:" + "e" * 64),
            }
            for label, mutate in mutations.items():
                tampered_graph = deepcopy(analysis_graph)
                mutate(tampered_graph)
                tampered_raw = canonical_json(tampered_graph)
                tampered_digest = cas.put(
                    BytesIO(tampered_raw),
                    max_bytes=len(tampered_raw),
                )
                with (
                    self.subTest(label=label),
                    mock.patch(
                        "aragorn.github_quarantine_receipt.sys.platform",
                        "linux",
                    ),
                    mock.patch(
                        "aragorn.github_recursive_artifact_graph_v4."
                        "_REQUIRED_BROKER_UID",
                        os.geteuid(),
                    ),
                    self.assertRaises(GitHubRecursiveArtifactGraphError),
                ):
                    verify_admission_artifact_graph(
                        cas,
                        tampered_digest,
                        expected_manifest_digest=release_manifest_digest,
                        expected_quarantine_receipt_digest=receipt_digest,
                        expected_gateway_profile_digest=gateway_profile,
                        expected_verifier_digest=_VERIFIER_DIGEST,
                        expected_release_asset_result_digests=(
                            analysis_result_digests
                        ),
                    )

            archive_hex = zip_digest.removeprefix("sha256:")
            (
                cas.root
                / "blobs"
                / "sha256"
                / archive_hex[:2]
                / archive_hex[2:]
            ).unlink()
            with (
                mock.patch(
                    "aragorn.github_quarantine_receipt.sys.platform",
                    "linux",
                ),
                mock.patch(
                    "aragorn.github_recursive_artifact_graph_v4._REQUIRED_BROKER_UID",
                    os.geteuid(),
                ),
                self.assertRaises(GitHubRecursiveArtifactGraphError),
            ):
                verify_admission_artifact_graph(
                    cas,
                    analysis_graph_digest,
                    expected_manifest_digest=release_manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile,
                    expected_verifier_digest=_VERIFIER_DIGEST,
                    expected_release_asset_result_digests=analysis_result_digests,
                )


if __name__ == "__main__":
    unittest.main()
