from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest import mock

from aragorn.artifact_closure import canonical_json
from aragorn.benchmark_handoff_v2 import import_declared_byte_transport
from aragorn.cas import CAS
from aragorn.github_expansion_proof import retain_github_expansion_proof
from aragorn.github_gateway import build_gateway_request
from aragorn.github_quarantine_receipt import (
    LINUX_CONTAINMENT_PROFILE,
    github_gateway_profile_digest,
)
from aragorn.github_recursive_gateway import (
    GitHubRecursiveGatewayError,
    _extend_release_asset_inventory_closure,
    _verify_release_assets,
    accept_recursive_gateway_output,
    quarantine_recursive_through_gateway,
    run_recursive_worker,
)
from aragorn.github_source_proof import retain_github_source_proof
from aragorn.zip_inventory import (
    MAX_ENTRIES,
    MAX_EXPANDED_BYTES,
    retain_zip_inventory,
    verify_zip_inventory,
)


def _oid(kind: str, payload: bytes) -> str:
    header = f"{kind} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _zip_bytes(*, shebang: bool = False) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr("package/main.py", b"print('retained')\n")
        archive.writestr("README.md", b"bounded release archive\n")
    raw = output.getvalue()
    return b"#!/usr/bin/env python3\n" + raw if shebang else raw


class GitHubRecursiveGatewayTests(unittest.TestCase):
    def test_release_asset_replay_requires_broker_pins_and_rejects_forgery(
        self,
    ) -> None:
        url = (
            "https://github.com/example/skills/releases/"
            "download/v1/checksums.txt"
        )
        content = b"fixture checksum\n"
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            cas.put_expected(
                BytesIO(content),
                expected_digest=digest,
                max_bytes=len(content),
            )
            result = {
                "schema": "aragorn/github-release-asset/v1",
                "source": {
                    "kind": "github_release_asset",
                    "host": "github.com",
                    "owner": "example",
                    "repository": "skills",
                    "tag": "v1",
                    "url": url,
                },
                "asset": {
                    "release_id": 1,
                    "asset_id": 2,
                    "name": "checksums.txt",
                    "size": len(content),
                    "digest": digest,
                    "github_digest": digest,
                    "content_type": "application/octet-stream",
                },
                "transport": {
                    "api_version": "2026-03-10",
                    "redirected": False,
                    "final_host": "api.github.com",
                },
                "closure": {"scope": "release_asset", "status": "complete"},
            }
            raw = canonical_json(result)
            result_digest = cas.put(BytesIO(raw), max_bytes=len(raw))
            entry = {"url": url, "result_digest": result_digest}
            pins = {
                url: {
                    "release_id": 1,
                    "asset_id": 2,
                    "digest": digest,
                    "github_digest": digest,
                    "content_type": "application/octet-stream",
                    "redirected": False,
                }
            }

            closure = _verify_release_assets(
                cas,
                (entry,),
                (url,),
                release_asset_pins=pins,
            )

            self.assertEqual(
                closure,
                {
                    result_digest: len(raw),
                    digest: len(content),
                },
            )
            for entries, discovered in (
                ((), (url,)),
                ((entry,), ()),
            ):
                with (
                    self.subTest(entries=entries, discovered=discovered),
                    self.assertRaises(GitHubRecursiveGatewayError),
                ):
                    _verify_release_assets(
                        cas,
                        entries,
                        discovered,
                        release_asset_pins=pins,
                    )

            forged_content = b"self-consistent bytes not selected by the broker\n"
            forged_asset_digest = (
                "sha256:" + hashlib.sha256(forged_content).hexdigest()
            )
            cas.put_expected(
                BytesIO(forged_content),
                expected_digest=forged_asset_digest,
                max_bytes=len(forged_content),
            )
            forged = deepcopy(result)
            forged["asset"]["size"] = len(forged_content)
            forged["asset"]["digest"] = forged_asset_digest
            forged["asset"]["github_digest"] = forged_asset_digest
            forged_raw = canonical_json(forged)
            forged_digest = cas.put(
                BytesIO(forged_raw),
                max_bytes=len(forged_raw),
            )
            with self.assertRaises(GitHubRecursiveGatewayError):
                _verify_release_assets(
                    cas,
                    ({"url": url, "result_digest": forged_digest},),
                    (url,),
                    release_asset_pins=pins,
                )

    def test_release_asset_v2_replay_closes_inventory_and_member_blobs(self) -> None:
        url = (
            "https://github.com/example/skills/releases/"
            "download/v1/bundle.pyz"
        )
        content = _zip_bytes(shebang=True)
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            cas.put_expected(
                BytesIO(content),
                expected_digest=digest,
                max_bytes=len(content),
            )
            inventory_digest = retain_zip_inventory(
                cas,
                digest,
                archive_name="bundle.pyz",
            )
            inventory = verify_zip_inventory(
                CAS(cas.root, read_only=True),
                inventory_digest,
                expected_archive_digest=digest,
                expected_archive_name="bundle.pyz",
            )
            result = {
                "schema": "aragorn/github-release-asset/v2",
                "source": {
                    "kind": "github_release_asset",
                    "host": "github.com",
                    "owner": "example",
                    "repository": "skills",
                    "tag": "v1",
                    "url": url,
                },
                "asset": {
                    "release_id": 1,
                    "asset_id": 2,
                    "name": "bundle.pyz",
                    "size": len(content),
                    "digest": digest,
                    "github_digest": digest,
                    "content_type": "application/octet-stream",
                },
                "transport": {
                    "api_version": "2026-03-10",
                    "redirected": False,
                    "final_host": "api.github.com",
                },
                "inventory_digest": inventory_digest,
                "closure": {"scope": "release_asset", "status": "complete"},
            }
            raw = canonical_json(result)
            result_digest = cas.put(BytesIO(raw), max_bytes=len(raw))
            pins = {
                url: {
                    "release_id": 1,
                    "asset_id": 2,
                    "digest": digest,
                    "github_digest": digest,
                    "content_type": "application/octet-stream",
                    "redirected": False,
                }
            }

            closure = _verify_release_assets(
                cas,
                ({"url": url, "result_digest": result_digest},),
                (url,),
                release_asset_pins=pins,
            )

            self.assertEqual(closure[result_digest], len(raw))
            self.assertEqual(closure[digest], len(content))
            self.assertEqual(
                closure[inventory_digest],
                len(cas.read(inventory_digest)),
            )
            for member in inventory["files"]:
                self.assertEqual(closure[member["digest"]], member["size"])

            incomplete = CAS(Path(temporary) / "incomplete")
            for retained_digest, retained_raw in (
                (digest, content),
                (inventory_digest, cas.read(inventory_digest)),
                (result_digest, raw),
            ):
                incomplete.put_expected(
                    BytesIO(retained_raw),
                    expected_digest=retained_digest,
                    max_bytes=len(retained_raw),
                )
            with self.assertRaisesRegex(
                GitHubRecursiveGatewayError,
                "verification failed",
            ):
                _verify_release_assets(
                    incomplete,
                    ({"url": url, "result_digest": result_digest},),
                    (url,),
                    release_asset_pins=pins,
                )

    def test_release_asset_v2_replay_bounds_cumulative_expanded_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            inventory_digest = cas.put(
                BytesIO(b"retained inventory"),
                max_bytes=len(b"retained inventory"),
            )
            member_digest = "sha256:" + "1" * 64
            inventory = {
                "totals": {"expanded_bytes": 3, "entries": 1},
                "files": [{"digest": member_digest, "size": 3}],
            }
            result = {
                "schema": "aragorn/github-release-asset/v2",
                "asset": {
                    "name": "bundle.pyz",
                    "digest": "sha256:" + "2" * 64,
                },
                "inventory_digest": inventory_digest,
            }
            closure: dict[str, int] = {}
            member_digests: set[str] = set()
            with (
                mock.patch(
                    "aragorn.github_recursive_gateway.verify_zip_inventory",
                    return_value=inventory,
                ),
                mock.patch(
                    "aragorn.github_recursive_gateway.MAX_EXPANDED_BYTES",
                    3,
                ),
            ):
                expanded_bytes, entry_count = (
                    _extend_release_asset_inventory_closure(
                        closure,
                        cas,
                        result,
                        expanded_bytes=0,
                        entry_count=0,
                        member_digests=member_digests,
                    )
                )
                with self.assertRaisesRegex(
                    GitHubRecursiveGatewayError,
                    "expanded bytes exceed their aggregate bound",
                ):
                    _extend_release_asset_inventory_closure(
                        closure,
                        cas,
                        result,
                        expanded_bytes=expanded_bytes,
                        entry_count=entry_count,
                        member_digests=member_digests,
                    )

    def test_automatic_release_pin_orchestration_remains_fail_closed(self) -> None:
        url = (
            "https://github.com/example/skills/releases/"
            "download/v1/checksums.txt"
        )
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(
                GitHubRecursiveGatewayError,
                "lack exact broker-held pins",
            ),
        ):
            _verify_release_assets(
                CAS(Path(temporary) / "cas"),
                ({"url": url, "result_digest": "sha256:" + "1" * 64},),
                (url,),
            )

    def test_recursive_wrapper_selects_the_hardened_supervisor_path(self) -> None:
        request = {"schema": "irrelevant to delegated supervisor"}
        with mock.patch(
            "aragorn.github_recursive_gateway._quarantine_through_gateway",
            return_value="accepted",
        ) as delegated:
            result = quarantine_recursive_through_gateway(
                request,
                gateway_root="/gateway",
                quarantine_state="/quarantine",
                worker_uid=501,
                worker_gid=20,
                python_executable="/usr/bin/python3",
                package_root="/opt/aragorn",
            )
        self.assertEqual(result, "accepted")
        self.assertTrue(delegated.call_args.kwargs["recursive"])

    def test_worker_exports_proof_bound_closure_without_credentials(self) -> None:
        content = b"# root\n"
        blob = _oid("blob", content)
        skill_tree_raw = b"100644 SKILL.md\0" + bytes.fromhex(blob)
        skill_tree = _oid("tree", skill_tree_raw)
        root_tree_raw = b"40000 demo\0" + bytes.fromhex(skill_tree)
        root_tree = _oid("tree", root_tree_raw)
        commit_raw = (
            f"tree {root_tree}\n".encode("ascii")
            + b"author Fixture <fixture@example.test> 1 +0000\n"
            + b"committer Fixture <fixture@example.test> 1 +0000\n\nfixture\n"
        )
        commit = _oid("commit", commit_raw)
        request = build_gateway_request("example", "skills", commit, "demo")
        closure_status = "complete"

        def fake_expansion(
            _repository: str,
            _commit: str,
            _skill_path: str,
            cas: CAS,
            **_kwargs: object,
        ) -> dict:
            digest = cas.put(BytesIO(content), max_bytes=len(content))
            files = [
                {
                    "path": "SKILL.md",
                    "size": len(content),
                    "digest": digest,
                    "git_blob_sha1": blob,
                    "executable": False,
                }
            ]
            tree_files = [
                {
                    key: files[0][key]
                    for key in ("path", "size", "digest", "executable")
                }
            ]
            manifest = {
                "schema": "aragorn/github-manifest/v1",
                "source": {
                    "kind": "github_commit",
                    "host": "github.com",
                    "owner": "example",
                    "repository": "skills",
                    "commit": commit,
                    "repository_hash_algorithm": "sha1",
                    "commit_tree": root_tree,
                    "skill_path": "demo",
                    "skill_tree": skill_tree,
                    "api_version": "2026-03-10",
                },
                "tree_digest": "sha256:"
                + hashlib.sha256(canonical_json(tree_files)).hexdigest(),
                "files": files,
                "closure": {"scope": "source_tree", "status": "complete"},
            }
            manifest_raw = canonical_json(manifest)
            manifest_digest = cas.put(
                BytesIO(manifest_raw),
                max_bytes=len(manifest_raw),
            )
            raw_objects = {
                ("commit", commit): commit_raw,
                ("tree", root_tree): root_tree_raw,
                ("tree", skill_tree): skill_tree_raw,
            }
            source_proof_digest = retain_github_source_proof(
                cas,
                manifest,
                raw_objects,
            )
            expansion = {
                "schema": "aragorn/github-expansion/v1",
                "profile": "phase0-exact-github-blob-expansion/v1",
                "assurance": (
                    "evaluation_only_github_api_membership_asserted_"
                    "blob_identity_reverified"
                ),
                "source": {
                    key: manifest["source"][key]
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
                "root_manifest_digest": manifest_digest,
                "root_tree_digest": manifest["tree_digest"],
                "comparator_subject_manifest_digest": None,
                "comparator_subject_tree_digest": None,
                "references": [],
                "objects": [],
                "accounting": {},
                "closure": {
                    "scope": "phase0_exact_github_blob_expansion",
                    "status": closure_status,
                    "unresolved": (
                        []
                        if closure_status == "complete"
                        else [
                            {
                                "reason_code": "RELEASE_OR_ARCHIVE_UNRESOLVED",
                                "subject": "SKILL.md",
                            }
                        ]
                    ),
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
                manifest_digest,
                raw_objects,
            )
            return {
                "schema": "aragorn/github-expansion-result/v1",
                "expansion_digest": expansion_digest,
                "root_manifest_digest": manifest_digest,
                "root_tree_digest": manifest["tree_digest"],
                "comparator_subject_manifest_digest": None,
                "comparator_subject_tree_digest": None,
                "expanded_object_count": 0,
                "accounting": {},
                "closure": expansion["closure"],
                "source_proof_digest": source_proof_digest,
                "expansion_proof_digest": expansion_proof_digest,
            }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gateway = root / "gateway"
            gateway.mkdir(mode=0o700)
            job = gateway / "job"
            with mock.patch(
                "aragorn.github_recursive_gateway.acquire_github_expansion",
                side_effect=fake_expansion,
            ) as acquire:
                result = run_recursive_worker(
                    request,
                    job,
                    pinned_api_addresses=("1.1.1.1",),
                    pinned_git_addresses=("8.8.8.8",),
                )

            self.assertEqual(result["closure_status"], "complete")
            self.assertIsInstance(result["expansion_proof_digest"], str)
            self.assertIsNone(acquire.call_args.kwargs["bearer_token"])
            self.assertEqual(
                acquire.call_args.kwargs["_pinned_addresses"],
                ("1.1.1.1",),
            )
            self.assertEqual(
                acquire.call_args.kwargs["_pinned_git_addresses"],
                ("8.8.8.8",),
            )
            imported = CAS(root / "imported")
            handoff = import_declared_byte_transport(
                job / "bundle",
                imported,
                expected_manifest_digest=result["handoff_manifest_digest"],
                expected_kind="github_source",
                expected_root_digest=result["manifest_digest"],
            )
            self.assertIn(
                result["expansion_digest"],
                {entry["digest"] for entry in handoff["blobs"]},
            )
            broker = root / "broker"
            broker.mkdir(mode=0o700)
            quarantine = broker / "quarantine"
            python_digest = "sha256:" + "1" * 64
            package_digest = "sha256:" + "2" * 64
            with (
                mock.patch(
                    "aragorn.github_quarantine_receipt.sys.platform",
                    "linux",
                ),
                mock.patch(
                    "aragorn.github_recursive_gateway."
                    "discover_recursive_github_release_asset_urls",
                    side_effect=AssertionError("v1 must retain its scanner contract"),
                ),
            ):
                accepted = accept_recursive_gateway_output(
                    request,
                    result,
                    job_root=job,
                    quarantine_state=quarantine,
                    worker_uid=os.geteuid(),
                    containment_profile=LINUX_CONTAINMENT_PROFILE,
                    python_executable_digest=python_digest,
                    gateway_package_tree_digest=package_digest,
                )
            self.assertEqual(accepted.manifest_digest, result["manifest_digest"])
            self.assertEqual(
                accepted.gateway_profile_digest,
                github_gateway_profile_digest(
                    containment_profile=LINUX_CONTAINMENT_PROFILE,
                    python_executable_digest=python_digest,
                    gateway_package_tree_digest=package_digest,
                ),
            )
            CAS(quarantine, read_only=True).verify(result["expansion_digest"])

            closure_status = "incomplete"
            partial_job = gateway / "partial-job"
            with mock.patch(
                "aragorn.github_recursive_gateway.acquire_github_expansion",
                side_effect=fake_expansion,
            ):
                partial = run_recursive_worker(
                    request,
                    partial_job,
                    pinned_api_addresses=("1.1.1.1",),
                    pinned_git_addresses=("8.8.8.8",),
                )
            self.assertEqual(partial["closure_status"], "incomplete")
            partial_imported = CAS(root / "partial-imported")
            partial_handoff = import_declared_byte_transport(
                partial_job / "bundle",
                partial_imported,
                expected_manifest_digest=partial["handoff_manifest_digest"],
                expected_kind="github_source",
                expected_root_digest=partial["manifest_digest"],
            )
            self.assertIn(
                partial["expansion_proof_digest"],
                {entry["digest"] for entry in partial_handoff["blobs"]},
            )

            release_url = (
                "https://github.com/example/skills/releases/"
                "download/v1/bundle.pyz"
            )
            release_bytes = _zip_bytes(shebang=True)
            release_digest = "sha256:" + hashlib.sha256(release_bytes).hexdigest()

            def fake_release(
                url: str,
                cas: CAS,
                **_kwargs: object,
            ) -> dict:
                cas.put_expected(
                    BytesIO(release_bytes),
                    expected_digest=release_digest,
                    max_bytes=len(release_bytes),
                )
                inventory_digest = retain_zip_inventory(
                    cas,
                    release_digest,
                    archive_name="bundle.pyz",
                )
                return {
                    "schema": "aragorn/github-release-asset/v2",
                    "source": {
                        "kind": "github_release_asset",
                        "host": "github.com",
                        "owner": "example",
                        "repository": "skills",
                        "tag": "v1",
                        "url": url,
                    },
                    "asset": {
                        "release_id": 1,
                        "asset_id": 2,
                        "name": "bundle.pyz",
                        "size": len(release_bytes),
                        "digest": release_digest,
                        "github_digest": release_digest,
                        "content_type": "application/octet-stream",
                    },
                    "transport": {
                        "api_version": "2026-03-10",
                        "redirected": True,
                        "final_host": "release-assets.githubusercontent.com",
                    },
                    "inventory_digest": inventory_digest,
                    "closure": {
                        "scope": "release_asset",
                        "status": "complete",
                    },
                }

            release_job = gateway / "release-job"
            with (
                mock.patch(
                    "aragorn.github_recursive_gateway.acquire_github_expansion",
                    side_effect=fake_expansion,
                ),
                mock.patch(
                    "aragorn.github_recursive_gateway."
                    "discover_recursive_github_release_asset_urls",
                    return_value=(release_url,),
                ),
                mock.patch(
                    "aragorn.github_recursive_gateway.acquire_github_release_asset",
                    side_effect=fake_release,
                ) as release_acquire,
            ):
                release_result = run_recursive_worker(
                    request,
                    release_job,
                    pinned_api_addresses=("1.1.1.1",),
                    pinned_git_addresses=("8.8.8.8",),
                    pinned_release_asset_addresses=("9.9.9.9",),
                )

            self.assertEqual(
                release_result["schema"],
                "aragorn/github-recursive-gateway-result/v2",
            )
            self.assertEqual(
                [entry["url"] for entry in release_result["release_assets"]],
                [release_url],
            )
            self.assertEqual(
                release_acquire.call_args.kwargs["_pinned_asset_addresses"],
                ("9.9.9.9",),
            )
            self.assertEqual(
                release_acquire.call_args.kwargs["max_asset_bytes"],
                16 * 1024 * 1024,
            )
            self.assertEqual(
                release_acquire.call_args.kwargs["_max_zip_expanded_bytes"],
                MAX_EXPANDED_BYTES,
            )
            self.assertEqual(
                release_acquire.call_args.kwargs["_max_zip_entries"],
                MAX_ENTRIES,
            )
            release_imported = CAS(root / "release-imported")
            release_handoff = import_declared_byte_transport(
                release_job / "bundle",
                release_imported,
                expected_manifest_digest=release_result[
                    "handoff_manifest_digest"
                ],
                expected_kind="github_source",
                expected_root_digest=release_result["manifest_digest"],
            )
            release_closure = {
                entry["digest"] for entry in release_handoff["blobs"]
            }
            self.assertIn(release_digest, release_closure)
            self.assertIn(
                release_result["release_assets"][0]["result_digest"],
                release_closure,
            )
            retained_result = json.loads(
                release_imported.read(
                    release_result["release_assets"][0]["result_digest"]
                )
            )
            retained_inventory = verify_zip_inventory(
                CAS(release_imported.root, read_only=True),
                retained_result["inventory_digest"],
                expected_archive_digest=release_digest,
                expected_archive_name="bundle.pyz",
            )
            self.assertIn(retained_result["inventory_digest"], release_closure)
            for member in retained_inventory["files"]:
                self.assertIn(member["digest"], release_closure)


if __name__ == "__main__":
    unittest.main()
