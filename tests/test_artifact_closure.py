from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path

from aragorn.acquire import ingest_local
from aragorn.artifact_closure import (
    ArtifactClosureError,
    canonical_json,
    load_retained_manifest,
    load_verified_retained_manifest,
    resolve_source_graph,
)
from aragorn.cas import CAS
from aragorn.cli import main
from aragorn.policy import Policy, evaluate_policy

COMMIT = "a" * 40


def _retain_manifest(cas: CAS, manifest: dict) -> str:
    content = canonical_json(manifest)
    return cas.put(BytesIO(content), max_bytes=len(content))


def _github_manifest(
    local: dict,
    cas: CAS,
    *,
    skill_path: str = ".",
) -> dict:
    return {
        "schema": "aragorn/github-manifest/v1",
        "source": {
            "kind": "github_commit",
            "host": "github.com",
            "owner": "example",
            "repository": "skill",
            "commit": COMMIT,
            "repository_hash_algorithm": "sha1",
            "commit_tree": "b" * 40,
            "skill_path": skill_path,
            "skill_tree": "c" * 40,
            "api_version": "2026-03-10",
        },
        "tree_digest": local["tree_digest"],
        "files": [
            {
                **entry,
                "git_blob_sha1": hashlib.sha1(
                    f"blob {entry['size']}\0".encode("ascii")
                    + cas.read(entry["digest"], max_bytes=entry["size"])
                ).hexdigest(),
            }
            for entry in local["files"]
        ],
        "closure": {"scope": "source_tree", "status": "complete"},
    }


def _replace_manifest_file(
    cas: CAS,
    manifest: dict,
    path: str,
    content: bytes,
) -> dict:
    candidate = json.loads(canonical_json(manifest))
    entry = next(item for item in candidate["files"] if item["path"] == path)
    entry["size"] = len(content)
    entry["digest"] = cas.put(BytesIO(content), max_bytes=len(content))
    if "git_blob_sha1" in entry:
        entry["git_blob_sha1"] = hashlib.sha1(
            f"blob {len(content)}\0".encode("ascii") + content
        ).hexdigest()
    tree_files = [
        {
            "path": item["path"],
            "size": item["size"],
            "digest": item["digest"],
            "executable": item["executable"],
        }
        for item in candidate["files"]
    ]
    candidate["tree_digest"] = (
        "sha256:" + hashlib.sha256(canonical_json(tree_files)).hexdigest()
    )
    return candidate


class ArtifactClosureTests(unittest.TestCase):
    def test_verified_github_manifest_rejects_git_lfs_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_bytes(
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + b"0" * 64 + b"\nsize 1\n"
            )
            cas = CAS(root / "state")
            manifest = _github_manifest(ingest_local(source, cas), cas)

            with self.assertRaisesRegex(ArtifactClosureError, "LFS pointer"):
                load_verified_retained_manifest(
                    cas,
                    _retain_manifest(cas, manifest),
                )

    def test_local_reference_resolves_but_cannot_unlock_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "scripts").mkdir()
            (source / "SKILL.md").write_text(
                "[setup](scripts/setup.sh)\n",
                encoding="utf-8",
            )
            (source / "scripts" / "setup.sh").write_text(
                "#!/bin/sh\nexit 0\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")
            manifest = ingest_local(source, cas)

            first = resolve_source_graph(manifest, cas)
            second = resolve_source_graph(manifest, cas)

            self.assertEqual(first, second)
            self.assertEqual(first["closure"]["status"], "complete")
            self.assertEqual(first["closure"]["scope"], "source_reference_graph")
            resolved = [edge for edge in first["edges"] if edge["status"] == "resolved"]
            self.assertEqual(len(resolved), 1)
            target = next(
                entry
                for entry in manifest["files"]
                if entry["path"] == "scripts/setup.sh"
            )
            self.assertEqual(
                resolved[0]["target"],
                {"path": "scripts/setup.sh", "digest": target["digest"]},
            )

            decision = evaluate_policy(
                Policy(),
                closure=first["closure"],
                results=(),
            )
            self.assertEqual(decision.verdict, "ERROR")
            self.assertEqual(
                decision.reason_codes,
                ("ARTIFACT_CLOSURE_INCOMPLETE",),
            )

    def test_release_mutable_and_dynamic_acquisition_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text(
                "\n".join(
                    (
                        "curl https://github.com/example/tool/releases/download/v1/tool.zip",
                        (
                            "[mutable](https://github.com/example/tool/"
                            "blob/main/install.sh)"
                        ),
                        "[issue](https://github.com/example/tool/issues/7)",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")
            graph = resolve_source_graph(ingest_local(source, cas), cas)

            reasons = {
                edge["reason_code"]
                for edge in graph["edges"]
                if edge["status"] == "unresolved"
            }
            self.assertEqual(graph["closure"]["status"], "incomplete")
            self.assertIn("RELEASE_OR_ARCHIVE_UNRESOLVED", reasons)
            self.assertIn("MUTABLE_GITHUB_REFERENCE", reasons)
            self.assertIn("DYNAMIC_OR_MUTABLE_ACQUISITION", reasons)
            issue = next(
                edge
                for edge in graph["edges"]
                if edge["reason_code"] == "GITHUB_METADATA_REFERENCE"
            )
            self.assertEqual(issue["status"], "non_artifact")

    def test_github_repository_urls_are_inert_only_as_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            repository = "https://github.com/example/project"
            (source / "SKILL.md").write_text(
                "\n".join(
                    (
                        f"[repository]({repository})",
                        f"<{repository}>",
                        f"gh repo clone {repository}",
                        f"docker build {repository}.git",
                        f"uv tool install {repository}",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")

            graph = resolve_source_graph(ingest_local(source, cas), cas)

            self.assertEqual(
                sum(
                    edge["reason_code"] == "GITHUB_METADATA_REFERENCE"
                    and edge["status"] == "non_artifact"
                    for edge in graph["edges"]
                ),
                2,
            )
            self.assertEqual(
                sum(
                    edge["reason_code"] == "EXTERNAL_REFERENCE_UNSUPPORTED"
                    and edge["status"] == "unresolved"
                    for edge in graph["edges"]
                ),
                3,
            )
            self.assertEqual(graph["closure"]["status"], "incomplete")

    def test_literal_interpreter_dependencies_fail_closed_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "scripts").mkdir()
            (source / "scripts" / "setup.sh").write_text(
                "#!/bin/sh\nexit 0\n",
                encoding="utf-8",
            )
            (source / "SKILL.md").write_text(
                "bash scripts/setup.sh\nbash ../payload.sh\npython missing.py\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")

            graph = resolve_source_graph(ingest_local(source, cas), cas)

            local_edges = [
                edge for edge in graph["edges"] if edge["reference_kind"] == "local"
            ]
            self.assertEqual(
                next(edge for edge in local_edges if edge["status"] == "resolved")[
                    "target"
                ]["path"],
                "scripts/setup.sh",
            )
            self.assertEqual(
                {
                    edge["reason_code"]
                    for edge in local_edges
                    if edge["status"] == "unresolved"
                },
                {
                    "LOCAL_ARTIFACT_NOT_RETAINED",
                    "LOCAL_REFERENCE_NOT_CANONICAL",
                },
            )
            self.assertEqual(graph["closure"]["status"], "incomplete")

    def test_option_bearing_interpreters_and_direct_execution_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "present.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            (source / "SKILL.md").write_text(
                "\n".join(
                    (
                        "bash -e ../payload.sh",
                        "python -u missing.py",
                        "env FOO=x bash missing.sh",
                        "env -i bash missing.sh",
                        "sudo -u nobody bash missing.sh",
                        "./setup.sh",
                        "./present.sh",
                        "command ./setup.sh",
                        "exec ./setup.sh",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")

            graph = resolve_source_graph(ingest_local(source, cas), cas)

            dynamic = [
                edge
                for edge in graph["edges"]
                if edge["reference_kind"] == "dynamic_command"
            ]
            self.assertEqual(len(dynamic), 5)
            self.assertTrue(
                all(
                    edge["reason_code"] == "DYNAMIC_OR_MUTABLE_ACQUISITION"
                    for edge in dynamic
                )
            )
            direct_edges = [
                edge for edge in graph["edges"] if edge["reference_kind"] == "local"
            ]
            self.assertEqual(len(direct_edges), 4)
            self.assertEqual(
                {(edge["status"], edge["reason_code"]) for edge in direct_edges},
                {
                    ("resolved", None),
                    ("unresolved", "LOCAL_ARTIFACT_NOT_RETAINED"),
                },
            )
            self.assertEqual(graph["closure"]["status"], "incomplete")

    def test_interpreter_names_in_benign_prose_are_not_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text(
                "\n".join(
                    (
                        "Python is a programming language.",
                        "Node is required for some development workflows.",
                        "Bash scripts are supported.",
                        "Ruby on Rails is a framework.",
                        "Perl was designed for text processing.",
                        "Python-based tooling is common.",
                        "Node.js is required by some packages.",
                        "Bash-compatible shells are widespread.",
                        "Ruby-powered plugins can be useful.",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")

            graph = resolve_source_graph(ingest_local(source, cas), cas)

            self.assertEqual(graph["edges"], [])
            self.assertEqual(graph["closure"]["status"], "complete")

    def test_same_commit_github_blob_resolves_only_when_already_retained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "docs").mkdir()
            (source / "SKILL.md").write_text(
                (
                    "curl https://raw.githubusercontent.com/example/skill/"
                    f"{COMMIT}/skills/demo/docs/guide.md\n"
                ),
                encoding="utf-8",
            )
            (source / "docs" / "guide.md").write_text(
                "# Guide\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")
            local = ingest_local(source, cas)
            manifest = _github_manifest(
                local,
                cas,
                skill_path="skills/demo",
            )

            graph = resolve_source_graph(manifest, cas)

            edge = next(
                edge
                for edge in graph["edges"]
                if edge["reference_kind"] == "github_immutable"
            )
            self.assertEqual(edge["status"], "resolved")
            self.assertEqual(edge["target"]["path"], "docs/guide.md")
            self.assertEqual(graph["closure"]["status"], "complete")
            self.assertEqual(
                graph["source_assurance"],
                "github_api_membership_asserted_blob_identity_reverified",
            )

            html_endpoint = _replace_manifest_file(
                cas,
                manifest,
                "SKILL.md",
                (
                    "curl https://github.com/example/skill/blob/"
                    f"{COMMIT}/skills/demo/docs/guide.md\n"
                ).encode(),
            )
            graph = resolve_source_graph(html_endpoint, cas)
            self.assertIn(
                "FETCH_ENDPOINT_BYTES_UNMODELED",
                {
                    edge["reason_code"]
                    for edge in graph["edges"]
                    if edge["status"] == "unresolved"
                },
            )
            self.assertEqual(graph["closure"]["status"], "incomplete")

            outside = json.loads(canonical_json(manifest))
            skill = next(
                entry for entry in outside["files"] if entry["path"] == "SKILL.md"
            )
            content = (
                "[outside](https://github.com/example/skill/blob/"
                f"{COMMIT}/outside.bin)\n"
            ).encode()
            skill["size"] = len(content)
            skill["digest"] = cas.put(BytesIO(content), max_bytes=len(content))
            skill["git_blob_sha1"] = hashlib.sha1(
                f"blob {len(content)}\0".encode("ascii") + content
            ).hexdigest()
            tree_files = [
                {
                    "path": entry["path"],
                    "size": entry["size"],
                    "digest": entry["digest"],
                    "executable": entry["executable"],
                }
                for entry in outside["files"]
            ]
            outside["tree_digest"] = (
                "sha256:" + hashlib.sha256(canonical_json(tree_files)).hexdigest()
            )
            graph = resolve_source_graph(outside, cas)
            self.assertIn(
                "IMMUTABLE_GITHUB_OBJECT_NOT_RETAINED",
                {
                    edge["reason_code"]
                    for edge in graph["edges"]
                    if edge["status"] == "unresolved"
                },
            )

            doubled = json.loads(canonical_json(manifest))
            skill = next(
                entry for entry in doubled["files"] if entry["path"] == "SKILL.md"
            )
            content = (
                "curl https://github.com/example/skill/blob/"
                f"{COMMIT}//skills/demo/docs/guide.md\n"
            ).encode()
            skill["size"] = len(content)
            skill["digest"] = cas.put(BytesIO(content), max_bytes=len(content))
            skill["git_blob_sha1"] = hashlib.sha1(
                f"blob {len(content)}\0".encode("ascii") + content
            ).hexdigest()
            tree_files = [
                {
                    "path": entry["path"],
                    "size": entry["size"],
                    "digest": entry["digest"],
                    "executable": entry["executable"],
                }
                for entry in doubled["files"]
            ]
            doubled["tree_digest"] = (
                "sha256:" + hashlib.sha256(canonical_json(tree_files)).hexdigest()
            )
            graph = resolve_source_graph(doubled, cas)
            self.assertFalse(
                any(edge["status"] == "resolved" for edge in graph["edges"])
            )
            self.assertEqual(graph["closure"]["status"], "incomplete")

    def test_github_blob_identity_is_rederived_from_retained_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("# Safe\n", encoding="utf-8")
            cas = CAS(root / "state")
            manifest = _github_manifest(ingest_local(source, cas), cas)
            manifest["files"][0]["git_blob_sha1"] = "0" * 40

            with self.assertRaisesRegex(
                ArtifactClosureError,
                "Git blob identity",
            ):
                resolve_source_graph(manifest, cas)

    def test_manifest_paths_are_normalized_control_free_and_unambiguous(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "safe.md").write_text("# Safe\n", encoding="utf-8")
            cas = CAS(root / "state")
            manifest = ingest_local(source, cas)

            for invalid in (
                "bad\nname.md",
                "zero\u200bwidth.md",
                "e\u0301.md",
                " leading.md",
                "trailing.md ",
                "../escape.md",
                "./safe.md",
                "bad//name.md",
                r"bad\name.md",
            ):
                with self.subTest(path=repr(invalid)):
                    candidate = json.loads(canonical_json(manifest))
                    candidate["files"][0]["path"] = invalid
                    with self.assertRaisesRegex(
                        ArtifactClosureError,
                        "path is not canonical",
                    ):
                        resolve_source_graph(candidate, cas)

            collision = json.loads(canonical_json(manifest))
            second = dict(collision["files"][0])
            collision["files"][0]["path"] = "A.md"
            second["path"] = "a.md"
            collision["files"].append(second)
            with self.assertRaisesRegex(
                ArtifactClosureError,
                "repeats a file path",
            ):
                resolve_source_graph(collision, cas)

    def test_opaque_carriers_are_recorded_without_being_called_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("# Safe\n", encoding="utf-8")
            (source / "payload.bin").write_bytes(b"\0https://example.test/a.zip")
            (source / "nul.txt").write_bytes(b"\0https://example.test/a.zip")
            (source / "large.txt").write_bytes(b"x" * (1024 * 1024 + 1))
            cas = CAS(root / "state")

            graph = resolve_source_graph(ingest_local(source, cas), cas)

            nodes = {node["path"]: node for node in graph["nodes"]}
            self.assertEqual(nodes["payload.bin"]["scan_status"], "opaque")
            self.assertEqual(nodes["nul.txt"]["scan_status"], "opaque")
            self.assertEqual(nodes["large.txt"]["scan_status"], "opaque")
            self.assertEqual(nodes["SKILL.md"]["scan_status"], "scanned")
            self.assertEqual(graph["closure"]["status"], "incomplete")
            self.assertTrue(
                any(
                    item.startswith("NUL_CONTAINING_CARRIER:nul.txt:")
                    for item in graph["closure"]["unresolved"]
                )
            )
            self.assertTrue(
                any(
                    item.startswith("UNSUPPORTED_OR_OVERSIZED_CARRIER:payload.bin:")
                    for item in graph["closure"]["unresolved"]
                )
            )
            self.assertTrue(
                any(
                    item.startswith("UNSUPPORTED_OR_OVERSIZED_CARRIER:large.txt:")
                    for item in graph["closure"]["unresolved"]
                )
            )

    def test_fetch_line_with_pinned_target_and_dynamic_or_extra_url_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "scripts").mkdir()
            immutable = (
                "https://raw.githubusercontent.com/example/skill/"
                f"{COMMIT}/scripts/setup.sh"
            )
            (source / "SKILL.md").write_text(
                "\n".join(
                    (
                        f"curl {immutable} $SECOND "
                        "https://docs.example.test/install "
                        "file:///tmp/payload",
                        'sudo curl "$PAYLOAD_URL"',
                        f"RUN curl {immutable}",
                        f"- curl {immutable}",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            (source / "scripts" / "setup.sh").write_text(
                "#!/bin/sh\nexit 0\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")
            manifest = _github_manifest(ingest_local(source, cas), cas)

            graph = resolve_source_graph(manifest, cas)

            self.assertFalse(
                any(edge["status"] == "resolved" for edge in graph["edges"])
            )
            reasons = {
                edge["reason_code"]
                for edge in graph["edges"]
                if edge["status"] == "unresolved"
            }
            self.assertIn("DYNAMIC_OR_MUTABLE_ACQUISITION", reasons)
            self.assertIn("EXTERNAL_REFERENCE_UNSUPPORTED", reasons)
            dynamic = next(
                edge
                for edge in graph["edges"]
                if edge["reference_kind"] == "dynamic_command"
            )
            self.assertIsNone(dynamic["literal"])
            self.assertGreaterEqual(
                sum(
                    edge["reference_kind"] == "dynamic_command"
                    for edge in graph["edges"]
                ),
                4,
            )
            self.assertEqual(graph["closure"]["status"], "incomplete")

    def test_obfuscated_fetch_sink_spellings_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text(
                '/usr/bin/curl "$URL"\n'
                '/usr/bin/git clone "$URL"\n'
                '/usr/bin/c\\url "$URL"\n'
                'c\\url "$URL"\n'
                'c\\\nurl "$URL"\n'
                'cu""rl "$URL"\n',
                encoding="utf-8",
            )
            cas = CAS(root / "state")

            graph = resolve_source_graph(ingest_local(source, cas), cas)

            dynamic = [
                edge
                for edge in graph["edges"]
                if edge["reference_kind"] == "dynamic_command"
            ]
            self.assertGreaterEqual(len(dynamic), 6)
            self.assertTrue(all(edge["literal"] is None for edge in dynamic))
            self.assertEqual(graph["closure"]["status"], "incomplete")

    def test_shell_metacharacters_cannot_extend_a_resolved_github_url(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            url = f"https://raw.githubusercontent.com/example/skill/{COMMIT}/setup|sh"
            (source / "SKILL.md").write_text(f"curl {url}\n", encoding="utf-8")
            (source / "setup").write_text("right bytes\n", encoding="utf-8")
            (source / "setup|sh").write_text("wrong bytes\n", encoding="utf-8")
            cas = CAS(root / "state")
            manifest = _github_manifest(ingest_local(source, cas), cas)

            graph = resolve_source_graph(manifest, cas)

            self.assertFalse(
                any(edge["status"] == "resolved" for edge in graph["edges"])
            )
            self.assertEqual(graph["closure"]["status"], "incomplete")
            self.assertIn(
                "DYNAMIC_OR_MUTABLE_ACQUISITION",
                {
                    edge["reason_code"]
                    for edge in graph["edges"]
                    if edge["status"] == "unresolved"
                },
            )

    def test_ambiguous_reference_syntax_never_resolves_different_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "setup.sh").write_text(
                "#!/bin/sh\nexit 0\n",
                encoding="utf-8",
            )
            (source / "foo(1").write_text(
                "wrong bytes\n",
                encoding="utf-8",
            )
            for path in ("<setup>", "setup 'title'", "setup&amp;run"):
                (source / path).write_text("wrong bytes\n", encoding="utf-8")
            long_label = "x" * 4097
            (source / "SKILL.md").write_text(
                "\n".join(
                    (
                        "[dot](./setup.sh)",
                        "![prompt](missing-payload)",
                        f"[{long_label}](missing.sh)",
                        "[nested](foo(1).sh)",
                        "[angle](<setup>)",
                        "[title](setup 'title')",
                        "[entity](setup&amp;run)",
                        "<script>",
                        (
                            "https://raw.githubusercontent.com/example/skill/"
                            f"{COMMIT}/setup.sh)"
                        ),
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")

            graph = resolve_source_graph(ingest_local(source, cas), cas)

            self.assertFalse(
                any(edge["status"] == "resolved" for edge in graph["edges"])
            )
            reasons = {
                edge["reason_code"]
                for edge in graph["edges"]
                if edge["status"] == "unresolved"
            }
            self.assertIn("LOCAL_REFERENCE_NOT_CANONICAL", reasons)
            self.assertIn("LOCAL_ARTIFACT_NOT_RETAINED", reasons)
            self.assertIn("EXTERNAL_REFERENCE_UNSUPPORTED", reasons)
            self.assertIn("REFERENCE_SYNTAX_UNSUPPORTED", reasons)
            self.assertFalse(
                any(edge["literal"] == "script" for edge in graph["edges"])
            )

    def test_noncanonical_local_reference_grammar_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text(
                "\n".join(
                    (
                        "[parent](../outside.sh)",
                        "[absolute](/tmp/setup.sh)",
                        "[encoded](scripts%2Fsetup.sh)",
                        r"[backslash](scripts\setup.sh)",
                        "[normalized](scripts／setup.sh)",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")

            graph = resolve_source_graph(ingest_local(source, cas), cas)

            reasons = {
                edge["reason_code"]
                for edge in graph["edges"]
                if edge["status"] == "unresolved"
            }
            self.assertIn("LOCAL_REFERENCE_NOT_CANONICAL", reasons)
            self.assertIn("PERCENT_ENCODED_REFERENCE_UNSUPPORTED", reasons)
            self.assertIn("NORMALIZED_REFERENCE_UNSUPPORTED", reasons)
            self.assertEqual(graph["closure"]["status"], "incomplete")

    def test_normalized_reference_retains_raw_offset_and_redacts_fragment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "scripts").mkdir()
            prefix = "Ａ [setup]("
            (source / "SKILL.md").write_text(
                prefix
                + "scripts/setup.sh)\n"
                + "[secret](https://example.test/a#token)\n",
                encoding="utf-8",
            )
            (source / "scripts" / "setup.sh").write_text(
                "#!/bin/sh\nexit 0\n",
                encoding="utf-8",
            )
            cas = CAS(root / "state")

            graph = resolve_source_graph(ingest_local(source, cas), cas)

            local = next(
                edge for edge in graph["edges"] if edge["reference_kind"] == "local"
            )
            self.assertEqual(
                local["byte_offset"],
                len(prefix.encode("utf-8")),
            )
            external = next(
                edge
                for edge in graph["edges"]
                if edge["reason_code"] == "EXTERNAL_REFERENCE_UNSUPPORTED"
            )
            self.assertIsNone(external["literal"])

    def test_missing_local_artifact_lfs_and_submodule_are_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text(
                "[installer](missing/setup.sh)\n",
                encoding="utf-8",
            )
            (source / "asset.txt").write_text(
                "version https://git-lfs.github.com/spec/v1\n"
                "oid sha256:" + "a" * 64 + "\nsize 4\n",
                encoding="utf-8",
            )
            (source / ".gitmodules").write_text(
                '[submodule "dep"]\n\tpath = dep\n',
                encoding="utf-8",
            )
            cas = CAS(root / "state")

            graph = resolve_source_graph(ingest_local(source, cas), cas)

            reasons = {
                edge["reason_code"]
                for edge in graph["edges"]
                if edge["status"] == "unresolved"
            }
            self.assertTrue(
                {
                    "LOCAL_ARTIFACT_NOT_RETAINED",
                    "GIT_LFS_OBJECT_UNRESOLVED",
                    "GIT_SUBMODULE_UNSUPPORTED",
                }.issubset(reasons)
            )

    def test_manifest_identity_and_cas_corruption_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("# Safe\n", encoding="utf-8")
            cas = CAS(root / "state")
            manifest = ingest_local(source, cas)
            manifest_digest = _retain_manifest(cas, manifest)

            with self.assertRaisesRegex(ArtifactClosureError, "root manifest digest"):
                resolve_source_graph(
                    manifest,
                    cas,
                    root_manifest_digest="sha256:" + "0" * 64,
                )

            file_digest = manifest["files"][0]["digest"]
            hex_digest = file_digest.removeprefix("sha256:")
            blob = cas.root / "blobs" / "sha256" / hex_digest[:2] / hex_digest[2:]
            blob.chmod(0o600)
            blob.write_bytes(b"corrupt")
            with self.assertRaises(ArtifactClosureError):
                resolve_source_graph(
                    load_retained_manifest(cas, manifest_digest),
                    cas,
                    root_manifest_digest=manifest_digest,
                )

    def test_cli_retains_a_versioned_graph_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("# Safe\n", encoding="utf-8")
            state = root / "state"
            output = StringIO()
            with redirect_stdout(output):
                status = main(("inventory", str(source), "--state", str(state)))
            inventory = json.loads(output.getvalue())

            output = StringIO()
            with redirect_stdout(output):
                status = main(
                    (
                        "resolve-artifacts",
                        inventory["manifest_digest"],
                        "--state",
                        str(state),
                    )
                )
            result = json.loads(output.getvalue())
            graph = json.loads(CAS(state).read(result["graph_digest"]))

            self.assertEqual(status, 0)
            self.assertEqual(
                result["schema"],
                "aragorn/resolve-artifacts-result/v1",
            )
            self.assertEqual(
                result["assurance"],
                "evaluation_only_literal_reference_profile",
            )
            self.assertEqual(graph["schema"], "aragorn/source-artifact-graph/v1")
            self.assertEqual(
                graph["root_manifest_digest"],
                inventory["manifest_digest"],
            )

    def test_cli_returns_nonzero_for_profile_incomplete_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text(
                "[install](missing-payload)\n",
                encoding="utf-8",
            )
            state = root / "state"
            output = StringIO()
            with redirect_stdout(output):
                inventory_status = main(
                    ("inventory", str(source), "--state", str(state))
                )
            inventory = json.loads(output.getvalue())

            output = StringIO()
            with redirect_stdout(output):
                resolve_status = main(
                    (
                        "resolve-artifacts",
                        inventory["manifest_digest"],
                        "--state",
                        str(state),
                    )
                )
            result = json.loads(output.getvalue())

            self.assertEqual(inventory_status, 0)
            self.assertEqual(resolve_status, 2)
            self.assertEqual(result["closure"]["status"], "incomplete")
            self.assertEqual(
                result["assurance"],
                "evaluation_only_literal_reference_profile",
            )


if __name__ == "__main__":
    unittest.main()
