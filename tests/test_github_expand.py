from __future__ import annotations

import base64
from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aragorn.cas import CAS, CASError
from aragorn.cli import main
import aragorn.github_acquire as github_acquire
import aragorn.github_expand as github_expand
from aragorn.github_expand import GitHubExpansionError, acquire_github_expansion


COMMIT = "a" * 40
ROOT_TREE = "b" * 40
SKILLS_TREE = "c" * 40
SKILL_TREE = "d" * 40
PAYLOADS_TREE = "e" * 40


def _git_blob_sha(content: bytes) -> str:
    value = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    return hashlib.sha1(value).hexdigest()


def _blob_document(content: bytes) -> dict[str, object]:
    return {
        "sha": _git_blob_sha(content),
        "size": len(content),
        "encoding": "base64",
        "content": base64.encodebytes(content).decode("ascii"),
    }


def _responses(
    skill_content: bytes,
    *,
    first_content: bytes = b"# first\n",
    second_content: bytes = b"# second\n",
    extra_skill_file: tuple[str, bytes] | None = None,
) -> dict[str, dict[str, object]]:
    prefix = "/repos/example/project"
    skill_blob = _git_blob_sha(skill_content)
    first_blob = _git_blob_sha(first_content)
    second_blob = _git_blob_sha(second_content)
    skill_entries: list[dict[str, object]] = [
        {
            "path": "SKILL.md",
            "mode": "100644",
            "type": "blob",
            "sha": skill_blob,
            "size": len(skill_content),
        }
    ]
    responses: dict[str, dict[str, object]] = {
        f"{prefix}/hash-algorithm": {"hash_algorithm": "sha1"},
        f"{prefix}/git/commits/{COMMIT}": {
            "sha": COMMIT,
            "tree": {"sha": ROOT_TREE},
        },
        f"{prefix}/git/trees/{ROOT_TREE}": {
            "sha": ROOT_TREE,
            "truncated": False,
            "tree": [
                {
                    "path": "payloads",
                    "mode": "040000",
                    "type": "tree",
                    "sha": PAYLOADS_TREE,
                },
                {
                    "path": "skills",
                    "mode": "040000",
                    "type": "tree",
                    "sha": SKILLS_TREE,
                },
            ],
        },
        f"{prefix}/git/trees/{SKILLS_TREE}": {
            "sha": SKILLS_TREE,
            "truncated": False,
            "tree": [
                {
                    "path": "demo",
                    "mode": "040000",
                    "type": "tree",
                    "sha": SKILL_TREE,
                }
            ],
        },
        f"{prefix}/git/trees/{PAYLOADS_TREE}": {
            "sha": PAYLOADS_TREE,
            "truncated": False,
            "tree": [
                {
                    "path": "one.txt",
                    "mode": "100644",
                    "type": "blob",
                    "sha": first_blob,
                    "size": len(first_content),
                },
                {
                    "path": "two.txt",
                    "mode": "100644",
                    "type": "blob",
                    "sha": second_blob,
                    "size": len(second_content),
                },
            ],
        },
        f"{prefix}/git/blobs/{skill_blob}": _blob_document(skill_content),
        f"{prefix}/git/blobs/{first_blob}": _blob_document(first_content),
        f"{prefix}/git/blobs/{second_blob}": _blob_document(second_content),
    }
    if extra_skill_file is not None:
        name, content = extra_skill_file
        blob = _git_blob_sha(content)
        skill_entries.append(
            {
                "path": name,
                "mode": "100644",
                "type": "blob",
                "sha": blob,
                "size": len(content),
            }
        )
        responses[f"{prefix}/git/blobs/{blob}"] = _blob_document(content)
    skill_entries.sort(key=lambda item: str(item["path"]))
    responses[f"{prefix}/git/trees/{SKILL_TREE}"] = {
        "sha": SKILL_TREE,
        "truncated": False,
        "tree": skill_entries,
    }
    return responses


class GitHubExpansionTests(unittest.TestCase):
    def expand(
        self,
        responses: dict[str, dict[str, object]],
        **limits: object,
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        CAS,
        list[str],
        tempfile.TemporaryDirectory[str],
    ]:
        temporary = tempfile.TemporaryDirectory()
        cas = CAS(Path(temporary.name) / "state")
        calls: list[str] = []

        def request(path: str, **kwargs: object) -> dict[str, object]:
            calls.append(path)
            document = responses.get(path)
            if document is None:
                raise AssertionError(f"unexpected request: {path}")
            budget = kwargs["budget"]
            budget.start_request()
            raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            budget.add_bytes(len(raw))
            return document

        try:
            with patch.object(github_acquire, "_request_json", side_effect=request):
                result = acquire_github_expansion(
                    "https://github.com/Example/Project",
                    COMMIT,
                    "skills/demo",
                    cas,
                    **limits,
                )
            expansion = json.loads(cas.read(result["expansion_digest"]))
        except BaseException:
            temporary.cleanup()
            raise
        return result, expansion, cas, calls, temporary

    def test_outside_root_recursion_is_verified_and_materialized(self) -> None:
        first_url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        second_url = (
            f"https://github.com/example/project/blob/{COMMIT}/payloads/two.txt"
        )
        responses = _responses(
            f"curl {first_url}\n".encode(),
            first_content=f"[next]({second_url})\n".encode(),
        )

        result, expansion, cas, calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)
        subject = json.loads(cas.read(result["comparator_subject_manifest_digest"]))

        self.assertEqual(result["closure"]["status"], "complete")
        self.assertEqual(
            [item["repository_path"] for item in expansion["objects"]],
            ["payloads/one.txt", "payloads/two.txt"],
        )
        self.assertEqual(
            [item["depth"] for item in expansion["objects"]],
            [1, 2],
        )
        self.assertEqual(
            [item["status"] for item in expansion["references"]],
            ["expanded", "expanded"],
        )
        self.assertEqual(
            [item["path"] for item in subject["files"]],
            [
                "SKILL.md",
                "__aragorn_expanded__/payloads/one.txt",
                "__aragorn_expanded__/payloads/two.txt",
            ],
        )
        self.assertEqual(
            expansion["accounting"]["budgets"]["expanded_objects"]["used"], 2
        )
        self.assertEqual(
            expansion["accounting"]["references"]["total_edges"],
            expansion["accounting"]["references"]["artifact_references"],
        )
        self.assertTrue(
            expansion["accounting"]["references"]["scan_complete"],
        )
        self.assertTrue(
            expansion["accounting"]["references"]["occurrences_complete"],
        )
        self.assertEqual(
            expansion["accounting"]["references"]["occurrences_omitted"],
            0,
        )
        self.assertEqual(
            calls.count(f"/repos/example/project/git/trees/{PAYLOADS_TREE}"),
            1,
        )

    def test_same_depth_acquisition_is_independent_of_root_reference_order(
        self,
    ) -> None:
        first_url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        second_url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/two.txt"
        )
        orders = (
            (first_url, second_url),
            (second_url, first_url),
        )
        for order in orders:
            with self.subTest(first=order[0].rsplit("/", 1)[-1]):
                root = "".join(
                    f"[{index}]({url})\n" for index, url in enumerate(order, start=1)
                ).encode()
                responses = _responses(
                    root,
                    first_content=b"[local](two.txt)\n",
                )

                result, expansion, _cas, _calls, temporary = self.expand(responses)
                self.addCleanup(temporary.cleanup)

                self.assertEqual(result["closure"]["status"], "complete")
                local_occurrences = [
                    item
                    for item in expansion["references"]
                    if item["source_repository_path"] == "payloads/one.txt"
                    and item["target_repository_path"] == "payloads/two.txt"
                ]
                self.assertEqual(len(local_occurrences), 1)
                self.assertEqual(
                    local_occurrences[0]["status"],
                    "expanded",
                )

    def test_deferred_local_reference_reaches_exact_blob_fixed_point(self) -> None:
        first_url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        second_url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/two.txt"
        )
        responses = _responses(
            f"[first]({first_url})\n".encode(),
            first_content=(f"[local](two.txt)\n[exact]({second_url})\n".encode()),
        )

        result, expansion, _cas, _calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["closure"]["status"], "complete")
        self.assertEqual(
            [item["repository_path"] for item in expansion["objects"]],
            ["payloads/one.txt", "payloads/two.txt"],
        )
        local_literal_digest = "sha256:" + hashlib.sha256(b"two.txt").hexdigest()
        local = next(
            item
            for item in expansion["references"]
            if item["source_repository_path"] == "payloads/one.txt"
            and item["target_repository_path"] == "payloads/two.txt"
            and item["literal_digest"] == local_literal_digest
        )
        self.assertEqual(local["status"], "expanded")
        self.assertEqual(local["literal_size"], len(b"two.txt"))
        second_object = next(
            item
            for item in expansion["objects"]
            if item["repository_path"] == "payloads/two.txt"
        )
        self.assertEqual(len(second_object["references"]), 2)
        self.assertEqual(
            expansion["accounting"]["references"]["deduplicated"],
            1,
        )

    def test_duplicate_references_fetch_one_object_and_retain_occurrences(self) -> None:
        url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        responses = _responses(f"[one]({url})\n[two]({url})\n".encode())

        result, expansion, _cas, calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["expanded_object_count"], 1)
        self.assertEqual(len(expansion["references"]), 2)
        self.assertEqual(expansion["accounting"]["references"]["deduplicated"], 1)
        one_blob = _git_blob_sha(b"# first\n")
        self.assertEqual(calls.count(f"/repos/example/project/git/blobs/{one_blob}"), 1)

    def test_reference_to_already_expanded_blob_counts_as_deduplicated(self) -> None:
        url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        responses = _responses(
            f"[first]({url})\n".encode(),
            first_content=f"[self]({url})\n".encode(),
        )

        result, expansion, _cas, calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["closure"]["status"], "complete")
        self.assertEqual(result["expanded_object_count"], 1)
        self.assertEqual(
            expansion["accounting"]["references"]["deduplicated"],
            1,
        )
        self.assertEqual(len(expansion["objects"][0]["references"]), 2)
        one_blob = _git_blob_sha(f"[self]({url})\n".encode())
        self.assertEqual(
            calls.count(f"/repos/example/project/git/blobs/{one_blob}"),
            1,
        )

    def test_budgets_publish_incomplete_receipts_without_subjects(self) -> None:
        first_url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        second_url = (
            f"https://github.com/example/project/blob/{COMMIT}/payloads/two.txt"
        )
        recursive = _responses(
            f"[first]({first_url})\n".encode(),
            first_content=f"[next]({second_url})\n".encode(),
        )
        cases = (
            (
                {"max_expanded_objects": 0},
                "EXPANDED_OBJECT_BUDGET_EXCEEDED",
            ),
            (
                {"max_expansion_depth": 1},
                "EXPANSION_DEPTH_BUDGET_EXCEEDED",
            ),
            (
                {"max_api_requests": 7},
                "ACQUISITION_BUDGET_EXCEEDED",
            ),
        )
        for limits, reason in cases:
            with self.subTest(reason=reason):
                result, expansion, cas, _calls, temporary = self.expand(
                    recursive, **limits
                )
                self.addCleanup(temporary.cleanup)
                self.assertEqual(result["closure"]["status"], "incomplete")
                self.assertIsNone(result["comparator_subject_manifest_digest"])
                self.assertIsNone(result["comparator_subject_tree_digest"])
                self.assertEqual(result["expanded_object_count"], 0)
                self.assertEqual(expansion["objects"], [])
                self.assertIn(
                    reason,
                    {
                        item["reason_code"]
                        for item in expansion["closure"]["unresolved"]
                    },
                )
                with self.assertRaises(CASError):
                    cas.read("sha256:" + hashlib.sha256(b"# first\n").hexdigest())

    def test_per_carrier_reference_exhaustion_is_a_bounded_receipt(self) -> None:
        responses = _responses(b"[fragment](#target)\n" * 10_001)

        result, expansion, _cas, _calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["closure"]["status"], "incomplete")
        self.assertIsNone(result["comparator_subject_manifest_digest"])
        self.assertEqual(
            expansion["closure"]["unresolved"],
            [
                {
                    "reason_code": "REFERENCE_BUDGET_EXCEEDED",
                    "subject": "SKILL.md",
                }
            ],
        )
        self.assertEqual(
            expansion["accounting"]["budgets"]["references"],
            {"limit": 10_000, "used": 10_000},
        )
        self.assertEqual(
            expansion["accounting"]["references"]["opaque_carriers"],
            0,
        )
        self.assertFalse(
            expansion["accounting"]["references"]["scan_complete"],
        )
        self.assertFalse(
            expansion["accounting"]["references"]["occurrences_complete"],
        )
        self.assertIsNone(
            expansion["accounting"]["references"]["occurrences_omitted"],
        )

    def test_malformed_reference_candidate_exhaustion_accounts_for_work(
        self,
    ) -> None:
        responses = _responses(b"](" * 10_001)

        result, expansion, _cas, _calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["closure"]["status"], "incomplete")
        self.assertEqual(
            expansion["closure"]["unresolved"][0]["reason_code"],
            "REFERENCE_BUDGET_EXCEEDED",
        )
        self.assertEqual(
            expansion["accounting"]["budgets"]["references"],
            {"limit": 10_000, "used": 10_000},
        )
        self.assertFalse(
            expansion["accounting"]["references"]["scan_complete"],
        )
        self.assertFalse(
            expansion["accounting"]["references"]["occurrences_complete"],
        )
        self.assertIsNone(
            expansion["accounting"]["references"]["occurrences_omitted"],
        )

    def test_global_reference_budget_marks_unknown_omissions(self) -> None:
        first_url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        second_url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/two.txt"
        )
        responses = _responses(f"[one]({first_url})\n[two]({second_url})\n".encode())

        result, expansion, _cas, calls, temporary = self.expand(
            responses,
            max_references=1,
        )
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["closure"]["status"], "incomplete")
        self.assertIn(
            "REFERENCE_BUDGET_EXCEEDED",
            {item["reason_code"] for item in expansion["closure"]["unresolved"]},
        )
        accounting = expansion["accounting"]["references"]
        self.assertFalse(accounting["scan_complete"])
        self.assertFalse(accounting["occurrences_complete"])
        self.assertIsNone(accounting["occurrences_omitted"])
        self.assertEqual(expansion["references"], [])
        first_blob = _git_blob_sha(b"# first\n")
        self.assertNotIn(
            f"/repos/example/project/git/blobs/{first_blob}",
            calls,
        )

    def test_semantic_failure_still_scans_every_retained_root_carrier(self) -> None:
        exact_url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        responses = _responses(
            b"[mutable](https://github.com/example/project/blob/main/p.txt)\n",
            extra_skill_file=("ZZ.md", f"[exact]({exact_url})\n".encode()),
        )

        result, expansion, _cas, calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["closure"]["status"], "incomplete")
        accounting = expansion["accounting"]["references"]
        self.assertTrue(accounting["scan_complete"])
        self.assertTrue(accounting["occurrences_complete"])
        self.assertEqual(accounting["occurrences_omitted"], 0)
        self.assertEqual(
            {item["source_repository_path"] for item in expansion["references"]},
            {"skills/demo/SKILL.md", "skills/demo/ZZ.md"},
        )
        first_blob = _git_blob_sha(b"# first\n")
        self.assertNotIn(
            f"/repos/example/project/git/blobs/{first_blob}",
            calls,
        )

    def test_record_size_failure_publishes_no_source_content(self) -> None:
        content = b"# safe\n"
        responses = _responses(content)
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")

            def request(path: str, **kwargs: object) -> dict[str, object]:
                document = responses.get(path)
                if document is None:
                    raise AssertionError(f"unexpected request: {path}")
                budget = kwargs["budget"]
                budget.start_request()
                raw = json.dumps(
                    document, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                budget.add_bytes(len(raw))
                return document

            with (
                patch.object(
                    github_acquire,
                    "_request_json",
                    side_effect=request,
                ),
                patch.object(github_expand, "MAX_RECORD_BYTES", 128),
                self.assertRaisesRegex(
                    GitHubExpansionError,
                    "root manifest exceeds its byte limit",
                ),
            ):
                acquire_github_expansion(
                    "https://github.com/Example/Project",
                    COMMIT,
                    "skills/demo",
                    cas,
                )

            with self.assertRaises(CASError):
                cas.read("sha256:" + hashlib.sha256(content).hexdigest())

    def test_expansion_record_overflow_becomes_a_compact_incomplete_receipt(
        self,
    ) -> None:
        url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        content = "".join(f"[{index}]({url})\n" for index in range(100)).encode()
        responses = _responses(content)

        complete, _expansion, cas, _calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)
        root_size = len(cas.read(complete["root_manifest_digest"]))
        subject_size = len(cas.read(complete["comparator_subject_manifest_digest"]))
        record_limit = max(root_size, subject_size, 4096)

        with patch.object(
            github_expand,
            "MAX_RECORD_BYTES",
            record_limit,
        ):
            result, compact, compact_cas, _calls, temporary2 = self.expand(responses)
        self.addCleanup(temporary2.cleanup)

        self.assertEqual(result["closure"]["status"], "incomplete")
        self.assertIsNone(result["comparator_subject_manifest_digest"])
        self.assertEqual(compact["references"], [])
        self.assertEqual(compact["objects"], [])
        self.assertFalse(compact["accounting"]["references"]["occurrences_complete"])
        self.assertTrue(compact["accounting"]["references"]["scan_complete"])
        self.assertEqual(
            compact["accounting"]["references"]["occurrences_omitted"],
            compact["accounting"]["references"]["artifact_references"],
        )
        self.assertGreater(
            compact["accounting"]["references"]["artifact_references"],
            0,
        )
        self.assertIn(
            "EXPANSION_RECORD_BUDGET_EXCEEDED",
            {item["reason_code"] for item in compact["closure"]["unresolved"]},
        )
        with self.assertRaises(CASError):
            compact_cas.read("sha256:" + hashlib.sha256(b"# first\n").hexdigest())

    def test_comparator_file_budget_is_an_incomplete_receipt_before_fetch(self) -> None:
        url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        responses = _responses(f"[payload]({url})\n".encode())

        with patch.object(github_expand, "_MAX_SUBJECT_FILES", 1):
            result, expansion, _cas, calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["closure"]["status"], "incomplete")
        self.assertIsNone(result["comparator_subject_manifest_digest"])
        self.assertEqual(
            expansion["closure"]["unresolved"],
            [
                {
                    "reason_code": "COMPARATOR_SUBJECT_FILE_BUDGET_EXCEEDED",
                    "subject": "payloads/one.txt",
                }
            ],
        )
        first_blob = _git_blob_sha(b"# first\n")
        self.assertNotIn(
            f"/repos/example/project/git/blobs/{first_blob}",
            calls,
        )

    def test_reserved_comparator_namespace_is_case_insensitive(self) -> None:
        responses = _responses(
            b"# safe\n",
            extra_skill_file=("__ARAGORN_EXPANDED__", b"collision\n"),
        )

        with self.assertRaisesRegex(
            GitHubExpansionError,
            "reserved comparator path",
        ):
            self.expand(responses)

    def test_materialized_path_limit_is_checked_before_fetch(self) -> None:
        url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        responses = _responses(f"[payload]({url})\n".encode())
        materialized_length = len(
            f"{github_expand.MATERIALIZED_PREFIX}/payloads/one.txt"
        )

        with patch.object(
            github_expand,
            "_MAX_SUBJECT_PATH_LENGTH",
            materialized_length - 1,
        ):
            result, expansion, _cas, calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["closure"]["status"], "incomplete")
        self.assertEqual(
            expansion["closure"]["unresolved"][0]["reason_code"],
            "COMPARATOR_SUBJECT_PATH_BUDGET_EXCEEDED",
        )
        first_blob = _git_blob_sha(b"# first\n")
        self.assertNotIn(
            f"/repos/example/project/git/blobs/{first_blob}",
            calls,
        )

    def test_unsupported_sibling_tree_entries_are_incomplete_receipts(self) -> None:
        url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        cases = (
            (
                {
                    "path": "unrelated-link",
                    "mode": "120000",
                    "type": "blob",
                    "sha": "f" * 40,
                    "size": 6,
                },
                "GIT_SYMLINK_UNSUPPORTED",
            ),
            (
                {
                    "path": "unrelated-submodule",
                    "mode": "160000",
                    "type": "commit",
                    "sha": "f" * 40,
                },
                "GIT_SUBMODULE_UNSUPPORTED",
            ),
        )
        tree_path = f"/repos/example/project/git/trees/{PAYLOADS_TREE}"
        for sibling, reason_code in cases:
            with self.subTest(reason_code=reason_code):
                responses = _responses(f"[payload]({url})\n".encode())
                responses[tree_path]["tree"].append(sibling)

                result, expansion, _cas, _calls, temporary = self.expand(responses)
                self.addCleanup(temporary.cleanup)

                self.assertEqual(result["closure"]["status"], "incomplete")
                self.assertIsNone(result["comparator_subject_manifest_digest"])
                self.assertIn(
                    reason_code,
                    {
                        item["reason_code"]
                        for item in expansion["closure"]["unresolved"]
                    },
                )

    def test_obfuscated_fetch_with_exact_url_never_queues_the_target(self) -> None:
        url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        responses = _responses(f"/usr/bin/c\\url {url}\n".encode())

        result, expansion, _cas, calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["closure"]["status"], "incomplete")
        self.assertIn(
            "DYNAMIC_OR_MUTABLE_ACQUISITION",
            {item["reason_code"] for item in expansion["closure"]["unresolved"]},
        )
        first_blob = _git_blob_sha(b"# first\n")
        self.assertNotIn(
            f"/repos/example/project/git/blobs/{first_blob}",
            calls,
        )

    def test_shell_prompt_lookalikes_never_become_literal_fetches(self) -> None:
        url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        for prefix in ("$", "$ ", ">", "> "):
            with self.subTest(prefix=prefix):
                responses = _responses(f"{prefix}curl {url}\n".encode())

                result, expansion, _cas, calls, temporary = self.expand(responses)
                self.addCleanup(temporary.cleanup)

                self.assertEqual(result["closure"]["status"], "incomplete")
                self.assertIn(
                    "DYNAMIC_OR_MUTABLE_ACQUISITION",
                    {
                        item["reason_code"]
                        for item in expansion["closure"]["unresolved"]
                    },
                )
                first_blob = _git_blob_sha(b"# first\n")
                self.assertNotIn(
                    f"/repos/example/project/git/blobs/{first_blob}",
                    calls,
                )

    def test_obfuscated_blob_endpoint_context_never_materializes_raw_bytes(
        self,
    ) -> None:
        blob_url = f"https://github.com/example/project/blob/{COMMIT}/payloads/one.txt"
        commands = (
            f"i`wr {blob_url}",
            f'c=cu; "$c"rl {blob_url}',
        )
        for command in commands:
            with self.subTest(command=command.split(" ", 1)[0]):
                responses = _responses(f"{command}\n".encode())

                result, expansion, _cas, calls, temporary = self.expand(responses)
                self.addCleanup(temporary.cleanup)

                self.assertEqual(result["closure"]["status"], "incomplete")
                self.assertIn(
                    "BARE_IMMUTABLE_REFERENCE_CONTEXT_UNSUPPORTED",
                    {
                        item["reason_code"]
                        for item in expansion["closure"]["unresolved"]
                    },
                )
                first_blob = _git_blob_sha(b"# first\n")
                self.assertNotIn(
                    f"/repos/example/project/git/blobs/{first_blob}",
                    calls,
                )

    def test_option_bearing_git_acquisition_lines_are_dynamic(self) -> None:
        commands = (
            "git -c protocol.version=2 clone https://github.com/example/project.git",
            "git -C /tmp clone git@github.com:example/project.git",
            "git submodule add https://github.com/example/project.git vendor",
        )
        responses = _responses(("\n".join(commands) + "\n").encode())

        result, expansion, _cas, _calls, temporary = self.expand(responses)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result["closure"]["status"], "incomplete")
        self.assertIn(
            "DYNAMIC_OR_MUTABLE_ACQUISITION",
            {item["reason_code"] for item in expansion["closure"]["unresolved"]},
        )

    def test_mutable_cross_source_and_opaque_carriers_are_incomplete(self) -> None:
        cases = (
            (
                _responses(
                    b"[mutable](https://github.com/example/project/blob/main/p.txt)\n"
                ),
                "MUTABLE_GITHUB_REFERENCE",
            ),
            (
                _responses(
                    (
                        "[cross](https://github.com/other/project/blob/"
                        f"{COMMIT}/payloads/one.txt)\n"
                    ).encode()
                ),
                "CROSS_SOURCE_GITHUB_REFERENCE",
            ),
            (
                _responses(
                    b"# safe\n",
                    extra_skill_file=("payload.bin", b"\xff\x00"),
                ),
                "OPAQUE_SOURCE_CARRIER",
            ),
        )
        for responses, reason in cases:
            with self.subTest(reason=reason):
                result, expansion, _cas, _calls, temporary = self.expand(responses)
                self.addCleanup(temporary.cleanup)
                self.assertEqual(result["closure"]["status"], "incomplete")
                self.assertIsNone(result["comparator_subject_manifest_digest"])
                self.assertEqual(expansion["objects"], [])
                self.assertIn(
                    reason,
                    {
                        item["reason_code"]
                        for item in expansion["closure"]["unresolved"]
                    },
                )
                accounting = expansion["accounting"]["references"]
                if reason == "OPAQUE_SOURCE_CARRIER":
                    self.assertFalse(accounting["scan_complete"])
                    self.assertFalse(accounting["occurrences_complete"])
                    self.assertIsNone(accounting["occurrences_omitted"])
                else:
                    self.assertTrue(accounting["scan_complete"])
                    self.assertTrue(accounting["occurrences_complete"])
                    self.assertEqual(accounting["occurrences_omitted"], 0)

    def test_cli_emits_versioned_complete_and_incomplete_results(self) -> None:
        immutable_url = (
            "https://raw.githubusercontent.com/example/project/"
            f"{COMMIT}/payloads/one.txt"
        )
        cases = (
            (_responses(f"[payload]({immutable_url})\n".encode()), 0, "complete"),
            (
                _responses(
                    b"[mutable](https://github.com/example/project/blob/main/p.txt)\n"
                ),
                2,
                "incomplete",
            ),
        )
        for responses, expected_status, expected_closure in cases:
            with self.subTest(closure=expected_closure):
                with tempfile.TemporaryDirectory() as temporary:
                    state = Path(temporary) / "state"

                    def request(path: str, **kwargs: object) -> dict[str, object]:
                        document = responses.get(path)
                        if document is None:
                            raise AssertionError(f"unexpected request: {path}")
                        budget = kwargs["budget"]
                        budget.start_request()
                        raw = json.dumps(
                            document, sort_keys=True, separators=(",", ":")
                        ).encode("utf-8")
                        budget.add_bytes(len(raw))
                        return document

                    output = StringIO()
                    with (
                        patch.object(
                            github_acquire,
                            "_request_json",
                            side_effect=request,
                        ),
                        redirect_stdout(output),
                    ):
                        status = main(
                            (
                                "expand-github",
                                "https://github.com/Example/Project",
                                COMMIT,
                                "skills/demo",
                                "--state",
                                str(state),
                            )
                        )

                    result = json.loads(output.getvalue())
                    self.assertEqual(status, expected_status)
                    self.assertEqual(
                        result["schema"],
                        "aragorn/github-expansion-result/v1",
                    )
                    self.assertEqual(
                        result["closure"]["status"],
                        expected_closure,
                    )
                    expansion = json.loads(CAS(state).read(result["expansion_digest"]))
                    self.assertEqual(expansion["closure"], result["closure"])
                    if expected_closure == "complete":
                        self.assertIsNotNone(
                            result["comparator_subject_manifest_digest"]
                        )
                    else:
                        self.assertIsNone(result["comparator_subject_manifest_digest"])


if __name__ == "__main__":
    unittest.main()
