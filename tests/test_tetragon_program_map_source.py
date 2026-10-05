"""Offline source custody only; no BPF operation or running-sensor claim."""

import hashlib
import json
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_LOCK = "benchmark/tetragon-program-map-source-v1.lock.json"
_LOCK_DIGEST = "sha256:d8b0789bf6ef615cafa344fda959a6992ddc74401f60b10eacafcfe000221649"
_TETRAGON = "1de2ed8ebea18e56257dc59597aa13bf8f0e471e"
_LINUX = "e8f897f4afef0031fe618a8e94127a0934896aba"


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class TetragonProgramMapSourceTests(unittest.TestCase):
    def read_pinned(self, path, digest, size=None):
        target = _ROOT / path
        self.assertEqual(target.resolve(strict=True), target)
        with target.open("rb") as stream:
            raw = stream.read((size if size is not None else 65536) + 1)
        if size is not None:
            self.assertEqual(len(raw), size)
        else:
            self.assertLessEqual(len(raw), 65536)
        self.assertEqual(_sha(raw), digest)
        return raw

    def lock(self):
        return json.loads(self.read_pinned(_LOCK, _LOCK_DIGEST, 14094))

    def test_complete_tetragon_files_and_unchanged_source_dependencies(self):
        manifest = self.lock()
        self.assertEqual(manifest["commit"], _TETRAGON)
        self.assertEqual(len(manifest["files"]), 15)
        self.assertEqual(len({r["path"] for r in manifest["files"]}), 15)
        for row in manifest["files"] + manifest["existing_source_inputs"]:
            raw = self.read_pinned(row["local_path"], row["digest"], row.get("bytes"))
            if "git_blob" in row:
                self.assertEqual(
                    hashlib.sha1(
                        b"blob " + str(len(raw)).encode() + b"\0" + raw
                    ).hexdigest(),
                    row["git_blob"],
                )
            if "path" in row:
                self.assertEqual(
                    row["local_path"],
                    "benchmark/tetragon-program-map-source-v1/" + row["path"],
                )
                self.assertEqual(
                    row["url"],
                    f"https://raw.githubusercontent.com/cilium/tetragon/{_TETRAGON}/"
                    + row["path"],
                )

    def test_linux_excerpts_preserve_line_ranges_and_query_contract(self):
        ref = self.lock()["linux_abi_excerpts"]
        document = json.loads(
            self.read_pinned(ref["local_path"], ref["digest"], ref["bytes"])
        )
        self.assertEqual(ref["commit"], _LINUX)
        self.assertEqual(document["commit"], _LINUX)
        self.assertIs(ref["full_sources_retained"], False)
        self.assertIs(ref["signature_verified"], False)
        self.assertEqual(len(document["files"]), 7)
        self.assertEqual(sum(len(row["excerpts"]) for row in document["files"]), 24)
        texts = {}
        for row in document["files"]:
            self.assertEqual(
                row["url"],
                f"https://raw.githubusercontent.com/torvalds/linux/{_LINUX}/"
                + row["path"],
            )
            self.assertRegex(row["git_blob"], r"^[0-9a-f]{40}$")
            self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(row["size"], 0)
            for excerpt in row["excerpts"]:
                self.assertGreater(excerpt["start_line"], 0)
                self.assertEqual(
                    len(excerpt["text"].splitlines()),
                    excerpt["end_line"] - excerpt["start_line"] + 1,
                )
            texts[row["path"]] = "\n".join(item["text"] for item in row["excerpts"])
        for token in (
            "used_maps",
            "used_map_cnt",
            "bpf_perf_link_fill_common",
            "name_len",
            "bpf_prog_bind_map",
        ):
            self.assertIn(token, texts["kernel/bpf/syscall.c"])
        for token in ("PTRACE_MODE_ATTACH_REALCREDS", "O_CLOEXEC", "if (flags)"):
            self.assertIn(token, texts["kernel/pid.c"])
        self.assertIn("PERF_EVENT_STATE_OFF", texts["kernel/events/core.c"])
        self.assertIn(
            "__NR_pidfd_getfd 438", texts["include/uapi/asm-generic/unistd.h"]
        )

    def test_association_and_responsiveness_claim_limits_remain_explicit(self):
        manifest = self.lock()
        for key in (
            "active_attachment_verified",
            "delivery_completeness_verified",
            "phase3_eligible",
            "production_activation_eligible",
            "run_conformance_eligible",
            "sensor_program_map_use_verified",
            "sensor_responsiveness_verified",
        ):
            self.assertIs(manifest[key], False)
        contract = manifest["selected_contract"]
        self.assertIs(
            contract["pidfd_getfd"]["duplicate_extends_object_lifetime"], True
        )
        self.assertIs(
            contract["program_info"]["association_can_include_instruction_unused_maps"],
            True,
        )
        self.assertIs(
            contract["program_info"]["association_proves_instruction_use"], False
        )
        self.assertIs(contract["perf_link"]["link_info_proves_enabled"], False)
        self.assertIs(contract["perf_link"]["link_info_proves_responsiveness"], False)
        self.assertIs(
            contract["base_exec"]["root_program_only_query_covers_send_chain"], False
        )
        self.assertEqual(contract["base_exec"]["tail_call_map"], "execve_calls")
        self.assertEqual(contract["base_exit"]["send_helper"], "event_output_metric")
        self.assertIn(
            "LEGACY_PERF_EVENT_IOCTL_LINK",
            contract["unsupported_by_initial_association_scope"],
        )


if __name__ == "__main__":
    unittest.main()
