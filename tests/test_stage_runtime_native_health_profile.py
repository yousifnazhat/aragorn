"""Caller-owned staging only; no service, root provisioning or runtime actions."""

from __future__ import annotations

import io
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from scripts import stage_runtime_native_health_profile as subject

_ACTIVATOR_PIN = (
    39602,
    "sha256:d22a9fbce56a5fa13ea5f2605b5ff89c16ba12e83402f6b97367b57a3099edce",
)
_PREDECESSOR_PIN = (
    18870,
    "sha256:ee01af6bbc9a3693e94e512b8615422093bcdca5bf21cf1291d1f616e7f3cf33",
)


class RuntimeNativeHealthProfileTests(unittest.TestCase):
    def test_exact_66_files_79_sources_21_dependencies_and_inert_hook(self):
        original, additions = subject._verified_payloads()
        final = original | additions
        self.assertEqual((len(original), len(additions), len(final)), (60, 7, 66))
        self.assertEqual(subject._PREDECESSOR_PIN, _PREDECESSOR_PIN)
        self.assertEqual(subject._ACTIVATOR_PIN, _ACTIVATOR_PIN)
        self.assertEqual(len(subject._SOURCE_PINS), 79)
        self.assertEqual(
            set(subject._SOURCE_PINS),
            set(subject.native._SOURCE_PINS)
            | set(subject._ADDED_PINS)
            | {subject._PREDECESSOR},
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "stage"
            report = subject.stage_runtime_native_health_profile(output)
            self.assertEqual(report["schema"], subject._SCHEMA)
            self.assertEqual(report["authority"], subject._AUTHORITY)
            self.assertEqual(
                tuple(
                    len(report[key])
                    for key in (
                        "files",
                        "source_inputs",
                        "new_dependencies",
                        "directories",
                    )
                ),
                (66, 79, 21, 16),
            )
            for name, (source, mode, raw) in final.items():
                path = output / name
                metadata = path.lstat()
                self.assertEqual(path.read_bytes(), raw)
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(
                    (
                        stat.S_IMODE(metadata.st_mode),
                        metadata.st_uid,
                        metadata.st_nlink,
                    ),
                    (mode, os.geteuid(), 1),
                )
                self.assertIn(
                    {
                        "path": "/" + name,
                        "source_name": source,
                        "mode": f"{mode:04o}",
                        "bytes": len(raw),
                        "digest": subject.base.overlay._digest(raw),
                    },
                    report["files"],
                )
            for row in report["new_dependencies"]:
                raw = final[subject._destination(row["name"])[0]][2]
                self.assertEqual(
                    (row["bytes"], row["digest"]),
                    (len(raw), subject.base.overlay._digest(raw)),
                )
            self.assertEqual(
                report["source_inputs"],
                [
                    {"name": name, "bytes": pin[0], "digest": pin[1]}
                    for name, pin in sorted(subject._SOURCE_PINS.items())
                ],
            )
            self.assertEqual(
                subject.base._directories(final) - subject.base._directories(original),
                set(subject._NEW_DIRECTORIES),
            )
            for directory in report["directories"]:
                metadata = (output / directory[1:]).lstat()
                self.assertTrue(stat.S_ISDIR(metadata.st_mode))
                self.assertEqual(
                    (stat.S_IMODE(metadata.st_mode), metadata.st_uid),
                    (0o755, os.geteuid()),
                )
            hook = output / subject._destination(subject._HOOK)[0]
            self.assertEqual(
                hook.read_bytes(),
                b"[Unit]\nOnSuccess=aragorn-runtime-health-response.service\nOnSuccessJobMode=fail\n",
            )
            for absent in ("etc", "run", "runtime", "var"):
                self.assertFalse((output / absent).exists(), absent)
            for name, value in report.items():
                if type(value) is bool:
                    self.assertIs(value, False, name)
            self.assertEqual(
                report["required_runtime_not_included"]["tree"],
                subject.native._RUNTIME_TREE,
            )
            self.assertIn("explicit hook opt-in", " ".join(report["missing_inputs"]))
            self.assertEqual({path.name for path in output.parent.iterdir()}, {"stage"})
            for kind in ("health", "response"):
                shim = output / f"usr/libexec/aragorn/aragorn-runtime-{kind}-service.py"
                # No arguments reaches usage refusal before any root path or identity read.
                result = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(shim)],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_activator_has_only_six_added_pins_and_preserves_every_other_byte(self):
        original, additions = subject._verified_payloads()
        destination = subject._destination(subject._ACTIVATOR)[0]
        before, after = original[destination][2], additions[destination][2]
        self.assertEqual(
            (len(after), subject.base.overlay._digest(after)), _ACTIVATOR_PIN
        )
        added = subject._added_lines()
        self.assertEqual(len(added.splitlines()), 6)
        self.assertEqual(after.count(b"\n" + added + b"EOF\n"), 1)
        self.assertEqual(
            after.replace(b"\n" + added + b"EOF\n", subject._ANCHOR), before
        )
        for name, payload in original.items():
            if name != destination:
                self.assertEqual((original | additions)[name], payload)
        final = original | additions
        for mode, digest, path in re.findall(
            rb"^(644|755) ([0-9a-f]{64}) (/usr/\S+)$", after, re.MULTILINE
        ):
            if path.decode()[1:] not in final:
                # The externally supplied interpreters are not staged. Their
                # already-frozen pin lines must remain byte-identical.
                self.assertIn(
                    path, {b"/usr/local/bin/python3.12", b"/usr/local/bin/node"}
                )
                self.assertIn(mode + b" " + digest + b" " + path + b"\n", before)
                continue
            source, expected_mode, raw = final[path.decode()[1:]]
            self.assertEqual(
                (int(mode, 8), "sha256:" + digest.decode()),
                (expected_mode, subject.base.overlay._digest(raw)),
                source,
            )
        for source, (_size, digest) in subject._ADDED_PINS.items():
            path, mode = subject._destination(source)
            self.assertEqual(
                after.count(f"{mode:o} {digest[7:]} /{path}\n".encode()), 1
            )
        syntax = subprocess.run(
            ["/bin/sh", "-n"], input=after, capture_output=True, timeout=3, check=False
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        for changed in (before + b"\n", after):
            with self.assertRaises(subject.RuntimeNativeHealthStageError):
                subject._render_activator(changed)
        for changed in (
            before.replace(subject._ANCHOR, b"\nOTHER\n"),
            before + subject._ANCHOR,
        ):
            with (
                mock.patch.object(
                    subject.native,
                    "_ACTIVATOR_PIN",
                    (len(changed), subject.base.overlay._digest(changed)),
                ),
                self.assertRaisesRegex(subject.RuntimeNativeHealthStageError, "anchor"),
            ):
                subject._render_activator(changed)

    def test_source_drift_and_nonregular_inputs_refuse_before_destination_creation(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for source in (*subject._ADDED_PINS, subject._PREDECESSOR):
                pins = dict(subject._SOURCE_PINS)
                pins[source] = (1, "sha256:" + "0" * 64)
                with (
                    self.subTest(source=source),
                    mock.patch.object(subject, "_SOURCE_PINS", pins),
                    self.assertRaises(subject.RuntimeNativeHealthStageError),
                ):
                    subject.stage_runtime_native_health_profile(root / "drift")
                self.assertFalse((root / "drift").exists())
            for pins in (
                dict(list(subject._SOURCE_PINS.items())[:-1]),
                {**subject._SOURCE_PINS, "extra": (1, "sha256:" + "0" * 64)},
            ):
                with (
                    mock.patch.object(subject, "_SOURCE_PINS", pins),
                    self.assertRaises(subject.RuntimeNativeHealthStageError),
                ):
                    subject.stage_runtime_native_health_profile(root / "inventory")
                self.assertFalse((root / "inventory").exists())
            with (
                mock.patch.object(subject, "_ACTIVATOR_PIN", (1, "sha256:" + "0" * 64)),
                self.assertRaises(subject.RuntimeNativeHealthStageError),
            ):
                subject.stage_runtime_native_health_profile(root / "render")
            self.assertFalse((root / "render").exists())
            fifo, link = root / "fifo", root / "link"
            os.mkfifo(fifo)
            link.symlink_to(fifo)
            read = subject.base.overlay._read_pinned
            source = next(iter(subject._ADDED_PINS))
            for candidate in (fifo, link):

                def substitute(
                    name, *pin, root=None, candidate=candidate, source=source, read=read
                ):
                    if name == source:
                        return read(candidate.name, *pin, root=candidate.parent)
                    return read(name, *pin, root=root)

                with (
                    self.subTest(candidate=candidate.name),
                    mock.patch.object(
                        subject.base.overlay, "_read_pinned", side_effect=substitute
                    ),
                    self.assertRaises(subject.RuntimeNativeHealthStageError),
                ):
                    subject.stage_runtime_native_health_profile(root / "nonregular")
                self.assertFalse((root / "nonregular").exists())

    def test_output_refusals_partial_publication_and_final_readback_mutations(self):
        original, additions = subject._verified_payloads()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            existing = root / "existing"
            existing.mkdir()
            link = root / "link"
            link.symlink_to(root / "absent")
            for output in (Path("relative"), existing, link, str(root / "wrong-type")):
                with (
                    self.subTest(output=output),
                    self.assertRaises(subject.RuntimeNativeHealthStageError),
                    mock.patch.object(subject, "_verified_payloads") as verify,
                ):
                    subject.stage_runtime_native_health_profile(output)
                verify.assert_not_called()
            apply = subject.base._apply_overrides
            for change in ("partial", "bytes", "mode", "extra", "hardlink"):

                def mutate(output, payloads, change=change, apply=apply):
                    if len(payloads) != 7:
                        return apply(output, payloads)
                    if change == "partial":
                        apply(output, dict(list(payloads.items())[:1]))
                        raise OSError("partial publication")
                    apply(output, payloads)
                    path = output / subject._destination(subject._HOOK)[0]
                    if change == "bytes":
                        path.write_bytes(path.read_bytes() + b"\n")
                    elif change == "mode":
                        path.chmod(0o600)
                    elif change == "extra":
                        (path.parent / "unexpected").mkdir()
                    else:
                        os.link(path, output / "linked")

                with (
                    self.subTest(change=change),
                    mock.patch.object(
                        subject.base, "_apply_overrides", side_effect=mutate
                    ),
                    self.assertRaises(subject.RuntimeNativeHealthStageError),
                ):
                    subject.stage_runtime_native_health_profile(root / change)
                self.assertTrue((root / change).is_dir())
            with (
                mock.patch.object(
                    subject,
                    "_verified_payloads",
                    side_effect=[(original, additions), (original, {})],
                ),
                self.assertRaises(subject.RuntimeNativeHealthStageError),
            ):
                subject.stage_runtime_native_health_profile(root / "late-source-drift")

    def test_fixed_directory_custody_and_all_descriptors_close_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve()
            parent = output / "usr"
            parent.mkdir()
            before = subject.base._parent_custody(parent)
            changed = (before[0], before[1] + 1, *before[2:])
            with (
                mock.patch.object(
                    subject.base, "_parent_custody", return_value=changed
                ),
                self.assertRaises(subject.RuntimeNativeHealthStageError),
            ):
                subject._add_directories(output)
            self.assertFalse((parent / "share").exists())
            subject._add_directories(output)
            with self.assertRaises(FileExistsError):
                subject._add_directories(output)
        for failure_at in (1, 4, "sync"):
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary).resolve()
                (output / "usr").mkdir()
                real_close, real_sync = os.close, os.fsync
                closed = []

                def close(
                    fd, failure_at=failure_at, real_close=real_close, closed=closed
                ):
                    real_close(fd)
                    closed.append(fd)
                    if len(closed) == failure_at:
                        raise OSError("close uncertainty")

                def sync(fd, failure_at=failure_at, real_sync=real_sync):
                    if failure_at == "sync":
                        raise OSError("sync uncertainty")
                    return real_sync(fd)

                with (
                    self.subTest(failure_at=failure_at),
                    mock.patch.object(subject.os, "close", side_effect=close),
                    mock.patch.object(subject.os, "fsync", side_effect=sync),
                    self.assertRaises((OSError, subject.RuntimeNativeHealthStageError)),
                ):
                    subject._add_directories(output)
                self.assertEqual(len(closed), 4)
                for fd in closed:
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_cli_failure_does_not_publish_a_success_manifest(self):
        output = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["stage", "/absent"]),
            mock.patch.object(
                subject,
                "stage_runtime_native_health_profile",
                side_effect=subject.RuntimeNativeHealthStageError("refused"),
            ),
            redirect_stdout(output),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(subject.main(), 1)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
