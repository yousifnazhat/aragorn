from __future__ import annotations

import ast
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aragorn import admission_protected_final_combined_v3_plugin_force_reinstall as old
from scripts import materialize_openclaw_final_v3_plugin_force_current_parent as subject

_ROOT = Path(__file__).resolve().parents[1]


class PluginForceCurrentParentBuildSourceTests(unittest.TestCase):
    def test_exact_build_sources_and_fail_closed_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "context"
            manifest = (
                subject.materialize_openclaw_final_v3_plugin_force_current_parent(
                    output
                )
            )
            self.assertEqual(manifest["schema"], subject._SCHEMA)
            self.assertEqual(manifest["authority"], subject._AUTHORITY)
            self.assertEqual(manifest["case_id"], old._ROUTE)
            self.assertEqual(manifest["parent_image_id"], old._IMAGE)
            self.assertIsNone(manifest["child_image_id"])
            for key in (
                "execution_performed",
                "qualification_eligible",
                "phase3_exit_eligible",
                "release_eligible",
            ):
                self.assertIs(manifest[key], False)
            self.assertEqual(len(manifest["unchanged_inherited_bundle"]), 7)
            evidence = json.loads((_ROOT / old._EVIDENCE["path"]).read_bytes())
            bundle = evidence["source_artifacts"]["probe_bundle"]
            self.assertEqual(
                manifest["unchanged_inherited_bundle"],
                [
                    {key: item[key] for key in ("name", "bytes", "digest")}
                    for item in bundle
                ],
            )
            self.assertEqual(
                {path.name for path in output.iterdir()}, set(subject._OUTPUTS)
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o555)
            for item in manifest["files"]:
                path = output / item["name"]
                raw = path.read_bytes()
                self.assertEqual(
                    (len(raw), subject.overlay._digest(raw)),
                    subject._OUTPUTS[item["name"]],
                )
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            recipe = (output / subject._RECIPE).read_text()
            collector = (output / subject._COLLECTOR).read_bytes()
            dockerfile = (output / "Dockerfile").read_text()
            ast.parse(collector)
            result = subprocess.run(
                ["/bin/sh", "-n", str(output / subject._RECIPE)],
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            for raw in (recipe, collector.decode(), dockerfile):
                self.assertNotIn(subject._OLD_PARENT, raw)
            self.assertTrue(dockerfile.startswith(f"FROM {old._IMAGE}\n"))
            self.assertNotIn("ARG ", dockerfile)
            self.assertNotIn("install ", dockerfile)
            self.assertNotIn("rm ", dockerfile)
            self.assertEqual(dockerfile.count("COPY "), 2)
            self.assertIn(f"    /src/scripts/{subject._COLLECTOR} \\", recipe)
            self.assertNotIn(f"    /src/{subject._OLD_COLLECTOR} \\", recipe)
            self.assertIn(
                f'python3.12 -I -S -B "$context/source/{subject._MATERIALIZER}" "$context/build"',
                recipe,
            )
            self.assertIn('    cd "$context/build"', recipe)
            self.assertIn("        -f Dockerfile \\", recipe)
            self.assertLess(
                recipe.index("git verify-commit --raw"),
                recipe.index("git archive --format=tar"),
            )
            for name in (subject._MATERIALIZER, *subject._INPUTS):
                self.assertIn(f"    {name} \\\n", recipe)
            for path, (size, digest, mode) in subject._INHERITED.items():
                self.assertIn(f"stat -c '%F:%u:%g:%a:%h:%s' {path}", dockerfile)
                self.assertIn(f"'regular file:0:0:{mode[1:]}:1:{size}'", dockerfile)
                self.assertIn(f"= {digest[7:]};", dockerfile)
            captured = {}

            def records(value):
                if isinstance(value, dict):
                    if {"path", "stat", "bytes", "digest"} <= value.keys():
                        captured[value["path"]] = value
                    for child in value.values():
                        records(child)
                elif isinstance(value, list):
                    for child in value:
                        records(child)

            records(evidence)
            uncaptured = set()
            for path, (size, digest, mode) in subject._INHERITED.items():
                if path not in captured:
                    uncaptured.add(path)
                    continue
                record = captured[path]
                self.assertEqual((record["bytes"], record["digest"]), (size, digest))
                self.assertEqual(
                    {
                        key: record["stat"][key]
                        for key in ("uid", "gid", "mode", "size", "nlink", "type")
                    },
                    {
                        "uid": 0,
                        "gid": 0,
                        "mode": mode,
                        "size": size,
                        "nlink": 1,
                        "type": "file",
                    },
                )
            # These six fixture hashes/sizes have bundle receipts, but their
            # standalone filesystem custody remains a future build-time check.
            self.assertEqual(
                uncaptured,
                {
                    "/route-input/plugin-force-reinstall/" + name
                    for name in subject._BUNDLE
                    if name.startswith(("baseline-source/", "candidate-source/"))
                },
            )
            self.assertEqual(len(subject._INHERITED) - len(uncaptured), 13)
            self.assertIn(subject._BUILD_CLEANUP, recipe)
            for shape in ("complete", "partial", "symlink", "writable"):
                with (
                    self.subTest(cleanup=shape),
                    tempfile.TemporaryDirectory(
                        prefix="aragorn-phase3-final-combined-v3-force-context.",
                        dir="/tmp",
                    ) as context,
                ):
                    leaf = Path(context) / "build"
                    if shape == "symlink":
                        leaf.symlink_to(output, target_is_directory=True)
                    else:
                        leaf.mkdir(mode=0o700)
                        shutil.copyfile(output / "Dockerfile", leaf / "Dockerfile")
                        leaf.chmod(
                            0o777
                            if shape == "writable"
                            else 0o555
                            if shape == "complete"
                            else 0o700
                        )
                    cleaned = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-S",
                            "-B",
                            "-c",
                            subject._BUILD_CLEANUP,
                            context,
                        ],
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                    if shape in {"symlink", "writable"}:
                        self.assertNotEqual(cleaned.returncode, 0)
                        self.assertTrue(leaf.exists())
                        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o555)
                    else:
                        self.assertEqual(cleaned.returncode, 0, cleaned.stderr.decode())
                        self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o700)
                        shutil.rmtree(leaf)
                        self.assertFalse(leaf.exists())
            # Runtime action functions must remain syntactically identical;
            # only outer parent/provenance bindings change.
            before = ast.parse((_ROOT / subject._OLD_COLLECTOR).read_bytes())
            after = ast.parse(collector)
            functions = (
                "_probe_bundle",
                "_prepare_gateway",
                "_run_route",
                "_coherent_case",
                "_decision",
                "_collect",
            )
            for name in functions:
                nodes = [
                    next(
                        node
                        for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == name
                    )
                    for tree in (before, after)
                ]
                self.assertEqual(ast.dump(nodes[0]), ast.dump(nodes[1]))
            # The archived renderer works as a standalone source tree with no
            # repository package or live container imports.
            checkout = root / "source"
            for name in (subject._MATERIALIZER, *subject._INPUTS):
                path = checkout / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(_ROOT / name, path)
            rendered = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(checkout / subject._MATERIALIZER),
                    str(root / "replayed"),
                ],
                cwd=root,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr.decode())
            self.assertEqual(json.loads(rendered.stdout), manifest)
            for name in subject._INPUTS:
                with self.subTest(changed_input=name):
                    path = checkout / name
                    raw = path.read_bytes()
                    path.write_bytes(b"!" + raw[1:])
                    absent = root / "rejected"
                    with (
                        mock.patch.object(subject, "_ROOT", checkout),
                        self.assertRaises(subject.PluginForceBuildSourceError),
                    ):
                        subject.materialize_openclaw_final_v3_plugin_force_current_parent(
                            absent
                        )
                    self.assertFalse(absent.exists())
                    path.write_bytes(raw)
            for transform, name in (
                (subject._recipe, subject._OLD_RECIPE),
                (subject._collector, subject._OLD_COLLECTOR),
            ):
                raw = (_ROOT / name).read_bytes()
                for changed in (
                    raw.replace(subject._OLD_PARENT.encode(), b"changed"),
                    raw + subject._OLD_PARENT.encode(),
                ):
                    with self.assertRaises(subject.PluginForceBuildSourceError):
                        transform(changed)
            with (
                mock.patch.object(subject, "_collector", side_effect=lambda raw: raw),
                self.assertRaises(subject.PluginForceBuildSourceError),
            ):
                subject.materialize_openclaw_final_v3_plugin_force_current_parent(
                    root / "wrong-render"
                )
            self.assertFalse((root / "wrong-render").exists())
            for path in (output, str(root / "not-path")):
                with self.assertRaises(subject.PluginForceBuildSourceError):
                    subject.materialize_openclaw_final_v3_plugin_force_current_parent(
                        path
                    )
            for kind in ("symlink", "hardlink", "fifo"):
                with self.subTest(kind=kind):
                    path = checkout / subject._OLD_RECIPE
                    path.unlink()
                    if kind == "symlink":
                        path.symlink_to(_ROOT / subject._OLD_RECIPE)
                    elif kind == "hardlink":
                        os.link(checkout / subject._OLD_COLLECTOR, path)
                    else:
                        os.mkfifo(path, 0o444)
                    with (
                        mock.patch.object(subject, "_ROOT", checkout),
                        self.assertRaises(subject.PluginForceBuildSourceError),
                    ):
                        subject.materialize_openclaw_final_v3_plugin_force_current_parent(
                            root / "unsafe"
                        )
                    self.assertFalse((root / "unsafe").exists())
            with (
                mock.patch.object(subject.overlay.os, "write", return_value=0),
                self.assertRaises(subject.PluginForceBuildSourceError),
            ):
                subject.materialize_openclaw_final_v3_plugin_force_current_parent(
                    root / "partial"
                )


if __name__ == "__main__":
    unittest.main()
