"""Existing collector + pinned Pi + real copy + independent replay. No guest or real clock."""
import hashlib
import json
import select
import subprocess
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Timer
from unittest import TestCase, mock

import test_pi_core_task_service as fixtures
from aragorn import phase3_measurement_collector as collector, pi_core_task_reference as reference
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.pi_core_paired_task_verify import verify_portable
from scripts import build_pi_core_linux as build


class FixedTaskPathTests(TestCase):
    def test_pi_copy_and_reply_are_inside_collectors_marks_in_each_mode(self):
        root = Path(__file__).resolve().parents[1]
        pkg = root / "packaging/pi-core"
        pins = json.loads((pkg / "offline-toolchain-v1.json").read_bytes())
        node = Path(pins["node"]["executable"])
        common = subprocess.check_output(["git","rev-parse","--path-format=absolute","--git-common-dir"],
                                         cwd=root, text=True, timeout=5).strip()
        deps = pkg / "node_modules"
        if not deps.is_dir():
            deps = Path(common).parent / "packaging/pi-core/node_modules"
        def checked_inputs():
            self.assertEqual(hashlib.sha256(node.read_bytes()).hexdigest(), pins["node"]["sha256"])
            self.assertEqual(build.sha256(build.canonical(build.tree_inventory(deps))), pins["dependency_tree_sha256"])
        checked_inputs()
        with TemporaryDirectory() as temp:
            folder = Path(temp).resolve()
            (folder / "node_modules").symlink_to(deps, target_is_directory=True)
            (folder / "paired-task.mjs").write_bytes((pkg / "paired-task.mjs").read_bytes())
            (folder / "check.mjs").write_bytes((root / "tests/fixtures/pi_core_task_stdio.mjs").read_bytes())
            writer = CAS(str(folder / "evidence"))
            reader = CAS(str(folder / "evidence"), read_only=True)
            def keep(raw):
                return writer.put(BytesIO(raw), max_bytes=1 << 20)
            source_pin = keep(Path(reference.__file__).read_bytes())
            def route(packet, call_service):
                with subprocess.Popen([str(node), "--permission", "--allow-fs-read=" + str(folder),
                        "--allow-fs-read=" + str(deps.resolve()), "--disallow-code-generation-from-strings", "./check.mjs"],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=folder,
                        env={"HOME":temp, "TMPDIR":temp, "PATH":"/usr/bin:/bin", "LC_ALL":"C"}) as child:
                    # Also bounds a partial line or a peer that never drains its input pipe.
                    watchdog = Timer(8, child.kill)
                    watchdog.start()
                    try:
                        def send(doc):
                            child.stdin.write(canonical_json(doc) + b"\n")
                            child.stdin.flush()
                        def receive():
                            self.assertTrue(select.select([child.stdout], [], [], 8)[0], "Pi fixture exceeded its deadline")
                            line = child.stdout.readline(65538)
                            if not line or child.poll() not in (None, 0):
                                self.fail("Pi fixture exited: " + child.communicate(timeout=2)[1][-2048:].decode(errors="replace"))
                            self.assertTrue(len(line) <= 65537 and line.endswith(b"\n"))
                            return json.loads(line)
                        send(packet)
                        service_request = receive()
                        trail.append("Pi to service")
                        send(call_service(service_request))
                        result = receive()
                        trail.append("Pi to manager")
                        extra, err = child.communicate(timeout=5)
                        self.assertEqual((child.returncode, extra), (0, b""), err[-2048:])
                        return result
                    finally:
                        watchdog.cancel()
                        if child.poll() is None:
                            child.kill()
                            child.wait(timeout=5)
            for index, mode in enumerate(("baseline","instrumented")):
                helper = fixtures.TaskServiceTests()
                task = "BENIGN_COPY_READBACK"
                request = helper.ticket(task, mode)["request"]
                trail = []
                def execute(req, mark):
                    self.assertEqual(req, request)
                    def stamp(name):
                        trail.append(name)
                        return mark(name)
                    receipt, _ = helper.copy_roundtrip(mode, collector_mark=stamp, pi_route=route)
                    return canonical_json(receipt)
                def verify(raw, req, bounds):
                    return verify_portable(raw, req, bounds, evidence_cas=reader, reference_source_pin=source_pin,
                        ticket_pin=keep(canonical_json(helper.last_ticket)), sidecar_pin=keep(canonical_json(helper.last_sidecar)))
                times = [100 + 100*index, 175 + 100*index]
                with self.subTest(mode=mode), mock.patch.object(collector,"_boottime_ns",side_effect=times):
                    semantics, bounds, _ = collector._sample(request, collector._TASK_BOUNDARIES, evidence_cas=writer,
                        execute=execute, verify=verify, guard=lambda: None, committed_at=1)
                    self.assertEqual(semantics, {"completed":True})
                    self.assertEqual(bounds, dict(zip(collector._TASK_BOUNDARIES, times)))
                    self.assertEqual(trail, ["TASK_ACCEPTED","Pi to service","Pi to manager","TASK_COMPLETED"])
        checked_inputs()
