"""One real host Python preparation, not a guest installation or a host profile."""
import json
from pathlib import Path
import stat
from unittest import TestCase

from scripts import prepare_pi_core_host_python_inputs as host
from scripts import prepare_pi_core_restricted_runtime as storage


class RetainedHostPython(TestCase):
    def test_retain_exact_relocated_python_inputs_without_bookworm_os(self):
        root = Path(__file__).resolve().parents[1]
        files = host.prepare_host_python_inputs(root)
        expected = "sha256:c03a2cacf42161b94c730948e4d1c1dcfd58aede8d003a16312fef0663f3a46e"
        work = storage.fresh(root, storage.BASE / ("host-python-" + expected[7:]))
        try:
            rows = [{"path": path, "size": f["size"], "digest": f["digest"]}
                    for path, f in sorted(files.items())]
            raw = host.image.canonical(rows)
            self.assertEqual(host.image.pin(raw), expected)
            self.assertEqual((len(rows), sum(r["size"] for r in rows)), (658, 24302223))
            self.assertEqual(sum("/lib-dynload/" in r["path"] for r in rows), 69)
            self.assertEqual(files[host.PREFIX + "/bin/python3.12"]["source_path"], host.image.PYTHON_SOURCE)
            source_rows = []
            for row in rows:
                name = row["path"]
                f = files[name]
                self.assertTrue(name.startswith(host.PREFIX + "/"))
                dest = work / "root" / name[1:]
                dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                storage.write(dest, f["raw"], f["mode"])
                self.assertEqual(stat.S_IMODE(dest.lstat().st_mode), f["mode"])
                # Valid empty Python package markers are part of this pinned namespace.
                self.assertEqual(host._pinned_bytes(dest, row["digest"], row["size"]), f["raw"])
                source_rows.append({**row, "source_path": f["source_path"], "mode": f["mode"]})
            storage.write(work / "host-python-files.json", raw)
            self.assertEqual(storage.read(work / "host-python-files.json"), raw)
            origins = host.image.canonical(source_rows)
            storage.write(work / "host-python-origins.json", origins)
            self.assertEqual(storage.read(work / "host-python-origins.json"), origins)
            outcome = {"status": "HOST_PYTHON_INPUTS_ONLY_NOT_INSTALLED", "files": len(rows),
                       "bytes": sum(r["size"] for r in rows), "host_python_files_digest": expected,
                       "origins_digest": host.image.pin(origins), "service_python_rows_digest": host.PYTHON_ROWS_PIN,
                       "release_digest": host.RELEASE_PIN, "host_profile_approved": False,
                       "os_libraries_selected": False, "guest_abi_verified": False,
                       "target_executed": False, "phase3_exit_eligible": False}
            storage.record(work / "outcome.json", outcome)
            print(json.dumps(outcome, sort_keys=True), flush=True)
        except Exception as error:
            storage.record(work / "refusal.json", {"reason": str(error)[:4096], "target_executed": False})
            raise
