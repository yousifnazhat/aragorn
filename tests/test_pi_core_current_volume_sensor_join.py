"""B84: strict replay of inert, separately pinned records, not observation or activation."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import unittest

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.pi_core_state_mounts import ACTION
from scripts.prepare_pi_core_coordinator_host import host_contract
from scripts import verify_pi_core_joined_sensor_state as replay
import test_pi_core_coordinator_entry as plans
import test_pi_core_sensor_luks_headers as b80
import test_pi_core_sensor_state_evidence as archived


_MODULES = ("pi_core_coordinator_entry", "pi_core_managed_bootstrap", "pi_core_service_lifecycle",
            "pi_core_sensor_state_entry", "pi_core_sensor_state_observer",
            "pi_core_sensor_state_custody", "pi_core_sensor_state_evidence", "pi_core_state_dm_mapping",
            "pi_core_state_backing_leaf", "pi_core_state_luks_headers")


def complete_plan(f):
    # Populate and pin a complete donor plan *before* the original managed
    # capture and public report are sealed by the existing inert fixture.
    complete, _ = plans.prepared()
    complete["service_configuration"] = f.plan["service_configuration"]
    for role in ("deployment", "launch"):
        complete[role]["digest"] = f.plan[role]["digest"]
    complete["sensor_state_observation"] = f.plan["sensor_state_observation"]
    py, std = "/usr/bin/python3.12", "/usr/lib/python3.12"
    modules = {"aragorn":"opt/aragorn/src/aragorn/__init__.py",
               **{"aragorn."+n:"opt/aragorn/src/aragorn/"+n+".py" for n in _MODULES}}
    paths = {*(Path("/"+p) for p in modules.values()), *host_contract._TOOLS,
             host_contract._WRAPPER, host_contract._LOADER, Path(py)}
    files = [dict(path=str(p), size=len(str(p).encode()), digest=archived.digest(str(p).encode())) for p in sorted(paths)]
    profile = dict(schema="aragorn/pi-core-coordinator-host/v1",target="linux-arm64-cpython312",
                   python_executable=py,wrapper_path=str(host_contract._WRAPPER),stdlib_roots=[std],sys_path=[std],
                   absent_sys_path=[],files=files)
    complete["host_profile_digest"] = f.b.put(canonical_json(profile))
    f.plan = complete
    f.b84_profile = profile
    f.b84_rows = [dict(module=n,path=p,digest=archived.digest(("/"+p).encode())) for n,p in modules.items()]


class CurrentVolumeAndSensorReplay(unittest.TestCase):
    def archive(self, *, view=b80.add_headers, change_sensor=lambda s:s):
        f = archived._JoinedSensorFixture()
        self.addCleanup(f.doCleanups)
        f.setUp(prepare_observation=view, prepare_plan=complete_plan,
                change_streams=lambda m,s:(m+b80.b79.SYSFS_MOUNT,change_sensor(s)))
        f.owner.update(source_before=deepcopy(f.b84_rows),source_after=deepcopy(f.b84_rows))
        for frame in (f.owner["host_before"],f.owner["host_after"]):
            frame.update(python_executable=f.b84_profile["python_executable"],files=len(f.b84_profile["files"]))
        return f

    def test_exact_v5_archive_cli_reports_current_join_and_not_health_or_unlock(self):
        f = self.archive()
        params = f.replay_args()
        params["archive"] = params["archive"].root
        flags = [v for k,val in params.items() for v in ("--"+k.replace("_","-"),str(val))]
        with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as errors:
            self.assertEqual(replay.main([*flags,"--require-current-volume-and-sensor"]),0,errors.getvalue())
        finding = json.loads(out.getvalue())
        for key in ("current_volume_and_sensor_records_matched","archive_sensor_subject_and_mount_bytes_matched",
                    "archive_manager_subject_and_mount_bytes_matched","sensor_read_only_bind_matched",
                    "kernel_whole_disk_leaf_matched","current_inline_luks2_metadata_matched"):
            self.assertIs(finding[key],True,key)
        for key in ("authenticated_unlock_verified","physical_asset_verified","exclusive_writer_verified",
                    "sensor_health_verified","worker_isolation_verified","same_capture_interval_verified",
                    "external_freshness_verified","phase3_exit_eligible"):
            self.assertIs(finding[key],False,key)

    def test_consumer_appearing_only_after_capture_cannot_establish_source_identity(self):
        f = self.archive()
        f.owner["source_before"] = f.owner["source_before"][:-1]
        with self.assertRaisesRegex(ValueError,"(?i)consum|source"):
            f.check(require_current_volume_and_sensor=True)

    def test_absent_or_substituted_sources_do_not_pass_even_after_repinning_owner(self):
        f = self.archive()
        good = f.b84_rows
        for case in ("absent","replaced"):
            with self.subTest(case=case):
                first, last = deepcopy(good), deepcopy(good)
                if case == "absent":
                    first = last = None
                else:
                    first[-1]["digest"] = last[-1]["digest"] = canonical_digest("different implementation")
                f.owner.update(source_before=first,source_after=last)
                with self.assertRaisesRegex(ValueError,"(?i)consum|source"):
                    f.check(require_current_volume_and_sensor=True)

    def test_sensor_pid_generation_mismatch_in_otherwise_consistent_independent_archive(self):
        f = self.archive()
        for role in (f.b.head["subjects"]["sensor"], f.b.capture["roles"]["sensor"]["before"],
                     f.b.capture["roles"]["sensor"]["after"]):
            role["start_ticks"] += 1
        self.assertIs(f.check()["archive_sensor_subject_and_mount_bytes_matched"],False)
        with self.assertRaisesRegex(ValueError,"(?i)sensor.*(generation|mount|subject)|independent sensor"):
            f.check(require_current_volume_and_sensor=True)

    def test_strict_selection_also_requires_the_independent_manager_generation(self):
        f = self.archive()
        for subject in (f.b.head["subjects"]["manager"],f.b.capture["roles"]["manager"]["before"],
                        f.b.capture["roles"]["manager"]["after"],f.outer.proof["manager"]):
            subject["pid"] = 170
        result = f.check()
        self.assertIs(result["archive_manager_subject_and_mount_bytes_matched"],False)
        self.assertIs(result["archive_sensor_subject_and_mount_bytes_matched"],True)
        with self.assertRaisesRegex(ValueError,"independent manager"):
            f.check(require_current_volume_and_sensor=True)

    def test_membership_preserved_but_different_original_sensor_mount_bytes_refuse(self):
        f = self.archive()
        role = f.b.capture["roles"]["sensor"]
        raw = f.b.reader.read(role["mountinfo"])
        role["mountinfo"] = f.b.put(raw+b"250 1 0:87 / /tmp/ordinary-ro ro - tmpfs tmpfs ro\n")
        self.assertIs(f.check()["archive_sensor_subject_and_mount_bytes_matched"],False)
        with self.assertRaisesRegex(ValueError,"(?i)sensor.*(generation|mount|subject)|independent sensor"):
            f.check(require_current_volume_and_sensor=True)

    def test_historical_volume_remains_scoped_and_cannot_satisfy_strict_consumer(self):
        f = self.archive(view=b80.b79.add_leaf)  # v4 lacks original v5 inline-header observations
        self.assertIs(f.check()["inline_luks2_header_verified"],False)
        with self.assertRaisesRegex(ValueError,"(?i)v5|current inline|inline LUKS2"):
            f.check(require_current_volume_and_sensor=True)

    def test_wrong_inline_encryption_identity_cannot_replace_independent_volume(self):
        f = self.archive(view=lambda s,v,vol:b80.add_headers(s,v,vol,encryption_uuid="773e7c7a-11ca-4b0a-babe-a02a3bb721bb"))
        with self.assertRaisesRegex(ValueError,"LUKS2 volume identity"):
            f.check(require_current_volume_and_sensor=True)

    def test_writable_state_does_not_pass_on_agreeing_resealed_mounts(self):
        src = (ACTION+" ro,nodev,nosuid,noexec").encode()
        f = self.archive(change_sensor=lambda s:s.replace(src,src.replace(b" ro,",b" rw,")))
        with self.assertRaisesRegex(ValueError,"state mount access or propagation differs"):
            f.check(require_current_volume_and_sensor=True)
