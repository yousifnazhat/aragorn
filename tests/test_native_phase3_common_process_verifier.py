"""Honest structural doubles only; these are not captures or acceptance samples.

No observer, service, historical test method or common identity producer runs.
The local fixture exercises only the new retained-record join boundary.
"""

from copy import deepcopy
import stat
import unittest

from aragorn import native_phase3_common_process_verifier as subject


CONTAINER = "c" * 64
BOOT = "00000000-1111-2222-3333-444444444444"


def _fixture():
    """Build labelled inert byte identities, never a host/guest capture envelope."""
    old = subject.frozen
    accounts = {
        "gateway": (992, 992),
        "worker": (997, 997),
        "sensor": (994, 994),
        "broker": (993, 997),
    }
    files = {}
    for index, path in enumerate(subject.FILE_PATHS):
        raw = ("inert structural fixture: " + path).encode()
        mode = (
            0o400
            if path in {*old.DYNAMIC_PATHS, subject.MEASUREMENT_BINDING}
            else 0o755
            if path == old._ENTRY
            else 0o644
        )
        uid, gid = (
            accounts["broker"]
            if path == old._POLICY
            else (1000, 1000)
            if path == old._ENTRY
            else (0, 0)
        )
        files[path] = {
            "bytes": len(raw),
            "digest": old._digest(raw),
            "identity": [
                1,
                100 + index,
                stat.S_IFREG | mode,
                uid,
                gid,
                1,
                len(raw),
                1,
                1,
            ],
        }
    pins = {path: row["digest"] for path, row in files.items()}
    records, observed, loaded = {}, {}, {}
    for index, (role, unit) in enumerate(old._UNITS.items()):
        uid, gid = accounts[role]
        fsuid, fsgid = accounts["worker"] if role == "sensor" else (uid, gid)
        uids, gids = [uid, uid, uid, fsuid], [gid, gid, gid, fsgid]
        pid, started = 101 + index, 1001 + index
        cgroup = f"/docker/{CONTAINER}/system.slice/{unit}"
        argv = subject._argv(role)
        state = {
            "Id": unit,
            "MainPID": str(pid),
            "ControlPID": "0",
            "ControlGroup": cgroup,
            "InvocationID": str(index + 1) * 32,
            "ActiveState": "active",
            "SubState": "running",
            "User": old._ACCOUNTS[role][0],
            "Group": old._ACCOUNTS[role][1],
            "ExecStart": "{ path="
            + argv[0]
            + " ; argv[]="
            + " ".join(argv)
            + " ; ignore_errors=no ; inert=yes }",
            "FragmentPath": "/usr/lib/systemd/system/" + unit,
            "DropInPaths": "",
        }
        groups = (
            sorted({997, 994})
            if role in {"broker", "sensor"}
            else [992, 997]
            if role == "worker"
            else [992]
        )
        records[role] = {
            "unit": state,
            "pid": pid,
            "start_time_ticks": started,
            "uids": uids,
            "gids": gids,
            "groups": groups,
            "cgroup": cgroup,
            "cgroup_identity": [1, 500 + index],
            "root_identity": [1, 600 + index],
            "mount_namespace": {"device": 1, "inode": 700 + index},
            "argv": ["openclaw-gateway"] if role == "gateway" else argv,
        }
        independent = {
            "pid": pid,
            "uid": uid,
            "gid": gid,
            "start_time_ticks": started,
            "cgroup": cgroup,
        }
        if role == "gateway":
            independent.update(cgroup_device=1, cgroup_inode=500 + index)
            outer = {key: state[key] for key in subject._GATEWAY_FIELDS & state.keys()}
            outer.update(
                LoadState="loaded",
                KillMode="control-group",
                Delegate="no",
                Restart="no",
                SendSIGKILL="yes",
            )
        else:
            independent.update(
                uids=list(uids),
                gids=list(gids),
                executable=old._PYTHON,
                command=" ".join(argv),
            )
            outer = state | {"StandardOutput": "journal"}
        observed[role] = {"unit": outer, "process": independent}
        views = {}
        for name, path in subject.CREDENTIALS[role].items():
            views[name] = deepcopy(files[path])
            views[name]["identity"][2:5] = [stat.S_IFREG | 0o400, uid, gid]
        code = (
            old._ENTRY
            if role == "gateway"
            else old._WORKER_CODE
            if role == "worker"
            else old._SHIMS[role]
        )
        views["code_view"] = deepcopy(files[code])
        loaded[role] = views
    joins = {
        "configuration_digest": pins[old._CONFIG],
        "worker_binding_digest": pins[old._WORKER],
        "policy_digest": pins[old._POLICY],
        "measurement_binding_digest": pins[subject.MEASUREMENT_BINDING],
        "grant_digest": pins[old._GRANT],
        "runtime_profile_digest": old._digest(b"inert profile"),
        "declared_runtime_digest_not_whole_tree_measurement": old._digest(
            b"inert runtime"
        ),
        "measurement_source_pins": {
            name: pins[path] for name, path in subject.MEASUREMENT_SOURCES.items()
        },
        "measurement_boot_id": BOOT,
        "declared_input_digests_not_cas_readback": {
            key: old._digest(("inert declared " + key).encode())
            for key in (
                "deployment_identity_digest",
                "measurement_schedule_digest",
                "collection_commitment_digest",
                "scheduled_measurement_request_digest",
                "path_digest",
                "payload_digest",
            )
        },
    }
    identity = {
        "schema": subject.IDENTITY_SCHEMA,
        "authority": subject.IDENTITY_AUTHORITY,
        "status": "LOCAL_COMMON_IDENTITY_MEASURED",
        "container_id": CONTAINER,
        "boot_id": BOOT,
        "files": files,
        "processes": records,
        "loaded_process_views": loaded,
        "broker_module_views": {
            name: deepcopy(files[path])
            for name, path in subject.MEASUREMENT_SOURCES.items()
        },
        "measured_joins": joins,
        "unresolved_dimensions": deepcopy(subject._UNRESOLVED),
        "limitations": list(subject.IDENTITY_LIMITATIONS),
        "fixed_python_launcher": {
            "path": "/usr/bin/python3.12",
            "target": old._PYTHON,
            "identity": [1, 900, stat.S_IFLNK | 0o777, 0, 0, 1, len(old._PYTHON), 1, 1],
        },
        **dict.fromkeys(subject.FALSE_FLAGS, False),
    }
    observer = {
        "schema": subject.OBSERVER_SCHEMA,
        "authority": subject.OBSERVER_AUTHORITY,
        "container_id": CONTAINER,
        "boot_id": BOOT.replace("-", ""),
        "processes": observed,
        "limitations": list(subject.OBSERVER_LIMITATIONS),
        **dict.fromkeys(subject.FALSE_FLAGS, False),
    }
    return identity, observer, pins


class NativeCommonProcessVerifierTests(unittest.TestCase):
    def setUp(self):
        self.identity, self.observer, self.pins = _fixture()

    def verify(self, *, identity=None, observer=None, **kwargs):
        identity = self.identity if identity is None else identity
        observer = self.observer if observer is None else observer
        return subject.verify_native_common_process_observations(
            identity,
            deepcopy(identity),
            observer,
            deepcopy(observer),
            **(
                {"expected_container_id": CONTAINER, "expected_file_digests": self.pins}
                | kwargs
            ),
        )

    def test_inert_structural_joins_keep_every_authority_flag_false(self):
        before = deepcopy((self.identity, self.observer, self.pins))
        result = self.verify()
        self.assertEqual(result["status"], "BOUNDED_COMMON_PROCESS_JOINS_VERIFIED")
        self.assertEqual(result["caller_pinned_files"], 26)
        self.assertEqual(
            set(result["joined_processes"]), {"gateway", "worker", "sensor", "broker"}
        )
        self.assertTrue(all(result[key] is False for key in subject.FALSE_FLAGS))
        self.assertEqual((self.identity, self.observer, self.pins), before)

    def test_before_after_pairs_are_not_replaceable_by_claimed_equality(self):
        for field, value in (("boot_id", "f" * 32), ("processes", {})):
            after = deepcopy(self.observer)
            after[field] = value
            with (
                self.subTest(field=field),
                self.assertRaises(subject.NativeCommonProcessVerificationError),
            ):
                subject.verify_native_common_process_observations(
                    self.identity,
                    deepcopy(self.identity),
                    self.observer,
                    after,
                    expected_container_id=CONTAINER,
                    expected_file_digests=self.pins,
                )
        after = deepcopy(self.identity)
        after["processes"]["broker"]["mount_namespace"]["inode"] += 1
        with self.assertRaises(subject.NativeCommonProcessVerificationError):
            subject.verify_native_common_process_observations(
                self.identity,
                after,
                self.observer,
                deepcopy(self.observer),
                expected_container_id=CONTAINER,
                expected_file_digests=self.pins,
            )

    def test_three_credential_broker_is_not_relabelled_two_credential_broker(self):
        identity, observer = deepcopy(self.identity), deepcopy(self.observer)
        record = identity["processes"]["broker"]
        removed = record["argv"].pop()
        record["unit"]["ExecStart"] = record["unit"]["ExecStart"].replace(
            " " + removed, ""
        )
        observer["processes"]["broker"]["unit"]["ExecStart"] = record["unit"][
            "ExecStart"
        ]
        observer["processes"]["broker"]["process"]["command"] = " ".join(record["argv"])
        with self.assertRaises(subject.NativeCommonProcessVerificationError):
            self.verify(identity=identity, observer=observer)

    def test_independent_kernel_epoch_and_gateway_inode_must_actually_join(self):
        changes = (
            ("broker", "pid", 400),
            ("worker", "start_time_ticks", 2000),
            ("sensor", "uid", 5),
            ("gateway", "cgroup_inode", 999),
            ("broker", "executable", "/tmp/python"),
            ("worker", "cgroup", "/wrong"),
        )
        for role, key, value in changes:
            observer = deepcopy(self.observer)
            observer["processes"][role]["process"][key] = value
            with (
                self.subTest(role=role, key=key),
                self.assertRaises(subject.NativeCommonProcessVerificationError),
            ):
                self.verify(observer=observer)

    def test_exact_envelopes_booleans_and_unit_fields_refuse(self):
        for target, key, value in (
            ("identity", "phase3_eligible", 0),
            ("observer", "metrics_eligible", True),
            ("observer", "schema", subject.IDENTITY_SCHEMA),
            ("identity", "extra", True),
            ("observer", "boot_id", "0" * 32),
        ):
            values = {
                "identity": deepcopy(self.identity),
                "observer": deepcopy(self.observer),
            }
            values[target][key] = value
            with (
                self.subTest(target=target, key=key),
                self.assertRaises(subject.NativeCommonProcessVerificationError),
            ):
                self.verify(**values)
        observer = deepcopy(self.observer)
        observer["processes"]["gateway"]["unit"]["Restart"] = "always"
        with self.assertRaises(subject.NativeCommonProcessVerificationError):
            self.verify(observer=observer)

    def test_file_pins_metadata_and_common26_inventory_are_checked(self):
        bad_pins = dict(self.pins)
        bad_pins[subject.MEASUREMENT_BINDING] = subject.frozen._digest(b"other")
        with self.assertRaises(subject.NativeCommonProcessVerificationError):
            self.verify(expected_file_digests=bad_pins)
        for key, value in (
            ("identity", [1, 2, stat.S_IFREG | 0o644, 0, 0, 1, 1, 1, 1]),
            ("bytes", True),
            ("digest", "invalid"),
        ):
            identity = deepcopy(self.identity)
            identity["files"][subject.MEASUREMENT_BINDING][key] = value
            with (
                self.subTest(key=key),
                self.assertRaises(subject.NativeCommonProcessVerificationError),
            ):
                self.verify(identity=identity)
        identity = deepcopy(self.identity)
        del identity["files"][subject.MEASUREMENT_BINDING]
        with self.assertRaises(subject.NativeCommonProcessVerificationError):
            self.verify(identity=identity)

    def test_loaded_measurement_credential_and_module_views_cannot_be_substituted(self):
        for container, key in (
            ("loaded_process_views", "decision-measurement-binding"),
            ("broker_module_views", "runtime_action_broker_v4.py"),
        ):
            identity = deepcopy(self.identity)
            view = (
                identity[container]["broker"][key]
                if container == "loaded_process_views"
                else identity[container][key]
            )
            view["digest"] = subject.frozen._digest(b"substituted inert bytes")
            with (
                self.subTest(container=container),
                self.assertRaises(subject.NativeCommonProcessVerificationError),
            ):
                self.verify(identity=identity)
        identity = deepcopy(self.identity)
        del identity["loaded_process_views"]["broker"]["decision-measurement-binding"]
        with self.assertRaises(subject.NativeCommonProcessVerificationError):
            self.verify(identity=identity)

    def test_first_reader_only_claims_are_validated_without_invented_second_fields(
        self,
    ):
        for key, value in (
            ("root_identity", [True, 1]),
            ("groups", [997]),
            ("mount_namespace", {"device": 1, "inode": 0}),
        ):
            identity = deepcopy(self.identity)
            identity["processes"]["broker"][key] = value
            with (
                self.subTest(key=key),
                self.assertRaises(subject.NativeCommonProcessVerificationError),
            ):
                self.verify(identity=identity)
        observer = deepcopy(self.observer)
        observer["processes"]["broker"]["process"]["mount_namespace"] = {
            "device": 1,
            "inode": 1,
        }
        with self.assertRaises(subject.NativeCommonProcessVerificationError):
            self.verify(observer=observer)

    def test_measured_digest_links_are_not_accepted_as_freeform_summaries(self):
        for key in (
            "grant_digest",
            "measurement_binding_digest",
            "measurement_boot_id",
        ):
            identity = deepcopy(self.identity)
            identity["measured_joins"][key] = "changed"
            with (
                self.subTest(key=key),
                self.assertRaises(subject.NativeCommonProcessVerificationError),
            ):
                self.verify(identity=identity)


if __name__ == "__main__":
    unittest.main()
