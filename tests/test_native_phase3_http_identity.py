"""Focused HTTP identity bridge checks, using inert bytes and kernel doubles.

No stager, observer, historical test method, socket, service or live capture runs.
The common function names/statuses remain stable; HTTP schemas prevent relabeling.
"""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import stat
from types import ModuleType, SimpleNamespace
import unittest

from scripts import materialize_native_phase3_http_identity as renderer
from scripts import materialize_runtime_http_collection as collection
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn import runtime_http_action as http
from aragorn.runtime_capability_grant import GRANT_AUTHORITY, GRANT_SCHEMA

ROOT = Path(__file__).resolve().parents[1]
PIN = "sha256:" + "a" * 64
BOOT = "00000000-1111-2222-3333-444444444444"
CONTAINER = "c" * 64
ACCOUNTS = {
    "gateway": (992, 992),
    "worker": (997, 997),
    "sensor": (994, 994),
    "broker": (993, 997),
}


def _module(raw, label):
    module = ModuleType("aragorn._http_identity_test_" + label)
    module.__package__ = "aragorn"
    exec(compile(raw, "<HTTP identity test " + label + ">", "exec"), module.__dict__)
    return module


def _subjects():
    source = {name: (ROOT / name).read_bytes() for name in renderer.INPUTS}
    rendered = renderer.render(source)
    identity = _module(rendered[renderer.IDENTITY], "reader")
    verifier = _module(rendered[renderer.VERIFIER], "verifier")
    measurements = collection.render(
        {name: (ROOT / name).read_bytes() for name in collection.INPUTS}
    )
    # Bind only this isolated test namespace, never imported production globals.
    identity.measurement = _module(measurements[collection.PRIOR], "measurement")
    return identity, verifier, source, rendered


def _documents(subject):
    old = subject.prior
    raw = {
        path: ("inert selected source " + path).encode() for path in subject.FILE_PATHS
    }
    fixture = {
        "schema": http.BINDING_SCHEMA,
        "fixture": {
            "container_id": CONTAINER,
            "boot_id": BOOT,
            "netns_device": 4,
            "netns_inode": 5,
        },
        "expected_broker_uid": 993,
        "expected_broker_gid": 997,
    }
    digests = http.action_digests("p3-lab-a001", fixture)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "version": 1,
        "sensor_digest": PIN,
    }
    profile = {"runtime_digest": PIN}
    grant = {
        "schema": GRANT_SCHEMA,
        "authority": GRANT_AUTHORITY,
        "grant_id": "f" * 64,
        "source_manifest_digest": PIN,
        "install_context_digest": PIN,
        "runtime_profile_digest": canonical_digest(profile),
        "runtime_digest": PIN,
        "active_skill_digest": PIN,
        "sensor_digest": PIN,
        "policy_digest": canonical_digest(policy),
        "policy_version": 1,
        "operation_digest": digests["operation_digest"],
        "issued_at_unix": 90,
        "expires_at_unix": 120,
        "max_actions": 1,
    }
    docs = {
        old._CONFIG: {
            "tools": {
                "alsoAllow": [
                    "aragorn_runtime_create",
                    "aragorn_runtime_http_canary",
                    "read",
                ]
            }
        },
        old._POLICY: policy,
        old._GRANT: grant,
        old._WORKER: {
            "schema": "aragorn/runtime-action-worker-binding/v1",
            "runtime_digest": PIN,
            "active_skill_digest": PIN,
            "policy_digest": canonical_digest(policy),
            "policy_version": 1,
        },
        old._RUNTIME: {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": PIN,
            "runtime_profile_digest": canonical_digest(profile),
        },
        old._OBSERVATION: {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": PIN,
            "runtime_profile": profile,
        },
        subject.HTTP_FIXTURE_BINDING: fixture,
    }
    docs[subject.MEASUREMENT_BINDING] = {
        "schema": "aragorn/runtime-broker-decision-measurement-binding/v1",
        "boot_id": BOOT,
        "attempt_id": "p3-lab-a001",
        "grant_digest": canonical_digest(grant),
        **{
            key: PIN
            for key in (
                "deployment_identity_digest",
                "measurement_schedule_digest",
                "collection_commitment_digest",
                "scheduled_measurement_request_digest",
            )
        },
        **{
            key: grant[key]
            for key in (
                "runtime_profile_digest",
                "sensor_digest",
                "runtime_digest",
                "policy_digest",
                "active_skill_digest",
                "operation_digest",
            )
        },
        **digests,
        "source_pins": {
            name: old._digest(raw[path])
            for name, path in subject.MEASUREMENT_SOURCES.items()
        },
    }
    raw.update({path: canonical_json(value) for path, value in docs.items()})
    return raw


def _inert_read(subject, raw, *, change=None):
    """Exercise the reader's actual control flow with no real OS operation."""
    original_prior = subject.prior
    roles = tuple(ACCOUNTS)
    records = {
        role: {"pid": 101 + i, "root_identity": [1, 201 + i]}
        for i, role in enumerate(roles)
    }
    reads, closed, descriptor_roles, counts = [], [], {}, {}
    next_fd = [10]

    def open_path(path, flags):
        next_fd[0] += 1
        fd = next_fd[0]
        descriptor_roles[fd] = (
            "observer" if path == "/" else roles[int(path.split("/")[2]) - 101]
        )
        return fd

    def read_at(fd, path, **args):
        role = descriptor_roles[fd]
        source = path
        for service, credentials in subject.CREDENTIALS.items():
            for credential, candidate in credentials.items():
                if (
                    path
                    == f"/run/credentials/{original_prior._UNITS[service]}/{credential}"
                ):
                    source = candidate
        key = (role, path)
        counts[key] = counts.get(key, 0) + 1
        content = raw[source]
        if change:
            content = change(key, counts[key], content)
        reads.append((role, path, counts[key], args))
        mode = next(iter(args["modes"]))
        metadata = {
            "bytes": len(content),
            "digest": canonical_digest(json.loads(content))
            if source == subject.HTTP_FIXTURE_BINDING
            else original_prior._digest(content),
            "identity": [
                1,
                2,
                stat.S_IFREG | mode,
                args["owner"],
                args.get("owner_gid", 0),
                1,
                len(content),
                3,
                4,
            ],
        }
        return content, metadata

    process = SimpleNamespace(
        _process_cgroup=lambda pid: f"/docker/{CONTAINER}/init.scope",
        require_live_pidfd=lambda fd: None,
        _executable_digest=lambda pid: original_prior._digest(
            raw[original_prior._executable_path(roles[pid - 101])]
        ),
        RuntimeActionObservationPublisherError=ValueError,
    )
    subject.prior = SimpleNamespace(**vars(original_prior))
    subject.prior.process = process
    subject.prior.broker = SimpleNamespace(
        require_owned_directory=lambda *a, **k: None,
        RuntimeActionBrokerError=ValueError,
    )
    subject.prior._accounts = lambda: ACCOUNTS
    subject.prior._boot = lambda: BOOT
    subject.prior._python_link = lambda fd: {"target": original_prior._PYTHON}
    subject.prior._open_pidfd = lambda record: 1000 + record["pid"]
    subject.prior._read_at = read_at
    subject._process = lambda role, *args: deepcopy(records[role])
    subject.sys = SimpleNamespace(platform="linux")
    subject.os = SimpleNamespace(
        geteuid=lambda: 0,
        pidfd_open=lambda *args: None,
        open=open_path,
        close=closed.append,
        O_RDONLY=os.O_RDONLY,
        O_DIRECTORY=os.O_DIRECTORY,
        O_NOFOLLOW=os.O_NOFOLLOW,
        O_CLOEXEC=os.O_CLOEXEC,
        fstat=lambda fd: SimpleNamespace(
            st_dev=1, st_ino=201 + roles.index(descriptor_roles[fd])
        ),
    )
    pins = {path: original_prior._digest(content) for path, content in raw.items()}
    result = subject.read_native_common_identity(
        expected_container_id=CONTAINER, expected_file_digests=pins
    )
    return result, reads, closed, pins


class NativeHttpIdentityTests(unittest.TestCase):
    def setUp(self):
        self.identity, self.verifier, self.source, self.rendered = _subjects()

    def test_exact_source_pins_reject_missing_mutated_and_reprocessed_inputs(self):
        for name in renderer.INPUTS:
            for value in (
                self.source[name] + b"\n",
                self.source[name].decode(),
                self.rendered[name],
            ):
                with (
                    self.subTest(name=name, value_type=type(value).__name__),
                    self.assertRaises(renderer.NativeHttpIdentityRenderError),
                ):
                    renderer.render(self.source | {name: value})
        with self.assertRaises(renderer.NativeHttpIdentityRenderError):
            renderer.render({})
        self.assertEqual(
            self.source, {name: (ROOT / name).read_bytes() for name in renderer.INPUTS}
        )

    def test_http_inventory_deduplicates_worker_and_ingress_without_losing_pins(self):
        reader, verifier = self.identity, self.verifier
        self.assertEqual(len(reader.FILE_PATHS), 41)
        self.assertEqual(len(set(reader.FILE_PATHS)), 41)
        self.assertEqual(set(reader.FILE_PATHS), set(verifier.FILE_PATHS))
        self.assertEqual(reader.MEASUREMENT_SOURCES, verifier.MEASUREMENT_SOURCES)
        self.assertEqual(len(reader.MEASUREMENT_SOURCES), 21)
        self.assertEqual(set(reader.MEASUREMENT_SOURCES), reader.measurement._SOURCES)
        self.assertEqual(reader.SCHEMA, verifier.IDENTITY_SCHEMA)
        self.assertNotIn("http-fixture", reader.CREDENTIALS["broker"])

    def test_credential_custody_and_measurement_bound_remain_path_specific(self):
        reader = self.identity
        fixture = reader._file_arguments(reader.HTTP_FIXTURE_BINDING, ACCOUNTS)
        self.assertEqual(
            fixture,
            {
                "owner": 0,
                "owner_gid": 997,
                "modes": {0o440},
                "limit": 4096,
                "require_read_only": False,
            },
        )
        self.assertEqual(
            reader._file_arguments(reader.MEASUREMENT_BINDING, ACCOUNTS)["limit"], 8192
        )
        self.assertEqual(
            reader._file_arguments(reader.MEASUREMENT_BINDING, ACCOUNTS)["modes"],
            {0o400},
        )
        self.assertEqual(
            reader._file_arguments(reader.ACTIVATOR, ACCOUNTS)["modes"], {0o755}
        )

    def test_fresh_http_documents_join_21_source_pins_and_fixed_action(self):
        reader = self.identity
        raw = _documents(reader)
        result = reader._joins(raw, BOOT, CONTAINER, ACCOUNTS)
        self.assertEqual(len(result["measurement_source_pins"]), 21)
        self.assertEqual(result["http_attempt_id"], "p3-lab-a001")
        self.assertEqual(
            result["http_fixture_binding"]["fixture"]["container_id"], CONTAINER
        )
        self.assertLessEqual(len(raw[reader.MEASUREMENT_BINDING]), 8192)

    def test_http_fixture_config_action_and_selected_source_mismatches_refuse(self):
        reader = self.identity
        original = _documents(reader)
        mutations = [
            (reader.HTTP_FIXTURE_BINDING, lambda x: x.update(expected_broker_gid=994)),
            (
                reader.HTTP_FIXTURE_BINDING,
                lambda x: x["fixture"].update(container_id="e" * 64),
            ),
            (
                reader.HTTP_FIXTURE_BINDING,
                lambda x: x["fixture"].update(
                    boot_id="99999999-1111-2222-3333-444444444444"
                ),
            ),
            (
                reader.prior._CONFIG,
                lambda x: x["tools"]["alsoAllow"].remove("aragorn_runtime_http_canary"),
            ),
            (reader.MEASUREMENT_BINDING, lambda x: x.update(path_digest=PIN)),
            (reader.MEASUREMENT_BINDING, lambda x: x.update(payload_digest=PIN)),
            (
                reader.MEASUREMENT_BINDING,
                lambda x: x["source_pins"].pop("runtime_http_action.py"),
            ),
        ]
        for path, mutate in mutations:
            raw = dict(original)
            value = json.loads(raw[path])
            mutate(value)
            raw[path] = canonical_json(value)
            with self.subTest(path=path), self.assertRaises(ValueError):
                reader._joins(raw, BOOT, CONTAINER, ACCOUNTS)

    def test_actual_reader_flow_reads_http_views_twice_without_loading_claims(self):
        reader = self.identity
        result, reads, closed, _ = _inert_read(reader, _documents(reader))
        self.assertEqual(len(result["files"]), 41)
        self.assertEqual(
            set(result["http_fixture_views"]), {"worker", "sensor", "broker"}
        )
        self.assertTrue(all(result[key] is False for key in reader._FALSE))
        for role in ("observer", "worker", "sensor", "broker"):
            rows = [
                row for row in reads if row[:2] == (role, reader.HTTP_FIXTURE_BINDING)
            ]
            self.assertEqual([row[2] for row in rows], [1, 2])
            self.assertTrue(
                all(
                    row[3]["modes"] == {0o440} and row[3]["owner_gid"] == 997
                    for row in rows
                )
            )
        self.assertEqual(len(closed), 9)
        self.assertEqual(
            reader.compare_native_common_identity(result, deepcopy(result))["status"],
            "CALLER_COMMON_MEASUREMENTS_EQUAL",
        )

    def test_http_process_view_changed_bytes_or_reread_refuse(self):
        for role, number in (
            ("worker", 1),
            ("sensor", 2),
            ("broker", 1),
            ("observer", 2),
        ):
            reader, _, _, _ = _subjects()
            with self.subTest(role=role, number=number), self.assertRaises(ValueError):
                _inert_read(
                    reader,
                    _documents(reader),
                    change=lambda key, count, raw: (
                        raw + b" "
                        if key == (role, reader.HTTP_FIXTURE_BINDING)
                        and count == number
                        else raw
                    ),
                )
