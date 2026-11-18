"""Offline contract checks; no captured deployment, delivered bytes, or qualification."""
import copy
import unittest

from aragorn import pi_core_installed_inventory_entry as installed
from aragorn import pi_core_provider_observation as provider
from aragorn import pi_core_restricted_profile as fixed
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_installed_inventory_entry as entry_fixture
from tests import test_pi_core_provider_observation as capture_fixture


def repack(docs):
    for name in ("source_inventory", "loader_inventory"):
        docs["profile"]["pins"][name + "_digest"] = canonical_digest(docs[name])
    docs["preparation"].update({key + "_digest": canonical_digest(docs[key])
        for key in ("source_inventory", "loader_inventory", "profile")})
    return installed.inventory.PreparedPiSourceInventories(
        *(canonical_json(docs[key]) for key in installed._ARTIFACTS))


class InstalledConsumer(entry_fixture.InstalledInventoryEntryTests):
    def restricted(self):
        self.source.update(schema=fixed.PLAN_SCHEMA,
            sources=[dict(path=fixed.ENTRY_PATH, digest="sha256:" + fixed.BUNDLE_SHA256)],
            required_sources=[fixed.ENTRY_PATH])
        self.source["pins"].update(gate_digest="sha256:" + fixed.GATE_SHA256, node_digest="sha256:" + fixed.NODE_SHA256)
        self.plan["source_plan"]["digest"] = canonical_digest(self.source)
        prepared = entry_fixture.prepared_artifacts(self.plan, self.source)
        docs = {key: installed.inventory._document(getattr(prepared, key + "_raw")) for key in installed._ARTIFACTS}
        docs["profile"]["schema"] = fixed.PROFILE_SCHEMA
        return docs

    def test_authenticated_successor_and_custody_without_launch(self):
        docs = self.restricted()
        self.prepare.return_value = repack(docs)
        result = self.invoke()
        self.assertEqual(result["artifacts"], docs)
        self.assertTrue(result["owned_views_closed"] and result["owned_inputs_closed"])
        self.assertFalse(result["phase3_exit_eligible"] or result["managed_call_attempted"])
        self.prepare.assert_called_once()

    def test_successor_plan_cannot_return_resealed_predecessor(self):
        docs = self.restricted()
        docs["profile"]["schema"] = installed.inventory.node.PROFILE_SCHEMA
        self.prepare.return_value = repack(docs)
        self.refuse()

    def test_predecessor_plan_cannot_return_resealed_successor(self):
        docs = self.restricted()
        self.plan, self.source = entry_fixture.prepared_inputs()
        docs["preparation"]["expected_manifest_digest"] = canonical_digest(self.source)
        self.prepare.return_value = repack(docs)
        self.refuse()

    def test_self_consistently_resealed_artifacts_cannot_change_input(self):
        base = self.restricted()
        for what in ("measured", "declared", "observer", "writable"):
            docs = copy.deepcopy(base)
            if what == "measured":
                docs["source_inventory"]["sources"][0]["digest"] = entry_fixture.pin("7")
            elif what == "declared":
                docs["profile"]["loader_files"][0]["path"] = "/lib/different-loader"
                docs["loader_inventory"]["loaders"][0]["path"] = "/lib/different-loader"
            elif what == "observer":
                docs["profile"]["pins"]["producer_digest"] = entry_fixture.pin("7")
            else:
                docs["loader_inventory"]["loaders"][0]["readonly_view"] = False
            self.prepare.return_value = repack(docs)
            with self.subTest(what=what):
                self.refuse()


def event_of(source, kind):
    return next(event for event in source["events"] if event["kind"] == kind)


def refresh_sources(source):
    source["bindings"]["source_inventory_digest"] = canonical_digest(
        dict(schema=installed.inventory.node.SOURCE_SCHEMA, sources=source["sources"]))


class HeldConsumer(capture_fixture.SourceBoundaryTests):
    def restricted(self):
        # Adapt the existing inert syscall transcript to the fixed release metadata.
        # No actual executable, file read, credential, or observation is used.
        record = self.source
        bundle = next(row for row in fixed.expected_files() if row["path"] == "pi-core/entrypoint.js")
        size = bundle["size"]
        record["bindings"].update(gate_digest="sha256:" + fixed.GATE_SHA256,
            node_digest="sha256:" + fixed.NODE_SHA256, runtime_digest=fixed.RUNTIME_DIGEST)
        self.values["activation"].update(executable_digest=record["bindings"]["node_digest"],
                                        runtime_digest=fixed.RUNTIME_DIGEST)
        record["required_sources"] = [fixed.ENTRY_PATH]
        row = record["sources"][0]
        row.update(path=fixed.ENTRY_PATH, digest=bundle["digest"])
        row["identity"]["size"] = size
        refresh_sources(record)
        enter, exit_event = event_of(record, "READ_ENTER"), event_of(record, "READ_EXIT")
        enter.update(path=row["path"], digest=row["digest"], identity=copy.deepcopy(row["identity"]), count=size)
        exit_event.update(identity=copy.deepcopy(row["identity"]), result=size)
        for event in record["events"]:
            if event["kind"] == "STOP" and event["seq"] == enter["call_id"]:
                event["args"][2] = size
            if event["kind"] == "STOP" and event["op"] == "EXIT" and enter["seq"] < event["seq"] < exit_event["seq"]:
                event["result"] = size
        record["accounting"]["bytes_read"] = size
        event_of(record, "EXEC").update(digest=record["bindings"]["node_digest"],
            raw_cmdline_hex=(b"\0".join(arg.encode("ascii") for arg in fixed.NODE_ARGV) + b"\0").hex())
        return record

    def rejects(self, record):
        with self.assertRaises(RuntimeError):
            self.validate(source_capture=record)

    def test_exact_restricted_transcript_returns_only_held_boundary(self):
        self.restricted()
        self.assertEqual(set(self.validate()), {"challenge", "clock", "boundary_boottime_ns"})

    def test_predecessor_transcript_on_authenticated_restricted_runtime_refuses(self):
        self.source["bindings"]["runtime_digest"] = self.values["activation"]["runtime_digest"] = fixed.RUNTIME_DIGEST
        self.rejects(self.source)

    def test_successor_capture_on_another_runtime_refuses(self):
        record = self.restricted()
        record["bindings"]["runtime_digest"] = self.values["activation"]["runtime_digest"] = entry_fixture.pin("7")
        self.rejects(record)

    def test_mixed_gate_node_or_source_pin_refuses(self):
        base = self.restricted()
        for key in ("gate_digest", "node_digest", "source", "inventory", "loader_inventory_digest"):
            record = copy.deepcopy(base)
            activation = copy.deepcopy(self.values["activation"])
            if key == "source":
                record["sources"][0]["digest"] = event_of(record, "READ_ENTER")["digest"] = entry_fixture.pin("7")
                refresh_sources(record)
            elif key == "inventory":
                record["sources"][0]["identity"]["inode"] += 1
            else:
                record["bindings"][key] = entry_fixture.pin("7")
                if key == "node_digest":
                    activation["executable_digest"] = event_of(record, "EXEC")["digest"] = entry_fixture.pin("7")
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.validate(source_capture=record, activation=activation)

    def test_missing_changed_or_extended_argv_refuses(self):
        base = self.restricted()
        for name in ("missing", "wrong-flag", "tail", "extra"):
            record = copy.deepcopy(base)
            event = event_of(record, "EXEC")
            if name == "missing":
                del event["raw_cmdline_hex"]
            elif name == "wrong-flag":
                event["raw_cmdline_hex"] = event["raw_cmdline_hex"].replace(fixed.NODE_ARGV[1].encode().hex(), "")
            elif name == "tail":
                event["raw_cmdline_hex"] = event["raw_cmdline_hex"][:-2]
            else:
                event["raw_cmdline_hex"] += b"another\0".hex()
            with self.subTest(name=name):
                self.rejects(record)

    def test_exec_requires_matching_immediate_kernel_stop_and_generation(self):
        base = self.restricted()
        for field, value in (("event", 128), ("event_message", 17), ("start_ticks", 9), ("status", 127), ("args", [])):
            record = copy.deepcopy(base)
            prior = record["events"][event_of(record, "EXEC")["seq"] - 2]
            self.assertEqual(prior["kind"], "STOP")
            prior[field] = value
            with self.subTest(field=field):
                self.rejects(record)
        record = copy.deepcopy(base)
        next(e for e in record["events"] if e["kind"] == "STOP" and e["syscall"] == 221)["syscall"] = 63
        self.rejects(record)

    def test_entry_must_be_required_and_entire_size_read_with_kernel_pair(self):
        base = self.restricted()
        for change in ("unrequired", "short", "wrong-count", "wrong-call", "wrong-file", "unjoined-result"):
            record = copy.deepcopy(base)
            enter, exit_event = event_of(record, "READ_ENTER"), event_of(record, "READ_EXIT")
            if change == "unrequired":
                record["required_sources"] = []
            elif change == "short":
                exit_event["result"] -= 1
                record["accounting"]["bytes_read"] -= 1
                next(e for e in record["events"] if e["kind"] == "STOP" and e["op"] == "EXIT"
                    and enter["seq"] < e["seq"] < exit_event["seq"])["result"] -= 1
            elif change == "wrong-count":
                record["events"][enter["call_id"] - 1]["args"][2] -= 1
            elif change == "wrong-call":
                enter["call_id"] = exit_event["call_id"] = 1
            elif change == "wrong-file":
                record["sources"][0]["identity"]["size"] += 1
                refresh_sources(record)
            else:
                exit_event["result"] -= 1
            with self.subTest(change=change):
                self.rejects(record)


def load_tests(loader, tests, pattern):
    # Only this assignment's checks; predecessor and unrelated publication suites
    # stay separate and the coordinator retains their successful fingerprints.
    return unittest.TestSuite(cls(name) for cls in (InstalledConsumer, HeldConsumer)
        for name in sorted(cls.__dict__) if name.startswith("test_"))
