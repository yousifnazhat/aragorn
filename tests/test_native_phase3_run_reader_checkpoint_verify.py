"""Independent contract fixtures only; no acquisition, vendor parser or filesystem."""
import copy
import hashlib
import json
import stat
import unittest

from aragorn.native_phase3_run_reader_checkpoint_verify import verify_reader_checkpoint


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def pin(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class CheckpointFixture:
    """Author raw records directly from the published schemas, with external pins."""

    def __init__(self, batch=b'{"process_exec":{}}\n', refresh=False):
        self.base = 1000000000
        base = self.base
        self.batch = batch
        reader = {"pid": 71, "start_time_ticks": 901, "uid": 1007, "gid": 1008}
        observer = {"pid": 31, "start_time_ticks": 801, "uid": 0, "gid": 0}
        clock = {"boot_id": "00000000-1111-2222-3333-444444444444", "clock_id": "CLOCK_BOOTTIME",
                 "time_namespace": {"device": 4, "inode": 9000}}
        self.provision = {
            "schema": "aragorn/native-phase3-reader-checkpoint-provision/v1",
            "epoch_digest": pin(b"epoch"), "session_id": "7" * 64,
            "reader": reader, "observer": observer, "clock": clock,
            "stream_digest": pin(b"stream"), "source_inventory_digest": pin(b"source inventory"),
            "access_inventory_digest": pin(b"access inventory"), "session_deadline_ns": base + 100000,
            "directories": [],
        }
        paths = ("/", "/var", "/var/lib", "/var/lib/aragorn-phase3-reader-events",
                 "/var/lib/aragorn-phase3-reader-checkpoints")
        for index, path in enumerate(paths):
            self.provision["directories"].append({
                "path": path, "device": 5, "inode": index + 1,
                "mode": stat.S_IFDIR | (0o755 if index < 3 else 0o700),
                "uid": reader["uid"] if index == 3 else 0,
                "gid": reader["gid"] if index == 3 else (20 if index < 3 else 0),
            })
        self.expectation = {
            "schema": "aragorn/native-phase3-reader-checkpoint-expectation/v1",
            "provision_digest": None, "phase": "REFRESH" if refresh else "CHALLENGE",
            "epoch_digest": self.provision["epoch_digest"], "request_digest": pin(b"request"),
            "challenge_digest": pin(b"challenge"), "trigger_digest": pin(b"refresh" if refresh else b"challenge"),
            "trigger_issued_ns": base + 10, "trigger_deadline_ns": base + 1000,
            "deadline_ns": base + 10000, "previous_checkpoint_digest": pin(b"previous") if refresh else None,
            "sequence_before": 1 if refresh else 0, "sequence_after": 2 if refresh else 1,
            "offset_before": 10 if refresh else 0, "records_before": 1 if refresh else 0,
            "reader_evidence_digest": pin(b"original reader evidence"),
            "reader_summary_digest": pin(b"original reader summary"), "reader_connection_epoch": "8" * 64,
            "reader_ack_ns": base if refresh else base + 100, "loss_scope_digest": pin(b"loss scope"),
        }
        self.manifest = {
            "schema": "aragorn/native-phase3-reader-checkpoint/v1", "provision_digest": None,
            "epoch_digest": self.provision["epoch_digest"], "session_id": self.provision["session_id"],
            "stream_digest": self.provision["stream_digest"], "clock": copy.deepcopy(clock),
            "trigger_received_ns": base + 20, "drain_finished_ns": base + 40,
            "raw_publish_started_ns": base + 50, "raw_readback_finished_ns": base + 60,
            "manifest_prepared_ns": base + 70, "loss_evidence_digest": None, "upstream_loss_state": "UNKNOWN",
        }
        for key in ("phase", "request_digest", "challenge_digest", "trigger_digest", "previous_checkpoint_digest",
                    "sequence_before", "sequence_after", "offset_before", "records_before", "loss_scope_digest"):
            self.manifest[key] = self.expectation[key]
        self.set_batch(batch)
        self.publication = {
            "schema": "aragorn/native-phase3-reader-checkpoint-publication/v1",
            "manifest_digest": None, "raw_digest": None, "sequence_after": self.expectation["sequence_after"],
            "manifest_publish_started_ns": base + 80, "manifest_readback_finished_ns": base + 90,
            "receipt_prepared_ns": base + 95,
        }
        self.acquisition = {
            "schema": "aragorn/native-phase3-reader-checkpoint-acquisition/v1",
            "provision_digest": None, "expectation_digest": None, "phase": self.expectation["phase"],
            "trigger_digest": self.expectation["trigger_digest"], "manifest_digest": None,
            "publication_digest": None, "batch_digest": None,
            "started_ns": base + 110, "source_readback_finished_ns": base + 120,
            "retention_started_ns": base + 130, "retention_finished_ns": base + 140,
            "observer": copy.deepcopy(observer), "clock": copy.deepcopy(clock),
            "acquisition_authenticity_verified": False, "sensor_health_verified": False,
            "effect_authorized": False, "run_qualified": False, "phase3_qualified": False,
        }

    def set_batch(self, batch):
        self.batch = batch
        count = batch.count(b"\n")
        self.manifest.update(raw_digest=pin(batch), raw_bytes=len(batch), raw_records=count,
                             offset_after=self.manifest["offset_before"] + len(batch),
                             records_after=self.manifest["records_before"] + count)
        reads, offset, index = [], self.manifest["offset_before"], 0
        for start in range(0, len(batch), 65536):
            size = min(65536, len(batch) - start)
            reads.append({"started_ns": self.base + index * 2 + 1, "finished_ns": self.base + index * 2 + 2,
                          "offset": offset, "bytes": size, "outcome": "DATA"})
            offset += size
            index += 1
        reads.append({"started_ns": self.base + 30, "finished_ns": self.base + 31,
                      "offset": offset, "bytes": 0, "outcome": "EAGAIN"})
        self.manifest["reads"] = reads

    def prior(self, offset, records, sequence=4):
        for document in (self.expectation, self.manifest):
            document.update(sequence_before=sequence, sequence_after=sequence + 1,
                            previous_checkpoint_digest=pin(b"prior checkpoint"),
                            offset_before=offset, records_before=records)
        self.publication["sequence_after"] = sequence + 1
        self.set_batch(self.batch)

    def bundle(self, raw_overrides=None):
        raw_overrides = raw_overrides or {}
        provision = copy.deepcopy(self.provision)
        provision_raw = raw_overrides.get("provision_raw", encode(provision))
        expectation = copy.deepcopy(self.expectation)
        expectation["provision_digest"] = pin(provision_raw)
        expectation_raw = raw_overrides.get("expectation_raw", encode(expectation))
        manifest = copy.deepcopy(self.manifest)
        manifest["provision_digest"] = pin(provision_raw)
        manifest_raw = raw_overrides.get("manifest_raw", encode(manifest))
        publication = copy.deepcopy(self.publication)
        publication.update(manifest_digest=pin(manifest_raw), raw_digest=pin(self.batch))
        publication_raw = raw_overrides.get("publication_raw", encode(publication))
        acquisition = copy.deepcopy(self.acquisition)
        acquisition.update(provision_digest=pin(provision_raw), expectation_digest=pin(expectation_raw),
                           manifest_digest=pin(manifest_raw), publication_digest=pin(publication_raw),
                           batch_digest=pin(self.batch))
        acquisition["source_files"], acquisition["retained_files"] = [], []
        artifacts = (("BATCH", self.batch), ("MANIFEST", manifest_raw), ("PUBLICATION", publication_raw))
        for index, (role, raw) in enumerate(artifacts):
            for key, owner, inode in (("source_files", provision["reader"], 101 + index),
                                      ("retained_files", provision["observer"], 201 + index)):
                acquisition[key].append({
                    "role": role, "device": 5, "inode": inode, "mode": stat.S_IFREG | 0o400,
                    "uid": owner["uid"], "gid": owner["gid"], "nlink": 1, "bytes": len(raw),
                    "mtime_ns": self.base - 1, "ctime_ns": self.base - 1, "digest": pin(raw),
                })
        acquisition_raw = raw_overrides.get("acquisition_raw", encode(acquisition))
        return {
            "manifest_raw": manifest_raw, "publication_raw": publication_raw,
            "batch_raw": self.batch, "acquisition_raw": acquisition_raw,
            "provision_raw": provision_raw, "expectation_raw": expectation_raw,
            "expected_provision_digest": pin(provision_raw), "expected_expectation_digest": pin(expectation_raw),
            "expected_acquisition_digest": pin(acquisition_raw),
        }


class ReaderCheckpointVerifyTests(unittest.TestCase):
    def reject(self, args):
        with self.assertRaises(ValueError):
            verify_reader_checkpoint(**args)

    def altered(self, case, role, change):
        name = role + "_raw"
        value = json.loads(case.bundle()[name])
        change(value)
        return case.bundle({name: encode(value)})

    def test_challenge_reconstructs_exact_output_without_authority(self):
        args = CheckpointFixture().bundle()
        result = verify_reader_checkpoint(**args)
        self.assertEqual(result, {
            "status": "CONSISTENT_CHECKPOINT_READBACK", "acquisition_digest": args["expected_acquisition_digest"],
            "manifest_digest": pin(args["manifest_raw"]), "trigger_digest": pin(b"challenge"),
            "sequence_after": 1, "offset_after": len(args["batch_raw"]), "records_after": 1,
            "stream_continuity": "UNKNOWN", "loss_completeness": "UNKNOWN",
            "acquisition_authenticity_verified": False, "sensor_health_verified": False,
            "effect_authorized": False, "run_qualified": False, "phase3_qualified": False,
        })

    def test_empty_initial_and_later_checkpoint_preserve_offsets(self):
        for prior in (False, True):
            with self.subTest(prior=prior):
                case = CheckpointFixture(b"")
                if prior:
                    case.prior(100, 3)
                result = verify_reader_checkpoint(**case.bundle())
                self.assertEqual(result["offset_after"], 100 if prior else 0)
                self.assertEqual(result["records_after"], 3 if prior else 0)
                self.assertEqual(result["sequence_after"], 5 if prior else 1)

    def test_refresh_preserves_original_ack_and_admits_later_publication(self):
        case = CheckpointFixture(refresh=True)
        self.assertLess(case.expectation["reader_ack_ns"], case.publication["receipt_prepared_ns"])
        result = verify_reader_checkpoint(**case.bundle())
        self.assertEqual(result["trigger_digest"], pin(b"refresh"))
        self.assertEqual(result["sequence_after"], 2)

    def test_raw_framing_does_not_claim_vendor_json_or_utf8_semantics(self):
        for batch in (b"not a vendor event\n", b"\xff\n", b"{ malformed }\n", b"\x00\n"):
            with self.subTest(batch=batch):
                result = verify_reader_checkpoint(**CheckpointFixture(batch).bundle())
                self.assertEqual(result["records_after"], 1)
                self.assertIs(result["sensor_health_verified"], False)

    def test_inclusive_record_batch_and_session_bounds(self):
        for batch in (b"x" * 65535 + b"\n", (b"x" * 65535 + b"\n") * 4, b"x\n" * 256):
            with self.subTest(bytes=len(batch)):
                case = CheckpointFixture(batch)
                case.prior(4194304 - len(batch), 4096 - batch.count(b"\n"))
                result = verify_reader_checkpoint(**case.bundle())
                self.assertEqual(result["offset_after"], 4194304)
                self.assertEqual(result["records_after"], 4096)

    def test_external_pins_cannot_be_satisfied_by_candidate_self_claims(self):
        for key in ("expected_provision_digest", "expected_expectation_digest", "expected_acquisition_digest"):
            for replacement in (None, True, "sha256:" + "A" * 64, pin(b"unrelated")):
                with self.subTest(key=key, replacement=replacement):
                    args = CheckpointFixture().bundle()
                    args[key] = replacement
                    self.reject(args)

    def test_raw_types_and_bounds_precede_json_parsing(self):
        bounds = {"provision_raw": 8192, "expectation_raw": 8192, "manifest_raw": 16384,
                  "publication_raw": 2048, "acquisition_raw": 16384, "batch_raw": 262144}
        for key, bound in bounds.items():
            values = ["{}", bytearray(b"{}"), None, b"x" * (bound + 1)]
            if key != "batch_raw":
                values.append(b"")
            for value in values:
                with self.subTest(key=key, kind=type(value), size=len(value) if value is not None else None):
                    args = CheckpointFixture().bundle()
                    args[key] = value
                    self.reject(args)

    def test_canonical_ascii_duplicate_nonfinite_and_trailing_rejection(self):
        case = CheckpointFixture()
        for name in ("provision_raw", "expectation_raw", "manifest_raw", "publication_raw", "acquisition_raw"):
            raw = case.bundle()[name]
            bad = (raw + b"\n", b" " + raw, b'{"schema":"duplicate",' + raw[1:],
                   b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'[]', b'null', b'{"x":"\xff"}')
            for candidate in bad:
                with self.subTest(name=name, candidate=candidate[:40]):
                    self.reject(case.bundle({name: candidate}))

    def test_all_record_inventories_and_schema_labels_are_exact(self):
        case = CheckpointFixture()
        for role in ("provision", "expectation", "manifest", "publication", "acquisition"):
            for change in (lambda value: value.update(extra=False), lambda value: value.pop("schema"),
                           lambda value: value.update(schema="aragorn/unrelated/v1")):
                with self.subTest(role=role, change=change):
                    self.reject(self.altered(case, role, change))

    def test_protected_role_identity_scalars_and_account_separation(self):
        for role, key, bad in (("reader", "uid", 0), ("reader", "gid", 0), ("observer", "uid", 1),
                               ("observer", "gid", 1), ("reader", "pid", 31), ("reader", "pid", True),
                               ("observer", "start_time_ticks", 0), ("reader", "uid", 2**32),
                               ("reader", "pid", 2**31), ("reader", "start_time_ticks", 2**63)):
            with self.subTest(role=role, key=key, bad=bad):
                case = CheckpointFixture()
                case.provision[role][key] = bad
                self.reject(case.bundle())

    def test_fixed_directory_inventory_type_ownership_and_permissions(self):
        for index, key, bad in ((0, "path", "/tmp"), (1, "uid", 1), (2, "mode", stat.S_IFDIR | 0o775),
                                (3, "mode", stat.S_IFDIR | 0o750), (3, "uid", 0), (3, "gid", 0),
                                (4, "uid", 1007), (4, "gid", 20), (4, "mode", stat.S_IFREG | 0o700),
                                (0, "inode", 0), (0, "device", True)):
            with self.subTest(index=index, key=key, bad=bad):
                case = CheckpointFixture()
                case.provision["directories"][index][key] = bad
                self.reject(case.bundle())
        case = CheckpointFixture()
        case.provision["directories"].reverse()
        self.reject(case.bundle())
        case.provision["directories"].pop()
        self.reject(case.bundle())

    def test_clock_schema_namespace_boot_and_domain(self):
        for role in ("provision", "manifest", "acquisition"):
            for change in (lambda clock: clock.update(clock_id="CLOCK_MONOTONIC"),
                           lambda clock: clock.update(boot_id="00000000-AAAA-2222-3333-444444444444"),
                           lambda clock: clock["time_namespace"].update(inode=0),
                           lambda clock: clock["time_namespace"].update(device=False),
                           lambda clock: clock["time_namespace"].update(extra=1)):
                with self.subTest(role=role, change=change):
                    self.reject(self.altered(CheckpointFixture(), role, lambda value: change(value["clock"])))
        for role in ("manifest", "acquisition"):
            self.reject(self.altered(CheckpointFixture(), role,
                                    lambda value: value["clock"]["time_namespace"].update(inode=9001)))

    def test_expectation_initial_sequence_prior_and_refresh_requirements(self):
        for key, bad in (("sequence_before", True), ("sequence_after", 2), ("previous_checkpoint_digest", pin(b"x")),
                         ("offset_before", 1), ("records_before", 1), ("phase", "LATER"),
                         ("trigger_digest", pin(b"different trigger")), ("epoch_digest", pin(b"other epoch")),
                         ("reader_connection_epoch", "g" * 64), ("reader_evidence_digest", None)):
            with self.subTest(key=key, bad=bad):
                case = CheckpointFixture()
                case.expectation[key] = bad
                self.reject(case.bundle())
        case = CheckpointFixture(refresh=True)
        case.expectation.update(sequence_before=0, sequence_after=1, previous_checkpoint_digest=None,
                                offset_before=0, records_before=0)
        self.reject(case.bundle())
        case = CheckpointFixture(refresh=True)
        case.expectation["previous_checkpoint_digest"] = None
        self.reject(case.bundle())
        case = CheckpointFixture(refresh=True)
        case.expectation.update(sequence_before=2**63 - 1, sequence_after=2**63)
        self.reject(case.bundle())

    def test_expectation_original_deadline_and_ack_order(self):
        for refresh, key, delta in ((False, "reader_ack_ns", 9), (False, "reader_ack_ns", 1000),
                                    (False, "trigger_issued_ns", 1000), (False, "deadline_ns", 999),
                                    (False, "deadline_ns", 100001), (True, "reader_ack_ns", 11),
                                    (True, "deadline_ns", 200000001)):
            with self.subTest(refresh=refresh, key=key, delta=delta):
                case = CheckpointFixture(refresh=refresh)
                if refresh and delta > 100000:
                    case.provision["session_deadline_ns"] = case.base + delta
                case.expectation[key] = case.base + delta
                self.reject(case.bundle())

    def test_raw_record_framing_and_batch_counts(self):
        for raw in (b"\n", b"a\n\n", b"a\r\n", b"unterminated", b"a\ntail", b"x" * 65536 + b"\n",
                    b"x\n" * 257, b"x" * 262144 + b"\n"):
            with self.subTest(prefix=raw[:20], size=len(raw)):
                self.reject(CheckpointFixture(raw).bundle())
        for key, bad in (("raw_digest", pin(b"different bytes")), ("raw_bytes", 0), ("raw_records", 0)):
            case = CheckpointFixture()
            case.manifest[key] = bad
            self.reject(case.bundle())

    def test_manifest_expected_joins_and_unknown_loss_ceiling(self):
        replacements = {"epoch_digest": pin(b"epoch2"), "session_id": "1" * 64,
                        "stream_digest": pin(b"stream2"), "phase": "REFRESH", "request_digest": pin(b"request2"),
                        "challenge_digest": pin(b"challenge2"), "trigger_digest": pin(b"trigger2"),
                        "previous_checkpoint_digest": pin(b"prior2"), "loss_scope_digest": pin(b"scope2"),
                        "loss_evidence_digest": pin(b"untrusted zero loss"), "upstream_loss_state": "COMPLETE"}
        for key, bad in replacements.items():
            with self.subTest(key=key):
                case = CheckpointFixture()
                case.manifest[key] = bad
                self.reject(case.bundle())

    def test_contiguous_offsets_record_counts_and_cumulative_bounds(self):
        for key, bad in (("offset_before", 1), ("offset_after", 0), ("records_before", 1),
                         ("records_after", 2), ("sequence_after", True), ("raw_bytes", True),
                         ("offset_after", 4194305), ("records_after", 4097)):
            with self.subTest(key=key):
                case = CheckpointFixture()
                case.manifest[key] = bad
                self.reject(case.bundle())
        for offset, records in ((4194304, 0), (0, 4096)):
            case = CheckpointFixture()
            case.prior(offset, records)
            self.reject(case.bundle())

    def test_read_entry_shape_serialization_and_exact_byte_accounting(self):
        changes = (lambda reads: reads.clear(), lambda reads: reads.extend(copy.deepcopy(reads) * 32),
                   lambda reads: reads[0].update(extra=True), lambda reads: reads[0].pop("offset"),
                   lambda reads: reads[0].update(started_ns=reads[0]["finished_ns"] + 1),
                   lambda reads: reads[1].update(started_ns=reads[0]["finished_ns"] - 1),
                   lambda reads: reads[0].update(offset=1), lambda reads: reads[1].update(offset=0),
                   lambda reads: reads[0].update(bytes=0), lambda reads: reads[0].update(bytes=True),
                   lambda reads: reads[0].update(bytes=65537), lambda reads: reads[0].update(outcome="EOF"),
                   lambda reads: reads[1].update(bytes=1), lambda reads: reads[1].update(outcome="POLL_READY"))
        for change in changes:
            with self.subTest(change=change):
                case = CheckpointFixture()
                change(case.manifest["reads"])
                self.reject(case.bundle())

    def test_sixty_four_serial_reads_fit_the_exact_inventory_bound(self):
        case = CheckpointFixture(b"x" * 62 + b"\n")
        base = case.base
        case.manifest["reads"] = [
            {"started_ns": base + index * 2 + 1, "finished_ns": base + index * 2 + 2,
             "offset": index, "bytes": 1, "outcome": "DATA"} for index in range(63)]
        case.manifest["reads"].append({"started_ns": base + 210, "finished_ns": base + 211,
                                       "offset": 63, "bytes": 0, "outcome": "EAGAIN"})
        case.manifest.update(trigger_received_ns=base + 200, drain_finished_ns=base + 220,
                             raw_publish_started_ns=base + 230, raw_readback_finished_ns=base + 240,
                             manifest_prepared_ns=base + 250)
        case.publication.update(manifest_publish_started_ns=base + 260,
                                manifest_readback_finished_ns=base + 270, receipt_prepared_ns=base + 280)
        case.expectation["reader_ack_ns"] = base + 300
        case.acquisition.update(started_ns=base + 310, source_readback_finished_ns=base + 320,
                                retention_started_ns=base + 330, retention_finished_ns=base + 340)
        result = verify_reader_checkpoint(**case.bundle())
        self.assertEqual(result["offset_after"], 63)

    def test_refresh_original_ack_plus_age_must_fit_uint(self):
        for ack, accepted in ((2**63 - 1 - 200000000, True), (2**63 - 200000000, False)):
            case = CheckpointFixture(refresh=True)
            shift = ack - case.base
            case.provision["session_deadline_ns"] += shift
            for document in (case.expectation, case.manifest, case.publication, case.acquisition):
                for key in document:
                    if key.endswith("_ns"):
                        document[key] += shift
            for entry in case.manifest["reads"]:
                entry["started_ns"] += shift
                entry["finished_ns"] += shift
            if accepted:
                verify_reader_checkpoint(**case.bundle())
            else:
                self.reject(case.bundle())

    def test_actual_post_trigger_eagain_is_required_for_idle_and_buffered_data(self):
        for batch in (b"", b"event\n"):
            case = CheckpointFixture(batch)
            case.manifest["reads"][-1].update(started_ns=case.base + 19, finished_ns=case.base + 19)
            self.reject(case.bundle())
        case = CheckpointFixture()
        case.manifest["reads"].pop()
        self.reject(case.bundle())
        case = CheckpointFixture(b"")
        case.manifest["reads"][-1]["outcome"] = "EOF"
        self.reject(case.bundle())

    def test_manifest_and_publication_timestamps_cannot_move_backwards(self):
        for key, delta in (("trigger_received_ns", 9), ("drain_finished_ns", 30),
                           ("raw_publish_started_ns", 39), ("raw_readback_finished_ns", 49),
                           ("manifest_prepared_ns", 59), ("manifest_prepared_ns", 1000)):
            case = CheckpointFixture()
            case.manifest[key] = case.base + delta
            self.reject(case.bundle())
        for key, delta in (("manifest_publish_started_ns", 69), ("manifest_readback_finished_ns", 79),
                           ("receipt_prepared_ns", 89), ("receipt_prepared_ns", 1000),
                           ("receipt_prepared_ns", 101)):
            case = CheckpointFixture()
            case.publication[key] = case.base + delta
            self.reject(case.bundle())

    def test_publication_pins_sequence_and_self_publication_fields(self):
        case = CheckpointFixture()
        for key, bad in (("manifest_digest", pin(b"different manifest")), ("raw_digest", pin(b"different raw")),
                         ("sequence_after", True), ("sequence_after", 2), ("receipt_readback_finished_ns", 1)):
            self.reject(self.altered(case, "publication", lambda value: value.update({key: bad})))
        case.manifest["manifest_readback_finished_ns"] = case.base + 90
        self.reject(case.bundle())

    def test_acquisition_cannot_precede_ack_trigger_or_receipt(self):
        for refresh, changes in ((False, {"started_ns": 99}), (True, {"started_ns": 9}),
                                 (True, {"started_ns": 50, "source_readback_finished_ns": 94}),
                                 (False, {"source_readback_finished_ns": 109}),
                                 (False, {"retention_started_ns": 119}),
                                 (False, {"retention_finished_ns": 129}),
                                 (False, {"retention_finished_ns": 10000})):
            with self.subTest(refresh=refresh, changes=changes):
                case = CheckpointFixture(refresh=refresh)
                case.acquisition.update({key: case.base + delta for key, delta in changes.items()})
                self.reject(case.bundle())

    def test_original_ack_max_age_is_strict_even_with_later_outer_budget(self):
        for age, accepted in ((199999999, True), (200000000, False)):
            case = CheckpointFixture()
            ack = case.expectation["reader_ack_ns"]
            case.provision["session_deadline_ns"] = ack + 300000000
            case.expectation["deadline_ns"] = ack + 250000000
            case.acquisition["retention_finished_ns"] = ack + age
            if accepted:
                verify_reader_checkpoint(**case.bundle())
            else:
                self.reject(case.bundle())

    def test_acquisition_context_artifact_and_observer_joins(self):
        case = CheckpointFixture()
        for key, bad in (("provision_digest", pin(b"other provision")), ("expectation_digest", pin(b"other expectation")),
                         ("phase", "REFRESH"), ("trigger_digest", pin(b"other trigger")),
                         ("manifest_digest", pin(b"other manifest")), ("publication_digest", pin(b"other receipt")),
                         ("batch_digest", pin(b"other batch"))):
            self.reject(self.altered(case, "acquisition", lambda value: value.update({key: bad})))
        for key, bad in (("pid", 32), ("start_time_ticks", 802), ("uid", False), ("gid", 1)):
            self.reject(self.altered(case, "acquisition", lambda value: value["observer"].update({key: bad})))

    def test_file_inventories_order_exact_metadata_and_no_alias(self):
        case = CheckpointFixture()
        for section in ("source_files", "retained_files"):
            for change in (lambda files: files.pop(), lambda files: files.reverse(),
                           lambda files: files[0].update(extra=1), lambda files: files[0].pop("mtime_ns"),
                           lambda files: files[0].update(inode=files[1]["inode"])):
                self.reject(self.altered(case, "acquisition", lambda value: change(value[section])))
        self.reject(self.altered(case, "acquisition", lambda value:
                                 value["retained_files"][0].update(inode=value["source_files"][0]["inode"])))

    def test_file_metadata_cannot_forge_raw_pins_or_owner_mode_links(self):
        case = CheckpointFixture()
        for section in ("source_files", "retained_files"):
            owner = 0 if section == "source_files" else 1007
            for key, bad in (("device", True), ("inode", 0), ("mode", stat.S_IFREG | 0o600),
                             ("mode", stat.S_IFIFO | 0o400), ("uid", owner), ("gid", 99),
                             ("nlink", 2), ("nlink", True), ("bytes", 0), ("mtime_ns", -1),
                             ("ctime_ns", 2**63), ("digest", pin(b"substitution"))):
                with self.subTest(section=section, key=key, bad=bad):
                    self.reject(self.altered(case, "acquisition", lambda value:
                                             value[section][0].update({key: bad})))

    def test_all_authority_flags_require_literal_false(self):
        for flag in ("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized",
                     "run_qualified", "phase3_qualified"):
            for bad in (True, 0, None, "false"):
                with self.subTest(flag=flag, bad=bad):
                    case = CheckpointFixture()
                    case.acquisition[flag] = bad
                    self.reject(case.bundle())

    def test_uint_fields_reject_booleans_negative_floats_and_overflow(self):
        fields = {"provision": ("session_deadline_ns",),
                  "expectation": ("trigger_issued_ns", "trigger_deadline_ns", "deadline_ns", "reader_ack_ns"),
                  "manifest": ("trigger_received_ns", "drain_finished_ns", "raw_publish_started_ns",
                               "raw_readback_finished_ns", "manifest_prepared_ns", "raw_records"),
                  "publication": ("manifest_publish_started_ns", "manifest_readback_finished_ns", "receipt_prepared_ns"),
                  "acquisition": ("started_ns", "source_readback_finished_ns", "retention_started_ns", "retention_finished_ns")}
        for role, keys in fields.items():
            for key in keys:
                for bad in (True, -1, 1.0, 2**63):
                    with self.subTest(role=role, key=key, bad=bad):
                        self.reject(self.altered(CheckpointFixture(), role, lambda value: value.update({key: bad})))

    def test_inputs_are_unchanged_and_output_has_no_paths_or_health_shortcuts(self):
        args = CheckpointFixture().bundle()
        before = copy.deepcopy(args)
        result = verify_reader_checkpoint(**args)
        self.assertEqual(args, before)
        self.assertEqual(len(result), 14)
        self.assertNotIn("NOT_SUBMITTED", result.values())
        self.assertFalse(any("path" in key or "complete" == value for key, value in result.items()))


if __name__ == "__main__":
    unittest.main()
