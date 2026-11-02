"""Independent checkpoint byte replay; no OS custody or stream-health claim."""
from __future__ import annotations

import hashlib
import json
import re
import stat

_PREFIX = "aragorn/native-phase3-reader-checkpoint"
_UINT_MAX = 2**63 - 1
_BATCH_MAX = 262144
_SESSION_BYTES = 4194304
_SESSION_RECORDS = 4096
_ACK_AGE = 200000000
_FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified",
          "effect_authorized", "run_qualified", "phase3_qualified")
_PATHS = ("/", "/var", "/var/lib", "/var/lib/aragorn-phase3-reader-events",
          "/var/lib/aragorn-phase3-reader-checkpoints")


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _fields(value, fields):
    _require(type(value) is dict and set(value) == set(fields), "FIELD_INVENTORY")


def _uint(value, minimum=0, maximum=_UINT_MAX):
    _require(type(value) is int and minimum <= value <= maximum, "UINT")
    return value


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "PIN")


def _nonce(value):
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "NONCE")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _raw(raw, limit, empty=False):
    _require(type(raw) is bytes and (0 if empty else 1) <= len(raw) <= limit, "RAW_BOUND")


def _parse(raw, limit):
    _raw(raw, limit)
    _require(raw.isascii(), "ASCII_JSON")

    def pairs(items):
        result = {}
        for name, value in items:
            _require(name not in result, "DUPLICATE_KEY")
            result[name] = value
        return result

    def constant(_):
        raise ValueError("NONFINITE")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
        _require(encoded == raw, "NONCANONICAL_JSON")
    except (ValueError, UnicodeError, RecursionError, OverflowError) as error:
        raise ValueError("JSON_REFUSED") from error
    _require(type(value) is dict, "RECORD_OBJECT")
    return value


def _process(value):
    _fields(value, ("pid", "start_time_ticks", "uid", "gid"))
    _uint(value["pid"], 1, 2147483647)
    _uint(value["start_time_ticks"], 1)
    _uint(value["uid"], 0, 4294967295)
    _uint(value["gid"], 0, 4294967295)


def _clock(value):
    _fields(value, ("boot_id", "clock_id", "time_namespace"))
    _require(type(value["boot_id"]) is str and re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]), "BOOT_ID")
    _require(value["clock_id"] == "CLOCK_BOOTTIME", "CLOCK_ID")
    namespace = value["time_namespace"]
    _fields(namespace, ("device", "inode"))
    _uint(namespace["device"])
    _uint(namespace["inode"], 1)


def _provision(raw, expected_digest):
    _pin(expected_digest)
    value = _parse(raw, 8192)
    _require(_digest(raw) == expected_digest, "PROVISION_PIN")
    _fields(value, ("schema", "epoch_digest", "session_id", "reader", "observer", "clock",
                    "stream_digest", "source_inventory_digest", "access_inventory_digest",
                    "directories", "session_deadline_ns"))
    _require(value["schema"] == _PREFIX + "-provision/v1", "PROVISION_SCHEMA")
    for key in ("epoch_digest", "stream_digest", "source_inventory_digest", "access_inventory_digest"):
        _pin(value[key])
    _nonce(value["session_id"])
    _process(value["reader"])
    _process(value["observer"])
    reader, observer = value["reader"], value["observer"]
    _require(reader["uid"] > 0 and reader["gid"] > 0 and observer["uid"] == observer["gid"] == 0
             and reader["pid"] != observer["pid"], "PROCESS_ROLES")
    _clock(value["clock"])
    _uint(value["session_deadline_ns"], 1)
    directories = value["directories"]
    _require(type(directories) is list and len(directories) == 5, "DIRECTORY_COUNT")
    for index, directory in enumerate(directories):
        _fields(directory, ("path", "device", "inode", "mode", "uid", "gid"))
        _require(directory["path"] == _PATHS[index], "DIRECTORY_PATH")
        _uint(directory["device"])
        _uint(directory["inode"], 1)
        mode = _uint(directory["mode"], 0, 0o177777)
        _uint(directory["uid"], 0, 4294967295)
        _uint(directory["gid"], 0, 4294967295)
        _require(stat.S_ISDIR(mode), "DIRECTORY_TYPE")
        if index < 3:
            _require(directory["uid"] == 0 and not mode & 0o022, "ANCESTOR_ACCESS")
        else:
            owner = reader if index == 3 else observer
            _require(mode == stat.S_IFDIR | 0o700 and directory["uid"] == owner["uid"]
                     and directory["gid"] == owner["gid"], "DIRECTORY_ACCESS")
    return value


def _expectation(raw, expected_digest, provision, provision_digest):
    _pin(expected_digest)
    value = _parse(raw, 8192)
    _require(_digest(raw) == expected_digest, "EXPECTATION_PIN")
    _fields(value, ("schema", "provision_digest", "phase", "epoch_digest", "request_digest",
                    "challenge_digest", "trigger_digest", "trigger_issued_ns", "trigger_deadline_ns",
                    "deadline_ns", "previous_checkpoint_digest", "sequence_before", "sequence_after",
                    "offset_before", "records_before", "reader_evidence_digest", "reader_summary_digest",
                    "reader_connection_epoch", "reader_ack_ns", "loss_scope_digest"))
    _require(value["schema"] == _PREFIX + "-expectation/v1", "EXPECTATION_SCHEMA")
    for key in ("provision_digest", "epoch_digest", "request_digest", "challenge_digest", "trigger_digest",
                "reader_evidence_digest", "reader_summary_digest", "loss_scope_digest"):
        _pin(value[key])
    _nonce(value["reader_connection_epoch"])
    _require(value["provision_digest"] == provision_digest
             and value["epoch_digest"] == provision["epoch_digest"], "EXPECTATION_CONTEXT")
    for key in ("trigger_issued_ns", "trigger_deadline_ns", "deadline_ns", "reader_ack_ns",
                "sequence_before", "sequence_after"):
        _uint(value[key])
    _uint(value["offset_before"], 0, _SESSION_BYTES)
    _uint(value["records_before"], 0, _SESSION_RECORDS)
    before = value["sequence_before"]
    _require(value["sequence_after"] == before + 1, "SEQUENCE_STEP")
    previous = value["previous_checkpoint_digest"]
    if before == 0:
        _require(previous is None and value["offset_before"] == value["records_before"] == 0,
                 "INITIAL_CHECKPOINT")
    else:
        _pin(previous)
    issued, trigger_deadline, deadline = (value[key] for key in (
        "trigger_issued_ns", "trigger_deadline_ns", "deadline_ns"))
    _require(issued < trigger_deadline <= deadline <= provision["session_deadline_ns"], "DEADLINE_ORDER")
    ack = value["reader_ack_ns"]
    if value["phase"] == "CHALLENGE":
        _require(value["trigger_digest"] == value["challenge_digest"]
                 and issued <= ack < trigger_deadline, "CHALLENGE_ACK")
    else:
        _require(value["phase"] == "REFRESH" and before > 0 and ack <= issued
                 and ack <= _UINT_MAX - _ACK_AGE
                 and deadline - ack <= _ACK_AGE,
                 "REFRESH_ACK")
    return value


def _batch(raw):
    _raw(raw, _BATCH_MAX, empty=True)
    if not raw:
        return 0
    _require(raw.endswith(b"\n"), "UNTERMINATED_BATCH")
    _require(raw.count(b"\n") <= 256, "RECORD_COUNT")
    records = raw.split(b"\n")[:-1]
    _require(all(record and len(record) + 1 <= 65536 and not record.endswith(b"\r")
                 for record in records), "RECORD_FRAMING")
    return len(records)


def _manifest(raw, batch, record_count, provision, expectation, provision_digest):
    value = _parse(raw, 16384)
    _fields(value, ("schema", "provision_digest", "epoch_digest", "session_id", "stream_digest", "phase",
                    "request_digest", "challenge_digest", "trigger_digest", "previous_checkpoint_digest",
                    "sequence_before", "sequence_after", "offset_before", "offset_after", "records_before",
                    "records_after", "clock", "trigger_received_ns", "reads", "drain_finished_ns", "raw_digest",
                    "raw_bytes", "raw_records", "raw_publish_started_ns", "raw_readback_finished_ns",
                    "manifest_prepared_ns", "loss_scope_digest", "loss_evidence_digest", "upstream_loss_state"))
    _require(value["schema"] == _PREFIX + "/v1" and value["provision_digest"] == provision_digest,
             "MANIFEST_SCHEMA_CONTEXT")
    for key in ("epoch_digest", "session_id", "stream_digest"):
        _require(value[key] == provision[key], "MANIFEST_PROVISION")
    for key in ("phase", "request_digest", "challenge_digest", "trigger_digest", "previous_checkpoint_digest",
                "sequence_before", "sequence_after", "offset_before", "records_before", "loss_scope_digest"):
        _require(value[key] == expectation[key], "MANIFEST_EXPECTATION")
    _clock(value["clock"])
    _require(value["clock"] == provision["clock"], "MANIFEST_CLOCK")
    _require(value["loss_evidence_digest"] is None and value["upstream_loss_state"] == "UNKNOWN", "LOSS_CLAIM")
    for key in ("sequence_before", "sequence_after", "trigger_received_ns", "drain_finished_ns",
                "raw_publish_started_ns", "raw_readback_finished_ns", "manifest_prepared_ns"):
        _uint(value[key])
    for key in ("offset_before", "offset_after"):
        _uint(value[key], 0, _SESSION_BYTES)
    for key in ("records_before", "records_after"):
        _uint(value[key], 0, _SESSION_RECORDS)
    _uint(value["raw_bytes"], 0, _BATCH_MAX)
    _uint(value["raw_records"], 0, 256)
    _require(value["raw_digest"] == _digest(batch) and value["raw_bytes"] == len(batch)
             and value["raw_records"] == record_count
             and value["offset_after"] == value["offset_before"] + len(batch)
             and value["records_after"] == value["records_before"] + record_count, "BATCH_JOIN")
    reads = value["reads"]
    _require(type(reads) is list and 1 <= len(reads) <= 64, "READ_COUNT")
    offset, previous_finish = value["offset_before"], 0
    for entry in reads:
        _fields(entry, ("started_ns", "finished_ns", "offset", "bytes", "outcome"))
        start, finish = _uint(entry["started_ns"]), _uint(entry["finished_ns"])
        _require(previous_finish <= start <= finish, "READ_CHRONOLOGY")
        _require(_uint(entry["offset"], 0, _SESSION_BYTES) == offset, "READ_OFFSET")
        count = _uint(entry["bytes"], 0, 65536)
        _require((entry["outcome"] == "DATA" and count > 0)
                 or (entry["outcome"] == "EAGAIN" and count == 0), "READ_OUTCOME")
        offset += count
        previous_finish = finish
    _require(offset == value["offset_after"] and reads[-1]["outcome"] == "EAGAIN"
             and reads[-1]["started_ns"] >= value["trigger_received_ns"], "DRAIN_COMPLETENESS")
    _require(expectation["trigger_issued_ns"] <= value["trigger_received_ns"]
             and previous_finish <= value["drain_finished_ns"] <= value["raw_publish_started_ns"]
             <= value["raw_readback_finished_ns"] <= value["manifest_prepared_ns"]
             < expectation["trigger_deadline_ns"], "MANIFEST_CHRONOLOGY")
    return value


def _publication(raw, manifest, manifest_digest, expectation):
    value = _parse(raw, 2048)
    _fields(value, ("schema", "manifest_digest", "raw_digest", "sequence_after",
                    "manifest_publish_started_ns", "manifest_readback_finished_ns", "receipt_prepared_ns"))
    _require(value["schema"] == _PREFIX + "-publication/v1" and value["manifest_digest"] == manifest_digest
             and value["raw_digest"] == manifest["raw_digest"], "PUBLICATION_PIN")
    _require(_uint(value["sequence_after"]) == manifest["sequence_after"], "PUBLICATION_SEQUENCE")
    for key in ("manifest_publish_started_ns", "manifest_readback_finished_ns", "receipt_prepared_ns"):
        _uint(value[key])
    _require(manifest["manifest_prepared_ns"] <= value["manifest_publish_started_ns"]
             <= value["manifest_readback_finished_ns"] <= value["receipt_prepared_ns"]
             < expectation["trigger_deadline_ns"], "PUBLICATION_CHRONOLOGY")
    if expectation["phase"] == "CHALLENGE":
        _require(value["receipt_prepared_ns"] <= expectation["reader_ack_ns"], "ACK_BEFORE_PUBLICATION")
    return value


def _files(entries, owner, artifacts):
    _require(type(entries) is list and len(entries) == 3, "FILE_COUNT")
    identities = []
    for entry, (role, raw) in zip(entries, artifacts):
        _fields(entry, ("role", "device", "inode", "mode", "uid", "gid", "nlink", "bytes",
                        "mtime_ns", "ctime_ns", "digest"))
        for key in ("device", "mtime_ns", "ctime_ns"):
            _uint(entry[key])
        _uint(entry["inode"], 1)
        _uint(entry["uid"], 0, 4294967295)
        _uint(entry["gid"], 0, 4294967295)
        _require(entry["role"] == role and _uint(entry["mode"]) == stat.S_IFREG | 0o400
                 and entry["uid"] == owner["uid"] and entry["gid"] == owner["gid"]
                 and _uint(entry["nlink"]) == 1 and _uint(entry["bytes"]) == len(raw)
                 and entry["digest"] == _digest(raw), "FILE_JOIN")
        identities.append((entry["device"], entry["inode"]))
    return identities


def verify_reader_checkpoint(
    manifest_raw: bytes, publication_raw: bytes, batch_raw: bytes, acquisition_raw: bytes, *,
    provision_raw: bytes, expectation_raw: bytes, expected_provision_digest: str,
    expected_expectation_digest: str, expected_acquisition_digest: str,
) -> dict:
    """Validate pinned records and raw framing, without authenticating their acquisition."""
    for raw, limit in ((provision_raw, 8192), (expectation_raw, 8192), (manifest_raw, 16384),
                       (publication_raw, 2048), (acquisition_raw, 16384)):
        _raw(raw, limit)
    _raw(batch_raw, _BATCH_MAX, empty=True)
    _pin(expected_acquisition_digest)
    _require(_digest(acquisition_raw) == expected_acquisition_digest, "ACQUISITION_PIN")
    provision = _provision(provision_raw, expected_provision_digest)
    expectation = _expectation(expectation_raw, expected_expectation_digest,
                               provision, expected_provision_digest)
    manifest = _manifest(manifest_raw, batch_raw, _batch(batch_raw), provision,
                         expectation, expected_provision_digest)
    manifest_digest = _digest(manifest_raw)
    publication = _publication(publication_raw, manifest, manifest_digest, expectation)
    acquisition = _parse(acquisition_raw, 16384)
    _fields(acquisition, ("schema", "provision_digest", "expectation_digest", "phase", "trigger_digest",
                          "manifest_digest", "publication_digest", "batch_digest", "started_ns",
                          "source_readback_finished_ns", "retention_started_ns", "retention_finished_ns",
                          "observer", "clock", "source_files", "retained_files", *_FLAGS))
    _require(acquisition["schema"] == _PREFIX + "-acquisition/v1"
             and acquisition["provision_digest"] == expected_provision_digest
             and acquisition["expectation_digest"] == expected_expectation_digest
             and acquisition["phase"] == expectation["phase"]
             and acquisition["trigger_digest"] == expectation["trigger_digest"], "ACQUISITION_CONTEXT")
    _require(acquisition["manifest_digest"] == manifest_digest
             and acquisition["publication_digest"] == _digest(publication_raw)
             and acquisition["batch_digest"] == _digest(batch_raw), "ACQUISITION_ARTIFACTS")
    _process(acquisition["observer"])
    _clock(acquisition["clock"])
    _require(acquisition["observer"] == provision["observer"]
             and acquisition["clock"] == provision["clock"], "ACQUISITION_IDENTITY")
    _require(all(acquisition[flag] is False for flag in _FLAGS), "CLAIM_PROMOTION")
    for key in ("started_ns", "source_readback_finished_ns", "retention_started_ns", "retention_finished_ns"):
        _uint(acquisition[key])
    _require(max(expectation["reader_ack_ns"], expectation["trigger_issued_ns"])
             <= acquisition["started_ns"] <= acquisition["source_readback_finished_ns"]
             <= acquisition["retention_started_ns"] <= acquisition["retention_finished_ns"]
             < expectation["deadline_ns"]
             and publication["receipt_prepared_ns"] <= acquisition["source_readback_finished_ns"]
             and acquisition["retention_finished_ns"] - expectation["reader_ack_ns"] < _ACK_AGE,
             "ACQUISITION_CHRONOLOGY")
    artifacts = (("BATCH", batch_raw), ("MANIFEST", manifest_raw), ("PUBLICATION", publication_raw))
    identities = _files(acquisition["source_files"], provision["reader"], artifacts)
    identities += _files(acquisition["retained_files"], provision["observer"], artifacts)
    _require(len(set(identities)) == 6, "FILE_IDENTITY_REUSE")
    return {
        "status": "CONSISTENT_CHECKPOINT_READBACK", "acquisition_digest": expected_acquisition_digest,
        "manifest_digest": manifest_digest, "trigger_digest": expectation["trigger_digest"],
        "sequence_after": manifest["sequence_after"], "offset_after": manifest["offset_after"],
        "records_after": manifest["records_after"], "stream_continuity": "UNKNOWN",
        "loss_completeness": "UNKNOWN", **{flag: False for flag in _FLAGS},
    }
