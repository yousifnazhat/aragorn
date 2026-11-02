"""Bounded, offline accounting of selected Tetragon Prometheus counters.

This is a restricted text-exposition parser, not a collector or health verdict.
The source lock fixes the selected candidate; it does not authenticate a scrape,
prove metric applicability, or establish producer continuity. Missing families
remain unknown. In particular, similarly named probe counters are not aliases.
"""

from __future__ import annotations

import hashlib
import re
from decimal import Decimal, InvalidOperation
from typing import Any

from . import runtime_tetragon_process as process

MAX_SCRAPE_BYTES = 1024 * 1024
MAX_LINE_BYTES = 16 * 1024
MAX_LINES = 16384
MAX_SERIES = 4096
MAX_LABELS = 16
PROFILE = "tetragon-v1.7.0-restricted-selected-loss-text/v1"
_U64 = (1 << 64) - 1
_NAME = r"[a-zA-Z_:][a-zA-Z0-9_:]*"
_LABEL = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*="')
_HEAD = re.compile(_NAME)
_NUMBER = re.compile(
    r"[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|Inf)|NaN"
)
_TYPES = {"counter", "gauge", "histogram", "summary", "untyped"}
_FALSE = {
    "producer_authenticity_verified": False,
    "producer_continuity_verified": False,
    "metric_applicability_verified": False,
    "supplemental_source_custody_verified": False,
    "reader_progress_verified": False,
    "delivery_completeness_verified": False,
    "sensor_health_verified": False,
    "runtime_attribution_verified": False,
    "run_conformance_eligible": False,
    "phase3_eligible": False,
    "production_activation_eligible": False,
}


class TetragonLossError(ValueError):
    """A bounded scrape or its selected counter comparison is ambiguous."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TetragonLossError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _labels(line: str, offset: int) -> tuple[tuple[tuple[str, str], ...], int]:
    labels: dict[str, str] = {}
    if offset == len(line) or line[offset] != "{":
        return (), offset
    offset += 1
    if offset < len(line) and line[offset] == "}":
        return (), offset + 1
    while offset < len(line):
        match = _LABEL.match(line, offset)
        _require(match is not None, "malformed metric labels")
        name = match[0][:-2]
        _require(
            len(name) <= 128 and name not in labels and len(labels) < MAX_LABELS,
            "duplicate or oversized label inventory",
        )
        offset = match.end()
        value: list[str] = []
        while offset < len(line) and line[offset] != '"':
            char = line[offset]
            offset += 1
            if char == "\\":
                _require(offset < len(line), "incomplete label escape")
                escaped = line[offset]
                _require(escaped in {'"', "\\", "n"}, "unsupported label escape")
                char = "\n" if escaped == "n" else escaped
                offset += 1
            _require(ord(char) >= 32 or char == "\n", "control byte in label")
            value.append(char)
        _require(offset < len(line), "unterminated label value")
        decoded = "".join(value)
        _require(len(decoded.encode("utf-8")) <= 4096, "label value exceeds bound")
        labels[name] = decoded
        offset += 1
        _require(offset < len(line), "unterminated label set")
        if line[offset] == "}":
            return tuple(sorted(labels.items())), offset + 1
        _require(line[offset] == ",", "malformed label separator")
        offset += 1
    raise TetragonLossError("unterminated label set")


def _counter(token: str) -> int:
    try:
        value = Decimal(token)
        _require(
            value.is_finite()
            and 0 <= value <= _U64
            and value == value.to_integral_value(),
            "selected counter is not an exact bounded nonnegative integer",
        )
        return int(value)
    except (InvalidOperation, ValueError, OverflowError) as exc:
        if isinstance(exc, TetragonLossError):
            raise
        raise TetragonLossError("invalid selected counter") from exc


def _parse(raw: bytes) -> dict[str, Any]:
    _require(
        type(raw) is bytes
        and 0 < len(raw) <= MAX_SCRAPE_BYTES
        and raw.endswith(b"\n")
        and b"\0" not in raw
        and b"\r" not in raw,
        "invalid scrape byte bound or framing",
    )
    lines = raw.split(b"\n")[:-1]
    _require(len(lines) <= MAX_LINES, "scrape line inventory exceeds bound")
    _require(all(len(line) <= MAX_LINE_BYTES for line in lines), "scrape line too long")
    try:
        text_lines = [line.decode("utf-8", "strict") for line in lines]
    except UnicodeError as exc:
        raise TetragonLossError("scrape is not UTF-8") from exc
    metadata: dict[str, dict[str, str]] = {}
    samples: dict[str, dict[tuple, tuple[int, str]]] = {
        name: {} for name in process.LOSS_METRICS
    }
    seen: set[tuple] = set()
    for line in text_lines:
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith(("# HELP ", "# TYPE ")):
                kind, separator, remaining = line[2:].partition(" ")
                name, separator, value = remaining.partition(" ")
                _require(
                    bool(separator)
                    and re.fullmatch(_NAME, name) is not None
                    and len(name) <= 128
                    and bool(value),
                    "malformed metric metadata",
                )
                record = metadata.setdefault(name, {})
                _require(kind not in record, "duplicate metric metadata")
                if kind == "TYPE":
                    _require(value in _TYPES, "unsupported metric TYPE")
                if name in samples:
                    _require(not samples[name], "selected metadata follows samples")
                    if kind == "TYPE":
                        _require(value == "counter", "selected metric is not a counter")
                record[kind] = value
            elif line.startswith(("# HELP", "# TYPE", "# EOF", "# UNIT")):
                raise TetragonLossError("unsupported exposition metadata")
            continue
        match = _HEAD.match(line)
        _require(match is not None and len(match[0]) <= 128, "invalid metric name")
        name = match[0]
        labels, offset = _labels(line, match.end())
        _require(
            offset < len(line) and line[offset] in " \t", "missing sample separator"
        )
        fields = line[offset:].split()
        _require(
            len(fields) in {1, 2}
            and len(fields[0]) <= 128
            and _NUMBER.fullmatch(fields[0]) is not None,
            "malformed metric sample",
        )
        if len(fields) == 2:
            _require(
                re.fullmatch(r"-?[0-9]{1,20}", fields[1]) is not None
                and -(1 << 63) <= int(fields[1]) < (1 << 63),
                "invalid sample timestamp",
            )
        key = (name, labels)
        _require(
            key not in seen and len(seen) < MAX_SERIES, "duplicate or excessive series"
        )
        seen.add(key)
        if name in samples:
            _require(len(fields) == 1, "selected sample timestamps are unsupported")
            _require(
                metadata.get(name, {}).get("TYPE") == "counter", "missing counter TYPE"
            )
            samples[name][labels] = (_counter(fields[0]), fields[0])
    families = {}
    for name, values in samples.items():
        families[name] = {
            "status": "OBSERVED" if values else "UNKNOWN_NOT_EXPOSED",
            "metadata": metadata.get(name, {}),
            "series": [
                {"labels": dict(labels), "value": value, "value_text": token}
                for labels, (value, token) in sorted(values.items())
            ]
            if values
            else None,
            "total": sum(value for value, _ in values.values()) if values else None,
        }
    return {
        "raw_digest": _digest(raw),
        "raw_bytes": len(raw),
        "all_series_count": len(seen),
        "families": families,
    }


def analyze_tetragon_loss_window(
    before: bytes, after: bytes, *, source_lock: bytes
) -> dict[str, Any]:
    """Compare selected raw counter reports without inferring live continuity.

    Every series must retain its exact decoded labels. Decreases, absent/present
    transitions and metadata changes refuse the comparison, even when totals
    could conceal them. Unknown families remain unknown, never synthetic zero.
    """
    try:
        lock = process.verify_source_lock(source_lock)
    except process.TetragonProcessError as exc:
        raise TetragonLossError("candidate source lock refused") from exc
    start, end = _parse(before), _parse(after)
    comparisons, missing = {}, []
    increased = False
    for name in process.LOSS_METRICS:
        first, last = start["families"][name], end["families"][name]
        _require(
            first["metadata"] == last["metadata"]
            and (first["series"] is None) == (last["series"] is None),
            "selected family inventory or metadata changed",
        )
        if first["series"] is None:
            missing.append(name)
            comparisons[name] = {
                "status": "UNKNOWN_NOT_EXPOSED",
                "delta": None,
                "series": None,
            }
            continue
        _require(
            [item["labels"] for item in first["series"]]
            == [item["labels"] for item in last["series"]],
            "selected label-series inventory changed",
        )
        series = []
        for left, right in zip(first["series"], last["series"], strict=True):
            _require(
                right["value"] >= left["value"], "selected counter reset or decrease"
            )
            delta = right["value"] - left["value"]
            increased |= delta > 0
            series.append(
                {
                    "labels": left["labels"],
                    "before": left["value"],
                    "after": right["value"],
                    "delta": delta,
                }
            )
        comparisons[name] = {
            "status": "OBSERVED",
            "delta": sum(row["delta"] for row in series),
            "series": series,
        }
    return {
        "schema": "aragorn/tetragon-selected-loss-window/v1",
        "authority": "OFFLINE_SELECTED_COUNTER_REPORTS_NOT_SENSOR_HEALTH_OR_COVERAGE_AUTHORITY",
        "profile": PROFILE,
        "status": "UNRESOLVED"
        if missing
        else "LOSS_OBSERVED"
        if increased
        else "NO_SELECTED_COUNTER_INCREASE_REPORTED",
        "source_commit": process.SOURCE_COMMIT,
        "source_lock_digest": process.SOURCE_LOCK_DIGEST,
        "source_lock_schema": lock["schema"],
        "candidate_process_profile": process.PROFILE,
        "selected_metrics": list(process.LOSS_METRICS),
        "before": start,
        "after": end,
        "families": comparisons,
        "missing_metrics": missing,
        "selected_counter_increase_observed": increased,
        "limitations": [
            "SOURCE_LOCK_NOT_RELEASE_BINARY_OR_SCRAPE_AUTHENTICATION",
            "SUPPLEMENTAL_SOURCE_CUSTODY_IS_SEPARATE_NOT_LOADED_OR_VERIFIED_HERE",
            "NO_PRODUCER_IDENTITY_RESTART_READER_OR_WINDOW_PROGRESS_VERIFICATION",
            "MISSING_METRICS_UNKNOWN_AND_NO_SIMILARLY_NAMED_COUNTER_SUBSTITUTION",
            "SPARSE_BPF_COUNTER_ABSENCE_DOES_NOT_PROVE_ZERO",
            "STABLE_REPORTED_INVENTORY_AND_COUNTERS_DO_NOT_PROVE_DELIVERY_COMPLETENESS",
            "NONZERO_BASELINES_RETAINED_NOT_NORMALIZED_TO_ZERO",
        ],
        **_FALSE,
    }
