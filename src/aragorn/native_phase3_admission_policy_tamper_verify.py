"""Independent retained-byte consistency checks; no native authenticity claim."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat

from .oci_worker_protocol import canonical_json

PREFIX = "aragorn/native-admission-policy-tamper-"
SNAPSHOT_LIMIT = 262144
ACTION_LIMIT = 65536
RECORD_LIMIT = 4194304
BINDINGS = ("context", "deployment", "config", "policy_executable", "node",
            "runtime_tree", "candidate", "baseline", "observer_source")
PATHS = {
    "config": "/run/credentials/aragorn-agent-gateway.service/openclaw-config",
    "policy_executable": "/usr/bin/printf",
}
OPERATIONS = ("OVERWRITE", "CHMOD", "UNLINK", "REPLACE_RENAME",
              "ADJACENT_SYMLINK", "PARENT_RETARGET")
PLUGIN = "aragorn-plugin-skill-replacement-fixture"
CANDIDATE = "/route-input/plugin-package-skill-replacement/candidate-source"
TARGET = "/var/lib/aragorn-agent-gateway/state/extensions/" + PLUGIN
ARGV = ["/usr/local/bin/node", "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "plugins", "install", CANDIDATE, "--force"]
STDERR = b"blocked by install policy: plugin installs disabled by Aragorn protected profile\n"
STDOUT = (b"Install policy target=plugin:aragorn-plugin-skill-replacement-fixture "
          b"request=plugin-dir/update origin=plugin-package pathKind=directory "
          b"source=local-path/user: " + STDERR)
FLAGS = ("policy_execution_verified", "admission_qualified", "phase3_qualified")
LIMITATIONS = [
    "PROTECTED_POLICY_INVOCATION_AUTHENTICITY_NOT_VERIFIED",
    "ENDPOINT_EQUALITY_NOT_INTERVAL_CUSTODY",
    "BASELINE_PRESERVATION_NOT_FRESH_TARGET_ABSENCE",
    "BASELINE_AND_CATALOG_DIGESTS_ARE_OBSERVER_ASSERTIONS",
    "NO_NATIVE_ADMISSION_OR_PHASE3_QUALIFICATION",
]


class PolicyTamperVerificationError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise PolicyTamperVerificationError(reason)


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields), "FIELD_INVENTORY")


def integer(value, minimum=0):
    require(type(value) is int and minimum <= value < 2**63, "INTEGER")
    return value


def pin(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "PIN")


def encode(raw):
    return base64.b64encode(raw).decode("ascii")


def decode(value, limit):
    require(type(value) is str and len(value) <= ((limit + 2) // 3) * 4, "BASE64_BOUND")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as error:
        raise PolicyTamperVerificationError("BASE64") from error
    require(len(raw) <= limit and encode(raw) == value, "BASE64_CANONICAL")
    return raw


def parse(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit and raw.isascii(), "RAW_BOUND")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_):
        raise PolicyTamperVerificationError("NONFINITE")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        require(canonical_json(value) == raw, "NONCANONICAL_JSON")
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError) as error:
        raise PolicyTamperVerificationError("JSON_REFUSED") from error


def absolute_path(value):
    require(type(value) is str and value.startswith("/") and not value.startswith("//")
            and "\x00" not in value and str(PurePosixPath(value)) == value
            and ".." not in PurePosixPath(value).parts, "PATH")


class EvidenceChecks:
    """Incremental guards also usable by the recorder; verifier replays every row."""

    def __init__(self, context_raw, bindings):
        exact(bindings, BINDINGS)
        for value in bindings.values():
            pin(value)
        context = parse(context_raw, SNAPSHOT_LIMIT)
        require(digest(context_raw) == bindings["context"], "CONTEXT_PIN")
        exact(context, ("schema", "nonce", "fixture", "gateway", "clock", "bindings",
                        "resources", "argv", "cwd", "environment", "subject"))
        require(context["schema"] == PREFIX + "context/v1", "CONTEXT_SCHEMA")
        require(type(context["nonce"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", context["nonce"]), "NONCE")
        require(context["bindings"] == {k: bindings[k] for k in BINDINGS if k != "context"},
                "CONTEXT_BINDINGS")
        fixture = context["fixture"]
        exact(fixture, ("container_id", "boot_id", "netns_device", "netns_inode"))
        require(type(fixture["container_id"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", fixture["container_id"]), "CONTAINER")
        require(type(fixture["boot_id"]) is str and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", fixture["boot_id"]), "BOOT")
        integer(fixture["netns_device"])
        integer(fixture["netns_inode"], 1)
        gateway = context["gateway"]
        exact(gateway, ("pid", "start_time_ticks", "uid", "gid"))
        for key, value in gateway.items():
            integer(value, 1 if key in ("pid", "start_time_ticks") else 0)
        require(gateway["uid"] == gateway["gid"] == 992, "PRIVILEGES")
        clock = context["clock"]
        exact(clock, ("boot_id", "clock_id", "time_namespace_device", "time_namespace_inode"))
        require(clock["boot_id"] == fixture["boot_id"]
                and clock["clock_id"] == "CLOCK_BOOTTIME", "CLOCK")
        integer(clock["time_namespace_device"])
        integer(clock["time_namespace_inode"], 1)
        require(context["argv"] == ARGV, "ARGV")
        absolute_path(context["cwd"])
        environment = context["environment"]
        require(type(environment) is dict, "ENVIRONMENT")
        for key, value in environment.items():
            require(type(key) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                    and type(value) is str and "\x00" not in value, "ENVIRONMENT_ENTRY")
        subject = context["subject"]
        exact(subject, ("plugin_id", "candidate_path", "target_path",
                        "candidate_digest", "baseline_digest"))
        require(subject == {"plugin_id": PLUGIN, "candidate_path": CANDIDATE,
                            "target_path": TARGET, "candidate_digest": bindings["candidate"],
                            "baseline_digest": bindings["baseline"]}, "SUBJECT")
        exact(context["resources"], PATHS)
        for name, resource in context["resources"].items():
            exact(resource, ("path", "digest", "identity", "ancestry"))
            require(resource["path"] == PATHS[name] and resource["digest"] == bindings[name],
                    "RESOURCE_BINDING")
            identity = resource["identity"]
            exact(identity, ("device", "inode", "mode", "uid", "gid", "nlink", "size",
                             "mtime_ns", "ctime_ns"))
            for key, value in identity.items():
                integer(value, 1 if key in ("inode", "size") else 0)
            require(stat.S_ISREG(identity["mode"]) and not identity["mode"] & 0o022
                    and identity["nlink"] == 1, "RESOURCE_METADATA")
            ancestry = resource["ancestry"]
            paths = [str(p) for p in reversed(PurePosixPath(resource["path"]).parents)]
            require(type(ancestry) is list and len(ancestry) == len(paths), "ANCESTRY")
            for row, path in zip(ancestry, paths):
                exact(row, ("path", "device", "inode", "mode", "uid", "gid"))
                require(row["path"] == path, "ANCESTRY_PATH")
                for key in ("device", "inode", "mode", "uid", "gid"):
                    integer(row[key], 1 if key == "inode" else 0)
                require(stat.S_ISDIR(row["mode"]), "ANCESTRY_TYPE")
        # Parsed context and copied pins cannot be changed by callbacks mutating caller dicts.
        self.context = context
        self.bindings = dict(bindings)

    def joined(self, value, schema, fields):
        exact(value, ("schema", "context_digest", "nonce", *fields))
        require(value["schema"] == PREFIX + schema + "/v1"
                and value["context_digest"] == self.bindings["context"]
                and value["nonce"] == self.context["nonce"], "OBSERVATION_JOIN")

    def snapshot(self, raw, earliest=0, catalog=None):
        value = parse(raw, SNAPSHOT_LIMIT)
        self.joined(value, "snapshot", ("observed_ns", "resources", "baseline_digest",
                                        "catalog_digest", "candidate_installed"))
        require(integer(value["observed_ns"]) >= earliest, "SNAPSHOT_CHRONOLOGY")
        require(value["baseline_digest"] == self.bindings["baseline"]
                and value["candidate_installed"] is False, "BASELINE_CHANGED")
        pin(value["catalog_digest"])
        require(catalog is None or value["catalog_digest"] == catalog, "CATALOG_CHANGED")
        exact(value["resources"], PATHS)
        for name, resource in value["resources"].items():
            exact(resource, ("path", "digest", "identity", "ancestry", "raw_base64"))
            expected = self.context["resources"][name]
            require(canonical_json({k: resource[k] for k in expected}) == canonical_json(expected),
                    "RESOURCE_CHANGED")
            content = decode(resource["raw_base64"], SNAPSHOT_LIMIT)
            require(len(content) == expected["identity"]["size"]
                    and digest(content) == expected["digest"], "RESOURCE_BYTES")
        return value

    def action_times(self, value, earliest):
        start, finish = integer(value["started_ns"]), integer(value["finished_ns"])
        require(earliest <= start <= finish, "ACTION_CHRONOLOGY")

    def mutation(self, raw, resource, operation, earliest):
        value = parse(raw, ACTION_LIMIT)
        self.joined(value, "operation", ("resource", "operation", "started_ns", "finished_ns",
                                        "result", "errno"))
        require(value["resource"] == resource and value["operation"] == operation, "OPERATION_ORDER")
        self.action_times(value, earliest)
        protective = value["result"] == "DENIED" and value["errno"] in ("EACCES", "EPERM", "EROFS")
        structural = (value["result"] == "STRUCTURAL_REFUSAL"
                      and operation in ("REPLACE_RENAME", "PARENT_RETARGET")
                      and value["errno"] in ("EXDEV", "EBUSY"))
        require(protective or structural, "UNEXPECTED_MUTATION_RESULT")
        return value

    def invocation(self, raw, earliest):
        value = parse(raw, ACTION_LIMIT)
        self.joined(value, "invocation", ("started_ns", "finished_ns", "argv", "exit_code",
                                          "stdout_base64", "stderr_base64", "policy_observation_digest"))
        self.action_times(value, earliest)
        require(value["argv"] == ARGV and type(value["exit_code"]) is int
                and value["exit_code"] == 1, "INVOCATION")
        require(decode(value["stdout_base64"], ACTION_LIMIT) == STDOUT
                and decode(value["stderr_base64"], ACTION_LIMIT) == STDERR, "CLI_BYTES")
        pin(value["policy_observation_digest"])
        return value


def verify_policy_tamper(raw: bytes, *, expected_digest: str, context_raw: bytes,
                         bindings: dict, expected_policy_observation_digest: str) -> dict:
    pin(expected_digest)
    pin(expected_policy_observation_digest)
    checks = EvidenceChecks(context_raw, bindings)
    value = parse(raw, RECORD_LIMIT)
    require(digest(raw) == expected_digest, "RECORD_PIN")
    exact(value, ("schema", "context_digest", "before", "attempts", "invocation", "after", *FLAGS))
    require(value["schema"] == PREFIX + "record/v1"
            and value["context_digest"] == checks.bindings["context"], "RECORD_JOIN")
    require(all(value[key] is False for key in FLAGS), "CLAIM_PROMOTION")
    snapshot = checks.snapshot(decode(value["before"], SNAPSHOT_LIMIT))
    catalog = snapshot["catalog_digest"]
    rows = value["attempts"]
    require(type(rows) is list and len(rows) == 12, "ATTEMPT_COUNT")
    protective = structural = 0
    for row, (resource, operation) in zip(rows, ((r, o) for r in PATHS for o in OPERATIONS)):
        exact(row, ("operation_base64", "snapshot_base64"))
        action = checks.mutation(decode(row["operation_base64"], ACTION_LIMIT),
                                 resource, operation, snapshot["observed_ns"])
        protective += action["result"] == "DENIED"
        structural += action["result"] == "STRUCTURAL_REFUSAL"
        snapshot = checks.snapshot(decode(row["snapshot_base64"], SNAPSHOT_LIMIT),
                                   action["finished_ns"], catalog)
    invocation = checks.invocation(decode(value["invocation"], ACTION_LIMIT), snapshot["observed_ns"])
    require(invocation["policy_observation_digest"] == expected_policy_observation_digest,
            "POLICY_OBSERVATION_PIN")
    checks.snapshot(decode(value["after"], SNAPSHOT_LIMIT), invocation["finished_ns"], catalog)
    return {"status": "CONSISTENT_POLICY_TAMPER_RECORD", "digest": expected_digest,
            "operations": 12, "protective_denials": protective, "structural_refusals": structural,
            **{key: False for key in FLAGS}, "limitations": list(LIMITATIONS)}
