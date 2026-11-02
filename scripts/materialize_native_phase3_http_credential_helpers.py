"""Finite credential-view helper successor; rendering never executes its output.

The public stage receipt is an exact source artifact. Services' loaded views
are distinct from root provisioning inputs; neither establishes qualification.
"""

from __future__ import annotations

import hashlib
import json

from scripts import materialize_native_phase3_http_ready_helpers as prior

INPUTS = prior.INPUTS
identity, preparation, setup, writer = prior.identity, prior.preparation, prior.setup, prior.writer
measurement = prior.measurement
REPORT = "benchmark/evidence/phase3-http-credential-staged-profile-v1.json"
STAGED_SCHEMA = "aragorn/runtime-phase3-http-credential-staged-profile/v1"
STAGED_PROFILE_PIN = (68263, "sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9")
STAGED_COUNTS = (94, 124, 50, 21)
HTTP_CONFIG_PIN = "sha256:7166a9634f1157853e3db16bc5d04ab8cdcbf6a218fdbada933bb430551423cd"
LIFECYCLE_LOG = "/var/lib/aragorn-agent-gateway/gateway-lifecycle.log"


def report(raw):
    """Validate actual retained public bytes, without staging or private reads."""
    if type(raw) is not bytes or (len(raw), "sha256:" + hashlib.sha256(raw).hexdigest()) != STAGED_PROFILE_PIN:
        raise ValueError("HTTP credential public report pin changed")
    value = json.loads(raw)
    if (json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") != raw
            or value["schema"] != STAGED_SCHEMA
            or tuple(len(value[key]) for key in ("files", "source_inputs", "new_dependencies", "directories")) != STAGED_COUNTS
            or value["gateway_config_digest_required_not_included"] != HTTP_CONFIG_PIN
            or any(value[key] is not False for key in (
                "http_service_credentials_observed", "gateway_lifecycle_log_observed",
                "http_fixture_provisioned", "http_runtime_activated", "http_collected",
                "measurement_collected", "phase3_qualification", "run_qualification"))):
        raise ValueError("HTTP credential public report contract changed")
    return value


def _change(raw, before, after, count=1):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != count:
        raise ValueError("HTTP credential helper anchor changed: " + before[:100].decode())
    changed = raw.replace(before, after)
    if changed.replace(after, before) != raw:
        raise ValueError("HTTP credential helper reversal changed")
    return changed


def _function(raw, name, before, after, count=1):
    marker = ("def " + name + "(").encode("ascii")
    if raw.count(marker) != 1:
        raise ValueError("HTTP credential helper function changed")
    start = raw.index(marker)
    end = raw.find(b"\n\ndef ", start + len(marker))
    section = raw[start:len(raw) if end < 0 else end].decode("ascii")
    return _change(raw, section, _change(section.encode(), before, after, count).decode())


_VIEW_READER = '''def _read_http_credential_view(root_fd, path, uid, gid):
    """Owned root observer read; no service API or provisioning-path fallback."""
    allowed = {f"/run/credentials/{prior._UNITS[role]}/http-fixture"
               for role in HTTP_FIXTURE_ROLES}
    allowed.add(f"/run/credentials/{prior._UNITS['broker']}/http-readiness")
    _require(path in allowed and type(uid) is int and uid > 0
        and type(gid) is int and gid > 0, "HTTP credential view changed")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    with ExitStack() as held:
        parent, ancestors = root_fd, []
        for part in Path(path).parts[1:-1]:
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            child = os.open(part, flags, dir_fd=parent)
            held.callback(os.close, child)
            current = os.fstat(child)
            identity = prior.broker._file_identity(current)[:5]
            _require(stat.S_ISDIR(current.st_mode) and current.st_uid in
                ({0, uid} if part == Path(path).parent.name else {0})
                and not stat.S_IMODE(current.st_mode) & 0o022
                and identity == prior.broker._file_identity(before)[:5],
                "HTTP credential ancestor changed")
            ancestors.append((parent, part, child, identity))
            parent = child
        fd = os.open(Path(path).name, flags & ~os.O_DIRECTORY, dir_fd=parent)
        held.callback(os.close, fd)
        before = os.fstat(fd)
        identity = prior.broker._file_identity(before)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 < before.st_size <= 4096
            and ((before.st_uid == uid and before.st_gid in {0, gid}
                  and stat.S_IMODE(before.st_mode) == 0o400)
                 or (before.st_uid == 0 and before.st_gid in {0, gid}
                     and stat.S_IMODE(before.st_mode) in {0o400, 0o440})),
            "HTTP loaded credential metadata changed")
        def guard():
            _require(identity == prior.broker._file_identity(os.fstat(fd))
                == prior.broker._file_identity(os.stat(Path(path).name,
                    dir_fd=parent, follow_symlinks=False))
                and os.fstatvfs(fd).f_flag & os.ST_RDONLY
                and os.fstatvfs(parent).f_flag & os.ST_RDONLY,
                "HTTP loaded credential custody changed")
            for directory, name, child, expected in ancestors:
                _require(expected == prior.broker._file_identity(os.fstat(child))[:5]
                    == prior.broker._file_identity(os.stat(name, dir_fd=directory,
                        follow_symlinks=False))[:5], "HTTP credential ancestry changed")
        guard()
        raw = os.pread(fd, 4097, 0)
        _require(len(raw) == before.st_size, "HTTP credential exact read changed")
        guard()
        return raw, {"bytes": len(raw), "digest": prior._digest(raw), "identity": list(identity)}


def _gateway_restart_environment(pid):
    """Keep all environment bytes internal; export only the fixed witness."""
    raw = prior.process._read_virtual_file(Path(f"/proc/{pid}/environ"), 16384)
    _require(raw.endswith(b"\\0") and 0 < len(raw) <= 16384,
        "gateway environment read changed")
    fields = raw[:-1].split(b"\\0")
    _require(all(b"=" in field for field in fields)
        and [field for field in fields if field.split(b"=", 1)[0] == b"OPENCLAW_NO_RESPAWN"]
            == [b"OPENCLAW_NO_RESPAWN=1"], "gateway native restart environment changed")
    return raw, {"OPENCLAW_NO_RESPAWN": "1"}


'''

_VIEW_CONSUMER = '''def _http_loaded_metadata(value, uid, gid, *, expected_bytes, expected_digest):
    result = frozen._metadata(value, owners={(0, 0), (0, gid), (uid, 0), (uid, gid)},
        modes={0o400, 0o440})
    _require(result["identity"][3] == 0
        or stat.S_IMODE(result["identity"][2]) == 0o400,
        "service-owned HTTP credential must be 0400")
    _require(result["bytes"] <= 4096 and result["bytes"] == expected_bytes
        and result["digest"] == expected_digest,
        "HTTP credential byte or protected-source binding changed")
    return result


def _http_gateway_environment(identity, pins):
    _require(identity["gateway_restart_environment"] == {"OPENCLAW_NO_RESPAWN": "1"}
        and pins[frozen._CONFIG] == HTTP_CREDENTIAL_CONFIG_PIN,
        "gateway credential configuration or environment witness changed")


'''


def _identity(raw, *, verifier):
    raw = _change(raw, "aragorn/native-phase3-http-live-identity/v2", "aragorn/native-phase3-http-live-identity/v3")
    raw = _change(raw,
        "HTTP_FIXTURE_PROCESS_ROOT_BYTES_NOT_APPLICATION_LOAD_OR_NETWORK_NAMESPACE_OBSERVATION",
        "HTTP_LOADED_CREDENTIAL_VIEWS_NOT_APPLICATION_ACK_OR_NETWORK_NAMESPACE_OBSERVATION")
    marker = ('    "GRANT_STRUCTURE_AND_BINDING_JOINS_NOT_CURRENT_LIVENESS_OR_AUTHORIZATION",\n'
              '    "LOCAL_ROOT_OBSERVER_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",\n'
              '    "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",')
    raw = _change(raw, marker, marker + '\n    "GATEWAY_ENVIRONMENT_WITNESS_NOT_INDEPENDENT_ENVIRONMENT_OR_APPLICATION_ATTESTATION",')
    if verifier:
        raw = _change(raw, "aragorn/native-phase3-http-process-verification/v2", "aragorn/native-phase3-http-process-verification/v3")
        raw = _change(raw, "def _files(",
            "HTTP_CREDENTIAL_CONFIG_PIN = " + repr(HTTP_CONFIG_PIN) + "\n\n\n" + _VIEW_CONSUMER + "def _files(")
        raw = _function(raw, "_envelopes", '        "http_readiness_views",', '        "http_readiness_views",\n        "gateway_restart_environment",')
        raw = _function(raw, "_files",
            '    view = frozen._metadata(ready_views["broker"], owners={(0, accounts["broker"][1])}, modes={0o440})',
            '    view = _http_loaded_metadata(ready_views["broker"], *accounts["broker"],\n'
            '        expected_bytes=files[HTTP_READINESS_BINDING]["bytes"],\n'
            '        expected_digest=pins[HTTP_READINESS_BINDING])')
        raw = _function(raw, "_files", '    for view in http_views.values():\n        frozen._metadata(view, owners={(0, accounts["broker"][1])}, modes={0o440})',
            '    for role, view in http_views.items():\n'
            '        _http_loaded_metadata(view, *accounts[role],\n'
            '            expected_bytes=files[HTTP_FIXTURE_BINDING]["bytes"],\n'
            '            expected_digest=pins[HTTP_FIXTURE_BINDING])')
        raw = _function(raw, "_files", '    joins = identity["measured_joins"]',
            '    _http_gateway_environment(identity, pins)\n    joins = identity["measured_joins"]')
    else:
        raw = _change(raw, "def _read(container: str, expected: dict) -> dict:", _VIEW_READER + "def _read(container: str, expected: dict) -> dict:")
        raw = _function(raw, "_joins", '        and configuration["tools"]["alsoAllow"]',
            '        and configuration.get("logging") == {"level": "info", "file": ' + repr(LIFECYCLE_LOG) + '}\n'
            '        and prior._digest(raw[prior._CONFIG]) == ' + repr(HTTP_CONFIG_PIN) + '\n'
            '        and configuration["tools"]["alsoAllow"]')
        raw = _function(raw, "_read", '        http_readiness_views = {}',
            '        http_readiness_views = {}\n        http_view_reads = []\n'
            '        gateway_environment = _gateway_restart_environment(records["gateway"]["pid"])')
        raw = _function(raw, "_read", '            if role in HTTP_FIXTURE_ROLES:\n                http_fixture_views[role] = view(\n                    HTTP_FIXTURE_BINDING, HTTP_FIXTURE_BINDING,\n                    _file_arguments(HTTP_FIXTURE_BINDING, accounts),\n                )',
            '            def http_view(name, source):\n'
            '                path = f"/run/credentials/{prior._UNITS[role]}/{name}"\n'
            '                uid, gid = accounts[role]\n'
            '                content, metadata = _read_http_credential_view(fd, path, uid, gid)\n'
            '                _require(content == raw[source], "HTTP loaded view differs from protected writer")\n'
            '                http_view_reads.append((fd, path, uid, gid, content, metadata))\n'
            '                return metadata\n\n'
            '            if role in HTTP_FIXTURE_ROLES:\n'
            '                http_fixture_views[role] = http_view("http-fixture", HTTP_FIXTURE_BINDING)')
        raw = _function(raw, "_read", '                http_readiness_views[role] = view(HTTP_READINESS_BINDING, HTTP_READINESS_BINDING,\n                    _file_arguments(HTTP_READINESS_BINDING, accounts))',
            '                http_readiness_views[role] = http_view("http-readiness", HTTP_READINESS_BINDING)')
        raw = _function(raw, "_read", '        for fd in pidfds.values():',
            '        for fd, path, uid, gid, content, metadata in http_view_reads:\n'
            '            _require(_read_http_credential_view(fd, path, uid, gid) == (content, metadata),\n'
            '                "HTTP loaded credential changed during identity observation")\n'
            '        _require(_gateway_restart_environment(records["gateway"]["pid"]) == gateway_environment,\n'
            '            "gateway environment changed during identity observation")\n'
            '        for fd in pidfds.values():')
        raw = _function(raw, "_read", '            "http_readiness_views": http_readiness_views,',
            '            "http_readiness_views": http_readiness_views,\n'
            '            "gateway_restart_environment": gateway_environment[1],')
        raw = _function(raw, "compare_native_common_identity", '        "http_readiness_views",',
            '        "http_readiness_views",\n        "gateway_restart_environment",')
        raw = _function(raw, "compare_native_common_identity", '        and type(before.get("http_readiness_views")) is dict',
            '        and before.get("gateway_restart_environment") == {"OPENCLAW_NO_RESPAWN": "1"}\n'
            '        and type(before.get("http_readiness_views")) is dict')
    return raw


def _transform(outputs, report_raw):
    """Internal finite delta over already verified ready94 generated outputs."""
    receipt = report(report_raw)
    if set(outputs) != set(INPUTS):
        raise ValueError("HTTP credential generated helper inventory changed")
    result = dict(outputs)
    raw = result[preparation.PREPARATION]
    raw = _change(raw, prior.STAGED_SCHEMA, STAGED_SCHEMA)
    raw = _change(raw, f"STAGED_PROFILE_PIN = {prior.STAGED_PROFILE_PIN!r}", f"STAGED_PROFILE_PIN = {STAGED_PROFILE_PIN!r}")
    raw = _change(raw, f"== {prior.STAGED_COUNTS!r}", f"== {STAGED_COUNTS!r}")
    raw = _change(raw, f"HTTP_CONFIG_PIN = {preparation.HTTP_CONFIG_PIN!r}", f"HTTP_CONFIG_PIN = {HTTP_CONFIG_PIN!r}")
    raw = _change(raw, 'and value["broker_readiness_observed"] is False',
        'and value["broker_readiness_observed"] is False\n'
        '        and value["http_service_credentials_staged"] is True\n'
        '        and value["http_service_credentials_observed"] is False\n'
        '        and value["gateway_native_restart_environment_staged"] is True\n'
        '        and value["gateway_lifecycle_logging_staged"] is True\n'
        '        and value["gateway_lifecycle_log_observed"] is False')
    for stem in ("native-common-static-pins", "native-common-deployment-preparation", "native-common-measured-case-request"):
        raw = _change(raw, stem + "/v4", stem + "/v5")
    result[preparation.PREPARATION] = raw
    template = next(row for row in receipt["files"] if row["path"] == writer.HTTP_TEMPLATE_PATH)
    raw = result[writer.SOURCE]
    raw = _change(raw, '_http.load_fixture_binding()', '_http.load_provisioned_fixture_binding()', 2)
    before = '_HTTP_TEMPLATE_PIN = (\n    2189,\n    "sha256:7c9ff65e1e258ae548cd523c8874f8d087313b5ab683aa780d482801fbc6c408",\n)'
    raw = _change(raw, before, '_HTTP_TEMPLATE_PIN = ' + repr((template["bytes"], template["digest"])))
    raw = _change(raw, 'type(template) is dict and canonical_json(template) == template_raw,',
        'type(template) is dict and canonical_json(template) == template_raw\n'
        '                and template.get("logging") == {"level": "info", "file": ' + repr(LIFECYCLE_LOG) + '},')
    result[writer.SOURCE] = raw
    result[setup.SOURCE] = _change(result[setup.SOURCE], "aragorn/native-http-case-setup/v2", "aragorn/native-http-case-setup/v3")
    for name in (identity.IDENTITY, identity.VERIFIER):
        result[name] = _identity(result[name], verifier=name == identity.VERIFIER)
    return result


def render(original):
    if type(original) is not dict or not set(INPUTS) | {REPORT} <= set(original):
        raise ValueError("HTTP credential helper source inventory changed")
    return _transform(prior.render({name: original[name] for name in INPUTS}), original[REPORT])


compose = render
