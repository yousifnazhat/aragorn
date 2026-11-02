"""Finite HTTP writer extension; renders bytes without importing fixture code.

The generated writer remains setup-only when used with the existing admission
activation interception. Its original no-argument entrypoint cannot invoke the
new required-argument writer. Frozen predecessors are never edited.
"""

from __future__ import annotations

import hashlib

SOURCE = "scripts/runtime_native_receipt_systemd_check.py"
INPUTS = {
    SOURCE: (
        50290,
        "5d1fc2cb45c1acd6a00b2bc42b7e1068c186e2c7fb00c2502372724f0238d8be",
    )
}
HTTP_TEMPLATE_PATH = "/opt/aragorn/runtime-http-gateway-template.json"
HTTP_TEMPLATE_PIN = (
    2189,
    "sha256:7c9ff65e1e258ae548cd523c8874f8d087313b5ab683aa780d482801fbc6c408",
)
HTTP_POLICY_ID = "owned-native-receipt-http-canary"


class NativeHttpWriterRenderError(ValueError):
    """Exact predecessor or finite reversible replacement changed."""


def _change(raw, before, after):
    old, new = before.encode("ascii"), after.encode("ascii")
    if old == new or raw.count(old) != 1 or new in raw:
        raise NativeHttpWriterRenderError("HTTP writer anchor changed")
    result = raw.replace(old, new)
    if result.replace(new, old) != raw:
        raise NativeHttpWriterRenderError("HTTP writer replacement is not reversible")
    return result


_HELPERS = '''
_HTTP_TEMPLATE = Path("/opt/aragorn/runtime-http-gateway-template.json")
_HTTP_TEMPLATE_PIN = (
    2189,
    "sha256:7c9ff65e1e258ae548cd523c8874f8d087313b5ab683aa780d482801fbc6c408",
)


def _http_writer_cleanup(primary, callback):
    # A successful setup exits through a private BaseException sentinel. A real
    # final-guard failure MUST replace that sentinel, not become only a note.
    try:
        callback()
    except BaseException as error:
        if isinstance(primary, (KeyboardInterrupt, SystemExit)):
            primary.add_note("HTTP_WRITER_FINAL_GUARD_OR_CLOSE_FAILED")
            raise primary from error
        if hasattr(primary, "http_provisioning_observation"):
            error.http_provisioning_observation = primary.http_provisioning_observation
        raise error from primary


def _prepare(*, expected_http_fixture, http_attempt_id, http_binding_writer):
    from aragorn import native_phase3_live_identity as _http_identity
    from aragorn import runtime_http_action as _http
    from aragorn import runtime_http_provisioning as _http_provision
    from aragorn.native_phase3_http_fixture import owned_http_fixture
    import json

    _expect(callable(http_binding_writer), "HTTP binding writer callback required")
    _http.effect_for_attempt(http_attempt_id)
    # Binding validation also copies the caller's fixture; no mutable caller
    # mapping is retained as the authority for subsequent writes.
    binding = _http_provision._new_binding(expected_http_fixture)
    expected = binding["fixture"]
    with owned_http_fixture(expected) as held:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        observation = None
        try:
            def read_template():
                return _http_identity._read_at(
                    root, str(_HTTP_TEMPLATE), owner=0, owner_gid=0,
                    modes={0o444}, limit=4096,
                )

            template_raw, template_metadata = read_template()
            _expect(
                (len(template_raw), prior._digest(template_raw)) == _HTTP_TEMPLATE_PIN,
                "HTTP gateway template pin changed",
            )
            template = json.loads(template_raw)
            _expect(
                type(template) is dict and canonical_json(template) == template_raw,
                "HTTP gateway template is not canonical without LF",
            )
            _http_provision._stopped()
            _expect(
                not os.path.lexists(_http.BINDING_PATH)
                and not os.path.lexists(provision._STORE)
                and not os.path.lexists(provision._GENESIS_SOURCE),
                "HTTP setup requires absent credential and native stream",
            )
            held.guard()
            _expect(read_template() == (template_raw, template_metadata),
                    "HTTP gateway template changed before writer capture")
            # Eighth writer expectation is captured BEFORE the absent-only
            # protected write. Callback failure never proceeds to provisioning.
            http_binding_writer(canonical_json(binding))
            held.guard()
            observation = _http_provision.provision_fixture_binding(expected)
            _expect(
                observation.get("completed") is True
                and observation.get("created") is True
                and observation.get("activation_performed") is False
                and observation.get("cleanup_failed") is False
                and observation.get("binding_digest") == canonical_digest(binding)
                and _http.load_fixture_binding() == binding,
                "HTTP credential provisioning or writer binding changed",
            )
            def guard():
                held.guard()
                _expect(read_template() == (template_raw, template_metadata),
                        "HTTP gateway template changed during setup")
                _expect(_http.load_fixture_binding() == binding,
                        "HTTP credential changed during setup")
                _http_provision._stopped()

            def gateway_reader(path):
                _expect(path == _HTTP_TEMPLATE, "HTTP gateway source path changed")
                guard()
                # A fresh parse prevents downstream mutation of the checked
                # template from changing later writer expectations.
                return json.loads(template_raw), {
                    "source": dict(template_metadata),
                    "canonical_bytes": len(template_raw),
                    "canonical_digest": prior._digest(template_raw),
                }

            guard()
            action = _http.action_digests(http_attempt_id, binding)
            try:
                return _prepare_http_inputs(action, gateway_reader, guard)
            finally:
                _http_writer_cleanup(sys.exception(), guard)
        except BaseException as error:
            if observation is not None and not hasattr(error, "http_provisioning_observation"):
                error.http_provisioning_observation = observation
            raise
        finally:
            # The fixture context separately retains namespace/process handles.
            # The root descriptor is ours even on pre-write refusal.
            _http_writer_cleanup(sys.exception(), lambda: os.close(root))


'''


def render(original):
    """Return one exact source replacement; no rendering output is executed."""
    if type(original) is not dict or not set(INPUTS) <= set(original):
        raise NativeHttpWriterRenderError("HTTP writer source inventory changed")
    raw = original[SOURCE]
    size, pin = INPUTS[SOURCE]
    if type(raw) is not bytes or len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
        raise NativeHttpWriterRenderError("HTTP writer predecessor pin changed")
    raw = _change(
        raw,
        "def _prepare() -> dict:\n",
        _HELPERS + "def _prepare_http_inputs(http_action, http_gateway_reader, http_guard) -> dict:\n",
    )
    raw = _change(
        raw,
        '    with patch.object(combined, "_CONFIG", v3._CONFIG):\n',
        '    with patch.object(combined, "_CONFIG", _HTTP_TEMPLATE), patch.object(\n'
        '        combined, "_canonical_source", http_gateway_reader\n'
        '    ):\n',
    )
    raw = _change(
        raw,
        '    fd = os.open(p37c.lineage._PROTECTED, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n'
        '    try:\n'
        '        action = p37c._action_digests(fd, p37b._TARGET, p37b._PAYLOAD)\n'
        '    finally:\n'
        '        os.close(fd)\n',
        '    action = dict(http_action)\n',
    )
    raw = _change(
        raw,
        '        "id": "owned-native-receipt-read-create",\n',
        '        "id": "owned-native-receipt-http-canary",\n',
    )
    raw = _change(
        raw,
        '    _phase("ACTIVATION")\n    _activate(p37c, _fixture_token(p37b))\n',
        '    http_guard()\n'
        '    _phase("ACTIVATION")\n    _activate(p37c, _fixture_token(p37b))\n',
    )
    return {SOURCE: raw}
