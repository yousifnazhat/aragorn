"""Render finite HTTP ingress over exact frozen common-profile source bytes.

Only returns source-keyed replacements. No installation, source execution,
credential provisioning, effects, tests or qualification occurs here.
"""

from __future__ import annotations

import hashlib

WORKER = "src/aragorn/runtime_action_worker.py"
SENSOR = "src/aragorn/runtime_action_observation_publisher.py"
PROFILED_SENSOR = "src/aragorn/runtime_action_observation_publisher_v2.py"
RECEIPTS = "src/aragorn/runtime_native_tool_receipts.py"
INGRESS = "src/aragorn/runtime_worker_ingress_measurement.py"
PLUGIN = "packaging/openclaw/aragorn-runtime-action-worker/index.js"
MANIFEST = "packaging/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json"
INTEGRATION = "packaging/openclaw/aragorn-runtime-native-tool-client/integration.cjs"
GATEWAY_CONFIG = (
    "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json"
)
GATEWAY_CONFIG_PIN = (
    2160,
    "sha256:2855474d8b709654fb8902c0dc69ec1f0a3a378518ec23bfb12c1eb9630824ab",
)
INPUTS = {
    WORKER: (
        49327,
        "sha256:1ba2bc446b0561d992ef800d324269ab6a428b2cb3449109fe771029317f850a",
    ),
    SENSOR: (
        21163,
        "sha256:288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90",
    ),
    PROFILED_SENSOR: (
        18345,
        "sha256:39b42a466eb248bbc5d176f9a5350a72f88afe85f98ea492bde882f7a3ba5c8e",
    ),
    RECEIPTS: (
        22210,
        "sha256:b1d3c1d1fcdc3745a166ea39a8123260574a98a0d5e3a0361bf92a43d7581459",
    ),
    INGRESS: (
        20731,
        "sha256:aba3d6b705f9b147fdf89f083ec6edcde7d3165ba1a8008cf4bcdcaee88fe17e",
    ),
    PLUGIN: (
        35434,
        "sha256:193415bea885023664ac44931d9faa096e02b3bc64aafc47113c17aca664566c",
    ),
    MANIFEST: (
        723,
        "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036",
    ),
    INTEGRATION: (
        5149,
        "sha256:a542165168c1d5655cad4fdde1e69609cfd87bfea2b9909a9343bcde00e1bbad",
    ),
}


class HttpIngressRenderError(ValueError):
    """The exact predecessor or a finite reversible anchor changed."""


def _replace(raw, before, after):
    old = before.encode("ascii") if isinstance(before, str) else before
    new = after.encode("ascii") if isinstance(after, str) else after
    if raw.count(old) != 1 or old == new or new in raw:
        raise HttpIngressRenderError("HTTP ingress anchor changed")
    value = raw.replace(old, new)
    if value.replace(new, old) != raw:
        raise HttpIngressRenderError("HTTP ingress replacement is not reversible")
    return value


def _import(raw):
    return _replace(
        raw,
        "from __future__ import annotations\n",
        "from __future__ import annotations\n\n"
        "from . import runtime_http_ingress as _http_ingress\n",
    )


def render_gateway_configuration(raw: bytes) -> bytes:
    """Transform the pinned fixture template before its first protected write.

    This is deliberately separate from installed runtime replacements: the
    common74 profile never included the protected gateway input/template. Its
    owned fixture setup must consume these bytes, not silently reuse create-only
    writer inputs or rewrite an already activated configuration.
    """
    if (
        type(raw) is not bytes
        or len(raw) != GATEWAY_CONFIG_PIN[0]
        or "sha256:" + hashlib.sha256(raw).hexdigest() != GATEWAY_CONFIG_PIN[1]
    ):
        raise HttpIngressRenderError("HTTP gateway configuration predecessor changed")
    return _replace(
        raw,
        b'"alsoAllow":["aragorn_runtime_create","read"]',
        b'"alsoAllow":["aragorn_runtime_create","aragorn_runtime_http_canary","read"]',
    )


_ACTION_CHECK = """            _require(
                action["payload_digest"]
                == "sha256:" + hashlib.sha256(payload).hexdigest()
                and action["operation_digest"]
                == canonical_digest(
                    {
                        "schema": "aragorn/runtime-file-operation/v1",
                        "operation": "create",
                    }
                )
            )
"""

_HTTP_JS = r"""
// Finite HTTP lab action: no host, URL, request bytes or retries are accepted.
const HTTP_TOOL_NAME = "aragorn_runtime_http_canary";
const HTTP_ATTEMPT = /^p3-lab-a(?:00[1-9]|01[0-9]|02[0-5])$/;

function httpEffectParameters(value) {
  if (!exactFields(value, ["attempt_id", ...Object.values(CONTEXT_FIELDS)]) ||
      typeof value.attempt_id !== "string" || !HTTP_ATTEMPT.test(value.attempt_id)) {
    throw new WorkerClientError("HTTP canary parameters are invalid", "NOT_SUBMITTED");
  }
  return value;
}

function buildHttpRequest(context, attemptId) {
  if (typeof attemptId !== "string" || !HTTP_ATTEMPT.test(attemptId) ||
      typeof context.toolCallDigest !== "string" || !DIGEST.test(context.toolCallDigest)) {
    throw new WorkerClientError("HTTP canary request is invalid", "NOT_SUBMITTED");
  }
  return {
    schema: "aragorn/runtime-http-worker-request/v1",
    authority: "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
    attempt_id: attemptId,
    session_id: requireIdentifier(context.sessionId, "session id"),
    run_id: requireIdentifier(context.runId, "run id"),
    tool_call_digest: context.toolCallDigest,
  };
}

function validateHttpBrokerResult(result, request) {
  const fields = [
    "schema", "authority", "request_digest", "effect_digest", "attempt_id",
    "observation_digest", "verdict", "reason_codes", "effect_status", "decision",
    "payload_decision", "transport", "run_conformance_eligible", "phase3_eligible",
    "production_activation_eligible",
  ];
  const effect = {schema: "aragorn/runtime-http-canary-effect/v1",
    operation: "http_canary_post", attempt_id: request.attempt_id};
  if (!exactFields(result, fields) ||
      result.schema !== "aragorn/runtime-http-broker-result/v1" ||
      result.authority !== "BROKER_HTTP_DECISION_ONLY_NOT_SINK_OR_RUN_QUALIFICATION" ||
      typeof result.request_digest !== "string" || !DIGEST.test(result.request_digest) ||
      typeof result.observation_digest !== "string" || !DIGEST.test(result.observation_digest) ||
      result.effect_digest !== sha256(Buffer.from(canonicalJson(effect), "ascii")) ||
      result.attempt_id !== request.attempt_id || !validReasonCodes(result.reason_codes) ||
      result.run_conformance_eligible !== false || result.phase3_eligible !== false ||
      result.production_activation_eligible !== false) {
    throw new WorkerClientError("HTTP broker result binding is invalid", "INDETERMINATE");
  }
  if (result.decision !== null) validateDecision(result.decision, result);
  if (result.payload_decision !== null) validateDecision(result.payload_decision, result);
  const transport = result.transport;
  if (transport !== null) {
    const transportFields = ["schema", "authority", "attempt_id", "fixture_binding_digest",
      "effect_digest", "action_digests", "connect_attempted", "sent_bytes", "response_bytes",
      "response_digest", "status", "error_code", "identity", "blocked_pre_effect",
      "causal_attribution", "measurement_collected", "run_eligible", "phase3_exit_eligible",
      "live_deployment_attested"];
    if (!exactFields(transport, transportFields) ||
        transport.schema !== "aragorn/runtime-http-action-result/v1" ||
        transport.authority !== "CREDENTIAL_BOUND_LAB_HTTP_TRANSPORT_ONLY_NOT_POLICY_AUTHORITY" ||
        transport.attempt_id !== request.attempt_id || transport.effect_digest !== result.effect_digest ||
        typeof transport.fixture_binding_digest !== "string" || !DIGEST.test(transport.fixture_binding_digest) ||
        !exactFields(transport.action_digests, ["operation_digest", "path_digest", "payload_digest"]) ||
        Object.values(transport.action_digests).some((value) => typeof value !== "string" || !DIGEST.test(value)) ||
        ["blocked_pre_effect", "causal_attribution", "measurement_collected", "run_eligible",
          "phase3_exit_eligible", "live_deployment_attested"].some((key) => transport[key] !== false)) {
      throw new WorkerClientError("HTTP transport binding is invalid", "INDETERMINATE");
    }
  }
  const allowed = result.verdict === "ALLOW" && result.effect_status === "SENT" &&
    result.reason_codes.length === 0 && result.decision?.verdict === "ALLOW" &&
    result.payload_decision?.verdict === "ALLOW" && transport?.status === "SENT" &&
    transport.connect_attempted === true && Number.isSafeInteger(transport.sent_bytes) &&
    transport.sent_bytes > 0 && transport.error_code === null;
  const blocked = result.verdict === "BLOCK" && result.effect_status === "NOT_PERFORMED" &&
    result.reason_codes.length > 0 && result.payload_decision === null &&
    (transport === null || (transport.status === "NOT_PERFORMED" &&
      transport.connect_attempted === false && transport.sent_bytes === 0 && transport.response_bytes === 0));
  if (!allowed && !blocked) {
    throw new WorkerClientError("HTTP broker result outcome is invalid", "INDETERMINATE");
  }
}
"""


def _plugin(raw):
    # Reuse the exact correlation and before/finalize hooks for the second tool.
    start = b"function register(api) {\n"
    end = b"\nmodule.exports = {\n"
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise HttpIngressRenderError("HTTP plugin registration anchors changed")
    registration = raw[raw.index(start) : raw.index(end)]
    http_registration = registration
    transforms = (
        ("function register(api) {", "function registerHttp(api) {"),
        ("      name: TOOL_NAME,", "      name: HTTP_TOOL_NAME,"),
        ('label: "Aragorn Runtime Create",', 'label: "Aragorn Runtime HTTP Canary",'),
        (
            'description: "Request one policy-mediated file creation through the Aragorn runtime action worker.",',
            'description: "Request one policy-mediated fixed HTTP canary in the owned isolated lab.",',
        ),
        ('required: ["content", "target_name"],', 'required: ["attempt_id"],'),
        (
            '          content: { type: "string", maxLength: MAX_PAYLOAD_BYTES },\n'
            '          target_name: { type: "string", pattern: TARGET_NAME.source, maxLength: 128 },',
            '          attempt_id: { type: "string", pattern: HTTP_ATTEMPT.source, maxLength: 11 },',
        ),
        ("effectParameters(preparedParams)", "httpEffectParameters(preparedParams)"),
        ("effectParameters(params)", "httpEffectParameters(params)"),
        (
            '          const payload = Buffer.from(bound.content, "utf8");\n'
            "          const request = buildRequest(correlation, bound.target_name, payload);",
            "          const request = buildHttpRequest(correlation, bound.attempt_id);",
        ),
        (
            "{ name: TOOL_NAME, optional: true }",
            "{ name: HTTP_TOOL_NAME, optional: true }",
        ),
    )
    for before, after in transforms:
        http_registration = _replace(http_registration, before, after)
    changes = (
        (start, start + b"  registerHttp(api);\n"),
        (
            "function validateBrokerResult(result, request) {\n",
            "function validateBrokerResult(result, request) {\n"
            '  if (request.schema === "aragorn/runtime-http-worker-request/v1") return validateHttpBrokerResult(result, request);\n',
        ),
        (
            'completed && result.broker_result.verdict === "ALLOW" && result.broker_result.effect_status === "CREATED";',
            'completed && result.broker_result.verdict === "ALLOW" && ["CREATED", "SENT"].includes(result.broker_result.effect_status);',
        ),
        (
            'nativeRequire(toolName === "read" || toolName === TOOL_NAME);',
            'nativeRequire(toolName === "read" || toolName === TOOL_NAME || toolName === HTTP_TOOL_NAME);',
        ),
        (
            "      if (toolName === TOOL_NAME) {\n        const bound = effectParameters(params.snapshot);",
            "      if (toolName === TOOL_NAME || toolName === HTTP_TOOL_NAME) {\n"
            "        const bound = toolName === HTTP_TOOL_NAME ? httpEffectParameters(params.snapshot) : effectParameters(params.snapshot);",
        ),
        (
            "        const request = buildRequest({\n"
            "          runId: correlation.run_id, sessionId: correlation.session_id,\n"
            "          toolCallDigest: correlation.tool_call_digest,\n"
            '        }, bound.target_name, Buffer.from(bound.content, "utf8"));',
            "        const actionContext = {runId: correlation.run_id, sessionId: correlation.session_id,\n"
            "          toolCallDigest: correlation.tool_call_digest};\n"
            "        const request = toolName === HTTP_TOOL_NAME ? buildHttpRequest(actionContext, bound.attempt_id) :\n"
            '          buildRequest(actionContext, bound.target_name, Buffer.from(bound.content, "utf8"));',
        ),
        (
            "    buildRequest,\n",
            "    buildRequest,\n    buildHttpRequest,\n    validateHttpBrokerResult,\n",
        ),
    )
    for before, after in changes:
        raw = _replace(raw, before, after)
    return raw + _HTTP_JS.encode("ascii") + b"\n" + http_registration


def render(original: dict[str, bytes]) -> dict[str, bytes]:
    """Return eight finite replacements keyed by their original source names."""
    if type(original) is not dict:
        raise HttpIngressRenderError("HTTP source mapping refused")
    for name, (size, digest) in INPUTS.items():
        raw = original.get(name)
        if (
            type(raw) is not bytes
            or len(raw) != size
            or "sha256:" + hashlib.sha256(raw).hexdigest() != digest
        ):
            raise HttpIngressRenderError(f"HTTP predecessor changed: {name}")
    output = {name: original[name] for name in INPUTS}
    for name in (WORKER, SENSOR, PROFILED_SENSOR, INGRESS):
        output[name] = _import(output[name])
    changes = {
        WORKER: (
            (
                '"alsoAllow": ["aragorn_runtime_create", "read"],',
                '"alsoAllow": ["aragorn_runtime_create", "aragorn_runtime_http_canary", "read"],',
            ),
            (
                '    document = _exact(value, _REQUEST_FIELDS, "worker request")\n',
                "    if _http_ingress.is_http_request(value):\n        return _http_ingress.worker_request(value)\n"
                '    document = _exact(value, _REQUEST_FIELDS, "worker request")\n',
            ),
            (
                '    action = _action_digests(protected_fd, request["target_name"], payload)\n',
                "    if _http_ingress.is_http_request(request):\n"
                "        return _http_ingress.worker_envelope(request, payload, binding, now_unix)\n"
                '    action = _action_digests(protected_fd, request["target_name"], payload)\n',
            ),
            (
                '    result = _exact(value, _BROKER_RESULT_FIELDS, "broker result")\n',
                "    if _http_ingress.is_http_envelope(envelope):\n"
                "        return _http_ingress.broker_result(value, envelope, binding)\n"
                '    result = _exact(value, _BROKER_RESULT_FIELDS, "broker result")\n',
            ),
            (
                'event["tool_name"] == "aragorn_runtime_create"',
                'event["tool_name"] == _http_ingress.tool_name(validated)',
            ),
        ),
        SENSOR: (
            (
                "    _validate_config(config)\n    pid, uid, gid = _runtime_peer(runtime_peer)\n",
                "    if _http_ingress.is_http_envelope(envelope):\n"
                "        return _http_ingress.observed_submission(envelope, runtime_peer, config)\n"
                "    _validate_config(config)\n    pid, uid, gid = _runtime_peer(runtime_peer)\n",
            ),
        ),
        PROFILED_SENSOR: (
            (
                '        "schema": "aragorn/runtime-observed-create-submission/v2",\n',
                '        "schema": (_http_ingress.PROFILED_SCHEMA if _http_ingress.is_http_envelope(envelope)\n'
                '                   else "aragorn/runtime-observed-create-submission/v2"),\n',
            ),
        ),
        RECEIPTS: (
            (
                'value["tool_name"] in {"read", "aragorn_runtime_create"}',
                'value["tool_name"] in {"read", "aragorn_runtime_create", "aragorn_runtime_http_canary"}',
            ),
        ),
        INGRESS: (
            (
                "    request = _document(value, 64 * 1024)\n",
                "    if _http_ingress.is_http_request(value):\n        return _http_ingress.worker_request(value)\n"
                "    request = _document(value, 64 * 1024)\n",
            ),
            (
                'event["tool_name"] == "aragorn_runtime_create"',
                'event["tool_name"] == _http_ingress.tool_name(request)',
            ),
            (
                _ACTION_CHECK,
                "            if _http_ingress.is_http_request(request):\n"
                "                _require(_http_ingress.action_matches(request, action))\n"
                "            else:\n"
                + "".join(
                    "    " + line for line in _ACTION_CHECK.splitlines(keepends=True)
                ),
            ),
        ),
        INTEGRATION: (
            (
                'toolName !== "read" && toolName !== "aragorn_runtime_create"',
                'toolName !== "read" && toolName !== "aragorn_runtime_create" && toolName !== "aragorn_runtime_http_canary"',
            ),
        ),
        MANIFEST: (
            (
                '"contracts":{"tools":["aragorn_runtime_create"]}',
                '"contracts":{"tools":["aragorn_runtime_create","aragorn_runtime_http_canary"]}',
            ),
            (
                '"toolMetadata":{"aragorn_runtime_create":{"optional":true}}',
                '"toolMetadata":{"aragorn_runtime_create":{"optional":true},"aragorn_runtime_http_canary":{"optional":true}}',
            ),
        ),
    }
    for name, entries in changes.items():
        for before, after in entries:
            output[name] = _replace(output[name], before, after)
    output[PLUGIN] = _plugin(output[PLUGIN])
    return output
