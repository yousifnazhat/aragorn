"""Pure, bounded OpenAI Responses projection; no credentials or network access.

The exact projected body is independently computable by the root data gate and
the provider service. A descriptor/digest does not confer send authority. Only
one initial text turn and the existing create tool are supported. Provider
metadata, reasoning and raw errors are never forwarded to the Pi worker.

Wire reference: https://developers.openai.com/api/reference/resources/responses/methods/create
Function schema: https://developers.openai.com/api/docs/guides/function-calling
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re

from . import pi_core_provider_mediation as mediation
from .oci_worker_protocol import canonical_digest, canonical_json

PROFILE_SCHEMA = "aragorn/pi-core-openai-profile/v1"
WIRE_SCHEMA = "aragorn/pi-core-openai-wire/v1"
HOST = "api.openai.com"
PORT = 443
PATH = "/v1/responses"
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 128 * 1024
_SAFE = 2**53 - 1
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")


class PiOpenAIResponsesError(ValueError):
    """Finite codec refusal; contains no provider response or credential bytes."""


def _require(condition, code):
    if not condition:
        raise PiOpenAIResponsesError(code)


def _fields(value, required, optional=frozenset()):
    _require(type(value) is dict and required <= set(value) <= required | optional,
             "OPENAI_FIELDS_REFUSED")


def _text(value, maximum=32768, *, empty=False):
    try:
        valid = type(value) is str and (empty or bool(value)) and len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        valid = False
    _require(valid, "OPENAI_TEXT_REFUSED")


def validate_profile(value):
    """Validate protected configuration only, without DNS or credential reads."""
    _fields(value, {"schema", "service_uid", "service_gid", "address", "ca_digest"})
    _require(value["schema"] == PROFILE_SCHEMA and all(type(value[field]) is int and
             1 <= value[field] <= 2**31 - 1 for field in ("service_uid", "service_gid")),
             "OPENAI_PROFILE_IDENTITY_REFUSED")
    _require(type(value["ca_digest"]) is str and _DIGEST.fullmatch(value["ca_digest"]) is not None,
             "OPENAI_CA_PIN_REFUSED")
    _require(type(value["address"]) is str and len(value["address"]) <= 45 and "%" not in value["address"],
             "OPENAI_ADDRESS_REFUSED")
    try:
        address = ipaddress.ip_address(value["address"])
    except ValueError:
        raise PiOpenAIResponsesError("OPENAI_ADDRESS_REFUSED") from None
    _require(str(address) == value["address"] and address.is_global and not any((
        address.is_private, address.is_loopback, address.is_link_local, address.is_multicast,
        address.is_reserved, address.is_unspecified)) and
        (address.version != 6 or address.ipv4_mapped is None), "OPENAI_ADDRESS_REFUSED")
    return json.loads(canonical_json(value))


def _bound(request, route):
    try:
        request = mediation.validate_provider_request(request)
        route = mediation.validate_route(route)
    except (RuntimeError, ValueError, TypeError, KeyError):
        raise PiOpenAIResponsesError("OPENAI_REQUEST_REFUSED") from None
    model = request["payload"]["model"]
    _require(model["provider"] == route["provider"] == "openai" and
             model["api"] == route["api"] == "openai-responses" and
             model["id"] == route["model"] and model["baseUrl"] == "https://api.openai.com/v1" and
             route["endpoint"] == {"scheme": "https", "host": HOST, "port": PORT, "path": "/v1"} and
             request["route_digest"] == canonical_digest(route), "OPENAI_ROUTE_BINDING_REFUSED")
    return request


def render_request(request, route):
    """Render exact approved text/tool semantics with no discovery or defaults."""
    request = _bound(request, route)
    payload = request["payload"]
    inputs = []
    for message in payload["messages"]:
        content = message["content"]
        texts = [content] if type(content) is str else [part["text"] for part in content]
        inputs.append({"role": message["role"], "content": [
            {"type": "input_text", "text": text} for text in texts]})
    tool = payload["messages"][0]["toolsAdded"][0]
    body = {"model": payload["model"]["id"], "input": inputs,
        "tools": [{"type": "function", **tool, "strict": True}],
        "parallel_tool_calls": False, "tool_choice": "auto", "store": False,
        "stream": False, "background": False, "truncation": "disabled",
        "max_output_tokens": payload["model"]["maxTokens"]}
    raw = canonical_json(body)
    _require(0 < len(raw) <= MAX_REQUEST_BYTES, "OPENAI_REQUEST_LIMIT")
    return raw


def wire_descriptor(request, route, profile):
    profile = validate_profile(profile)
    body = render_request(request, route)
    return {"schema": WIRE_SCHEMA, "method": "POST", "host": HOST, "port": PORT,
        "path": PATH, "address": profile["address"],
        "body_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        "profile_digest": canonical_digest(profile)}


def _decode(raw, maximum):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum, "OPENAI_RESPONSE_LIMIT")

    def pairs(items):
        value = {}
        for key, item in items:
            _require(key not in value, "OPENAI_DUPLICATE_KEY")
            value[key] = item
        return value

    def invalid_constant(_value):
        raise PiOpenAIResponsesError("OPENAI_NONFINITE_NUMBER")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise PiOpenAIResponsesError("OPENAI_JSON_REFUSED") from None
    remaining = 8192

    def visit(item, depth=0):
        nonlocal remaining
        remaining -= 1
        _require(remaining >= 0 and depth <= 32, "OPENAI_STRUCTURE_LIMIT")
        if type(item) is str:
            _text(item, maximum, empty=True)
        elif type(item) is float:
            _require(math.isfinite(item), "OPENAI_NONFINITE_NUMBER")
        elif type(item) is list:
            for child in item:
                visit(child, depth + 1)
        elif type(item) is dict:
            for key, child in item.items():
                _text(key, maximum, empty=True)
                visit(child, depth + 1)
    visit(value)
    return value


def _status(item):
    _require("status" not in item or item["status"] == "completed", "OPENAI_ITEM_INCOMPLETE")


def _reasoning(item):
    """Allow only known non-executable reasoning fields, then discard all."""
    _fields(item, {"type", "id", "summary"}, {"status", "content", "encrypted_content"})
    _text(item["id"], 4096)
    _status(item)
    for field, kind in (("summary", "summary_text"), ("content", "reasoning_text")):
        if field not in item:
            continue
        _require(type(item[field]) is list and len(item[field]) <= 16, "OPENAI_REASONING_REFUSED")
        for part in item[field]:
            _fields(part, {"type", "text"})
            _require(part["type"] == kind, "OPENAI_REASONING_REFUSED")
            _text(part["text"], empty=True)
    if item.get("encrypted_content") is not None:
        _text(item["encrypted_content"], MAX_RESPONSE_BYTES, empty=True)


def parse_response(raw, request):
    """Parse a completed response into a bounded untrusted Pi result only.

    Top-level API metadata is deliberately filtered, not replayed. Output items
    are a closed union: text messages, one fixed function call, and known inert
    reasoning. This function never retries or converts provider refusal/error
    into a completion. Its caller must retain possible-send uncertainty.
    """
    try:
        request = mediation.validate_provider_request(request)
    except (RuntimeError, ValueError, TypeError, KeyError):
        raise PiOpenAIResponsesError("OPENAI_REQUEST_REFUSED") from None
    model = request["payload"]["model"]
    _require(model["provider"] == "openai" and model["api"] == "openai-responses" and
             model["baseUrl"] == "https://api.openai.com/v1", "OPENAI_ROUTE_BINDING_REFUSED")
    value = _decode(raw, MAX_RESPONSE_BYTES)
    required = {"object", "status", "model", "output", "usage", "error", "incomplete_details"}
    _require(type(value) is dict and required <= set(value) and value["object"] == "response" and
             value["status"] == "completed" and value["error"] is None and value["incomplete_details"] is None and
             value["model"] == request["payload"]["model"]["id"], "OPENAI_RESPONSE_NOT_COMPLETED")
    _require(type(value["output"]) is list and 1 <= len(value["output"]) <= 32, "OPENAI_OUTPUT_REFUSED")
    content, calls = [], 0
    for item in value["output"]:
        _require(type(item) is dict, "OPENAI_OUTPUT_REFUSED")
        kind = item.get("type")
        if kind == "reasoning":
            _reasoning(item)
        elif kind == "message":
            _fields(item, {"type", "id", "status", "role", "content"}, {"phase"})
            _text(item["id"], 4096)
            _require(item["status"] == "completed" and item["role"] == "assistant" and
                     ("phase" not in item or item["phase"] in ("commentary", "final_answer")) and
                     type(item["content"]) is list and len(item["content"]) <= 16, "OPENAI_MESSAGE_REFUSED")
            for part in item["content"]:
                _fields(part, {"type", "text"}, {"annotations", "logprobs"})
                _require(part["type"] == "output_text" and all(type(part[field]) is list
                         for field in ("annotations", "logprobs") if field in part), "OPENAI_TEXT_OUTPUT_REFUSED")
                _text(part["text"], empty=True)
                content.append({"type": "text", "text": part["text"]})
        elif kind == "function_call":
            _fields(item, {"type", "call_id", "name", "arguments"}, {"id", "status", "async", "caller"})
            _status(item)
            if "id" in item:
                _text(item["id"], 4096)
            _require("async" not in item or item["async"] is False, "OPENAI_ASYNC_TOOL_REFUSED")
            _require("caller" not in item or item["caller"] is None or item["caller"] == {"type": "direct"},
                     "OPENAI_INDIRECT_TOOL_REFUSED")
            _text(item["call_id"], 4096)
            _text(item["arguments"], MAX_REQUEST_BYTES)
            calls += 1
            _require(calls == 1 and item["name"] == "aragorn_runtime_create", "OPENAI_TOOL_REFUSED")
            args = _decode(item["arguments"].encode("utf-8"), MAX_REQUEST_BYTES)
            content.append({"type": "toolCall", "id": item["call_id"], "name": item["name"], "arguments": args})
        else:
            raise PiOpenAIResponsesError("OPENAI_OUTPUT_REFUSED")
    usage = value["usage"]
    _require(type(usage) is dict and {"input_tokens", "output_tokens", "total_tokens"} <= set(usage) and
             all(type(usage[field]) is int and 0 <= usage[field] <= _SAFE for field in
                 ("input_tokens", "output_tokens", "total_tokens")) and
             usage["total_tokens"] == usage["input_tokens"] + usage["output_tokens"], "OPENAI_USAGE_REFUSED")
    result = {"schema": mediation.RESULT_SCHEMA, "authority": mediation.RESULT_AUTHORITY,
        "request_digest": canonical_digest(request), "status": "COMPLETED", "completion": {
            "stop_reason": "toolUse" if calls else "stop", "content": content,
            "usage": {"input_tokens": usage["input_tokens"], "output_tokens": usage["output_tokens"]}}}
    try:
        return mediation.validate_provider_result(result, canonical_digest(request))
    except (RuntimeError, ValueError, TypeError, KeyError):
        raise PiOpenAIResponsesError("OPENAI_COMPLETION_REFUSED") from None
