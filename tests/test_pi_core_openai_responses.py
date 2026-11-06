"""Only pure Responses codec checks; no provider, credential or live operation."""

import copy
import hashlib
import json
import os
import socket
import subprocess
import unittest
from contextlib import ExitStack
from unittest import mock

from aragorn import pi_core_openai_responses as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_provider_mediation as fixtures


def route():
    return {"schema": "aragorn/pi-core-provider-route/v1", "provider": "openai", "api": "openai-responses",
        "model": "explicit-fixture-model", "endpoint": {"scheme": "https", "host": "api.openai.com",
                                                        "port": 443, "path": "/v1"}}


def request():
    value = fixtures.request()
    value["route_digest"] = canonical_digest(route())
    value["payload"]["model"].update(provider="openai", api="openai-responses", id="explicit-fixture-model",
        baseUrl="https://api.openai.com/v1", maxTokens=512)
    return value


def profile():
    # Authored public numeric fixture only; never an asserted/resolved API IP.
    return {"schema": subject.PROFILE_SCHEMA, "service_uid": 1201, "service_gid": 1202,
        "address": "8.8.8.8", "ca_digest": "sha256:" + "c" * 64}


def response():
    return {"id": "resp_fixture", "object": "response", "status": "completed",
        "model": "explicit-fixture-model", "error": None, "incomplete_details": None,
        "output": [{"id": "msg_fixture", "type": "message", "status": "completed", "role": "assistant",
                    "content": [{"type": "output_text", "text": "Owned fixture result", "annotations": [], "logprobs": []}]}],
        "usage": {"input_tokens": 3, "output_tokens": 5, "total_tokens": 8,
                  "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}},
        "temperature": 1.0, "metadata": {"fixture_only": "never forwarded"}}


def function_call():
    return {"type": "function_call", "id": "fc_fixture", "call_id": "call_fixture",
        "name": "aragorn_runtime_create", "status": "completed",
        "arguments": json.dumps({"target_name": "owned.txt", "content": "owned fixture bytes"})}


class PiCoreOpenAIResponsesTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for owner, names in ((socket, ("socket", "socketpair", "create_connection", "getaddrinfo")),
                             (subprocess, ("run", "Popen")), (os, ("open", "system"))):
            for name in names:
                self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("pure codec attempted I/O")))

    def parse(self, value):
        return subject.parse_response(json.dumps(value, ensure_ascii=True).encode("utf-8"), request())

    def refused(self, value):
        with self.assertRaises(subject.PiOpenAIResponsesError):
            self.parse(value)

    def test_profile_is_exact_and_detached_without_dns(self):
        value = profile()
        result = subject.validate_profile(value)
        self.assertEqual(result, value)
        self.assertIsNot(result, value)
        value["address"] = "1.1.1.1"
        self.assertEqual(result["address"], "8.8.8.8")

    def test_canonical_global_ipv6_is_accepted(self):
        value = profile()
        value["address"] = "2001:4860:4860::8888"
        self.assertEqual(subject.validate_profile(value), value)

    def test_profile_identity_schema_and_extra_fields_are_strict(self):
        changes = [lambda value: value.update(schema="other"), lambda value: value.update(service_uid=0),
            lambda value: value.update(service_gid=True), lambda value: value.update(service_uid=2**31),
            lambda value: value.update(secret="fixture"), lambda value: value.pop("service_gid")]
        for mutate in changes:
            value = profile(); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(subject.PiOpenAIResponsesError):
                subject.validate_profile(value)

    def test_ca_digest_requires_exact_lowercase_without_newline(self):
        for digest in ("sha256:" + "C" * 64, "sha256:" + "c" * 64 + "\n", "c" * 64, None):
            value = profile(); value["ca_digest"] = digest
            with self.subTest(digest=digest), self.assertRaises(subject.PiOpenAIResponsesError):
                subject.validate_profile(value)

    def test_non_global_mapped_scoped_and_noncanonical_addresses_refuse(self):
        for address in ("localhost", "127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1",
                "192.0.2.1", "0.0.0.0", "224.0.0.1", "240.0.0.1", "8.8.8.8\n", "008.8.8.8",
                "::", "::1", "fe80::1", "fc00::1", "ff02::1", "::ffff:8.8.8.8",
                "2001:4860:4860::8888%eth0", "2001:4860:4860:0:0:0:0:8888", "2001:db8::1"):
            value = profile(); value["address"] = address
            with self.subTest(address=address), self.assertRaises(subject.PiOpenAIResponsesError):
                subject.validate_profile(value)

    def test_full_request_body_has_fixed_explicit_noncontinuing_contract(self):
        value = request()
        messages = value["payload"]["messages"]
        expected = {"model": value["payload"]["model"]["id"], "input": [
            {"role": message["role"], "content": [{"type": "input_text", "text": message["content"]}]}
            for message in messages],
            "tools": [{"type": "function", **messages[0]["toolsAdded"][0], "strict": True}],
            "parallel_tool_calls": False, "tool_choice": "auto", "store": False, "stream": False,
            "background": False, "truncation": "disabled", "max_output_tokens": 512}
        raw = subject.render_request(value, route())
        self.assertEqual(raw, canonical_json(expected))
        self.assertIs(type(raw), bytes)
        self.assertNotIn(b"timestamp", raw)
        self.assertNotIn(b"activation_id", raw)
        self.assertNotIn(b"baseUrl", raw)

    def test_input_text_blocks_keep_order_and_unicode_without_joining(self):
        value = request()
        value["payload"]["messages"][0]["content"] = [{"type": "text", "text": "first"}, {"type": "text", "text": ""}]
        value["payload"]["messages"][1]["content"] = [{"type": "text", "text": "café 🛡"}, {"type": "text", "text": "second\nline"}]
        body = json.loads(subject.render_request(value, route()))
        self.assertEqual(body["input"][0]["content"], [{"type": "input_text", "text": "first"}, {"type": "input_text", "text": ""}])
        self.assertEqual(body["input"][1]["content"], [{"type": "input_text", "text": "café 🛡"}, {"type": "input_text", "text": "second\nline"}])

    def test_renderer_cannot_change_provider_api_or_base_url(self):
        for field, invalid in (("provider", "other"), ("api", "openai-completions"),
                               ("baseUrl", "https://api.openai.com/v1?override=1")):
            value = request(); value["payload"]["model"][field] = invalid
            with self.subTest(field=field), self.assertRaises(subject.PiOpenAIResponsesError):
                subject.render_request(value, route())

    def test_renderer_refuses_route_endpoint_overrides_even_with_matching_digest(self):
        for field, invalid in (("host", "elsewhere.example"), ("port", 8443), ("path", "/v2"), ("scheme", "http")):
            destination = route(); destination["endpoint"][field] = invalid
            value = request(); value["route_digest"] = canonical_digest(destination)
            with self.subTest(field=field), self.assertRaises(subject.PiOpenAIResponsesError):
                subject.render_request(value, destination)

    def test_model_and_route_digest_are_exact_not_defaults(self):
        for mutate in (lambda value: value.update(route_digest="sha256:" + "a" * 64),
                       lambda value: value["payload"]["model"].update(id="different")):
            value = request(); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(subject.PiOpenAIResponsesError):
                subject.render_request(value, route())

    def test_renderer_refuses_credentials_unknown_fields_and_continuations(self):
        changes = [lambda value: value["payload"]["model"].update(apiKey="not-a-real-key"),
            lambda value: value["payload"].update(previous_response_id="resp_x"),
            lambda value: value["payload"]["messages"].append({"role": "assistant", "content": []}),
            lambda value: value["payload"]["messages"][0]["toolsAdded"][0].update(name="shell")]
        for mutate in changes:
            value = request(); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(subject.PiOpenAIResponsesError):
                subject.render_request(value, route())

    def test_renderer_enforces_body_limit(self):
        with mock.patch.object(subject, "MAX_REQUEST_BYTES", 1), self.assertRaises(subject.PiOpenAIResponsesError):
            subject.render_request(request(), route())

    def test_wire_descriptor_binds_exact_body_endpoint_address_and_profile(self):
        raw = subject.render_request(request(), route())
        self.assertEqual(subject.wire_descriptor(request(), route(), profile()), {
            "schema": subject.WIRE_SCHEMA, "method": "POST", "host": "api.openai.com", "port": 443,
            "path": "/v1/responses", "address": "8.8.8.8",
            "body_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "profile_digest": canonical_digest(profile())})

    def test_changed_prompt_or_profile_changes_corresponding_wire_binding(self):
        original = subject.wire_descriptor(request(), route(), profile())
        value = request(); value["payload"]["messages"][1]["content"] += " changed"
        changed = subject.wire_descriptor(value, route(), profile())
        self.assertNotEqual(changed["body_digest"], original["body_digest"])
        pinned = profile(); pinned["ca_digest"] = "sha256:" + "d" * 64
        self.assertNotEqual(subject.wire_descriptor(request(), route(), pinned)["profile_digest"], original["profile_digest"])

    def test_text_response_projects_only_existing_result_and_usage(self):
        result = self.parse(response())
        self.assertEqual(result, {"schema": subject.mediation.RESULT_SCHEMA, "authority": subject.mediation.RESULT_AUTHORITY,
            "request_digest": canonical_digest(request()), "status": "COMPLETED", "completion": {
                "stop_reason": "stop", "content": [{"type": "text", "text": "Owned fixture result"}],
                "usage": {"input_tokens": 3, "output_tokens": 5}}})
        self.assertEqual(subject.mediation.validate_provider_result(result, canonical_digest(request())), result)
        self.assertNotIn("never forwarded", canonical_json(result).decode("ascii"))

    def test_text_response_preserves_content_order_unicode_and_empty_text(self):
        value = response()
        value["output"][0]["content"] = [{"type": "output_text", "text": text} for text in ("café 🛡", "", "last")]
        self.assertEqual([part["text"] for part in self.parse(value)["completion"]["content"]], ["café 🛡", "", "last"])

    def test_one_function_call_uses_call_id_not_provider_item_id(self):
        value = response(); value["output"] = [function_call()]
        result = self.parse(value)["completion"]
        self.assertEqual(result["stop_reason"], "toolUse")
        self.assertEqual(result["content"], [{"type": "toolCall", "id": "call_fixture", "name": "aragorn_runtime_create",
            "arguments": {"target_name": "owned.txt", "content": "owned fixture bytes"}}])

    def test_mixed_text_and_single_call_keep_order(self):
        value = response(); value["output"].append(function_call())
        self.assertEqual([part["type"] for part in self.parse(value)["completion"]["content"]], ["text", "toolCall"])

    def test_known_reasoning_metadata_is_validated_then_discarded(self):
        value = response(); value["output"].insert(0, {"type": "reasoning", "id": "rs_fixture", "status": "completed",
            "summary": [{"type": "summary_text", "text": "discard-summary"}],
            "content": [{"type": "reasoning_text", "text": "discard-reasoning"}], "encrypted_content": "discard-encrypted"})
        result = self.parse(value)
        self.assertNotIn("discard-", canonical_json(result).decode("ascii"))
        self.assertEqual(len(result["completion"]["content"]), 1)

    def test_unknown_or_executable_reasoning_fields_refuse(self):
        for item in ({"type": "reasoning", "id": "rs", "summary": [], "tool": "shell"},
                     {"type": "reasoning", "id": "rs", "summary": [{"type": "function_call", "text": "bad"}]}):
            value = response(); value["output"].insert(0, item); self.refused(value)

    def test_noncompleted_statuses_never_become_success(self):
        for status in ("in_progress", "incomplete", "failed", "cancelled", "queued", None):
            value = response(); value["status"] = status
            with self.subTest(status=status): self.refused(value)

    def test_error_or_incomplete_details_refuse_without_raw_error_leak(self):
        for field in ("error", "incomplete_details"):
            value = response(); value[field] = {"message": "FIXTURE_PROVIDER_SECRET"}
            with self.assertRaises(subject.PiOpenAIResponsesError) as caught:
                self.parse(value)
            self.assertNotIn("FIXTURE_PROVIDER_SECRET", str(caught.exception))

    def test_response_model_must_match_explicit_request(self):
        value = response(); value["model"] = "alias-or-another-model"; self.refused(value)

    def test_wrong_response_object_missing_required_fields_and_nonobject_refuse(self):
        value = response(); value["object"] = "chat.completion"; self.refused(value)
        value = response(); value.pop("error"); self.refused(value)
        for value in ([], None, "response"):
            with self.subTest(value=value): self.refused(value)

    def test_refusal_is_not_converted_into_a_text_completion(self):
        value = response(); value["output"][0]["content"] = [{"type": "refusal", "refusal": "no"}]
        self.refused(value)

    def test_unknown_hosted_or_programmatic_output_items_refuse(self):
        for kind in ("web_search_call", "computer_call", "code_interpreter_call", "program", "function_call_output"):
            value = response(); value["output"].append({"type": kind})
            with self.subTest(kind=kind): self.refused(value)

    def test_unknown_function_or_multiple_calls_refuse(self):
        value = response(); call = function_call(); call["name"] = "shell"; value["output"] = [call]
        self.refused(value)
        value["output"] = [function_call(), function_call()]; self.refused(value)

    def test_async_namespaced_and_indirect_function_calls_refuse(self):
        for fields in ({"async": True}, {"namespace": "other"}, {"caller": {"type": "program", "caller_id": "p"}}):
            value = response(); call = function_call(); call.update(fields); value["output"] = [call]
            with self.subTest(fields=fields): self.refused(value)

    def test_explicit_direct_synchronous_function_metadata_is_filtered(self):
        value = response(); call = function_call(); call.update({"async": False, "caller": {"type": "direct"}})
        value["output"] = [call]
        self.assertNotIn("caller", self.parse(value)["completion"]["content"][0])

    def test_bad_function_arguments_remain_refused_by_existing_create_contract(self):
        for args in ({"target_name": "../escape", "content": "x"}, {"target_name": "ok.txt", "content": "x", "extra": 1},
                     {"target_name": "ok.txt", "content": 1}, [], None):
            value = response(); call = function_call(); call["arguments"] = json.dumps(args); value["output"] = [call]
            with self.subTest(args=args): self.refused(value)

    def test_duplicate_keys_inside_function_argument_json_refuse(self):
        value = response(); call = function_call()
        call["arguments"] = '{"target_name":"ok.txt","content":"one","content":"two"}'
        value["output"] = [call]; self.refused(value)

    def test_duplicate_response_keys_and_nonfinite_numbers_refuse(self):
        raw = json.dumps(response()).encode("utf-8")
        for changed in (raw.replace(b'"status": "completed"', b'"status":"completed","status":"completed"', 1),
                        raw.replace(b'"temperature": 1.0', b'"temperature": NaN'),
                        raw.replace(b'"temperature": 1.0', b'"temperature": 1e999')):
            with self.subTest(changed=changed[:30]), self.assertRaises(subject.PiOpenAIResponsesError):
                subject.parse_response(changed, request())

    def test_invalid_utf8_lone_surrogates_and_trailing_documents_refuse(self):
        raw = json.dumps(response()).encode("utf-8")
        for changed in (b"\xff", raw + b"{}", raw.replace(b"Owned fixture result", b"\\ud800")):
            with self.subTest(changed=changed[:30]), self.assertRaises(subject.PiOpenAIResponsesError):
                subject.parse_response(changed, request())

    def test_response_byte_and_structure_bounds_refuse(self):
        for raw in (b" " * (subject.MAX_RESPONSE_BYTES + 1), b"[" * 40 + b"0" + b"]" * 40, b"", bytearray(b"{}")):
            with self.subTest(length=len(raw)), self.assertRaises(subject.PiOpenAIResponsesError):
                subject.parse_response(raw, request())

    def test_empty_or_reasoning_only_output_is_not_a_completion(self):
        for output in ([], [{"type": "reasoning", "id": "rs", "summary": []}]):
            value = response(); value["output"] = output; self.refused(value)

    def test_output_items_and_final_content_limits_refuse(self):
        value = response(); value["output"] *= 33; self.refused(value)
        value = response(); value["output"][0]["content"] *= 17; self.refused(value)
        value = response(); value["output"][0]["content"][0]["text"] = "x" * 32769; self.refused(value)

    def test_item_status_role_and_unknown_message_fields_refuse(self):
        for fields in ({"status": "incomplete"}, {"role": "user"}, {"tool_calls": []}, {"phase": "unknown"}):
            value = response(); value["output"][0].update(fields)
            with self.subTest(fields=fields): self.refused(value)

    def test_usage_is_required_integer_bounded_and_consistent(self):
        for usage in (None, {"input_tokens": 1, "output_tokens": 2},
            {"input_tokens": True, "output_tokens": 2, "total_tokens": 3},
            {"input_tokens": 1, "output_tokens": 2.0, "total_tokens": 3},
            {"input_tokens": -1, "output_tokens": 2, "total_tokens": 1},
            {"input_tokens": 1, "output_tokens": 2, "total_tokens": 4},
            {"input_tokens": 2**53, "output_tokens": 0, "total_tokens": 2**53}):
            value = response(); value["usage"] = usage
            with self.subTest(usage=usage): self.refused(value)

    def test_response_parser_rejects_non_openai_request_profile(self):
        value = request(); value["payload"]["model"]["provider"] = "other"
        with self.assertRaises(subject.PiOpenAIResponsesError):
            subject.parse_response(json.dumps(response()).encode(), value)


if __name__ == "__main__":
    unittest.main()
