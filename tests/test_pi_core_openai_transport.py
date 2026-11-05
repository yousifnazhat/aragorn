"""New OpenAI transport checks; every network, TLS, identity and file edge is mocked.

The actual transport/parser/codecs run. No actual credential, socket, TLS trust,
provider response, process, DNS lookup or service is used or proven here.
"""

import copy
import hashlib
import json
import linecache
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_openai_transport as subject
from aragorn import pi_core_provider_service as service
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_provider_mediation as fixtures


CA = b"-----BEGIN CERTIFICATE-----\nINERT-NOT-A-CERTIFICATE\n-----END CERTIFICATE-----\n"
SECRET = b"inert-test-key-NOT-A-REAL-CREDENTIAL"


def data():
    request = fixtures.request()
    route = {"schema": "aragorn/pi-core-provider-route/v1", "provider": "openai", "api": "openai-responses",
             "model": "fixture-model", "endpoint": {"scheme": "https", "host": "api.openai.com", "port": 443, "path": "/v1"}}
    request["route_digest"] = canonical_digest(route)
    request["payload"]["model"].update(provider="openai", api="openai-responses", id="fixture-model",
                                       baseUrl="https://api.openai.com/v1")
    profile = {"schema": "aragorn/pi-core-openai-profile/v1", "service_uid": 8001, "service_gid": 8002,
               "address": "8.8.8.8", "ca_digest": "sha256:" + hashlib.sha256(CA).hexdigest()}
    return request, route, profile


def response_body():
    return canonical_json({"object": "response", "status": "completed", "model": "fixture-model",
        "error": None, "incomplete_details": None,
        "output": [{"type": "message", "id": "fixture-message", "status": "completed", "role": "assistant",
                    "content": [{"type": "output_text", "text": "owned fixture output", "annotations": []}]}],
        "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}})


def http_response(*, body=None, headers=None, status=b"HTTP/1.1 200 OK"):
    body = response_body() if body is None else body
    headers = [b"Content-Type: application/json", b"Content-Length: " + str(len(body)).encode()] if headers is None else headers
    return status + b"\r\n" + b"\r\n".join(headers) + b"\r\n\r\n" + body


def preserve_traceback_diagnostics(stack):
    # Python 3.14 imports os locally inside linecache. Keep traceback filenames
    # and line numbers, but omit source lookup while product OS edges are trapped.
    stack.enter_context(mock.patch.object(linecache, "getlines", return_value=[]))
    stack.enter_context(mock.patch.object(linecache, "checkcache", return_value=None))


class InertTransportTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        preserve_traceback_diagnostics(self.stack)
        self.events = []
        for owner, name in ((socket, "socketpair"), (socket, "create_connection"), (socket, "getaddrinfo"),
                            (socket, "gethostbyname"), (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        for name in ("open", "close", "read", "lstat", "stat", "fstat", "write", "mkdir", "unlink", "rename"):
            self.stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError("unmocked filesystem access")))
        for name in ("fork", "posix_spawn", "posix_spawnp", "pidfd_open"):
            self.stack.enter_context(mock.patch.object(os, name, create=True, side_effect=AssertionError("process operation forbidden")))
        self.stack.enter_context(mock.patch.object(subject.sys, "platform", "linux"))
        # macOS lacks this Linux flag; socket construction itself is mocked.
        self.stack.enter_context(mock.patch.object(socket, "SOCK_CLOEXEC", 0x80000, create=True))
        for name, value in (("getuid", 8001), ("geteuid", 8001), ("getgid", 8002), ("getegid", 8002)):
            self.stack.enter_context(mock.patch.object(os, name, return_value=value))
        self.groups = self.stack.enter_context(mock.patch.object(os, "getgroups", return_value=[]))
        self.stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
        self.cgroup = self.stack.enter_context(mock.patch.object(subject.process, "_read_virtual_file", return_value=subject.CGROUP))
        self.now = self.stack.enter_context(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.request, self.route, self.profile = data()
        self.wire = subject.codec.wire_descriptor(self.request, self.route, self.profile)
        self.authority = object.__new__(service.PiProviderServiceAuthority)
        for name, value in (("request", self.request), ("route", self.route), ("profile", self.profile),
                            ("wire", self.wire), ("deadline", 110.0)):
            self.stack.enter_context(mock.patch.object(service.PiProviderServiceAuthority, name,
                new_callable=mock.PropertyMock, side_effect=lambda v=value: copy.deepcopy(v)))
        self.begin = self.stack.enter_context(mock.patch.object(service.PiProviderServiceAuthority, "begin",
            side_effect=lambda: self.events.append("begin")))
        self.check = self.stack.enter_context(mock.patch.object(service.PiProviderServiceAuthority, "check",
            side_effect=lambda phase, wire: self.events.append(("check", phase)) or (phase, copy.deepcopy(wire))))
        self.permit = self.stack.enter_context(mock.patch.object(service, "validate_permit",
            side_effect=lambda permit, phase, wire: self.events.append(("permit", phase))))

        def read(path, **kwargs):
            self.events.append(("read", str(path)))
            return {subject.PROFILE_PATH: canonical_json(self.profile), subject.CA_PATH: CA,
                    subject.CREDENTIAL_PATH: SECRET}[path]

        self.read = self.stack.enter_context(mock.patch.object(subject, "_read_protected", side_effect=read))
        self.raw = mock.Mock(name="inert raw socket")
        self.tls = mock.Mock(name="inert TLS socket")
        for connection, name in ((self.raw, "raw"), (self.tls, "tls")):
            connection.getpeername.return_value = (self.profile["address"], 443)
            connection.close.side_effect = lambda n=name: self.events.append(("close", n))
        self.raw.connect.side_effect = lambda destination: self.events.append(("connect", destination))
        self.tls.do_handshake.side_effect = lambda: self.events.append("handshake")
        self.tls.version.return_value = "TLSv1.3"
        self.tls.selected_alpn_protocol.return_value = "http/1.1"
        self.tls.compression.return_value = None
        self.sent = []

        def send(raw):
            self.events.append("send")
            self.sent.append(raw)
            return len(raw)

        self.tls.send.side_effect = send
        self.tls.recv.side_effect = [http_response(), b""]
        self.context = mock.Mock(name="inert TLS context")
        self.context.wrap_socket.return_value = self.tls
        self.context_factory = self.stack.enter_context(mock.patch.object(ssl, "SSLContext", return_value=self.context))
        self.socket_factory = self.stack.enter_context(mock.patch.object(socket, "socket", return_value=self.raw))

    def execute(self):
        return subject.execute_openai_request(self.authority, profile=self.profile)

    def refused(self, code=None, *, connected=False, sent=False, cleanup="OWNED_TRANSPORT_CLOSED"):
        with self.assertRaises(subject.PiOpenAITransportError) as caught:
            self.execute()
        error = caught.exception
        self.assertEqual(error.status, "INDETERMINATE" if connected else "NOT_SUBMITTED")
        self.assertEqual(error.connect_attempted, connected)
        self.assertEqual(error.send_attempted, sent)
        self.assertEqual(error.cleanup, cleanup)
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertNotIn(SECRET.decode(), str(error))
        self.assertIn(error.code, subject._CODES)
        if code is not None:
            self.assertEqual(error.code, code)
        return error

    def test_actual_codec_parser_and_transport_perform_one_bound_request_then_close(self):
        observed = self.execute()
        self.assertEqual(observed["cleanup"], "OWNED_TRANSPORT_CLOSED")
        self.assertEqual(observed["result"]["status"], "COMPLETED")
        self.assertEqual(observed["result"]["request_digest"], canonical_digest(self.request))
        self.assertEqual(observed["result"]["completion"]["content"], [{"type": "text", "text": "owned fixture output"}])
        self.assertTrue(observed["connect_attempted"] and observed["send_attempted"])
        self.assertEqual(len(self.sent), 1)
        header, body = self.sent[0].split(b"\r\n\r\n", 1)
        self.assertEqual(body, subject.codec.render_request(self.request, self.route))
        self.assertIn(b"Authorization: Bearer " + SECRET, header)
        self.assertIn(b"Connection: close", header)
        self.assertNotIn(SECRET.decode(), json.dumps(observed))
        self.assertEqual(self.events[-2:], [("close", "tls"), ("close", "raw")])
        self.assertLess(self.events.index(("permit", "CONNECT")), self.events.index(("connect", ("8.8.8.8", 443))))
        self.assertLess(self.events.index("handshake"), self.events.index(("check", "SEND")))
        self.assertEqual(self.events[self.events.index("send") - 1], ("permit", "SEND"))

    def test_only_explicit_ca_sni_certificate_verification_and_http11_are_configured(self):
        self.execute()
        self.context_factory.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(self.context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertIs(self.context.check_hostname, True)
        self.assertEqual(self.context.verify_mode, ssl.CERT_REQUIRED)
        self.context.load_verify_locations.assert_called_once_with(cadata=CA.decode("ascii"))
        self.context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
        self.context.wrap_socket.assert_called_once_with(self.raw, server_hostname="api.openai.com", do_handshake_on_connect=False)

    def test_plain_json_authority_is_not_a_capability(self):
        with self.assertRaises(subject.PiOpenAITransportError):
            subject.execute_openai_request({}, profile=self.profile)
        self.begin.assert_not_called()
        self.socket_factory.assert_not_called()

    def test_source_profile_must_match_held_authority_and_protected_file(self):
        self.profile["address"] = "1.1.1.1"
        self.refused("PROVIDER_PROFILE_REFUSED")
        self.socket_factory.assert_not_called()

    def test_wrong_service_identity_or_extra_groups_prevents_socket(self):
        self.groups.return_value = [8002, 999]
        self.refused("PROVIDER_IDENTITY_REFUSED")
        self.socket_factory.assert_not_called()

    def test_wrong_cgroup_prevents_socket(self):
        self.cgroup.return_value = b"0::/user.slice/worker\n"
        self.refused("PROVIDER_IDENTITY_REFUSED")
        self.socket_factory.assert_not_called()

    def test_proxy_api_key_and_ca_environment_overrides_are_rejected(self):
        for key in ("HTTPS_PROXY", "OPENAI_API_KEY", "SSL_CERT_FILE", "requests_ca_bundle"):
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: "inert"}):
                self.refused("PROVIDER_ENVIRONMENT_REFUSED")
        self.socket_factory.assert_not_called()

    def test_ca_digest_mismatch_does_not_load_trust_or_connect(self):
        original = self.read.side_effect
        self.read.side_effect = lambda path, **kwargs: b"changed" if path == subject.CA_PATH else original(path, **kwargs)
        self.refused("PROVIDER_CA_REFUSED")
        self.context_factory.assert_not_called()

    def test_secret_whitespace_crlf_non_ascii_and_oversize_are_refused(self):
        original = self.read.side_effect
        for secret in (b"", b"secret\r\nX: injected", b"secret key", b"\xff", b"x" * 4097):
            with self.subTest(secret_length=len(secret)):
                self.read.side_effect = lambda path, _secret=secret, **kwargs: _secret if path == subject.CREDENTIAL_PATH else original(path, **kwargs)
                self.refused("PROVIDER_CREDENTIAL_REFUSED")
        self.socket_factory.assert_not_called()

    def test_connect_permit_refusal_never_attempts_connection(self):
        self.check.side_effect = RuntimeError(SECRET.decode())
        self.refused("PROVIDER_AUTHORITY_REFUSED")
        self.raw.connect.assert_not_called()
        self.raw.close.assert_called_once()

    def test_local_expired_connect_permit_never_attempts_connection(self):
        self.permit.side_effect = RuntimeError(SECRET.decode())
        self.refused("PROVIDER_AUTHORITY_REFUSED")
        self.raw.connect.assert_not_called()

    def test_send_permit_is_fresh_after_handshake_and_refusal_never_sends(self):
        self.check.side_effect = lambda phase, wire: (_ for _ in ()).throw(RuntimeError("expired health")) if phase == "SEND" else object()
        self.refused("PROVIDER_AUTHORITY_REFUSED", connected=True)
        self.tls.send.assert_not_called()

    def test_connection_failure_is_never_retried_or_mislabeled_not_submitted(self):
        self.raw.connect.side_effect = OSError(SECRET.decode())
        self.refused("PROVIDER_CONNECT_FAILED", connected=True)
        self.raw.connect.assert_called_once()
        self.tls.send.assert_not_called()

    def test_connected_peer_must_equal_pinned_numeric_address(self):
        self.raw.getpeername.return_value = ("127.0.0.1", 443)
        self.refused("PROVIDER_PEER_REFUSED", connected=True)
        self.context.wrap_socket.assert_not_called()

    def test_tls_handshake_error_never_sends_a_credential(self):
        self.tls.do_handshake.side_effect = ssl.SSLError(SECRET.decode())
        self.refused("PROVIDER_TLS_REFUSED", connected=True)
        self.tls.send.assert_not_called()

    def test_unexpected_alpn_or_tls_version_cannot_select_another_protocol(self):
        self.tls.selected_alpn_protocol.return_value = "h2"
        self.refused("PROVIDER_TLS_REFUSED", connected=True)
        self.tls.send.assert_not_called()

    def test_partial_send_is_indeterminate_and_not_completed_with_another_write(self):
        self.tls.send.side_effect = lambda raw: len(raw) - 1
        self.refused("PROVIDER_SHORT_SEND", connected=True, sent=True)
        self.tls.send.assert_called_once()
        self.tls.recv.assert_not_called()

    def test_send_exception_is_redacted_and_never_retried(self):
        self.tls.send.side_effect = OSError(SECRET.decode())
        self.refused("PROVIDER_SEND_FAILED", connected=True, sent=True)
        self.tls.send.assert_called_once()

    def test_original_deadline_expired_after_tls_refuses_send(self):
        self.tls.do_handshake.side_effect = lambda: setattr(self.now, "return_value", 111.0)
        self.refused("PROVIDER_DEADLINE_REFUSED", connected=True)
        self.tls.send.assert_not_called()

    def test_original_deadline_is_not_renewed_during_body_reads(self):
        self.tls.recv.side_effect = lambda count: setattr(self.now, "return_value", 111.0) or http_response()
        self.refused("PROVIDER_DEADLINE_REFUSED", connected=True, sent=True)

    def test_owned_tls_and_raw_closes_are_attempted_when_one_fails(self):
        self.tls.close.side_effect = OSError(SECRET.decode())
        self.refused("PROVIDER_CLEANUP_HOLD", connected=True, sent=True, cleanup="CLEANUP_HOLD")
        self.raw.close.assert_called_once()

    def test_preconnect_file_cleanup_failure_is_preserved(self):
        self.read.side_effect = subject.PiOpenAITransportError("PROVIDER_CLEANUP_HOLD", cleanup="CLEANUP_HOLD")
        self.refused("PROVIDER_CLEANUP_HOLD", cleanup="CLEANUP_HOLD")
        self.socket_factory.assert_not_called()

    def test_chunked_json_is_bounded_decoded_and_requires_terminal_chunk_and_eof(self):
        body = response_body()
        chunked = hex(len(body))[2:].encode() + b"\r\n" + body + b"\r\n0\r\n\r\n"
        self.tls.recv.side_effect = [http_response(body=chunked,
            headers=[b"Content-Type: application/json", b"Transfer-Encoding: chunked"]), b""]
        self.assertEqual(self.execute()["result"]["status"], "COMPLETED")

    def test_http_redirect_and_non_success_never_follow_another_destination(self):
        self.tls.recv.side_effect = [http_response(status=b"HTTP/1.1 302 Found")]
        self.refused("PROVIDER_HTTP_REFUSED", connected=True, sent=True)
        self.socket_factory.assert_called_once()

    def test_transfer_encoding_content_length_ambiguity_is_rejected(self):
        self.tls.recv.side_effect = [http_response(headers=[b"Content-Type: application/json",
            b"Content-Length: 1", b"Transfer-Encoding: chunked"])]
        self.refused("PROVIDER_HTTP_REFUSED", connected=True, sent=True)

    def test_duplicate_content_length_is_rejected_even_when_equal(self):
        self.tls.recv.side_effect = [http_response(headers=[b"Content-Type: application/json",
            b"Content-Length: 1", b"Content-Length: 1"])]
        self.refused("PROVIDER_HTTP_REFUSED", connected=True, sent=True)

    def test_compression_unknown_encoding_and_close_delimited_body_are_rejected(self):
        for headers in ([b"Content-Type: application/json", b"Content-Length: 1", b"Content-Encoding: gzip"],
                        [b"Content-Type: application/json", b"Transfer-Encoding: identity"],
                        [b"Content-Type: application/json"]):
            with self.subTest(headers=headers):
                self.tls.recv.side_effect = [http_response(headers=headers)]
                self.refused("PROVIDER_HTTP_REFUSED", connected=True, sent=True)

    def test_header_size_count_and_obsolete_folding_are_bounded(self):
        for headers in ([b"X-Too-Large: " + b"x" * subject.MAX_HEADERS],
                        [b"X-Count: value"] * 65, [b" folded: no"]):
            with self.subTest(header_count=len(headers)):
                self.tls.recv.side_effect = [http_response(headers=headers)]
                self.refused(connected=True, sent=True)

    def test_body_limit_precedes_body_read(self):
        self.tls.recv.side_effect = [http_response(body=b"", headers=[b"Content-Type: application/json",
            b"Content-Length: 131073"])]
        self.refused("PROVIDER_RESPONSE_LIMIT", connected=True, sent=True)

    def test_truncated_body_is_indeterminate(self):
        self.tls.recv.side_effect = [http_response()[:-1], b""]
        self.refused("PROVIDER_HTTP_REFUSED", connected=True, sent=True)

    def test_extra_body_bytes_cannot_be_ignored(self):
        self.tls.recv.side_effect = [http_response() + b"second-response"]
        self.refused("PROVIDER_HTTP_REFUSED", connected=True, sent=True)

    def test_complete_body_without_eof_is_not_a_complete_transport(self):
        self.tls.recv.side_effect = [http_response(), TimeoutError("no EOF")]
        self.refused(connected=True, sent=True)

    def test_chunk_extensions_trailers_or_missing_terminator_refuse(self):
        for body in (b"1;extension=yes\r\nx\r\n0\r\n\r\n", b"0\r\nX: trailer\r\n\r\n", b"1\r\nx!"):
            with self.subTest(body=body):
                self.tls.recv.side_effect = [http_response(body=body,
                    headers=[b"Content-Type: application/json", b"Transfer-Encoding: chunked"]), b""]
                self.refused(connected=True, sent=True)

    def test_provider_error_json_is_not_forwarded_or_promoted_to_completion(self):
        self.tls.recv.side_effect = [http_response(body=canonical_json({"error": SECRET.decode()})), b""]
        self.refused("PROVIDER_RESPONSE_REFUSED", connected=True, sent=True)


class ProtectedProviderInputTests(unittest.TestCase):
    """Exercise actual protected readers against a purely mocked file table."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        preserve_traceback_diagnostics(self.stack)
        self.files = {subject.PROFILE_PATH: canonical_json(data()[2]), subject.CA_PATH: CA,
                      subject.CREDENTIAL_PATH: SECRET}
        self.paths = {Path("/")}
        for path in self.files:
            self.paths.update(path.parents)
            self.paths.add(path)
        self.meta = {}
        for index, path in enumerate(sorted(self.paths)):
            is_file = path in self.files
            private = path == subject.CREDENTIAL_PATH or path == subject.CREDENTIAL_PATH.parent
            mode = 0o400 if private and is_file else 0o500 if private else 0o444 if is_file else 0o755
            self.meta[path] = SimpleNamespace(st_dev=1, st_ino=index + 1,
                st_mode=(stat.S_IFREG if is_file else stat.S_IFDIR) | mode,
                st_uid=8001 if private else 0, st_gid=8002 if private else 0,
                st_nlink=1 if is_file else 2, st_size=len(self.files[path]) if is_file else 0,
                st_mtime_ns=1, st_ctime_ns=1)
        self.fds, self.offsets, self.closed, self.opens = {}, {}, [], []

        def opened(path, flags, *, dir_fd=None):
            path = Path(path)
            if str(path).startswith("/proc/self/fd/"):
                parts = path.parts
                path = self.fds[int(parts[-2])] / parts[-1]
            elif dir_fd is not None:
                path = self.fds[dir_fd] / path
            descriptor = len(self.opens) + 10
            self.opens.append((path, flags, dir_fd))
            self.fds[descriptor], self.offsets[descriptor] = path, 0
            if flags & os.O_DIRECTORY and not stat.S_ISDIR(self.meta[path].st_mode):
                raise OSError("not a directory")
            if flags & os.O_NOFOLLOW and stat.S_ISLNK(self.meta[path].st_mode):
                raise OSError("symlink refused")
            return descriptor

        def read(fd, maximum):
            value = self.files[self.fds[fd]][self.offsets[fd]:self.offsets[fd] + maximum]
            self.offsets[fd] += len(value)
            return value

        def named(path, *, dir_fd=None, follow_symlinks=True):
            self.assertFalse(follow_symlinks)
            return self.meta[self.fds[dir_fd] / path]

        self.open = self.stack.enter_context(mock.patch.object(os, "open", side_effect=opened))
        self.read = self.stack.enter_context(mock.patch.object(os, "read", side_effect=read))
        self.stat = self.stack.enter_context(mock.patch.object(os, "stat", side_effect=named))
        self.fstat = self.stack.enter_context(mock.patch.object(os, "fstat", side_effect=lambda fd: self.meta[self.fds[fd]]))
        self.stack.enter_context(mock.patch.object(os, "lstat", side_effect=lambda path: self.meta[Path(path)]))
        self.close = self.stack.enter_context(mock.patch.object(os, "close", side_effect=self.closed.append))
        self.stack.enter_context(mock.patch.object(socket, "socket", side_effect=AssertionError("network forbidden")))
        self.stack.enter_context(mock.patch.object(subprocess, "run", side_effect=AssertionError("process forbidden")))

    def test_public_profile_is_descriptor_read_without_service_identity_assertion(self):
        with mock.patch.object(os, "geteuid", side_effect=AssertionError("public profile must not assert service UID")):
            self.assertEqual(subject.read_profile(), data()[2])
        self.assertEqual(len(self.closed), len(self.opens))
        self.assertEqual(len(set(self.closed)), len(self.closed))
        self.assertTrue(all(flags & os.O_NOFOLLOW for _, flags, _ in self.opens))

    def test_fixed_secret_uses_existing_reader_via_owned_parent_and_closes_all(self):
        value = subject._read_protected(subject.CREDENTIAL_PATH, maximum=4096, private_uid=8001, private_gid=8002)
        self.assertEqual(value, SECRET)
        self.assertEqual(len(self.closed), len(self.opens))
        self.assertEqual(self.opens[-1][0], subject.CREDENTIAL_PATH)
        self.assertTrue(self.opens[-1][1] & os.O_NOFOLLOW)

    def test_writable_or_nonroot_public_ancestor_is_refused(self):
        self.meta[Path("/etc/aragorn")].st_mode = stat.S_IFDIR | 0o777
        with self.assertRaises(subject.PiOpenAITransportError):
            subject.read_profile()
        self.assertEqual(len(self.closed), len(self.opens))

    def test_linked_ancestor_is_not_traversed(self):
        self.meta[Path("/etc/aragorn")].st_mode = stat.S_IFLNK | 0o777
        with self.assertRaises(subject.PiOpenAITransportError):
            subject.read_profile()
        self.assertEqual(len(self.closed), len(self.opens) - 1)

    def test_public_profile_requires_root_readonly_single_link(self):
        self.meta[subject.PROFILE_PATH].st_nlink = 2
        with self.assertRaises(subject.PiOpenAITransportError):
            subject.read_profile()
        self.assertEqual(len(self.closed), len(self.opens))

    def test_private_credential_directory_cannot_be_mutable_by_service(self):
        self.meta[subject.CREDENTIAL_PATH.parent].st_mode = stat.S_IFDIR | 0o700
        with self.assertRaises(subject.PiOpenAITransportError):
            subject._read_protected(subject.CREDENTIAL_PATH, maximum=4096, private_uid=8001, private_gid=8002)
        self.assertEqual(len(self.closed), len(self.opens))

    def test_credential_group_or_other_read_permission_is_rejected(self):
        self.meta[subject.CREDENTIAL_PATH].st_mode = stat.S_IFREG | 0o444
        with self.assertRaises(subject.PiOpenAITransportError):
            subject._read_protected(subject.CREDENTIAL_PATH, maximum=4096, private_uid=8001, private_gid=8002)

    def test_secret_name_replacement_after_read_is_refused(self):
        original = self.stat.side_effect
        count = 0

        def replaced(path, **kwargs):
            nonlocal count
            item = copy.copy(original(path, **kwargs))
            if path == subject.CREDENTIAL_PATH.name:
                count += 1
                if count > 1: item.st_ino += 100
            return item

        self.stat.side_effect = replaced
        with self.assertRaises(subject.PiOpenAITransportError) as caught:
            subject._read_protected(subject.CREDENTIAL_PATH, maximum=4096, private_uid=8001, private_gid=8002)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(len(self.closed), len(self.opens))

    def test_parent_close_failure_attempts_other_owned_closes_and_holds(self):
        def close(fd):
            self.closed.append(fd)
            if fd == 11: raise OSError("close uncertain")

        self.close.side_effect = close
        with self.assertRaises(subject.PiOpenAITransportError) as caught:
            subject.read_profile()
        self.assertEqual(caught.exception.cleanup, "CLEANUP_HOLD")
        self.assertEqual(len(self.closed), len(self.opens))
        self.assertEqual(len(set(self.closed)), len(self.closed))

    def test_existing_credential_reader_close_failure_is_not_hidden_by_parent_cleanup(self):
        def close(fd):
            self.closed.append(fd)
            if self.fds[fd] == subject.CREDENTIAL_PATH:
                raise OSError("credential close uncertain")

        self.close.side_effect = close
        with self.assertRaises(subject.PiOpenAITransportError) as caught:
            subject._read_protected(subject.CREDENTIAL_PATH, maximum=4096, private_uid=8001, private_gid=8002)
        self.assertEqual(caught.exception.code, "PROVIDER_CLEANUP_HOLD")
        self.assertEqual(caught.exception.cleanup, "CLEANUP_HOLD")
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(len(self.closed), len(self.opens))
        self.assertEqual(len(set(self.closed)), len(self.closed))


if __name__ == "__main__":
    unittest.main()
