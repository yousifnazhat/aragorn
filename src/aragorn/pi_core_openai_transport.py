"""One credential-isolated OpenAI request; no startup, DNS, retry or fallback.

Only the sealed service authority may enter this transport. Protected permits
authorize the first connect/send edges, not atomic revocation of an in-flight
network operation. The original deadline bounds every subsequent I/O. This is
source implementation, not installed credential/egress or Phase 3 evidence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import time

from . import pi_core_openai_responses as codec
from . import runtime_action_broker as broker
from . import runtime_action_service as credentials
from . import runtime_process_profile as process

PROFILE_PATH = Path("/etc/aragorn/pi-provider-profile.json")
CA_PATH = Path("/etc/aragorn/pi-provider-ca.pem")
CREDENTIAL_PATH = Path("/run/credentials/aragorn-pi-provider.service/openai-api-key")
CGROUP = b"0::/system.slice/aragorn-pi-provider.service\n"
HOST = "api.openai.com"
MAX_HEADERS = 16 * 1024
MAX_CA = 1024 * 1024
MAX_RESPONSE = 128 * 1024
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_TOKEN = re.compile(rb"[\x21-\x7e]{1,4096}\Z")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_CODES = frozenset({"PROVIDER_AUTHORITY_REFUSED", "PROVIDER_IDENTITY_REFUSED", "PROVIDER_ENVIRONMENT_REFUSED",
    "PROVIDER_PROFILE_REFUSED", "PROVIDER_FILE_REFUSED", "PROVIDER_CREDENTIAL_REFUSED", "PROVIDER_CA_REFUSED",
    "PROVIDER_DEADLINE_REFUSED", "PROVIDER_CONNECT_FAILED", "PROVIDER_PEER_REFUSED", "PROVIDER_TLS_REFUSED",
    "PROVIDER_SEND_FAILED", "PROVIDER_SHORT_SEND", "PROVIDER_HTTP_REFUSED", "PROVIDER_RESPONSE_LIMIT",
    "PROVIDER_RESPONSE_REFUSED", "PROVIDER_CLEANUP_HOLD", "PROVIDER_TRANSPORT_FAILED"})


class PiOpenAITransportError(RuntimeError):
    """Finite redacted uncertainty; never contains secret/provider error text."""

    def __init__(self, code, *, status="NOT_SUBMITTED", cleanup="OWNED_TRANSPORT_CLOSED",
                 connect_attempted=False, send_attempted=False):
        self.code = code if code in _CODES else "PROVIDER_TRANSPORT_FAILED"
        self.status = status
        self.cleanup = cleanup
        self.connect_attempted = connect_attempted
        self.send_attempted = send_attempted
        super().__init__(self.code)


def _require(value, code):
    if not value:
        raise PiOpenAITransportError(code)


def _remaining(deadline):
    now = time.monotonic()
    _require(type(deadline) in (int, float) and math.isfinite(deadline) and now < deadline <= now + 30,
             "PROVIDER_DEADLINE_REFUSED")
    return deadline - now


def _directory_metadata(info, *, private_uid=None, private_gid=None):
    _require(stat.S_ISDIR(info.st_mode) and not stat.S_IMODE(info.st_mode) & 0o022,
             "PROVIDER_FILE_REFUSED")
    if private_uid is None:
        _require(info.st_uid == info.st_gid == 0, "PROVIDER_FILE_REFUSED")
    else:
        _require(info.st_uid in (0, private_uid) and not stat.S_IMODE(info.st_mode) & 0o227 and
                 (not stat.S_IMODE(info.st_mode) & 0o070 or info.st_gid in (0, private_gid)),
                 "PROVIDER_CREDENTIAL_REFUSED")


def _read_protected(path, *, maximum, private_uid=None, private_gid=None):
    """Hold and recheck every parent; use existing descriptor-relative readers.

    The fixed credential helper is reached through an already-held parent FD,
    never through an ambient CREDENTIALS_DIRECTORY or worker-selected path.
    No owned close is retried; all remaining handles are attempted on failure.
    """
    descriptors, identities = [], []
    raw = None
    failed = None
    cleanup_failed = False
    reader_entered = reader_completed = False
    try:
        descriptor = os.open("/", _DIRECTORY)
        descriptors.append(descriptor)
        for index, name in enumerate((None, *path.parts[1:-1])):
            if name is not None:
                descriptor = os.open(name, _DIRECTORY, dir_fd=descriptors[-1])
                descriptors.append(descriptor)
            info = os.fstat(descriptor)
            private = private_uid is not None and index == len(path.parts) - 2
            _directory_metadata(info, private_uid=private_uid if private else None,
                                private_gid=private_gid if private else None)
            identities.append(broker._directory_identity(info))
        parent = descriptors[-1]
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 0 < before.st_size <= maximum, "PROVIDER_FILE_REFUSED")
        if private_uid is None:
            _require(before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o444,
                     "PROVIDER_FILE_REFUSED")
            reader_entered = True
            raw = broker._read_owned_bytes_at(parent, path.name, max_bytes=maximum,
                expected_uid=0, exact_mode=0o444, label="protected provider public input")
            reader_completed = True
        else:
            _require((before.st_uid == private_uid and stat.S_IMODE(before.st_mode) == 0o400) or
                     (before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) in (0o400, 0o440)),
                     "PROVIDER_CREDENTIAL_REFUSED")
            reader_entered = True
            raw = credentials._read_credential_bytes(Path(f"/proc/self/fd/{parent}") / path.name,
                private_uid, label="provider secret")
            reader_completed = True
        _require(type(raw) is bytes and 0 < len(raw) <= maximum and len(raw) == before.st_size and
                 broker._file_identity(before) == broker._file_identity(
                     os.stat(path.name, dir_fd=parent, follow_symlinks=False)), "PROVIDER_FILE_REFUSED")
        for index, fd in enumerate(descriptors):
            _require(broker._directory_identity(os.fstat(fd)) == identities[index], "PROVIDER_FILE_REFUSED")
            named = os.lstat("/") if index == 0 else os.stat(path.parts[index],
                dir_fd=descriptors[index - 1], follow_symlinks=False)
            _require(broker._directory_identity(named) == identities[index], "PROVIDER_FILE_REFUSED")
    except BaseException as error:
        failed = error.code if isinstance(error, PiOpenAITransportError) else "PROVIDER_FILE_REFUSED"
        # Existing readers close their own descriptor internally. Any exception
        # can include an uncertain close; closing our parents cannot establish
        # that hidden file handle's cleanup. Never retry or claim it closed.
        cleanup_failed = reader_entered and not reader_completed
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException:
                cleanup_failed = True
    if cleanup_failed:
        raw = None
        raise PiOpenAITransportError("PROVIDER_CLEANUP_HOLD", cleanup="CLEANUP_HOLD")
    if failed is not None:
        raw = None
        raise PiOpenAITransportError(failed)
    return raw


def read_profile():
    """Read public configuration without asserting the caller is the service."""
    result = None
    failed = None
    cleanup = "OWNED_TRANSPORT_CLOSED"
    try:
        raw = _read_protected(PROFILE_PATH, maximum=4096)
        result = codec.validate_profile(broker._parse_canonical_document(raw, "provider profile"))
    except BaseException as error:
        failed = error.code if isinstance(error, PiOpenAITransportError) else "PROVIDER_PROFILE_REFUSED"
        cleanup = getattr(error, "cleanup", cleanup)
    if failed is not None:
        raise PiOpenAITransportError(failed, cleanup=cleanup)
    return result


def _identity(profile):
    _require(sys.platform == "linux" and
             (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) ==
             (profile["service_uid"], profile["service_uid"], profile["service_gid"], profile["service_gid"]) and
             all(group == profile["service_gid"] for group in os.getgroups()), "PROVIDER_IDENTITY_REFUSED")
    _require(process._read_virtual_file(Path("/proc/self/cgroup"), 4096) == CGROUP,
             "PROVIDER_IDENTITY_REFUSED")
    denied = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ssl_cert_file", "ssl_cert_dir",
              "requests_ca_bundle", "curl_ca_bundle", "node_extra_ca_certs", "pythonhttpsverify"}
    _require(not any(key.lower() in denied or key.lower().startswith("openai_")
                     for key in os.environ), "PROVIDER_ENVIRONMENT_REFUSED")


def _peer(connection, profile):
    peer = connection.getpeername()
    _require(type(peer) is tuple and len(peer) in (2, 4) and peer[1] == 443 and
             ipaddress.ip_address(peer[0]) == ipaddress.ip_address(profile["address"]) and
             (len(peer) == 2 or peer[3] == 0), "PROVIDER_PEER_REFUSED")


class _Reader:
    """A single bounded HTTP/1.1 response, without file wrappers or retries."""

    def __init__(self, connection, deadline):
        self.connection, self.deadline = connection, deadline
        self.buffer, self.total = bytearray(), 0

    def recv(self):
        self.connection.settimeout(_remaining(self.deadline))
        chunk = self.connection.recv(4096)
        _require(type(chunk) is bytes, "PROVIDER_HTTP_REFUSED")
        self.total += len(chunk)
        _require(self.total <= MAX_RESPONSE + 2 * MAX_HEADERS, "PROVIDER_RESPONSE_LIMIT")
        _remaining(self.deadline)
        return chunk

    def line(self, limit):
        while True:
            end = self.buffer.find(b"\r\n")
            if end >= 0:
                _require(end + 2 <= limit and b"\n" not in self.buffer[:end] and b"\r" not in self.buffer[:end],
                         "PROVIDER_HTTP_REFUSED")
                value = bytes(self.buffer[:end])
                del self.buffer[:end + 2]
                return value
            _require(len(self.buffer) < limit and b"\n" not in self.buffer, "PROVIDER_HTTP_REFUSED")
            chunk = self.recv()
            _require(bool(chunk), "PROVIDER_HTTP_REFUSED")
            self.buffer.extend(chunk)

    def exact(self, count):
        _require(0 <= count <= MAX_RESPONSE, "PROVIDER_RESPONSE_LIMIT")
        while len(self.buffer) < count:
            chunk = self.recv()
            _require(bool(chunk), "PROVIDER_HTTP_REFUSED")
            self.buffer.extend(chunk)
        value = bytes(self.buffer[:count])
        del self.buffer[:count]
        return value

    def eof(self):
        _require(not self.buffer and self.recv() == b"", "PROVIDER_HTTP_REFUSED")


def _response(connection, deadline):
    reader = _Reader(connection, deadline)
    first = reader.line(MAX_HEADERS)
    _require(re.fullmatch(rb"HTTP/1\.1 200(?: [\x20-\x7e]{0,128})?", first) is not None,
             "PROVIDER_HTTP_REFUSED")
    used = len(first) + 2
    headers = {}
    for _ in range(65):
        line = reader.line(MAX_HEADERS - used)
        used += len(line) + 2
        if not line:
            break
        _require(b":" in line and line[:1] not in (b" ", b"\t"), "PROVIDER_HTTP_REFUSED")
        name, value = line.split(b":", 1)
        _require(_HEADER_NAME.fullmatch(name) is not None and
                 all(byte == 9 or 32 <= byte <= 126 for byte in value), "PROVIDER_HTTP_REFUSED")
        name, value = name.lower(), value.strip(b" \t").lower()
        if name in (b"content-length", b"transfer-encoding", b"content-encoding", b"content-type", b"connection", b"trailer"):
            _require(name not in headers, "PROVIDER_HTTP_REFUSED")
            headers[name] = value
    else:
        raise PiOpenAITransportError("PROVIDER_RESPONSE_LIMIT")
    _require(used <= MAX_HEADERS and b"trailer" not in headers and
             headers.get(b"content-encoding", b"identity") == b"identity" and
             re.fullmatch(rb"application/json(?:;[ \t]*charset=utf-8)?", headers.get(b"content-type", b"")) is not None,
             "PROVIDER_HTTP_REFUSED")
    length, transfer = headers.get(b"content-length"), headers.get(b"transfer-encoding")
    _require((length is None) != (transfer is None), "PROVIDER_HTTP_REFUSED")
    if length is not None:
        _require(re.fullmatch(rb"(?:0|[1-9][0-9]{0,8})", length) is not None, "PROVIDER_HTTP_REFUSED")
        count = int(length)
        _require(0 < count <= MAX_RESPONSE, "PROVIDER_RESPONSE_LIMIT")
        body = reader.exact(count)
    else:
        _require(transfer == b"chunked", "PROVIDER_HTTP_REFUSED")
        body = bytearray()
        framing = 0
        for _ in range(1024):
            size = reader.line(16)
            framing += len(size) + 4
            _require(framing <= MAX_HEADERS and re.fullmatch(rb"[0-9a-fA-F]{1,8}", size) is not None,
                     "PROVIDER_HTTP_REFUSED")
            count = int(size, 16)
            _require(len(body) + count <= MAX_RESPONSE, "PROVIDER_RESPONSE_LIMIT")
            if not count:
                _require(reader.line(2) == b"", "PROVIDER_HTTP_REFUSED")
                break
            body.extend(reader.exact(count))
            _require(reader.exact(2) == b"\r\n", "PROVIDER_HTTP_REFUSED")
        else:
            raise PiOpenAITransportError("PROVIDER_RESPONSE_LIMIT")
        _require(bool(body), "PROVIDER_HTTP_REFUSED")
        body = bytes(body)
    reader.eof()
    return body


def execute_openai_request(authority, *, profile):
    """Attempt exactly one pinned connection/request with two fresh permits."""
    from . import pi_core_provider_service as service

    raw_socket = tls_socket = None
    credential = outgoing = None
    connect_attempted = send_attempted = False
    result = None
    failure = None
    cleanup_failed = False
    stage = "PROVIDER_AUTHORITY_REFUSED"
    try:
        _require(type(authority) is service.PiProviderServiceAuthority, stage)
        authority.begin()
        deadline = authority.deadline
        _remaining(deadline)
        stage = "PROVIDER_PROFILE_REFUSED"
        profile = codec.validate_profile(profile)
        _require(profile == authority.profile == read_profile(), stage)
        request, route = authority.request, authority.route
        wire = codec.wire_descriptor(request, route, profile)
        _require(wire == authority.wire, stage)
        body = codec.render_request(request, route)
        _identity(profile)
        stage = "PROVIDER_CA_REFUSED"
        ca = _read_protected(CA_PATH, maximum=MAX_CA)
        _require("sha256:" + hashlib.sha256(ca).hexdigest() == profile["ca_digest"], stage)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=ca.decode("ascii"))
        context.set_alpn_protocols(["http/1.1"])
        stage = "PROVIDER_CREDENTIAL_REFUSED"
        credential = _read_protected(CREDENTIAL_PATH, maximum=4096,
            private_uid=profile["service_uid"], private_gid=profile["service_gid"])
        _require(_TOKEN.fullmatch(credential) is not None, stage)
        outgoing = (b"POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\n"
            b"Authorization: Bearer " + credential + b"\r\nContent-Type: application/json\r\n"
            b"Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)
        # Python bytes cannot promise zeroization. No secret enters a receipt,
        # repr, environment, exception message, subprocess argument or Pi frame.
        credential = None
        address = ipaddress.ip_address(profile["address"])
        raw_socket = socket.socket(socket.AF_INET if address.version == 4 else socket.AF_INET6,
                                   socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        stage = "PROVIDER_AUTHORITY_REFUSED"
        permit = authority.check("CONNECT", wire)
        raw_socket.settimeout(_remaining(deadline))
        service.validate_permit(permit, "CONNECT", wire)
        stage = "PROVIDER_CONNECT_FAILED"
        connect_attempted = True
        raw_socket.connect((str(address), 443))
        _remaining(deadline)
        _peer(raw_socket, profile)
        stage = "PROVIDER_TLS_REFUSED"
        tls_socket = context.wrap_socket(raw_socket, server_hostname=HOST, do_handshake_on_connect=False)
        tls_socket.settimeout(_remaining(deadline))
        tls_socket.do_handshake()
        _remaining(deadline)
        _peer(tls_socket, profile)
        _require(tls_socket.version() in ("TLSv1.2", "TLSv1.3") and
                 tls_socket.selected_alpn_protocol() in (None, "http/1.1") and tls_socket.compression() is None, stage)
        _identity(profile)
        stage = "PROVIDER_AUTHORITY_REFUSED"
        permit = authority.check("SEND", wire)
        tls_socket.settimeout(_remaining(deadline))
        service.validate_permit(permit, "SEND", wire)
        stage = "PROVIDER_SEND_FAILED"
        send_attempted = True
        sent = tls_socket.send(outgoing)
        _require(type(sent) is int and sent == len(outgoing), "PROVIDER_SHORT_SEND")
        outgoing = None
        _remaining(deadline)
        stage = "PROVIDER_HTTP_REFUSED"
        raw = _response(tls_socket, deadline)
        stage = "PROVIDER_RESPONSE_REFUSED"
        result = codec.parse_response(raw, request)
        _remaining(deadline)
    except BaseException as error:
        failure = error.code if isinstance(error, PiOpenAITransportError) else stage
        cleanup_failed = getattr(error, "cleanup", None) == "CLEANUP_HOLD"
    finally:
        credential = outgoing = None
        for connection in (tls_socket, raw_socket):
            if connection is not None:
                try:
                    connection.close()
                except BaseException:
                    cleanup_failed = True
    if cleanup_failed or failure is not None:
        raise PiOpenAITransportError("PROVIDER_CLEANUP_HOLD" if cleanup_failed else failure,
            status="INDETERMINATE" if connect_attempted else "NOT_SUBMITTED",
            cleanup="CLEANUP_HOLD" if cleanup_failed else "OWNED_TRANSPORT_CLOSED",
            connect_attempted=connect_attempted, send_attempted=send_attempted)
    return {"result": result, "cleanup": "OWNED_TRANSPORT_CLOSED",
            "connect_attempted": connect_attempted, "send_attempted": send_attempted}
