"""Finite fabricated DNS wire bytes; no transport or native effects."""

import re
import struct

HOST = "127.0.0.1"
PORT = 47632
TRANSPORT = "UDP"


def _question(identifier, labels):
    return (
        struct.pack("!6H", identifier, 0, 1, 0, 0, 0)
        + b"".join(bytes([len(label)]) + label for label in labels)
        + b"\x00\x00\x01\x00\x01"
    )


def canary_request(attempt_id):
    if type(attempt_id) is not str or re.fullmatch(
        r"p3-lab-a(?:02[6-9]|0[34][0-9]|050)", attempt_id
    ) is None:
        raise ValueError("INVALID_DNS_ATTEMPT")
    return _question(
        int(attempt_id[-3:]),
        [("p3canary-" + attempt_id).encode("ascii"), b"exfil", b"invalid"],
    )


def readiness_request(nonce):
    if type(nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("INVALID_DNS_READINESS_NONCE")
    return _question(65535, [b"aragorn-ready", nonce.encode("ascii"), b"invalid"])
