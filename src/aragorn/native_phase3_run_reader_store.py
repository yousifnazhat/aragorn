"""Exclusive reader claims and evidence in one provisioned root-only directory.

Residue is permanent refusal, never recovery authority. Local root custody does
not establish sensor health, effect authority or independent acquisition proof.
"""

import json
import os
import re
import stat
import sys
import threading

from . import native_phase3_run_reader_response as leaf
from .runtime_action_broker import _file_identity, write_all


_ROOT = ("var", "lib", "aragorn-phase3-reader")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class ReaderStoreError(ValueError):
    def __init__(self, original, cleanup_failures=()):
        super().__init__("reader store refused; preserve every claim and evidence file")
        self.original_failure = original
        self.cleanup_failures = tuple(cleanup_failures)


def _document(raw, maximum):
    leaf._require(type(raw) is bytes and 0 < len(raw) <= maximum, "store record size")

    def refuse_constant(_value):
        raise ValueError("non-finite store record")

    value = json.loads(raw, parse_constant=refuse_constant)
    leaf._require(type(value) is dict and leaf._canonical(value) == raw, "canonical store object")
    return value


class ReaderStore:
    """One minted claim and one evidence retention; no caller-selected path."""

    def __init__(self, claim_raw):
        self._directories, self._files, self._owned = [], [], []
        self._closed = self._uncertain = False
        self._claim_attempted = self._retain_attempted = False
        self._pid = os.getpid()
        self._claim = claim_raw
        try:
            self._environment()
            claim = leaf._keys(_document(claim_raw, 4096), "schema connection_epoch challenge")
            leaf._require(claim["schema"] == "aragorn/native-phase3-run-reader-claim/v1", "claim schema")
            leaf._require(type(claim["connection_epoch"]) is str
                          and re.fullmatch(r"[0-9a-f]{64}", claim["connection_epoch"]), "claim epoch")
            challenge = leaf._keys(claim["challenge"],
                                   "epoch_digest request_digest boundary nonce issued_ns deadline_ns sequence_before")
            for key in ("epoch_digest", "request_digest"):
                leaf._pin(challenge[key])
            leaf._require(challenge["boundary"] == "BEFORE_FIRST_EFFECT"
                          and type(challenge["nonce"]) is str
                          and re.fullmatch(r"[0-9a-f]{64}", challenge["nonce"]), "claim challenge")
            for key in ("issued_ns", "deadline_ns", "sequence_before"):
                leaf._uint(challenge[key])
            leaf._require(challenge["issued_ns"] < challenge["deadline_ns"], "claim interval")
            self._claim_name = "claim-" + leaf._digest(challenge)[7:] + ".json"
            parent = None
            for name in ("/", *_ROOT):
                fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
                self._owned.append(fd)
                metadata = os.fstat(fd)
                leaf._require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 0
                              and not stat.S_IMODE(metadata.st_mode) & 0o022
                              and (name != _ROOT[-1] or stat.S_IMODE(metadata.st_mode) == 0o700),
                              "reader directory custody")
                self._directories.append((parent, name, fd, _file_identity(metadata)[:5]))
                parent = fd
            self._guard()
        except BaseException as original:
            cleanup = self._close_all()
            raise ReaderStoreError(original, cleanup) from original

    def _environment(self):
        leaf._require(not self._closed and not self._uncertain, "closed or uncertain reader store")
        leaf._require(sys.platform == "linux" and os.getresuid() == os.getresgid() == (0, 0, 0)
                      and os.getpid() == threading.get_native_id() == self._pid, "reader store owner changed")

    def _custody(self):
        self._environment()
        for parent, name, fd, identity in self._directories:
            leaf._require(identity == _file_identity(os.fstat(fd))[:5]
                          == _file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5],
                          "reader directory replaced")

    def _guard(self):
        try:
            self._custody()
            for name, fd, identity, raw in self._files:
                leaf._require(identity == _file_identity(os.fstat(fd))
                              == _file_identity(os.stat(name, dir_fd=self._directories[-1][2], follow_symlinks=False)),
                              "reader file replaced")
                leaf._require(os.pread(fd, len(raw) + 1, 0) == raw, "reader file readback changed")
                leaf._require(identity == _file_identity(os.fstat(fd))
                              == _file_identity(os.stat(name, dir_fd=self._directories[-1][2], follow_symlinks=False)),
                              "reader file changed during readback")
            self._custody()
        except BaseException:
            self._uncertain = True
            raise

    def _publish(self, name, raw):
        self._guard()
        parent = self._directories[-1][2]
        try:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o400, dir_fd=parent)
        except FileExistsError:
            # A known duplicate creates no uncertainty; a refused leaf can still be retained.
            self._guard()
            raise
        except BaseException:
            self._uncertain = True
            raise
        self._owned.append(fd)
        try:
            metadata = os.fstat(fd)
            leaf._require(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o400
                          and metadata.st_uid == metadata.st_gid == 0 and metadata.st_nlink == 1
                          and metadata.st_size == 0, "new reader file custody")
            initial = _file_identity(metadata)[:6]
            leaf._require(initial == _file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False))[:6],
                          "new reader file replaced")
            self._guard()
            write_all(fd, raw)
            self._guard()
            metadata = os.fstat(fd)
            leaf._require(_file_identity(metadata)[:6] == initial and metadata.st_size == len(raw),
                          "reader write custody")
            self._files.append((name, fd, _file_identity(metadata), raw))
            self._guard()
            os.fsync(fd)
            self._guard()
            os.fsync(parent)
            self._guard()
            return raw
        except BaseException:
            self._uncertain = True
            raise

    def consume_once(self, claim_raw):
        leaf._require(not self._claim_attempted, "claim callback reused")
        self._claim_attempted = True
        self._guard()
        leaf._require(type(claim_raw) is bytes and claim_raw == self._claim, "claim callback changed")
        return self._publish(self._claim_name, claim_raw)

    def retain(self, evidence_raw, *, expected_digest):
        leaf._require(not self._retain_attempted, "retention callback reused")
        self._retain_attempted = True
        self._guard()
        _document(evidence_raw, 131072)
        leaf._pin(expected_digest)
        leaf._require(leaf._raw_digest(evidence_raw) == expected_digest, "evidence digest")
        self._publish("evidence-" + expected_digest[7:] + ".json", evidence_raw)
        return {"digest": expected_digest, "bytes": len(evidence_raw)}

    def final_readback(self):
        self._guard()

    def _close_all(self):
        self._closed = True
        owned, self._owned = self._owned, []
        failures = []
        for fd in reversed(owned):
            try:
                os.close(fd)
            except BaseException as exc:
                failures.append(exc)
        return failures

    def close(self):
        leaf._require(not self._closed, "reader store already closed")
        failures = self._close_all()
        if failures:
            raise ReaderStoreError(failures[0], failures)
