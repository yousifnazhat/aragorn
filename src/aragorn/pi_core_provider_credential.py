"""Metadata-only custody of one operator-provided systemd credential source.

Only the service manager reads the held file through its descriptor path. This
owner never reads, copies, hashes, deletes or changes credential bytes. Holding
the source confers neither provider approval nor permission to start a service.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat

from . import pi_core_service_configuration as configuration
from . import pi_core_service_provision as custody
from . import pi_core_os_provision as provision

_SEAL = object()
_PATH = re.compile(r"/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*\Z")
_FILE = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC


class PiProviderCredentialError(provision.PiOsProvisionError):
    """The operator source or its protected lifetime could not be held."""


def _require(value, reason):
    if not value:
        raise PiProviderCredentialError(reason)


def _source_path(path):
    _require(isinstance(path, Path) and path.is_absolute() and
             _PATH.fullmatch(str(path)) is not None and len(str(path)) <= 4096 and
             len(path.parts) <= 34 and not set(path.parts).intersection({".", ".."}) and
             path.parts[1] not in {"proc", "sys", "dev"}, "unsafe provider credential source path")


def _file(descriptor):
    value = os.fstat(descriptor)
    _require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_gid == 0 and
             stat.S_IMODE(value.st_mode) == 0o400 and value.st_nlink == 1 and
             1 <= value.st_size <= 4096 and not os.get_inheritable(descriptor),
             "unsafe provider credential source metadata")
    return provision._identity(value)


class PiProviderCredential:
    """One descriptor-pinned source, usable only in its original root process."""

    __slots__ = ("_seal", "_path", "_chain", "_identities", "_fd", "_identity",
                 "_inputs", "_deadline", "_pid", "_active")

    def __init__(self, seal, path, chain, descriptor, provider_inputs, deadline):
        _require(seal is _SEAL, "provider credential requires its protected factory")
        self._seal, self._path, self._chain = seal, path, chain
        self._identities = [(provision._identity if index == len(chain) - 1 else
                            custody._directory_identity)(os.fstat(fd)) for index, fd in enumerate(chain)]
        self._fd, self._identity = descriptor, _file(descriptor)
        self._inputs, self._deadline = provider_inputs, deadline
        self._pid, self._active = os.getpid(), True

    def _live(self):
        _require(type(self) is PiProviderCredential and getattr(self, "_seal", None) is _SEAL and
                 getattr(self, "_active", False), "provider credential custody is inactive or was not minted")
        provision._require_root()
        provision._deadline(self._deadline)
        _require(os.getpid() == self._pid, "provider credential owner process changed")

    @property
    def provider_inputs(self):
        self._live()
        return self._inputs

    @property
    def deadline(self):
        self._live()
        return self._deadline

    @property
    def source(self):
        self.guard()
        return f"/proc/{self._pid}/fd/{self._fd}"

    @property
    def observation(self):
        self._live()
        return {"schema": "aragorn/pi-core-held-provider-credential/v1",
                "authority": "HELD_SOURCE_METADATA_NOT_PROVIDER_OR_EGRESS_APPROVAL",
                "credential_read": False, "activation_performed": False,
                "phase3_exit_eligible": False}

    def guard(self, *, deadline=None):
        self._live()
        bounded = self._deadline if deadline is None else deadline
        provision._deadline(bounded)
        _require(bounded <= self._deadline, "provider credential guard cannot extend its deadline")
        _require(type(self._inputs) is configuration.PiProviderInputs, "exact public provider custody required")
        self._inputs.guard(deadline=bounded)
        custody._chain_guard(self._path.parent, self._chain, self._identities, bounded)
        _require(_file(self._fd) == self._identity == provision._identity(os.stat(
                 self._path.name, dir_fd=self._chain[-1], follow_symlinks=False)),
                 "provider credential source changed")
        custody._chain_guard(self._path.parent, self._chain, self._identities, bounded)
        provision._deadline(bounded)
        # Cleanup may use the original lease bound; this guard grants no request authority.


@contextmanager
def hold_provider_credential(source, *, provider_inputs, deadline):
    """Hold an already approved operator file; never acquire or read a key."""
    fds, held = [], None
    try:
        provision._require_root()
        provision._deadline(deadline)
        _source_path(source)
        _require(type(provider_inputs) is configuration.PiProviderInputs,
                 "exact public provider custody required")
        provider_inputs.guard(deadline=deadline)
        chain = custody._open_chain(source.parent, deadline)
        fds.extend(chain)
        descriptor = os.open(source.name, _FILE, dir_fd=chain[-1])
        fds.append(descriptor)
        held = PiProviderCredential(_SEAL, source, chain, descriptor, provider_inputs, deadline)
        held.guard()
        yield held
        held.guard()
    finally:
        if held is not None:
            held._active = False
        provision._close_all(list(reversed(fds)))
