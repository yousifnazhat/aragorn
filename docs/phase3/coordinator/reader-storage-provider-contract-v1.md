# Root-owned reader storage and one-shot caller contract

Base: verified published `d87572182584f9c106393a2ca952c69703b6da6d`.
Coordinator ownership: new `src/aragorn/native_phase3_run_reader_store.py`,
`src/aragorn/native_phase3_run_reader_acquisition.py`,
`tests/test_native_phase3_run_reader_store.py`, this contract and the registry.
This assignment does not overlap the RUN lane's independent evidence consumer.
No test, protected runtime directory, deployment or live exchange is released here.

## Scope and interface

Implement the missing durable callbacks and an owning production caller of the
existing `native_phase3_run_reader_response.acquire_reader_response` leaf.
Keep that signed leaf unchanged. The caller API is:

```python
acquire_owned_reader_response(
    connection, *, epoch_raw: bytes, expected_epoch_digest: str,
    request_digest: str, sequence_before: int,
) -> dict
```

The connection is transferred exclusively to this call by the future protected
accepted-transport provider. Existing AF_UNIX/SOCK_SEQPACKET, peer identity,
nonblocking, credentials, PIDFD and namespace checks remain in the existing leaf.
There is no socket path, socketpair, transport fallback or caller-supplied callback.
The caller closes the connection on every terminal outcome, including input
refusal and interruption. Close failures prohibit success and retain the original
failure alongside cleanup failures. Do not retry close on an ambiguous descriptor.

Require the independently caller-held expected epoch digest to match the raw
epoch; deriving its digest alone does not establish expected identity.
After validating the bounded canonical epoch and request/sequence fields, mint a
fresh 32-byte random nonce and separate random connection epoch. Build the exact
existing challenge and seven bindings using the actual CLOCK_BOOTTIME reading
and epoch timeout. Validate with the existing leaf's input contract before use.
Never accept a recovered challenge, caller-selected nonce or previous claim as
resume authority. Fresh issuance after restart prevents absence after a crash
from becoming permission to retry an old challenge. Entropy or clock failure
refuses. The existing leaf checks process/boot/time-domain joins before sending.

Return the reader record only after durable retention, final store readback and
all owned descriptor cleanup succeeds. Also return the exact challenge bytes,
bindings, connection epoch, evidence bytes and digest so an independent caller
can retain/replay the observed result. Preserve these values and any partial
evidence on a bounded custom exception when the call fails; represent unavailable
values explicitly. None of these metadata joins establishes sensor health,
acquisition authenticity, effect authority or RUN/Phase 3 qualification.

## Fixed storage custody and callbacks

Use only the root-provisioned fixed directory
`/var/lib/aragorn-phase3-reader`, root:root 0700. Provisioning/installation is a
subsequent coordinator integration obligation. The provider must not create or
repair this directory, change permissions, clean residue or accept a caller path.
Require Linux, stable root UID/GID identity and the original process/main thread.
Hold nofollow directory descriptors from `/` through the fixed root. Each root
ancestor is root-owned and not group/world writable. Recheck held and named
device/inode/mode/UID/GID joins before and after mutations/readback. Unrelated
directory timestamp changes do not invalidate custody. Reject use after close,
fork, thread transfer, identity change or any prior uncertain operation.

Bind one store instance to the exact internally minted canonical claim. The
`consume_once(claim_raw)` callback accepts only those identical bytes and is
one-shot even when it fails. Key the final filename by the nested challenge's
canonical digest, independently of the connection epoch. Use exclusive final-name
creation with O_EXCL/O_NOFOLLOW/CLOEXEC; any existing file, link, directory,
partial/corrupt record or concurrent winner refuses, including identical bytes.
Never overwrite, rename away, expire or delete a claim. Do not take the broker's
serialization lock. A partial write or failed sync leaves permanent refusal
residue and no send authorization.

Reuse safe existing write/identity helpers where applicable, but not replacing
publication or idempotent-existing-claim helpers. Claims are bounded to 4096
bytes; exact regular single-link files are root:root 0400. Complete write,
file fsync, directory fsync and exact held/named readback precede acknowledgment.
Retain file descriptors/identities for a final readback guard before return.

`retain(evidence_raw, expected_digest=...)` has the existing exact callback ABI:
return only `{"digest": expected_digest, "bytes": len(evidence_raw)}` after
bounded canonical evidence (131072 bytes maximum), digest validation, exclusive
immutable publication and the same durability/readback guards. Use a separate
`evidence-<digest>.json` namespace in the fixed root. It is also one-shot; partial
or uncertain evidence remains untouched. The sink retains refused/partial leaf
records as well as complete ACK/TIMEOUT supplements. It does not reinterpret
their semantics or promote the leaf's literal false authority flags.

Retention following a claim failure is allowed only if storage custody itself
remains trustworthy; an uncertain store fails closed. Preserve original failure
and partial bytes in the outer exception when retention cannot succeed.

## Review and selected validation

Before registration: review stable source, all actual imports and generated or
fixture dependencies. New focused checks must cover exclusive duplicate claims
across connection epochs, partial writes/sync failures and residue preservation,
directory/file substitution, symlink/hardlink/owner/mode/size rejection, exact
readback/digest bounds, fork/thread/closed reuse, fresh issuance, production leaf
callback wiring, connection cleanup and original/cleanup/retention failures.
Use only fabricated bytes and mocks or fresh inert temporary storage; no real
protected sink, socket exchange, historical test methods or cache copying.

This completes a persistence provider and its one-shot caller only. The actual
accepted endpoint, telemetry read-loop checkpoint, deployed source inventory,
loss/program/map observations and serialized broker health gate remain explicit
dependencies. A retained ACK alone does not establish any of those properties.
