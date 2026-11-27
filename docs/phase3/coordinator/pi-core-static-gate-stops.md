# D3: distinguish the static worker's first and final stops

Parent: signed main `5b2dfa4447597875cfea9744c9bed37779d7e788`. No change to the
gate, worker, guest image or launch authority.

The task owner now checks **where the original worker stopped**, not how many times
it appeared stopped. The offline instruction check read the retained 4,176-byte
ARM64 gate (SHA-256 `2a54fd7f91e1349ceecad3ac27ec6d111230c1913f4030ae91a67fa4210cab7a`).
It verified two different return PCs: `0x210524` before the filesystem-view check
and `0x21054c` after it, before the gate can execute Node.

1. Spend the original pair/mode claim. Read FIRST from the claimed, untraced worker
   before publishing its channels, and require it still at FIRST after publication.
2. Before tracer attachment, the owner must observe FINAL on that same worker.
3. The bound tracer thread must independently read FINAL again in tracing-stop
   before the owner returns a one-shot pre-exec receipt. It binds the claim,
   worker generation, gate and pinned Node invocation. The later service release
   requires the owner's internal authorization **as well as** the existing
   executing-observer and health checks. A receipt passed back by a caller grants nothing.

Each sample guards the original process and gate file, reads the syscall row and
executable mapping twice, and retains the matched raw rows. The instruction pointer
must resolve to the reviewed file offset in the protected gate's executable mapping.
Linux arm64 can [clear the syscall number before signal delivery](https://github.com/torvalds/linux/blob/v6.8/arch/arm64/kernel/signal.c#L1133-L1169);
the [kernel proc reader](https://github.com/torvalds/linux/blob/v6.8/fs/proc/base.c#L603-L625)
then reports `-1 SP PC`. The PC is evidence of a **site**, not of the sender or success
of a signal. Unknown rows refuse. The API does not send a signal, attach a tracer,
resume Node, or prove exclusive control over other privileged processes.

## Offline evidence

| Affected stage | Checks | Passing fingerprint (SHA-256) |
| --- | ---: | --- |
| Retained ELF sites and passive reader | 7 | `da20048b8e2dd4d4207be05eeb6dd254db69c637f048599f02131dc99346b391` |
| Ordered stops and pre-Node authorization | 5 | `57118bb1ac20ff2c269192ae700b3e7be209fe15cc76535580ab63827c8b5136` |
| Task-owner dispatch boundary | 11 | `b2ca6e52982e17971b62ee3fe0d88b9e9bbb3a02161f17140250997d6a975b21` |

The new checks failed first on the missing reader/site verifier, order guard and
owner connection. The passing paths used the original binary for instruction
identity and inert process records for stop order. A lone FIRST, repeated FIRST,
FINAL before FIRST, regression to FIRST at the tracer, and a substituted start
time or unit invocation at the same PID all refused. Restoring a substituted
generation did not revive the authorization. Loss of channel custody after the
tracer check prevented the owner from returning its receipt. No live proof or
new qualification sample was produced.

## Remaining

1. **D2:** useful pilot and installed-identity evidence still require their own prerequisites and authorization.
2. **D3:** connect the static tracer to the actual pinned Node exec-stop on the
   same generation, then entrypoint reads, independent replay and retirement.
   Both the service control pump and instrumented sensor loss accounting remain open.
3. **D4:** finish the independent verifier inventory before freezing the deployment.
4. **D5:** separately authorize fresh acceptance, measurements, cleanup and replay.
