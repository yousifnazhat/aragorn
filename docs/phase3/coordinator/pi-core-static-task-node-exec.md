# D3: observe the pinned Node exec-stop before task release

Parent: signed main `227e437b1ac279b759789b22300bdb407a51b66c`. This
changes the fixed-task owner and observer, not the gate, worker or guest image.

The [final gate authorization](pi-core-static-gate-stops.md) grants a single
opportunity to observe the transition. On the same tracer thread, call
`task.observe_node_exec(observer)` **while the exec event is pending**, before
consuming it. The owner checks the original claim and channel custody on each
side. It does not accept an externally supplied status, executable name or receipt.

- The observer peeks without consuming the event on the original pidfd. It
  requires a trapped exec notification for the claimed PID and UID, not an
  ordinary trap or a later snapshot of a Node process. Linux defines the
  [event status](https://github.com/torvalds/linux/blob/v6.8/include/linux/ptrace.h#L135-L143)
  and [non-consuming wait result](https://github.com/torvalds/linux/blob/v6.8/kernel/exit.c#L1173-L1215).
- While the process is stopped under the original tracer, the observer compares
  the kernel executable handle with the original hash-checked Node descriptor.
  It reads the entire NUL-delimited argv through EOF and checks the process
  start time, systemd invocation and guest clock against the spent claim. The
  reported former thread ID must equal the original singleton PID. A second
  peek must still see the same event.
- A match yields a receipt linked to the exact final-gate authorization. Missing
  or substituted evidence spends this observation opportunity; restoring the
  original fields does not revive it. Service release needs the owner's internal
  match **and** its existing active-observer and health checks. The peek neither
  sets the tracer's executed flag nor claims any entrypoint bytes were read.

## Evidence

The connected check drove the real owner, gate ordering, file-identity and
argv readers on the same held local descriptors, with inert Linux process and
event records. A matching observation passed. A different executable, appended
argument, changed start time or changed unit invocation refused both observation
and release. Other cases rejected a plain trap, consumed event, wrong former TID,
replaced tracer session, replay and loss of channel custody.

| Affected offline stage | Passing checks | Fingerprint (SHA-256) |
| --- | ---: | --- |
| Stopped-role custody | 4 | `c38a49325e700ce1966125509e0913c172075467de8aa99abc0f4b93ad718f7f` |
| Static observer and source binding | 9 | `81d09d1ecbf8f6013e6718ca00d61e56daebbe85829feeb541b47e9641f30554` |
| Gate order and Node exec observation | 8 | `82b33d56bd0ab4da33c7b2528ba1fa8309f386f12639a5de66f4a7ae0a4f95ec` |
| Owner dispatch | 12 | `c9c5c26193e8d9aba8f61beff15c12a1fccf52bff959fe1e8b6241c4e4497b82` |

The new tests first failed on the absent observation and release guards. The
stricter argv read also caught a legacy fixture that returned the first bytes
on every read instead of EOF. Only the fixture was corrected; the refusal remains.
No process tracing, VM execution, provider call, measurement or qualification run.

**Next acceptance:** the static tracer's event handler invokes this observation
before consuming the exec event, and independent replay on the same generation
accepts a complete read of the pinned entrypoint but refuses missing byte ranges
or reads from a substituted file. Neither an exec receipt nor a file hash alone
is evidence that Node consumed the source. D2 pilot, D4 freeze and D5 live
acceptance holds are unchanged.
