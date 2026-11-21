# B101 — refuse stale availability after publication and lock release

The Pi action service may finish writing or reading a grant while it is
valid, then take long enough to release its lock that it is no longer valid.
Previously the recovery and preparation callers could return `AVAILABLE`
using the earlier sample. The manager's independent readback had the same gap
when it closed the handles it used to verify the grant.

The two existing [broker paths](../../../src/aragorn/pi_core_request_recovery.py)
now check the original operation deadline after the lock returns and the
result has been copied. Only an `AVAILABLE` result additionally needs the
current wall clock inside the grant's original issue/expiry interval. A
caller-provided timestamp cannot replace that final sample. Terminal states
are historical facts; reporting them does not require an unexpired grant.

If a read-only operation misses the boundary, it refuses. If publication or
archival was already attempted, the result remains indeterminate: do not
remove written state, renew the grant, retry the write, or retry an effect.
The [independent manager readback](../../../src/aragorn/pi_core_service_lifecycle.py)
likewise withholds its positive status until its lock and handles close and
the clocks still permit a return. A late refusal retains the original grant
and state observations and the known cleanup outcome. The base-only preflight
does not claim the grant is available. None of these snapshots is future
authority: membership, liveness and effect-time checks remain necessary.

**Verification:** Only the two new offline stages ran, both passing on the
first attempt: seven broker return-boundary checks
(`6ce3ef29aff123c79b81e53625fa8aca290e01a2fd800a32ce578ee8ed8ebe24`)
and five manager readback checks
(`1aa80ecde4ff47764eec0fd61fcba6ddf9dda0326c9aa44142d1b7315dea0113`).
Inert clocks crossed the original wall or monotonic boundary during writes
or closes; no actual service, disk, provider, grant publication or effect ran.
After the run, Git flagged a trailing blank line in the seven-check test
file. Removing it changed no implementation, assertion or line location;
the original and final test bytes were compared and their parsed trees,
including locations, matched. No suite was rerun and no cached fingerprint
was relabeled for the formatted file.

1. **D2:** These are source-level recovery guards, not measured pilot timing.
   Keep the B94 manager/service inventories unchanged: they contain older
   sources. Include these changes in the next signed-source successor when
   the worker observer and its private receipt scope are settled. Keep both
   socket directories non-listable and B49 null. The physical output observer,
   state custody, sensor health, full timings and authorized pilot remain open.
2. **D3:** Complete admission, RUN/health, and real workload coverage.
3. **D4:** Close the independent 29-requirement inventory before freezing.
4. **D5:** Separately authorize fresh acceptance, 100 attempts and 100 task
   pairs, followed by cleanup verification and independent replay.
