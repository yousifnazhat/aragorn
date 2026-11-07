# D2 provider terminal custody handoff

Base: signed integration `3a56d30767821062239d8a05b018714e2fb904e6`.
Scope: source-only lifecycle/channel correction; no service activation, provider
egress, credential provisioning, retry, deadline extension or qualification.

## Change and trust boundary

The existing provider mediator validates the exact authenticated v2 terminal
RESULT, cleanup and one-shot CONNECT/SEND sequence before calling the held
`PiServiceChannels.retire_provider`. Previously this transition allowed provider
exit in channel checks, but its lifecycle callback still required all services
live. Thus an already-exited one-shot provider could never retire successfully.

The channel now forwards its existing terminal exception only while an internal
one-shot transition is active. Ordinary guards cannot opt into that exception;
nested retirement refuses, and a failed transition clears the temporary flag
without marking the provider retired. Successful retirement remains irreversible.
The lifecycle uses the same captured channel/process expectations, not caller
wire claims, and preserves full checks for the action and sensor services.

A provider still alive receives all existing generation/readback checks. An
exited provider requires its retained PIDFD, exact terminal unit generation and
immutable properties, and empty/removed original cgroup. A collected transient
unit is accepted only with the existing exact unit-absence and held cgroup
empty/removal checks. Foreign generations, reused cgroup names, residual
processes and changed channel peers refuse. Retirement never marks cleanup
complete, closes PIDFDs early, authorizes another provider request, or extends
the original deadline. Normal cleanup remains the existing ownership-safe path.

`retire_provider` is a trusted root in-process API. It does not itself parse an
authenticated provider packet: its existing mediator caller establishes that
precondition. This batch does not claim isolation from malicious root Python or
turn private Python state into a hardware security boundary. Native provider
START remains unavailable; mandatory independent source/health prerequisites
and explicit pilot authorization still block activation.

## Owned files and proposed focused stage

- `src/aragorn/pi_core_service_lifecycle.py`
- `src/aragorn/pi_core_service_channels.py`
- `tests/test_pi_core_service_retirement.py`
- This handoff document.

Proposed stage: `pi-core-service-retirement-offline`, selecting only
`test_pi_core_service_retirement`: **33 new focused checks**, `needs: []`,
`timeout_seconds: 120`. All effects and kernel observations are inert; no old
test classes are imported or inherited and no historical cases are selected.
The lane did not execute this stage, imports, builds or tests. Registration,
review, execution, signed checkpoint and publication belong to the coordinator.
No additional legacy selection is needed: the new module directly composes the
real changed channel and lifecycle guards, including the unchanged unavailable
and no-lifecycle paths, without importing historical test classes.

Exact transitive source input closure: reuse the **82 `src/` paths** in the
already-reviewed `pi-core-service-lifecycle-offline` registry entry, excluding
its old test and fixture paths; add only
`tests/test_pi_core_service_retirement.py`. There are no new implementation
imports. This is an explicit 83-file input set, not a glob, whole-schema sweep
or a dependency on rerunning the old lifecycle stage. Preserve failed records
and run only a materially corrected affected selection if a check fails.

Review covered: the authenticated mediator's terminal caller; channel
retirement/guard/close; lifecycle attachment/live generation, unit collection,
retired generation and cleanup; and the no-lifecycle compatibility path.
No activation/qualification property is promoted by this source-only change.
