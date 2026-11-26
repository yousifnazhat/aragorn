# D3: source observer bound to the fixed static worker

Parent: signed main `2dad10af8d7a897060bec6d95352b093cdb51c48`.
The fixed-task owner now creates the source observer from the bytes of its
durable claim, after both roles have stopped and before publishing their
channels. It does not select a worker from a PID supplied by the task.

The observer borrows duplicates of the owner's original pidfd, proc directory,
unit, gate, Node and entrypoint descriptors. The unit is read in PID 1's view;
the other three files are read in the worker's view. The original hashes and
file identities are checked against the reviewed task-worker release. Later checks
compare the still-open, protected objects with the current names rather than
rehashing Node. The process must still match the claim's start ticks, credentials,
cgroup, unit invocation, guest boot and clock namespace.

The initial receipt is explicitly `STOPPED_BINDING_ONLY`. A different invocation
at the same PID invalidates that intake; restoring the old fields cannot make it
usable again. Passing an observer from another claim to the owner cannot reach the
health or service handoff. The intake neither attaches to the process nor resumes it.
It does not replace the transient launch profile, change the retained guest image, or
issue activation authority.

## Evidence

| New or affected offline stage | Passing checks | Fingerprint |
| --- | ---: | --- |
| Static observer binding and intake | 8 | `890838d6656e95dc9b77bf587651c6e1f96824449975b0d91d7b1ac052f18032` |
| Original stopped-role custody | 4 | `91bb62c6096aaa5c538f64b1b6e06a99e4bdbb376a7d64698cf37b0151cb6ec6` |
| Claim-to-dispatch integration | 9 | `4ef7047efbe06d1fb3af4b1c1dfe18ba4eaa8ad2b5f1eab0c7c5f674c1a0a6ea` |

The new stage failed first with the missing observer intake. The positive case
compared the selected gate and entrypoint pins with the signed build catalog.
Negative cases included replacing a code descriptor, changing start ticks or
invocation at the same PID, wrong argv/tracer, and a changed clock or closed owner.
The checks used real local descriptor duplication with inert Linux and systemd
readbacks. There was no guest execution, actual kernel trace, or measurement.

## Remaining D2–D5

1. **D2:** no change to the installed-identity, useful-pilot or authorization holds.
2. **D3:** distinguish the gate's first stop from its final pre-exec stop on the
   original generation. A static unit and a sampled stopped state alone cannot
   distinguish them. Connect bounded trace ownership, actual entrypoint reads,
   independent replay and verified retirement without allowing the transient
   profile as fallback. Keep instrumented tasks blocked while upstream loss is
   unknown. The same-thread service control pump and other coverage remain open.
3. **D4:** close the independent verifier inventory and prerequisites before freeze.
4. **D5:** separately authorized fresh attempts and pairs, cleanup, and independent replay.
