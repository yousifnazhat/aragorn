# D2 B87 — check the socket bind in the stopped worker's own root

The restricted, provider-enabled [startup observer](../../../src/aragorn/pi_core_node_source_observer.py)
now checks the worker's mount *before releasing the initial gate stop*. B81
already checked who owned each socket and what was in each directory, but
it walked the manager's root. A correct manager-side result alone would not
detect a different or writable mount at the same path inside the worker.

The [fixed-path check](../../../src/aragorn/pi_core_owned_socket_directories.py)
uses the original stopped task and its held root. The launcher declares one
read-only bootstrap bind; the two role directories and their named endpoints
must belong to it and match the manager's named filesystem objects. A listening
socket handle is not the inode of its filesystem name. No directory is made
listable to Pi, no socket is contacted and no mount is changed. Losing the
stop or failing the comparison leaves the original manager evidence incomplete
and blocks the bootstrap exchange.

**Evidence boundary.** This is a startup check by the trusted observer, not a
new private recording or an offline proof of what Pi did. B81 retains its
manager-only status and format. Establishing Pi's own lookup, listing denial
and process-relative links still requires the actual task's bounded probe
results and independent replay. Do not reuse B36 launch authority for B86's
gate, or treat a changed observer as part of a previously pinned guest.

**Focused offline results:** five mount checks passed
(`761c872ee7266cf8b72da233c54e5a0f08e33430e7db658ee4154b0757f305d7`);
eight stopped-owner checks passed
(`fbb7de7b49a0caae0a4b1d8e72a4546712220edc300593701421f1a3110ac1c1`).
Neither stage needed a retry. No archive build, guest, socket exchange or
private evidence capture ran.

1. D2: connect the fixed gate to its matching observer and private reader;
   pin the resulting observer for installation. Actual health, protected state,
   recovery, timings and the useful pilot remain unproved. B49 stays null.
2. D3: connect remaining admission, RUN/health and workload paths on that deployment.
3. D4: complete the independent evidence mapping for 29 requirements, then freeze.
4. D5: separately authorize fresh acceptance, 100 attempts and 100 task pairs,
   with cleanup verification and independent replay.
