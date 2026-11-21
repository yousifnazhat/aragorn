# D2 decision: what counts as evidence in Pi's protected filesystem view?

**Status: approved for offline engineering; no exception has qualified.**
Keep confinement and verify the exceptions. The four named device masks approved in
[B58](pi-core-worker-mask-decision.md) are not a general exception for
unreadable directories or Linux process links. The following is a source
compatibility finding; no guest was started.

**A demonstrated conflict in the useful path.** The [request dispatcher](../../../src/aragorn/pi_core_native_request.py)
and [provider dispatcher](../../../src/aragorn/pi_core_native_provider.py)
create their respective `requests` and `provider` directories below
`/run/aragorn-pi-bootstrap`, set owner root, group to the worker group, and
verify mode 0711. The [supervisor](../../../src/aragorn/pi_core_native_supervisor.py)
prepares these channels before launching the provider-enabled worker. The
[launcher](../../../src/aragorn/pi_core_confined_launch.py) binds the parent
read-only and runs Pi with a non-root UID and no capabilities. Under the intended
permissions Pi may look up a known socket, but it may not enumerate its parent.
The [ordinary walk](../../../src/aragorn/pi_core_state_exposure.py) requires two
successful listings and inspection of every child. A root listing, or an empty
list in place of a denial, would not prove what Pi observed. The capture-only
route does not start the dispatchers; its success cannot settle this conflict.
The worker's [provider client](../../../packaging/pi-core/provider.ts) also
requires the parent to be mode 0711, and the [request client](../../../packaging/pi-core/worker.ts)
relies on its frozen helper's same check. Changing only the directory modes
would break the current clients.

**A separate kernel-view issue.** The pinned systemd 259.5 source
(`80ed55a8a69c4bd1fb12a36659303372b37baf9ee224ef4f032db4b748be0f76`,
`src/core/namespace.c` and `src/shared/dev-setup.c`) prepares proc and private
device links for this profile. The launcher sets `ProtectProc=invisible` and
`ProcSubset=pid`. Looking up `/proc/self` from another task identifies the
observer, not Pi; `/dev/fd` can lead into that same process-relative view.
Aragorn's [existing observer](../../../src/aragorn/pi_core_stopped_mask_view.py)
also distinguishes kernel namespace handles from regular mounted files. B58
does not represent an ordinary link resolving to an unlisted internal mount,
nor arbitrary permission errors. The installed link inventory, options and
return values are not known. Do not invent any of them or skip `/proc` or `/sys`.

**Approved proof.** Keep B58 and its existing format unchanged. Under
`/run/aragorn-pi-bootstrap`, only `requests/request.sock` and
`provider/provider.sock` are in scope. Do not widen the 0711 directories.
Require both sides: the authenticated manager's complete membership and
socket identities, and separate evidence that the actual confined worker
can look up the expected objects but cannot list their parents. Neither side
can stand in for the other. This does not establish socket readiness.

For process-relative links, prove each fixed result for the actual task,
root, namespace and, where relevant, descriptor generation; resolving
`/proc/self`, `/proc/thread-self` or `/dev/fd` as the observer is not a
substitute. Reject unexplained paths, aliases, permission errors or changes.
Do not drop a directory from the walk, infer an empty listing, or admit
state on manager evidence alone. No host, storage, key, spending, B49
change, pilot or qualification run is authorized by this decision.
