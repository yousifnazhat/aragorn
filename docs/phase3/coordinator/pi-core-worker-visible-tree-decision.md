# D2 decision needed: what counts as evidence in Pi's protected filesystem view?

**Status: proposed, not approved.** The four named device masks approved in
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

**Recommended: preserve permissions and design a versioned proof.** Keep B58
and its guarantees unchanged. For the two fixed service directories, design
a proof combining the authenticated manager's complete directory membership
and socket identities with independent evidence of the worker's precise
lookup rights. For fixed process-relative links, bind each special result to
the actual task, root, namespace and descriptor generation. Define how the
independent reader checks each case; reject every unexplained path or change.
Do not call a structural proof a successful Pi directory listing. Approval
would authorize offline design and implementation only, not qualification of
the resulting profile or an exception for the rest of the filesystem.

**Alternative: keep the literal walk and redesign the worker view.** Expose
only the named socket endpoints and construct a worker view whose required
paths can all be verified under the existing rules. Re-assess the runtime's
proc/sys dependencies and the launcher before choosing this alternative.
Merely setting group-read on the socket directories cannot settle the kernel
link issue. Neither choice authorizes a VM, spending, or changing B49.
