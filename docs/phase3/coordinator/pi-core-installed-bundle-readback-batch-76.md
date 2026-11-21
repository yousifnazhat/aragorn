# D3 batch 76 — compare the installed-tree report with approved bundle bytes

The protected install/update entry already reopened the published version and
hashed its contents ([producer checkpoint](pi-core-d3-parallel-release-1.md)).
Until this batch the final coordinator report published a digest of the
transaction, but not the digest measured on that reopened tree.

The fixed `--install-bundle` route now emits
`aragorn/pi-core-bundle-install-report/v2`. It releases
`observed_tree_digest` only after a normal, clean return, matching transaction
and observed tree, successful post-call guard, both outer closes and the
original deadline. A possible publication is not permission to retry: a
subsequent failure withholds the measurement and preserves known effect
metadata. Earlier v1 reports are unchanged and cannot prove this comparison.

The [offline reader](../../../scripts/verify_pi_core_installed_bundle_readback.py)
uses a read-only CAS. Supply four **independently obtained** expected pins:
the protected owner's exact stdout including its final LF; the approved
install plan; the context; and the admitted source manifest. The archive must
also contain the host profile and deployment descriptor named by the plan and
the manifest's original member bytes. The reader requires the reviewed wrapper
(`9466bbe553b557a710a9d7ee2e2164a4fbf0e4f8a1442d4683ea2e8516ab5cfa`)
and install entry (`d74ff1cb8c0b8626ad388eacd6255ad640fa00896b2d86eae2848d533da00564`)
in that profile. An older producer cannot be upgraded by relabeling a report;
a changed producer requires review. The reader checks the custody and
deployment bindings and compares the reported measurement to a tree rebuilt
from those member bytes. No guest path is opened and the reader does not
install or repair anything. Hashes supplied by the report itself are not an
independent source of authority.

This compares a protected install-time measurement with retained bytes.
It does not reobserve the live filesystem, authenticate a self-selected
report, replay a private transaction or revocation decision, or prove the
worker later consumed the bundle. It contributes to exact-bytes/install/update
coverage; it is not a full `MP1/ADM-01/exact-admitted-bytes`,
`MP1/ADM-02/install` or `MP1/ADM-02/update` verdict.

The [B75 guest payload](pi-core-observed-storage-guest-batch-75.md) is
preserved at its original pin and does **not** contain this new wrapper.
Pin a successor as part of the next deployment assembly before asking for an
installed report. B49 is unchanged and no install, VM, provider or live
capture was run.

Only `pi-core-installed-bundle-readback-offline` ran: **23 passed** (15
affected dispatch checks and eight reader checks), first execution, fingerprint
`sha256:c24950ca6ff2a08c0322feac7c43878efad7a861d4e7ee7a05d80fded4517cc1`.
The connected test uses the real wrapper's stdout and privately retained
fixture bytes with an inert install entry. It is not a deployed receipt.

1. **D2 open:** worker-view and volume backing/writer/current-head evidence,
   installed health, recovery, timing and a separately authorized useful pilot.
2. **D3 open:** installed-byte report path connected offline; remaining
   admission paths, action-boundary RUN/health evidence and workloads still open.
3. **D4 not frozen:** connect and independently review all 29 managed
   requirements before freezing a single deployment.
4. **D5 not authorized:** fresh admission inventory, 100 attempts, 100 task
   pairs, cleanup and independent replay follow freeze and separate authorization.
