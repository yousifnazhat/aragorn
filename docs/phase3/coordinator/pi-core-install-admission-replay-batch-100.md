# B100 — replay the admission decision named by an install report

[B76](pi-core-installed-bundle-readback-batch-76.md) answers “did the owner
report the same tree as the retained bundle?” The new opt-in mode also asks
“did the original admission evidence actually yield ALLOW for that tree, and
was this context absent from the plan's revocation list?” It does not issue a
new decision or start an installer. Historical B76 callers keep their original
output and do not need any additional blobs.

Use the same independently selected owner, plan, context and manifest pins as
B76. Do not derive the expected values from an install report submitted for
verification. To request the extra check:

```sh
PYTHONPATH=src:. python3 -B -m scripts.verify_pi_core_installed_bundle_readback \
  --archive "$PRIVATE_ARCHIVE" --owner-pin "$OWNER" --plan-pin "$PLAN" \
  --context-pin "$CONTEXT" --manifest-pin "$MANIFEST" --replay-admission
```

The read-only archive must contain the canonical revocation document named by
the original plan and the decision, graph, policy, ordered analyzer receipts
and their referenced objects. The original context supplies the verifier
expectations. The existing decision verifier reconstructs the graph and
analyzer results, evaluates the deployment's pinned policy, and compares the
original decision bytes to that result. A label saying `ALLOW` does not
suffice. The returned finding identifies the decision and revocation-list
digests, not private analyzer output.

The list contains **install context IDs**, not skill digests. Absence from one
nominated snapshot does not establish that the context was unexpired or
unrevoked at publication or is valid today. Matching recorded materialization
is not a live filesystem observation, proof of the transaction preimage, or
worker consumption. This change does not select a policy or generate a
decision for the [public pilot candidate](pi-core-public-candidate-closure-batch-97.md).

**Verification:** Only `pi-core-install-admission-replay-offline` ran: five
new checks passed on the first run, fingerprint
`sha256:98ca1fa61c9200d1eaebb266d1afea72c0de261bedde66a3fe1c14223858c83b`.
The positive case replays inert test inputs; a non-ALLOW, a forged ALLOW,
missing originals, a different verifier, and a listed context are refused.
The strict CLI prints no private parser details on refusal. No real analyzer,
installation, worker, guest or provider was started.

1. **D2:** Nominate the original pilot policy and analyzer evidence. Keep the
   socket directories non-listable; the stopped-worker mount check is not
   Pi's own result. Settle the narrow private lookup/link receipt before
   changing recording scope. Installed state, health, recovery, full timing,
   independent file output and cleanup still need evidence. B49 stays null.
2. **D3:** Connect the remaining admission, RUN/health and workload paths.
3. **D4:** Close the evidence-to-verifier inventory for the 29 requirements,
   then freeze one deployment.
4. **D5:** Separately authorize fresh acceptance, 100 attempts, 100 task pairs,
   cleanup verification and independent replay. No live pilot or freeze here.
