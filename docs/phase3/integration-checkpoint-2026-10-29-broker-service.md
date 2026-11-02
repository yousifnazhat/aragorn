# Integration checkpoint: guarded broker reader service, 29 October

Original verified signed service delivery:
`721e63cbb8f3bc47fe5fd58cbc8793538c4851db`.
It is committed directly on the owning `codex/phase3-runtime-prevention` branch,
preserving all original lane ancestry. No active lane checkout was changed.
The exact three service paths are source, focused test and coordinator handoff.

## Reviewed implementation and actual selected results

The service connects the real public context and reader-session APIs, owns the
fixed guard listener and readiness writer, and retains a bounded refusal exchange
and terminal custody. Its profile remains HTTP_REFUSAL_ONLY: this is not usable
positive enforcement, complete health or Phase 3 qualification.

The 23-file closure includes original signed Admission context `018959a`.
Root and independent source review confirmed the actual inputs and mocked native
test boundaries. Registration `2c6487d5f5e137e372b60f37f40344de004afc92` added
only `native-broker-reader-service`; the previous 126 registry rows are unchanged.

Only this stage ran:

- First fingerprint `sha256:1a49e077a561c7c630b742bf3a06f616aaa8cefc31ed4b8f63a0b79984da9b44`:
  FAIL, 43 methods passed and one failed. The shared fixture incorrectly treated
  a reused descriptor number as the old cancellation pipe. The original result,
  logs and failure fingerprint remain unchanged.
- Correction schedule `3144fcebf33b9bd748ce84a36906a421b15c8e41` approved the
  minimal fixture-only repair after diagnosis and independent review. Production
  and all test assertions remained unchanged. The same stage's changed-input run
  passed all 44 methods, exit 0, at matching pre/post fingerprint
  `sha256:3a3931727362b25199c19374d6f2e82a967664c2eacd5fe05b39f1582a826201`.

This was not an unchanged retry. No other stage, broad regression, historical
test, cache copy, live operation, service activation or private cleanup ran.
All prior unaffected evidence and unrelated drafts are preserved.

Source SHA-256 remains
`99b61fa1a258464a64017d4dad6231d9bd5f7cd87ff03c2e85f490a58ee048ed`;
corrected test SHA-256 is
`474fd55ec3914de29ea11d0da3eb041a63549eed52544abe614f49f8dbec589f`.
`coordinator/broker-reader-service-handoff.md` records both original evidence
directories and every result/log/preflight size and hash. Root inspected actual
method outcomes, preflight, logs, signatures and post-run source pins. Native
context/session composition, installed source identity and sensor authority are
explicitly not established by the modeled service-unit result.

## Next owners and remaining plan

The completed service implementation is ready for normal push and PR #1 update;
the final containing checkpoint hash and remote verification are reported after
publication. PR #1 stays draft, with no merge to main or release implied.
RUN-health's 69-method bootstrap and Workloads' 32-method lineage corrections
remain separate unexecuted drafts from the preceding batch. This run neither
changes nor schedules them. Root owns their next source/closure review and the
shared registration, protected launch and final composition work.

1. Service unit delivery is complete. Review and separately schedule RUN bootstrap
   and Workloads lineage corrections; sign and integrate only reviewed deliveries.
2. Finish protected launch and actual HTTP/DNS/destructive/admission/RUN/loss
   paths, genuine a100, cancellation, full request/task timing and four paired tasks.
3. Close the existing 48-entry verifier/path/source-custody inventory and freeze
   one supported deployment.
4. After prerequisites and separate operational release, perform the required
   fresh 31 cases, 100 action attempts and 100 task pairs, independently replay,
   evaluate the existing exit gate and verify approved cleanup. Phase 3 remains
   incomplete; operational and qualification holds are unchanged.
