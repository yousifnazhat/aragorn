# HTTP reader client: first selected scheduling v1

Review base: signed published ac7f95157315a0ae834f0fba62954f1137bbd2bd.
This schedule takes effect only at its containing verified signed published checkpoint.
Root executes only this new stage in its own integration worktree.

Root and independent review inspected the complete stable client and all38 cases.
The initial35-method candidate was never executed. Its two confirmed gaps are
corrected: healthy post-BOUND constructor failure attempts one public terminal
finish/readback before close; configure rechecks the original accept deadline
following slow cleanup and final guards. Three genuinely late regression methods
cover terminal retention, retained actual terminal publication failure, and expiry
during final namespace close. No remaining concrete source/closure blocker found.

## Exact reviewed closure


| Path | SHA-256 | Bytes |
| --- | --- | ---: |
| `src/aragorn/__init__.py` | `4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01` | 78 |
| `src/aragorn/cas.py` | `c5642f910ac4b2d6172a59a02105b359cb43d3a2f2e2240368229d3436ad4859` | 19508 |
| `src/aragorn/native_phase3_broker_reader_client.py` | `4aac15356d113588c70cf676d665bf3887ef947fdf0b777869be5bea67db617c` | 73130 |
| `src/aragorn/native_phase3_broker_reader_protocol.py` | `8d17e7930d2c560ade4b5c0fb5b539e00ecbfb3fb9f40d910d271dd42eb48007` | 9400 |
| `src/aragorn/native_phase3_http_canary_contract.py` | `bcdd7b92d3ddaddb4ab38ce5cabcdbd68c7f87c79a6251f81c1bb225313946c2` | 9776 |
| `src/aragorn/oci_worker_protocol.py` | `0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b` | 22775 |
| `src/aragorn/phase3_deployment.py` | `d4f4ce6e43dd59b85b84db88c502e8cb8b5180a38a9ecdb2ab58ef1e3033a9dd` | 3882 |
| `src/aragorn/phase3_quantitative_metrics.py` | `09b3c3848ba7700efbb468f614b40a71e472ddbf116643fb280a564bdb50af2e` | 25613 |
| `src/aragorn/runtime_action_broker.py` | `94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21` | 79641 |
| `src/aragorn/runtime_action_broker_v2.py` | `a77d7c5cc2b607b9234f6758283bdff74c73586651e6aa7d5a9e3c3ab48b14e3` | 18164 |
| `src/aragorn/runtime_action_broker_v3.py` | `408f0b5373139c93b13e61fcf4ea6791865841806f0a9aa8a269e095cd0d9f8d` | 30803 |
| `src/aragorn/runtime_action_broker_v4.py` | `ab7d08105229ee3dd58f8dca5c20156d5e260e2b79f0ed2b4c08693c3cf6174a` | 45748 |
| `src/aragorn/runtime_action_decision.py` | `3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d` | 17731 |
| `src/aragorn/runtime_action_observation_publisher.py` | `288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90` | 21163 |
| `src/aragorn/runtime_broker_decision_measurement.py` | `cb374ad8d1b7dc591fa554ab0590e8c39eb3ac287589ce26da67b4d5fc0e454e` | 19164 |
| `src/aragorn/runtime_capability_grant.py` | `058aa743c6bdebffe1660120d88886d465aaaa5192171979e466ba6ce20f5681` | 9741 |
| `src/aragorn/runtime_http_action.py` | `823ffdcaf114bdc8bcd7ca43009f67d6bf46969d4a27856e104ceedc979b0ac5` | 21866 |
| `src/aragorn/runtime_http_run_submission.py` | `728bcfeee5a92881fbc0ea96d6df4389840da8661132d38e5fed7cb284bc1844` | 30779 |
| `src/aragorn/runtime_process_profile.py` | `a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68` | 16131 |
| `tests/test_native_phase3_broker_reader_client.py` | `46bc7d3ae08ab3377dc7e8ddcd7137e296c8761e4d8d14680c5ea08675b78f3f` | 46825 |


Handoff11319 bytes sha256:91dd1eb0441d50e7ec36925b0d962974e1593cce34624cb1788b98f283890e27.
All20 actual source sizes/pins match. Eager imports and conservative late measurement
closure are listed, including real journal/codec/helpers. The unavailable generated
measurement accessor and all reached native operations are explicit unit boundaries.
No fixtures, generated source execution or historical TestCase imports are hidden.
This stage cannot establish native identity/custody, installed sources, actual paired
execution, positive enforcement or final qualification. All qualification flags remain false.

## Registration and owning execution

Append only native-broker-reader-client to benchmark/phase3-pipeline-v1.json.
Existing124 rows remain deep-equal. Tests=[test_native_phase3_broker_reader_client],
exact20 inputs above, needs=[], timeout_seconds=120. Runner29048 bytes
sha256:46163b06a07679d157d1d37b23a8b627ea52fce1e37808753937ebbfd6edee58;
worker lock12748 bytes
sha256:945fd7620689d38962297a61f5e888f3156b90780e7ea8d3bf62a1459d75d0f4
remain unchanged; actual checkout/toolchain/environment enter the fingerprint.
After normal signed publication and remote-tip match, inspect:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py status native-broker-reader-client
```

Reuse an actual matching PASS. Only if NEW execute once:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-broker-reader-client
```

Retain actual result, logs and pre/post fingerprint on either outcome. No unchanged
retry. Review actual outcome before staging the exact v14 source/test/handoff,
commit -S, verify-commit, normal push and remote-tip verification. No historical
suites, copied caches, live operations, private retention or cleanup.

1. Integrate reviewed providers with newly necessary focused validation.
2. Wire actual HTTP/DNS/destructive, admission/RUN/a100, cancellation, full timing
   and four paired contexts using protected providers and complete source inventories.
3. Close the existing48-entry ledger and freeze only after real paths close.
4. Separately release same-deployment31/100/100 campaign, replay, gate and approved cleanup.
