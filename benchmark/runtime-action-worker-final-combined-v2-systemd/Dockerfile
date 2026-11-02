ARG V1_FINAL_BASE

FROM ${V1_FINAL_BASE}

ARG V1_FINAL_BASE

COPY packaging/activate-runtime-action-worker-host.sh \
    /src/packaging/activate-runtime-action-worker-host.sh
COPY src/aragorn/runtime_action_worker.py \
    /src/src/aragorn/runtime_action_worker.py
COPY benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v2.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v2.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v2.lock.json \
    /src/benchmark/admission/openclaw-v2026.7.1/
COPY benchmark/runtime-action-worker-final-combined-v2-systemd/ \
    /src/benchmark/runtime-action-worker-final-combined-v2-systemd/
COPY route-input/ /route-input/
COPY scripts/capture_runtime_action_worker_final_combined_v2_systemd.sh \
    scripts/materialize_fixed_admission_probes.py \
    scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py \
    scripts/runtime_action_worker_final_combined_v2_systemd_probe.py \
    scripts/runtime_action_worker_final_route_systemd_probe.py \
    /src/scripts/

# V2 is one additive source/install refresh over the exact retained V1 child.
# The singleton skill and OpenClaw runtime remain inherited and immutable.
RUN set -eux; \
    test "$V1_FINAL_BASE" = \
        "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/runtime_action_worker.py | cut -d ' ' -f 1)" = \
        16e77024f715d1b7f2c600df16e5878e23f584753444fef998cf9b4742603d60; \
    test "$(sha256sum /usr/libexec/aragorn/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        589d8174e2d175e1680b4a3b5b29acc6db33660ffe0cd682b7f07fa6f9de7a64; \
    test "$(sha256sum /opt/aragorn/runtime-profile/template-skill/SKILL.md | cut -d ' ' -f 1)" = \
        eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa; \
    test "$(stat -c '%u:%g:%a:%h:%s' /opt/aragorn/runtime-profile/template-skill/SKILL.md)" = \
        0:0:444:1:140; \
    test "$(sha256sum /src/src/aragorn/runtime_action_worker.py | cut -d ' ' -f 1)" = \
        a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        52dbdae05a0a394b7314d87337b1a536ba3cf9a0b999d95432341daa068ca5cf; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v2.json | cut -d ' ' -f 1)" = \
        d145feb4e935e6f86c7e2bfdeefcaec5fa4ebf8f044ffa472bd7589b03bf4fe8; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v2.json | cut -d ' ' -f 1)" = \
        615928c74bb467ed1422aa19c0ca3266fec21e6a9b195ff32e7e2fae86f966fc; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v2.lock.json | cut -d ' ' -f 1)" = \
        4832dc99c016bd8c0f6d97133dbb7d3681d4ad18c1c225c94f10a51d6df839c1; \
    test "$(find /route-input -mindepth 1 -maxdepth 3 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'archive-source-force-replacement:d' \
            'archive-source-force-replacement/protected-archive-replacement-probe.mjs:f' \
            'config-entry-activation:d' \
            'config-entry-activation/protected-config-activation-probe.mjs:f' \
            'cron-rescan:d' \
            'cron-rescan/protected-cron-rescan-probe.mjs:f' \
            'cron-rescan/protected-observation-v1.mjs:f' \
            'curator-restore-activation:d' \
            'curator-restore-activation/protected-curator-restore-denial-probe.mjs:f' \
            'curator-restore-activation/protected-observation-v1.mjs:f' \
            'fresh-session-reset:d' \
            'fresh-session-reset/protected-route-probe.mjs:f' \
            'missing-prompt-blob-rebuild:d' \
            'missing-prompt-blob-rebuild/protected-observation-v1.mjs:f' \
            'missing-prompt-blob-rebuild/protected-prompt-rebuild-probe.mjs:f' \
            'plugin-enable-activation:d' \
            'plugin-enable-activation/protected-plugin-enable-probe.mjs:f' \
            'plugin-force-reinstall:d' \
            'plugin-force-reinstall/baseline-source:d' \
            'plugin-force-reinstall/baseline-source/index.js:f' \
            'plugin-force-reinstall/baseline-source/openclaw.plugin.json:f' \
            'plugin-force-reinstall/baseline-source/package.json:f' \
            'plugin-force-reinstall/candidate-source:d' \
            'plugin-force-reinstall/candidate-source/index.js:f' \
            'plugin-force-reinstall/candidate-source/openclaw.plugin.json:f' \
            'plugin-force-reinstall/candidate-source/package.json:f' \
            'plugin-force-reinstall/protected-plugin-force-reinstall-probe.py:f' \
            'session-snapshot-consumer:d' \
            'session-snapshot-consumer/protected-observation-v1.mjs:f' \
            'session-snapshot-consumer/protected-session-snapshot-fixed-probe.mjs:f' \
            'workshop-proposal-apply:d' \
            'workshop-proposal-apply/PROPOSAL.md:f' \
            'workshop-proposal-apply/protected-route-probe.mjs:f' \
            | sort)"; \
    test "$(sha256sum /route-input/archive-source-force-replacement/protected-archive-replacement-probe.mjs | cut -d ' ' -f 1)" = \
        4ead71ad73da16579fb85bc1287cb760a8b8b90838de9a9ea0ad2091fca87479; \
    test "$(sha256sum /route-input/config-entry-activation/protected-config-activation-probe.mjs | cut -d ' ' -f 1)" = \
        69a2c203e566128a2968b35b85b130cd50107b3ba9367512a50e56e73e65ca93; \
    test "$(sha256sum /route-input/cron-rescan/protected-cron-rescan-probe.mjs | cut -d ' ' -f 1)" = \
        94d3b47162fd1bdc97028f44115ef54acfe8b7a296210a47a8a24a71771bb2d0; \
    test "$(sha256sum /route-input/cron-rescan/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        91febf12bd6aa2e98f63b14001a74213c653c2eb9c8c7db57a55b3520fdd4f22; \
    test "$(sha256sum /route-input/curator-restore-activation/protected-curator-restore-denial-probe.mjs | cut -d ' ' -f 1)" = \
        c43bbcc718df29114e9edcee8f8d6e8d3ad96f5c4dfc7e5b29b4743f3128f60d; \
    test "$(sha256sum /route-input/curator-restore-activation/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        91febf12bd6aa2e98f63b14001a74213c653c2eb9c8c7db57a55b3520fdd4f22; \
    test "$(sha256sum /route-input/fresh-session-reset/protected-route-probe.mjs | cut -d ' ' -f 1)" = \
        65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1; \
    test "$(sha256sum /route-input/missing-prompt-blob-rebuild/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        91febf12bd6aa2e98f63b14001a74213c653c2eb9c8c7db57a55b3520fdd4f22; \
    test "$(sha256sum /route-input/missing-prompt-blob-rebuild/protected-prompt-rebuild-probe.mjs | cut -d ' ' -f 1)" = \
        9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7; \
    test "$(sha256sum /route-input/plugin-enable-activation/protected-plugin-enable-probe.mjs | cut -d ' ' -f 1)" = \
        b31dc052d9eaffb4712de2a716f958afeb54399452aaaf47a714ee216da1ed92; \
    test "$(sha256sum /route-input/plugin-force-reinstall/protected-plugin-force-reinstall-probe.py | cut -d ' ' -f 1)" = \
        6b4adf647cef823f5cfee73d0130c06ab4612e37fb704246a56fe4dca03c0bbe; \
    test "$(sha256sum /route-input/plugin-force-reinstall/baseline-source/index.js | cut -d ' ' -f 1)" = \
        631cc6f036f3cdf2f8fa6c814a27da075bf8c37fd2fe3681a55f7f5e593dd4ea; \
    test "$(sha256sum /route-input/plugin-force-reinstall/baseline-source/openclaw.plugin.json | cut -d ' ' -f 1)" = \
        9b93a70d606ec63c32d15dd9021dc603df9bdf680b74789c675f5227c1c6b077; \
    test "$(sha256sum /route-input/plugin-force-reinstall/baseline-source/package.json | cut -d ' ' -f 1)" = \
        cf817f208ceb1f4bb211d5cc97b190f6ba54cb27f34d7864b9fea5adc74a679e; \
    test "$(sha256sum /route-input/plugin-force-reinstall/candidate-source/index.js | cut -d ' ' -f 1)" = \
        0d4abd050921ecb1c29c8c97457654184137c65644ca9b3e21a920284ce5178b; \
    test "$(sha256sum /route-input/plugin-force-reinstall/candidate-source/openclaw.plugin.json | cut -d ' ' -f 1)" = \
        5579b471618e53e8fd72df36ad0128bb6310c0fc8111be6db31a18c672b5053c; \
    test "$(sha256sum /route-input/plugin-force-reinstall/candidate-source/package.json | cut -d ' ' -f 1)" = \
        7e73514c5369d1d90524663baff896f41f71e21540d1b0a311a73aaf456ee8de; \
    test "$(sha256sum /route-input/session-snapshot-consumer/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        91febf12bd6aa2e98f63b14001a74213c653c2eb9c8c7db57a55b3520fdd4f22; \
    test "$(sha256sum /route-input/session-snapshot-consumer/protected-session-snapshot-fixed-probe.mjs | cut -d ' ' -f 1)" = \
        9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11; \
    test "$(sha256sum /route-input/workshop-proposal-apply/PROPOSAL.md | cut -d ' ' -f 1)" = \
        a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a; \
    test "$(sha256sum /route-input/workshop-proposal-apply/protected-route-probe.mjs | cut -d ' ' -f 1)" = \
        07676570b96d8c0c54f40bd44f4132a2cdb06cb36002dd6f6c406f49afc3a705; \
    install -m 0644 /src/src/aragorn/runtime_action_worker.py \
        /usr/lib/aragorn/aragorn/runtime_action_worker.py; \
    install -m 0755 /src/packaging/activate-runtime-action-worker-host.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    cmp /src/src/aragorn/runtime_action_worker.py \
        /usr/lib/aragorn/aragorn/runtime_action_worker.py; \
    cmp /src/packaging/activate-runtime-action-worker-host.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    test "$(stat -c '%u:%g:%a:%h' /usr/lib/aragorn/aragorn/runtime_action_worker.py)" = \
        0:0:644:1; \
    test "$(stat -c '%u:%g:%a:%h' /usr/libexec/aragorn/activate-runtime-action-worker-host.sh)" = \
        0:0:755:1; \
    find /route-input -type d -exec chmod 0555 {} +; \
    chmod 0555 \
        /src/packaging/activate-runtime-action-worker-host.sh \
        /src/scripts/capture_runtime_action_worker_final_combined_v2_systemd.sh \
        /src/scripts/materialize_fixed_admission_probes.py \
        /src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py \
        /src/scripts/runtime_action_worker_final_combined_v2_systemd_probe.py \
        /src/scripts/runtime_action_worker_final_route_systemd_probe.py; \
    find /route-input -type f -exec chmod 0444 {} +; \
    chmod 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v2.json \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v2.json \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v2.lock.json \
        /src/benchmark/runtime-action-worker-final-combined-v2-systemd/Dockerfile \
        /src/src/aragorn/runtime_action_worker.py
