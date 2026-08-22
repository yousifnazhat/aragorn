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
        e89b5c456d276e6c14b403a976db4a1fa9f7e4fa7ce4a35e6d1431a7a1b9de18; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v2.json | cut -d ' ' -f 1)" = \
        2772bca6629607247e2a5c056282b4748ab5bb6d024fd742c9755fb915281ddb; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v2.json | cut -d ' ' -f 1)" = \
        615928c74bb467ed1422aa19c0ca3266fec21e6a9b195ff32e7e2fae86f966fc; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v2.lock.json | cut -d ' ' -f 1)" = \
        c5773a0b8829d1dbdd9fa89d7dc93e995ee54ea723208daa59b0951d50e76fd5; \
    test "$(find /route-input -mindepth 1 -maxdepth 2 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'cron-rescan:d' \
            'cron-rescan/protected-cron-rescan-probe.mjs:f' \
            'cron-rescan/protected-observation-v1.mjs:f' \
            'fresh-session-reset:d' \
            'fresh-session-reset/protected-route-probe.mjs:f' \
            'missing-prompt-blob-rebuild:d' \
            'missing-prompt-blob-rebuild/protected-observation-v1.mjs:f' \
            'missing-prompt-blob-rebuild/protected-prompt-rebuild-probe.mjs:f' \
            'session-snapshot-consumer:d' \
            'session-snapshot-consumer/protected-observation-v1.mjs:f' \
            'session-snapshot-consumer/protected-session-snapshot-fixed-probe.mjs:f' \
            | sort)"; \
    test "$(sha256sum /route-input/cron-rescan/protected-cron-rescan-probe.mjs | cut -d ' ' -f 1)" = \
        94d3b47162fd1bdc97028f44115ef54acfe8b7a296210a47a8a24a71771bb2d0; \
    test "$(sha256sum /route-input/cron-rescan/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        13baaac69f323603f2029eb1dc675f7438d51e0b9440befe775758a38c09a321; \
    test "$(sha256sum /route-input/fresh-session-reset/protected-route-probe.mjs | cut -d ' ' -f 1)" = \
        ac23d68064c1a904649c6c1064f8c7729768fe516eef1e6d7c2bdc6b4e12d299; \
    test "$(sha256sum /route-input/missing-prompt-blob-rebuild/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        13baaac69f323603f2029eb1dc675f7438d51e0b9440befe775758a38c09a321; \
    test "$(sha256sum /route-input/missing-prompt-blob-rebuild/protected-prompt-rebuild-probe.mjs | cut -d ' ' -f 1)" = \
        9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7; \
    test "$(sha256sum /route-input/session-snapshot-consumer/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        13baaac69f323603f2029eb1dc675f7438d51e0b9440befe775758a38c09a321; \
    test "$(sha256sum /route-input/session-snapshot-consumer/protected-session-snapshot-fixed-probe.mjs | cut -d ' ' -f 1)" = \
        9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11; \
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
    chmod 0555 \
        /route-input \
        /route-input/* \
        /src/packaging/activate-runtime-action-worker-host.sh \
        /src/scripts/capture_runtime_action_worker_final_combined_v2_systemd.sh \
        /src/scripts/materialize_fixed_admission_probes.py \
        /src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py \
        /src/scripts/runtime_action_worker_final_combined_v2_systemd_probe.py \
        /src/scripts/runtime_action_worker_final_route_systemd_probe.py; \
    chmod 0444 \
        /route-input/*/* \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v2.json \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v2.json \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v2.lock.json \
        /src/benchmark/runtime-action-worker-final-combined-v2-systemd/Dockerfile \
        /src/src/aragorn/runtime_action_worker.py
