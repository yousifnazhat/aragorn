ARG V3_FORCE_BASE

# Exact retained proposal child; its rootfs is itself an additive child of the
# exact V3 force-policy parent supplied and rechecked by the capture recipe.
FROM sha256:601a0b582406193cf031b0f5512b564464452a60a00bc97098266182ccd13ff7

ARG V3_FORCE_BASE

COPY benchmark/runtime-action-worker-final-combined-v3-core-updater-plugin-replacement-systemd/ \
    /src/benchmark/runtime-action-worker-final-combined-v3-core-updater-plugin-replacement-systemd/
COPY benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-audit-listener.mjs \
    benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-index.js \
    benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-openclaw.plugin.json \
    benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-package.json \
    benchmark/admission/openclaw-v2026.7.1/protected-core-updater-plugin-replacement-v3-probe.mjs \
    /src/benchmark/admission/openclaw-v2026.7.1/
COPY src/aragorn/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py \
    /src/src/aragorn/
COPY scripts/capture_runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd.sh \
    scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py \
    scripts/materialize_openclaw_final_v3_rebound_probes.py \
    scripts/runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd_probe.py \
    /src/scripts/

RUN set -eux; \
    test "$V3_FORCE_BASE" = \
        "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"; \
    test "$(sha256sum /src/scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py | cut -d ' ' -f 1)" = \
        ffdc59114c0ec55bbd5c0c32a1da6facdce71e8c21bfc36169221122e1b486b9; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py)" = \
        'regular file:0:0:700:1:8295'; \
    test "$(sha256sum /src/scripts/materialize_openclaw_final_v3_rebound_probes.py | cut -d ' ' -f 1)" = \
        8321a6c423b03c283d175185de6886ca12aaa08c244f81b67be3a73a47279a1c; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/materialize_openclaw_final_v3_rebound_probes.py)" = \
        'regular file:0:0:600:1:7691'; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd_probe.py | cut -d ' ' -f 1)" = \
        1f719f57f05053e54840ee08cfa8c02801262801598c378037152ca82d656553; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd_probe.py)" = \
        'regular file:0:0:700:1:19423'; \
    test "$(sha256sum /src/scripts/capture_runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd.sh | cut -d ' ' -f 1)" = \
        e9931c492ec19ac3f7f136e837839266b97fb2336679aea4db6c5aff5ab58510; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/capture_runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd.sh)" = \
        'regular file:0:0:700:1:8009'; \
    test "$(sha256sum /src/src/aragorn/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py | cut -d ' ' -f 1)" = \
        dcd168fa59ad74597d6184c4d57f284fac1d86393485b9be177963f26e9bbcca; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/src/aragorn/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py)" = \
        'regular file:0:0:600:1:27946'; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-core-updater-plugin-replacement-v3-probe.mjs | cut -d ' ' -f 1)" = \
        358fa6968024e9ef951727237a9722ff7a5d1d4b1ea1e9fb37270d14a1a6f9fa; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-core-updater-plugin-replacement-v3-probe.mjs)" = \
        'regular file:0:0:600:1:27038'; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-audit-listener.mjs | cut -d ' ' -f 1)" = \
        91670edb5383e6f23137733bb128da7f437a74cd279f5dc33139443399230f6f; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-audit-listener.mjs)" = \
        'regular file:0:0:600:1:2971'; \
    materialized=/tmp/core-updater-plugin-replacement-v3; \
    /usr/local/bin/python3.12 \
        /src/scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py \
        "$materialized"; \
    test "$(find "$materialized" -mindepth 1 -maxdepth 3 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'candidate-source:d' \
            'candidate-source/index.js:f' \
            'candidate-source/openclaw.plugin.json:f' \
            'candidate-source/package.json:f' \
            'core-updater-plugin-replacement-audit-listener.mjs:f' \
            'protected-core-updater-plugin-replacement-v3-probe.mjs:f' \
            'protected-route-action-probe.mjs:f' \
            | sort)"; \
    test "$(sha256sum "$materialized/protected-core-updater-plugin-replacement-v3-probe.mjs" | cut -d ' ' -f 1)" = \
        358fa6968024e9ef951727237a9722ff7a5d1d4b1ea1e9fb37270d14a1a6f9fa; \
    test "$(sha256sum "$materialized/protected-route-action-probe.mjs" | cut -d ' ' -f 1)" = \
        2e655f7039cf6f2c06f815b281bb7a5ca7a84ed48ef44cf4d2ce8dfdc7df6902; \
    test "$(sha256sum "$materialized/core-updater-plugin-replacement-audit-listener.mjs" | cut -d ' ' -f 1)" = \
        91670edb5383e6f23137733bb128da7f437a74cd279f5dc33139443399230f6f; \
    cmp "$materialized/protected-core-updater-plugin-replacement-v3-probe.mjs" \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-core-updater-plugin-replacement-v3-probe.mjs; \
    cmp "$materialized/core-updater-plugin-replacement-audit-listener.mjs" \
        /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-audit-listener.mjs; \
    find /route-input -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; \
    install -d -m 0555 \
        /route-input/core-updater-plugin-replacement \
        /route-input/core-updater-plugin-replacement/candidate-source; \
    install -m 0444 \
        "$materialized/protected-core-updater-plugin-replacement-v3-probe.mjs" \
        "$materialized/protected-route-action-probe.mjs" \
        "$materialized/core-updater-plugin-replacement-audit-listener.mjs" \
        /route-input/core-updater-plugin-replacement/; \
    install -m 0444 "$materialized/candidate-source/index.js" \
        /route-input/core-updater-plugin-replacement/candidate-source/index.js; \
    install -m 0444 "$materialized/candidate-source/openclaw.plugin.json" \
        /route-input/core-updater-plugin-replacement/candidate-source/openclaw.plugin.json; \
    install -m 0444 "$materialized/candidate-source/package.json" \
        /route-input/core-updater-plugin-replacement/candidate-source/package.json; \
    chmod -R u+w "$materialized"; \
    rm -rf -- "$materialized"; \
    test "$(find /route-input -mindepth 1 -maxdepth 3 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'core-updater-plugin-replacement:d' \
            'core-updater-plugin-replacement/candidate-source:d' \
            'core-updater-plugin-replacement/candidate-source/index.js:f' \
            'core-updater-plugin-replacement/candidate-source/openclaw.plugin.json:f' \
            'core-updater-plugin-replacement/candidate-source/package.json:f' \
            'core-updater-plugin-replacement/core-updater-plugin-replacement-audit-listener.mjs:f' \
            'core-updater-plugin-replacement/protected-core-updater-plugin-replacement-v3-probe.mjs:f' \
            'core-updater-plugin-replacement/protected-route-action-probe.mjs:f' \
            | sort)"; \
    /usr/local/bin/node --check \
        /route-input/core-updater-plugin-replacement/protected-core-updater-plugin-replacement-v3-probe.mjs; \
    /usr/local/bin/node --check \
        /route-input/core-updater-plugin-replacement/protected-route-action-probe.mjs; \
    /usr/local/bin/node --check \
        /route-input/core-updater-plugin-replacement/core-updater-plugin-replacement-audit-listener.mjs; \
    /usr/local/bin/node --check \
        /route-input/core-updater-plugin-replacement/candidate-source/index.js; \
    chmod 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-audit-listener.mjs \
        /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-index.js \
        /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-openclaw.plugin.json \
        /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-package.json \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-core-updater-plugin-replacement-v3-probe.mjs \
        /src/src/aragorn/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py \
        /src/benchmark/runtime-action-worker-final-combined-v3-core-updater-plugin-replacement-systemd/Dockerfile; \
    chmod 0555 \
        /src/scripts/capture_runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd.sh \
        /src/scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py \
        /src/scripts/materialize_openclaw_final_v3_rebound_probes.py \
        /src/scripts/runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd_probe.py; \
    find /route-input -type d -exec chmod 0555 {} +; \
    find /route-input -type f -exec chmod 0444 {} +; \
    test -z "$(find /route-input -mindepth 1 ! -type d ! -type f -print -quit)"
