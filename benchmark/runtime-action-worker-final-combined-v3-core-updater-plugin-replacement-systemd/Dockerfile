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
        dafa4fc1f21d72be7ab25eca917c75ed4a0ae2a524fa24abc96f791ba040d9a0; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py)" = \
        'regular file:0:0:700:1:8219'; \
    test "$(sha256sum /src/scripts/materialize_openclaw_final_v3_rebound_probes.py | cut -d ' ' -f 1)" = \
        8321a6c423b03c283d175185de6886ca12aaa08c244f81b67be3a73a47279a1c; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/materialize_openclaw_final_v3_rebound_probes.py)" = \
        'regular file:0:0:600:1:7691'; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd_probe.py | cut -d ' ' -f 1)" = \
        c0b3a015c31671de0b67d4873c3ad02b744513122fcf0cbf5d1f6b7044667f86; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd_probe.py)" = \
        'regular file:0:0:700:1:18786'; \
    test "$(sha256sum /src/scripts/capture_runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd.sh | cut -d ' ' -f 1)" = \
        e9931c492ec19ac3f7f136e837839266b97fb2336679aea4db6c5aff5ab58510; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/capture_runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd.sh)" = \
        'regular file:0:0:700:1:8009'; \
    test "$(sha256sum /src/src/aragorn/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py | cut -d ' ' -f 1)" = \
        ea4dfe6b52318ce5e70bb6810a95ebbd3af0c76300fd7c12a78727c7203993c2; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/src/aragorn/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py)" = \
        'regular file:0:0:600:1:27805'; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-core-updater-plugin-replacement-v3-probe.mjs | cut -d ' ' -f 1)" = \
        db868cc300cac7f07bc2aafb0619a6f326d3d70015b1821744e9f4d9ebc07760; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-core-updater-plugin-replacement-v3-probe.mjs)" = \
        'regular file:0:0:600:1:26844'; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-audit-listener.mjs | cut -d ' ' -f 1)" = \
        66da837cb9c1f54ce66ccf5f3c2012021715bf6848005f545102d18155976545; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-audit-listener.mjs)" = \
        'regular file:0:0:600:1:2947'; \
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
        db868cc300cac7f07bc2aafb0619a6f326d3d70015b1821744e9f4d9ebc07760; \
    test "$(sha256sum "$materialized/protected-route-action-probe.mjs" | cut -d ' ' -f 1)" = \
        18f17a79ba6c72b247857d9213abc1093f699a2000e4d8c4f5192b719e905132; \
    test "$(sha256sum "$materialized/core-updater-plugin-replacement-audit-listener.mjs" | cut -d ' ' -f 1)" = \
        66da837cb9c1f54ce66ccf5f3c2012021715bf6848005f545102d18155976545; \
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
