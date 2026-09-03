ARG V3_FORCE_BASE

FROM sha256:8530f76a96d88820d288761f022e318970dda93d01536919fbc16076b7983e63 AS git-source

# Exact retained proposal child; its rootfs is itself an additive child of the
# exact V3 force-policy parent supplied and rechecked by the capture recipe.
FROM sha256:601a0b582406193cf031b0f5512b564464452a60a00bc97098266182ccd13ff7

ARG V3_FORCE_BASE

# ponytail: this bounded file:// route needs only Git and git-upload-pack;
# copy the full Git runtime if a future route exercises another transport.
COPY --from=git-source /usr/bin/git /usr/bin/git

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
    ln -s git /usr/bin/git-upload-pack; \
    test "$V3_FORCE_BASE" = \
        "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"; \
    test "$(sha256sum /usr/bin/git | cut -d ' ' -f 1)" = \
        54af380ba6ca1b36305358e99427a31ae4b0af5dc5cb6d0198c6f2f16e97651d; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /usr/bin/git)" = \
        'regular file:0:0:755:1:3756992'; \
    test "$(readlink /usr/bin/git-upload-pack)" = git; \
    test "$(/usr/bin/git --version)" = 'git version 2.39.5'; \
    test "$(sha256sum /src/scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py | cut -d ' ' -f 1)" = \
        379480a1493e17381a3a0572b24d3e0c8c612cbfaf0ff3ac7a167d90dd4ff03e; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py)" = \
        'regular file:0:0:700:1:8295'; \
    test "$(sha256sum /src/scripts/materialize_openclaw_final_v3_rebound_probes.py | cut -d ' ' -f 1)" = \
        8321a6c423b03c283d175185de6886ca12aaa08c244f81b67be3a73a47279a1c; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/materialize_openclaw_final_v3_rebound_probes.py)" = \
        'regular file:0:0:600:1:7691'; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd_probe.py | cut -d ' ' -f 1)" = \
        c1c315c9428e01b04176f2af39d7760a61031c7bf8fbee370db0bf8be90a13cc; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd_probe.py)" = \
        'regular file:0:0:700:1:19454'; \
    test "$(sha256sum /src/scripts/capture_runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd.sh | cut -d ' ' -f 1)" = \
        3dd7550d3cc3ac816e35423f42a2923fc749e087e5640cfb619dc524170e365b; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/capture_runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd.sh)" = \
        'regular file:0:0:700:1:8364'; \
    test "$(sha256sum /src/src/aragorn/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py | cut -d ' ' -f 1)" = \
        6d43a5101e32b9b175d39a900e7e0a3ae20544cb20836ddd05cb7aa345829bef; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/src/aragorn/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py)" = \
        'regular file:0:0:600:1:28641'; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-core-updater-plugin-replacement-v3-probe.mjs | cut -d ' ' -f 1)" = \
        e7c38a03ee2d1d2927a228444cf7172ad67dc5dbbd11acfeaaf11345cd67c30c; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-core-updater-plugin-replacement-v3-probe.mjs)" = \
        'regular file:0:0:600:1:27682'; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-audit-listener.mjs | cut -d ' ' -f 1)" = \
        37aa36c0d9b6d66dd3af8a7ca3d0bd557bb9a727383d8fb9126dd5d7e2426edc; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-audit-listener.mjs)" = \
        'regular file:0:0:600:1:3177'; \
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
        e7c38a03ee2d1d2927a228444cf7172ad67dc5dbbd11acfeaaf11345cd67c30c; \
    test "$(sha256sum "$materialized/protected-route-action-probe.mjs" | cut -d ' ' -f 1)" = \
        2e655f7039cf6f2c06f815b281bb7a5ca7a84ed48ef44cf4d2ce8dfdc7df6902; \
    test "$(sha256sum "$materialized/core-updater-plugin-replacement-audit-listener.mjs" | cut -d ' ' -f 1)" = \
        37aa36c0d9b6d66dd3af8a7ca3d0bd557bb9a727383d8fb9126dd5d7e2426edc; \
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
