ARG V3_FORCE_BASE

FROM ${V3_FORCE_BASE}

ARG V3_FORCE_BASE

COPY benchmark/admission/openclaw-v2026.7.1/protected-cron-rescan-v2-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs \
    /src/benchmark/admission/openclaw-v2026.7.1/
COPY benchmark/runtime-action-worker-final-combined-v3-cron-rescan-systemd/ \
    /src/benchmark/runtime-action-worker-final-combined-v3-cron-rescan-systemd/
COPY scripts/capture_runtime_action_worker_final_combined_v3_cron_rescan_systemd.sh \
    scripts/materialize_fixed_admission_probes.py \
    scripts/materialize_openclaw_final_v3_rebound_probes.py \
    scripts/runtime_action_worker_final_combined_v3_cron_rescan_systemd_probe.py \
    scripts/runtime_action_worker_final_combined_v3_fresh_session_reset_systemd_probe.py \
    /src/scripts/

# Isolate one exact, materialized V3 cron bundle over the retained force-policy
# image. Materialization binds bytes only; the collector deliberately emits no
# semantic qualification or admission authority.
RUN set -eux; \
    test "$V3_FORCE_BASE" = \
        "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json | cut -d ' ' -f 1)" = \
        2855474d8b709654fb8902c0dc69ec1f0a3a378518ec23bfb12c1eb9630824ab; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json)" = 2160; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v3.json | cut -d ' ' -f 1)" = \
        3229bd747088199d8bae074bbc27a415169fa21f86462408434ecdb43c5b2a6c; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v3.json)" = 5302; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v3.lock.json | cut -d ' ' -f 1)" = \
        3bbcc6568cf713f9e534f84f7a92e313b5aa357065759bd01b5f24a594fb5822; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v3.lock.json)" = 7620; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host-v3.sh | cut -d ' ' -f 1)" = \
        3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c; \
    test "$(sha256sum /usr/libexec/aragorn/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py | cut -d ' ' -f 1)" = \
        c9e3e43e4d122575cc362e2ec73b2fc4b57d4ad465a1d49e4b94291d935217ad; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_combined_v3_fresh_session_reset_systemd_probe.py | cut -d ' ' -f 1)" = \
        467af8df703ca43e97e8b8158f2c085ffecdc5c6e37bff4ef257095d1178fd25; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py | cut -d ' ' -f 1)" = \
        48c4a6d269f29080cf88d750205d40731f66fc13415aa76f6afeff0f8259e809; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_route_systemd_probe.py | cut -d ' ' -f 1)" = \
        50e96d42459a40d0a87ce2cdd215bace14072a626281a3fc733efb5b22831355; \
    test "$(sha256sum /src/scripts/materialize_fixed_admission_probes.py | cut -d ' ' -f 1)" = \
        0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec; \
    test "$(stat -c '%s' /src/scripts/materialize_fixed_admission_probes.py)" = 87912; \
    test "$(sha256sum /src/scripts/materialize_openclaw_final_v3_rebound_probes.py | cut -d ' ' -f 1)" = \
        8321a6c423b03c283d175185de6886ca12aaa08c244f81b67be3a73a47279a1c; \
    test "$(stat -c '%s' /src/scripts/materialize_openclaw_final_v3_rebound_probes.py)" = 7691; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-cron-rescan-v2-probe.mjs | cut -d ' ' -f 1)" = \
        3733b27d34e692271b0ac7c93956017d55b318fef1dcabc27e3478531c0e47b3; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-cron-rescan-v2-probe.mjs)" = 36202; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs)" = 13609; \
    find /route-input -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; \
    /usr/local/bin/python3.12 \
        /src/scripts/materialize_openclaw_final_v3_rebound_probes.py \
        ADM-02/reload/cron-rescan /route-input/cron-rescan; \
    test "$(find /route-input -mindepth 1 -maxdepth 2 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'cron-rescan:d' \
            'cron-rescan/protected-cron-rescan-probe.mjs:f' \
            'cron-rescan/protected-observation-v1.mjs:f' \
            | sort)"; \
    test "$(sha256sum /route-input/cron-rescan/protected-cron-rescan-probe.mjs | cut -d ' ' -f 1)" = \
        94d3b47162fd1bdc97028f44115ef54acfe8b7a296210a47a8a24a71771bb2d0; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /route-input/cron-rescan/protected-cron-rescan-probe.mjs)" = \
        'regular file:0:0:444:1:35318'; \
    test "$(sha256sum /route-input/cron-rescan/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /route-input/cron-rescan/protected-observation-v1.mjs)" = \
        'regular file:0:0:444:1:16324'; \
    test "$(stat -c '%F:%u:%g:%a:%h' /route-input/cron-rescan)" = \
        'directory:0:0:555:2'; \
    /usr/local/bin/node --check \
        /route-input/cron-rescan/protected-cron-rescan-probe.mjs; \
    /usr/local/bin/node --check \
        /route-input/cron-rescan/protected-observation-v1.mjs; \
    chmod 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-cron-rescan-v2-probe.mjs \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs \
        /src/benchmark/runtime-action-worker-final-combined-v3-cron-rescan-systemd/Dockerfile; \
    chmod 0555 \
        /src/scripts/capture_runtime_action_worker_final_combined_v3_cron_rescan_systemd.sh \
        /src/scripts/materialize_fixed_admission_probes.py \
        /src/scripts/materialize_openclaw_final_v3_rebound_probes.py \
        /src/scripts/runtime_action_worker_final_combined_v3_cron_rescan_systemd_probe.py \
        /src/scripts/runtime_action_worker_final_combined_v3_fresh_session_reset_systemd_probe.py; \
    test -z "$(find /route-input -mindepth 1 ! -type d ! -type f -print -quit)"
