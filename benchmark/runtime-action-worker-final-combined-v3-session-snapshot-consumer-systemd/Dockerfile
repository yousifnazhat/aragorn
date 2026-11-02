ARG V3_FORCE_BASE

FROM ${V3_FORCE_BASE}

ARG V3_FORCE_BASE

COPY benchmark/admission/openclaw-v2026.7.1/protected-session-snapshot-fixed-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs \
    /src/benchmark/admission/openclaw-v2026.7.1/
COPY benchmark/runtime-action-worker-final-combined-v3-session-snapshot-consumer-systemd/ \
    /src/benchmark/runtime-action-worker-final-combined-v3-session-snapshot-consumer-systemd/
COPY scripts/capture_runtime_action_worker_final_combined_v3_session_snapshot_consumer_systemd.sh \
    scripts/materialize_fixed_admission_probes.py \
    scripts/materialize_openclaw_final_v3_rebound_probes.py \
    scripts/runtime_action_worker_final_combined_v3_session_snapshot_consumer_systemd_probe.py \
    scripts/runtime_action_worker_final_combined_v3_fresh_session_reset_systemd_probe.py \
    /src/scripts/

# Isolate one exact, materialized V3 session-snapshot-consumer bundle over the retained force-policy
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
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-session-snapshot-fixed-probe.mjs | cut -d ' ' -f 1)" = \
        1efe13c3beb3ac2ff6fc1293aa64875c95424f1576a10b12943f0b875af223e2; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-session-snapshot-fixed-probe.mjs)" = 41345; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs)" = 13609; \
    find /route-input -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; \
    /usr/local/bin/python3.12 \
        /src/scripts/materialize_openclaw_final_v3_rebound_probes.py \
        ADM-02/reload/session-snapshot-consumer \
        /route-input/session-snapshot-consumer; \
    test "$(find /route-input -mindepth 1 -maxdepth 2 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'session-snapshot-consumer:d' \
            'session-snapshot-consumer/protected-session-snapshot-fixed-probe.mjs:f' \
            'session-snapshot-consumer/protected-observation-v1.mjs:f' \
            | sort)"; \
    test "$(sha256sum /route-input/session-snapshot-consumer/protected-session-snapshot-fixed-probe.mjs | cut -d ' ' -f 1)" = \
        9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /route-input/session-snapshot-consumer/protected-session-snapshot-fixed-probe.mjs)" = \
        'regular file:0:0:444:1:42266'; \
    test "$(sha256sum /route-input/session-snapshot-consumer/protected-observation-v1.mjs | cut -d ' ' -f 1)" = \
        672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /route-input/session-snapshot-consumer/protected-observation-v1.mjs)" = \
        'regular file:0:0:444:1:16324'; \
    test "$(stat -c '%F:%u:%g:%a:%h' /route-input/session-snapshot-consumer)" = \
        'directory:0:0:555:2'; \
    /usr/local/bin/node --check \
        /route-input/session-snapshot-consumer/protected-session-snapshot-fixed-probe.mjs; \
    /usr/local/bin/node --check \
        /route-input/session-snapshot-consumer/protected-observation-v1.mjs; \
    chmod 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-session-snapshot-fixed-probe.mjs \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs \
        /src/benchmark/runtime-action-worker-final-combined-v3-session-snapshot-consumer-systemd/Dockerfile; \
    chmod 0555 \
        /src/scripts/capture_runtime_action_worker_final_combined_v3_session_snapshot_consumer_systemd.sh \
        /src/scripts/materialize_fixed_admission_probes.py \
        /src/scripts/materialize_openclaw_final_v3_rebound_probes.py \
        /src/scripts/runtime_action_worker_final_combined_v3_session_snapshot_consumer_systemd_probe.py \
        /src/scripts/runtime_action_worker_final_combined_v3_fresh_session_reset_systemd_probe.py; \
    test -z "$(find /route-input -mindepth 1 ! -type d ! -type f -print -quit)"
