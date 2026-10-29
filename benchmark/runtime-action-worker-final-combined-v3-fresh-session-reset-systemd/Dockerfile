ARG V3_FORCE_BASE

FROM ${V3_FORCE_BASE}

ARG V3_FORCE_BASE

COPY benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs \
    /src/benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs
COPY benchmark/runtime-action-worker-final-combined-v3-fresh-session-reset-systemd/ \
    /src/benchmark/runtime-action-worker-final-combined-v3-fresh-session-reset-systemd/
COPY scripts/capture_runtime_action_worker_final_combined_v3_fresh_session_reset_systemd.sh \
    scripts/materialize_fixed_admission_probes.py \
    scripts/runtime_action_worker_final_combined_v3_fresh_session_reset_systemd_probe.py \
    /src/scripts/

# This is one route-only child of the exact retained V3 force-policy image. The
# checked-in probe is deterministically materialized to the pinned V2 route
# input, then transformed only where its V2 config identity is embedded. The
# route action and observation logic otherwise remain byte-derived from signed
# sources.
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
    test "$(sha256sum /usr/bin/printf | cut -d ' ' -f 1)" = \
        2c7b0151ee3c1ba4e829209f2ff4336de9d97143e22bf87c7448539112139957; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /usr/bin/printf)" = \
        'regular file:0:0:755:1:68480'; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py | cut -d ' ' -f 1)" = \
        c9e3e43e4d122575cc362e2ec73b2fc4b57d4ad465a1d49e4b94291d935217ad; \
    source=/src/benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs; \
    materialized_dir=/tmp/fresh-session-reset-v2; \
    v2=/src/benchmark/admission/openclaw-v2026.7.1/protected-route-v2-probe.mjs; \
    v3=/src/benchmark/admission/openclaw-v2026.7.1/protected-route-v3-probe.mjs; \
    old=b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e; \
    new=dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c; \
    test "$(sha256sum "$source" | cut -d ' ' -f 1)" = \
        3d9615bbfae6c86b272c862de2faaf55f24cc7018a5e77f912f2b4f527162504; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' "$source")" = \
        'regular file:0:0:600:1:34185'; \
    test "$(sha256sum /src/scripts/materialize_fixed_admission_probes.py | cut -d ' ' -f 1)" = \
        0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/materialize_fixed_admission_probes.py)" = \
        'regular file:0:0:600:1:87912'; \
    /usr/local/bin/python3.12 \
        /src/scripts/materialize_fixed_admission_probes.py \
        --final-combined-v2 "$materialized_dir" \
        protected-route-probe.mjs; \
    install -m 0644 \
        "$materialized_dir/protected-route-probe.mjs" "$v2"; \
    rm -rf -- "$materialized_dir"; \
    test "$(sha256sum "$v2" | cut -d ' ' -f 1)" = \
        65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' "$v2")" = \
        'regular file:0:0:644:1:44825'; \
    test "$(grep -F -o "$old" "$v2" | wc -l)" = 2; \
    test "$(grep -F -o "$new" "$v2" | wc -l)" = 0; \
    test "$(grep -F -o 'configuration.file?.size === 1880' "$v2" | wc -l)" = 1; \
    test "$(grep -F -o 'configuration.file?.size === 2159' "$v2" | wc -l)" = 0; \
    install -m 0644 "$v2" "$v3"; \
    sed -i \
        -e "s/$old/$new/g" \
        -e 's/configuration.file?.size === 1880/configuration.file?.size === 2159/' \
        "$v3"; \
    test "$(grep -F -o "$old" "$v3" | wc -l)" = 0; \
    test "$(grep -F -o "$new" "$v3" | wc -l)" = 2; \
    test "$(grep -F -o 'configuration.file?.size === 1880' "$v3" | wc -l)" = 0; \
    test "$(grep -F -o 'configuration.file?.size === 2159' "$v3" | wc -l)" = 1; \
    test "$(sha256sum "$v3" | cut -d ' ' -f 1)" = \
        4687054e9d7ea264c6772de4e0560fafb195ebbbfc7397333297abd6cc4347ff; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' "$v3")" = \
        'regular file:0:0:644:1:44825'; \
    find /route-input -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; \
    install -d -m 0555 /route-input/fresh-session-reset; \
    install -m 0444 "$v3" \
        /route-input/fresh-session-reset/protected-route-probe.mjs; \
    test "$(find /route-input -mindepth 1 -maxdepth 2 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'fresh-session-reset:d' \
            'fresh-session-reset/protected-route-probe.mjs:f' \
            | sort)"; \
    test "$(sha256sum /route-input/fresh-session-reset/protected-route-probe.mjs | cut -d ' ' -f 1)" = \
        4687054e9d7ea264c6772de4e0560fafb195ebbbfc7397333297abd6cc4347ff; \
    /usr/local/bin/node --check "$v3"; \
    chmod 0444 "$source" "$v2" "$v3" \
        /route-input/fresh-session-reset/protected-route-probe.mjs \
        /src/benchmark/runtime-action-worker-final-combined-v3-fresh-session-reset-systemd/Dockerfile; \
    chmod 0555 \
        /src/scripts/capture_runtime_action_worker_final_combined_v3_fresh_session_reset_systemd.sh \
        /src/scripts/materialize_fixed_admission_probes.py \
        /src/scripts/runtime_action_worker_final_combined_v3_fresh_session_reset_systemd_probe.py; \
    find /route-input -type d -exec chmod 0555 {} +; \
    test -z "$(find /route-input -mindepth 1 ! -type d ! -type f -print -quit)"
