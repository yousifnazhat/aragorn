ARG V3_FORCE_BASE

FROM ${V3_FORCE_BASE}

ARG V3_FORCE_BASE

COPY benchmark/admission/openclaw-v2026.7.1/protected-plugin-enable-probe.mjs \
    /src/benchmark/admission/openclaw-v2026.7.1/protected-plugin-enable-probe.mjs
COPY benchmark/runtime-action-worker-final-combined-v3-plugin-enable-systemd/ \
    /src/benchmark/runtime-action-worker-final-combined-v3-plugin-enable-systemd/
COPY scripts/capture_runtime_action_worker_final_combined_v3_plugin_enable_systemd.sh \
    scripts/runtime_action_worker_final_combined_v3_plugin_enable_systemd_probe.py \
    /src/scripts/

# This is one route-only child of the exact retained V3 force-policy image. The
# checked-in V2 enable probe is transformed only where its V2 config identity is
# embedded; the route action and observation logic otherwise remain byte-derived
# from that signed source.
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
    source=/src/benchmark/admission/openclaw-v2026.7.1/protected-plugin-enable-probe.mjs; \
    target=/src/benchmark/admission/openclaw-v2026.7.1/protected-plugin-enable-v3-probe.mjs; \
    old=b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e; \
    new=dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c; \
    test "$(sha256sum "$source" | cut -d ' ' -f 1)" = \
        b31dc052d9eaffb4712de2a716f958afeb54399452aaaf47a714ee216da1ed92; \
    test "$(stat -c '%u:%g:%a:%h:%s' "$source")" = 0:0:644:1:23594; \
    test "$(grep -F -o "$old" "$source" | wc -l)" = 2; \
    test "$(grep -F -o "$new" "$source" | wc -l)" = 0; \
    test "$(grep -F -o 'file.size === 1880' "$source" | wc -l)" = 1; \
    test "$(grep -F -o 'file.size === 2159' "$source" | wc -l)" = 0; \
    test "$(grep -F -o 'current_v2_configuration_pinned' "$source" | wc -l)" = 1; \
    test "$(grep -F -o 'current_v3_configuration_pinned' "$source" | wc -l)" = 0; \
    install -m 0644 "$source" "$target"; \
    sed -i \
        -e "s/$old/$new/g" \
        -e 's/file.size === 1880/file.size === 2159/' \
        -e 's/current_v2_configuration_pinned/current_v3_configuration_pinned/' \
        "$target"; \
    test "$(grep -F -o "$old" "$target" | wc -l)" = 0; \
    test "$(grep -F -o "$new" "$target" | wc -l)" = 2; \
    test "$(grep -F -o 'file.size === 1880' "$target" | wc -l)" = 0; \
    test "$(grep -F -o 'file.size === 2159' "$target" | wc -l)" = 1; \
    test "$(grep -F -o 'current_v2_configuration_pinned' "$target" | wc -l)" = 0; \
    test "$(grep -F -o 'current_v3_configuration_pinned' "$target" | wc -l)" = 1; \
    test "$(sha256sum "$target" | cut -d ' ' -f 1)" = \
        5b4f38b55770f51071f467072f186a316feb8ea0373c5621a6ceb3e7edb4489a; \
    test "$(stat -c '%s' "$target")" = 23594; \
    find /route-input -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; \
    install -d -m 0555 /route-input/plugin-enable-activation; \
    install -m 0444 "$target" \
        /route-input/plugin-enable-activation/protected-plugin-enable-v3-probe.mjs; \
    test "$(find /route-input -mindepth 1 -maxdepth 2 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'plugin-enable-activation:d' \
            'plugin-enable-activation/protected-plugin-enable-v3-probe.mjs:f' \
            | sort)"; \
    test "$(sha256sum /route-input/plugin-enable-activation/protected-plugin-enable-v3-probe.mjs | cut -d ' ' -f 1)" = \
        5b4f38b55770f51071f467072f186a316feb8ea0373c5621a6ceb3e7edb4489a; \
    /usr/local/bin/node \
        /route-input/plugin-enable-activation/protected-plugin-enable-v3-probe.mjs \
        self-check >/tmp/plugin-enable-v3-self-check.json; \
    test "$(/usr/local/bin/python3.12 -c \
        'import json; print(json.load(open("/tmp/plugin-enable-v3-self-check.json"))["status"])')" = \
        SELF_CHECK_OK; \
    rm -f /tmp/plugin-enable-v3-self-check.json; \
    chmod 0444 "$source" "$target" \
        /route-input/plugin-enable-activation/protected-plugin-enable-v3-probe.mjs \
        /src/benchmark/runtime-action-worker-final-combined-v3-plugin-enable-systemd/Dockerfile; \
    chmod 0555 \
        /src/scripts/capture_runtime_action_worker_final_combined_v3_plugin_enable_systemd.sh \
        /src/scripts/runtime_action_worker_final_combined_v3_plugin_enable_systemd_probe.py; \
    find /route-input -type d -exec chmod 0555 {} +; \
    test -z "$(find /route-input -mindepth 1 ! -type d ! -type f -print -quit)"
