ARG V2_FORCE_BASE

FROM ${V2_FORCE_BASE}

ARG V2_FORCE_BASE

COPY benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v3.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v3.lock.json \
    benchmark/admission/openclaw-v2026.7.1/protected-plugin-force-reinstall-v3-probe.py \
    /src/benchmark/admission/openclaw-v2026.7.1/
COPY benchmark/runtime-action-worker-final-combined-v3-plugin-force-reinstall-systemd/ \
    /src/benchmark/runtime-action-worker-final-combined-v3-plugin-force-reinstall-systemd/
COPY scripts/capture_runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd.sh \
    scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py \
    /src/scripts/

# V3 is one additive, force-route-only child of the exact retained V2 force image.
# The shared V2 activator source remains byte-for-byte unchanged. A separately
# named V3 source is transformed once, verified, and installed over the runtime
# activator so source/install custody remains explicit without rewriting V2.
RUN set -eux; \
    test "$V2_FORCE_BASE" = \
        "sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b"; \
    test "$(stat -c '%u:%g:%a:%h:%s' /src/packaging/activate-runtime-action-worker-host.sh)" = \
        0:0:555:1:30504; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        52dbdae05a0a394b7314d87337b1a536ba3cf9a0b999d95432341daa068ca5cf; \
    test "$(stat -c '%u:%g:%a:%h:%s' /usr/libexec/aragorn/activate-runtime-action-worker-host.sh)" = \
        0:0:755:1:30504; \
    test "$(sha256sum /usr/libexec/aragorn/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        52dbdae05a0a394b7314d87337b1a536ba3cf9a0b999d95432341daa068ca5cf; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_combined_v2_systemd_probe.py | cut -d ' ' -f 1)" = \
        03fcf63cd6f68521e261ecb8dc558c2a906b59338ce96a20688098f2066dc550; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_route_systemd_probe.py | cut -d ' ' -f 1)" = \
        50e96d42459a40d0a87ce2cdd215bace14072a626281a3fc733efb5b22831355; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/runtime_action_worker.py | cut -d ' ' -f 1)" = \
        a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873; \
    test "$(sha256sum /opt/aragorn/runtime-profile/template-skill/SKILL.md | cut -d ' ' -f 1)" = \
        eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa; \
    test "$(stat -c '%u:%g:%a:%h:%s' /opt/aragorn/runtime-profile/template-skill/SKILL.md)" = \
        0:0:444:1:140; \
    test "$(sha256sum /usr/bin/printf | cut -d ' ' -f 1)" = \
        2c7b0151ee3c1ba4e829209f2ff4336de9d97143e22bf87c7448539112139957; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /usr/bin/printf)" = \
        'regular file:0:0:755:1:68480'; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json | cut -d ' ' -f 1)" = \
        2855474d8b709654fb8902c0dc69ec1f0a3a378518ec23bfb12c1eb9630824ab; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json)" = 2160; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v3.json | cut -d ' ' -f 1)" = \
        3229bd747088199d8bae074bbc27a415169fa21f86462408434ecdb43c5b2a6c; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v3.json)" = 5302; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v3.lock.json | cut -d ' ' -f 1)" = \
        3bbcc6568cf713f9e534f84f7a92e313b5aa357065759bd01b5f24a594fb5822; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v3.lock.json)" = 7620; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-plugin-force-reinstall-v3-probe.py | cut -d ' ' -f 1)" = \
        58ba8c44ef474588dd48c8afaca01681c26d8a0b45c153994463c87e719f115a; \
    test "$(stat -c '%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-plugin-force-reinstall-v3-probe.py)" = 30362; \
    test "$(sha256sum /route-input/plugin-force-reinstall/protected-plugin-force-reinstall-probe.py | cut -d ' ' -f 1)" = \
        6b4adf647cef823f5cfee73d0130c06ab4612e37fb704246a56fe4dca03c0bbe; \
    old=b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e; \
    new=dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c; \
    test "$(grep -F -o "$old" /src/packaging/activate-runtime-action-worker-host.sh | wc -l)" = 1; \
    test "$(grep -F -o "$new" /src/packaging/activate-runtime-action-worker-host.sh | wc -l)" = 0; \
    install -m 0555 /src/packaging/activate-runtime-action-worker-host.sh \
        /src/packaging/activate-runtime-action-worker-host-v3.sh; \
    sed -i "s/$old/$new/" \
        /src/packaging/activate-runtime-action-worker-host-v3.sh; \
    test "$(grep -F -o "$old" /src/packaging/activate-runtime-action-worker-host-v3.sh | wc -l)" = 0; \
    test "$(grep -F -o "$new" /src/packaging/activate-runtime-action-worker-host-v3.sh | wc -l)" = 1; \
    test "$(stat -c '%u:%g:%a:%h:%s' /src/packaging/activate-runtime-action-worker-host-v3.sh)" = \
        0:0:555:1:30504; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host-v3.sh | cut -d ' ' -f 1)" = \
        3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c; \
    install -m 0755 /src/packaging/activate-runtime-action-worker-host-v3.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    cmp /src/packaging/activate-runtime-action-worker-host-v3.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    test "$(stat -c '%u:%g:%a:%h:%s' /usr/libexec/aragorn/activate-runtime-action-worker-host.sh)" = \
        0:0:755:1:30504; \
    test "$(sha256sum /usr/libexec/aragorn/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c; \
    find /route-input -mindepth 1 -maxdepth 1 \
        ! -name plugin-force-reinstall -exec rm -rf -- {} +; \
    rm /route-input/plugin-force-reinstall/protected-plugin-force-reinstall-probe.py; \
    install -m 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-plugin-force-reinstall-v3-probe.py \
        /route-input/plugin-force-reinstall/protected-plugin-force-reinstall-v3-probe.py; \
    find /route-input -type d -exec chmod 0555 {} +; \
    find /route-input -type f -exec chmod 0444 {} +; \
    test -z "$(find /route-input -mindepth 1 ! -type d ! -type f -print -quit)"; \
    test "$(find /route-input -mindepth 1 -maxdepth 3 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'plugin-force-reinstall:d' \
            'plugin-force-reinstall/baseline-source:d' \
            'plugin-force-reinstall/baseline-source/index.js:f' \
            'plugin-force-reinstall/baseline-source/openclaw.plugin.json:f' \
            'plugin-force-reinstall/baseline-source/package.json:f' \
            'plugin-force-reinstall/candidate-source:d' \
            'plugin-force-reinstall/candidate-source/index.js:f' \
            'plugin-force-reinstall/candidate-source/openclaw.plugin.json:f' \
            'plugin-force-reinstall/candidate-source/package.json:f' \
            'plugin-force-reinstall/protected-plugin-force-reinstall-v3-probe.py:f' \
            | sort)"; \
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
    test "$(sha256sum /route-input/plugin-force-reinstall/protected-plugin-force-reinstall-v3-probe.py | cut -d ' ' -f 1)" = \
        58ba8c44ef474588dd48c8afaca01681c26d8a0b45c153994463c87e719f115a; \
    chmod 0555 \
        /src/packaging/activate-runtime-action-worker-host-v3.sh \
        /src/scripts/capture_runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd.sh \
        /src/scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py; \
    chmod 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v3.json \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v3.lock.json \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-plugin-force-reinstall-v3-probe.py \
        /src/benchmark/runtime-action-worker-final-combined-v3-plugin-force-reinstall-systemd/Dockerfile
