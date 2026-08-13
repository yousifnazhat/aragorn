ARG P38D_BASE

FROM ${P38D_BASE}

ARG P38D_BASE

COPY packaging/activate-runtime-action-worker-host.sh \
    /src/packaging/activate-runtime-action-worker-host.sh
COPY benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v1.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v1.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v1.lock.json \
    /src/benchmark/admission/openclaw-v2026.7.1/
COPY benchmark/runtime-action-worker-final-combined-systemd/ \
    /src/benchmark/runtime-action-worker-final-combined-systemd/
COPY scripts/capture_runtime_action_worker_final_combined_systemd.sh \
    scripts/runtime_action_worker_final_combined_systemd_probe.py \
    /src/scripts/

# The final layer changes no unit: it binds the measured runtime, canonical
# config, singleton skill, current activator, and thin P3.7c wrapper only.
RUN set -eux; \
    test "$P38D_BASE" = \
        "sha256:fb4794e886c2bef6ab450d28fc59ee3347ed2c2426d116c81781dc1d4bf09847"; \
    test "$(sha256sum /usr/libexec/aragorn/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        b395941f2ebfbb5593460e125cbcb4d9a1aea9a6ec63a09baa181dfd350a5ab2; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        589d8174e2d175e1680b4a3b5b29acc6db33660ffe0cd682b7f07fa6f9de7a64; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v1.json | cut -d ' ' -f 1)" = \
        3b7218cb95bae1f7cfa3c00b499337af39bf55e3658430bfcbae62edd388d235; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v1.json | cut -d ' ' -f 1)" = \
        78d7f9c5c4264c7950001b73dc9b8508dec0bb47d33b9258069106c550240670; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v1.lock.json | cut -d ' ' -f 1)" = \
        495f783f0bf1f942d186ba0720cc23ff9693995ff885226a88ab5ce5e5b76c3b; \
    test "$(sha256sum /src/benchmark/runtime-action-worker-final-combined-systemd/SKILL.md | cut -d ' ' -f 1)" = \
        eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa; \
    test "$(sha256sum /usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/index.js | cut -d ' ' -f 1)" = \
        71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b; \
    test "$(sha256sum /usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json | cut -d ' ' -f 1)" = \
        d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036; \
    test "$(sha256sum /usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/package.json | cut -d ' ' -f 1)" = \
        0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2; \
    install -m 0755 /src/packaging/activate-runtime-action-worker-host.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    install -d -m 0555 \
        /opt \
        /opt/aragorn \
        /opt/aragorn/runtime-profile \
        /opt/aragorn/runtime-profile/template-skill; \
    install -m 0444 \
        /src/benchmark/runtime-action-worker-final-combined-systemd/SKILL.md \
        /opt/aragorn/runtime-profile/template-skill/SKILL.md; \
    cmp /src/packaging/activate-runtime-action-worker-host.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    cmp /src/benchmark/runtime-action-worker-final-combined-systemd/SKILL.md \
        /opt/aragorn/runtime-profile/template-skill/SKILL.md; \
    test "$(stat -c '%u:%g:%a:%h:%s' /opt/aragorn/runtime-profile/template-skill/SKILL.md)" = \
        0:0:444:1:140; \
    chmod 0555 \
        /src/packaging/activate-runtime-action-worker-host.sh \
        /src/scripts/capture_runtime_action_worker_final_combined_systemd.sh \
        /src/scripts/runtime_action_worker_final_combined_systemd_probe.py; \
    chmod 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v1.json \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v1.json \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v1.lock.json \
        /src/benchmark/runtime-action-worker-final-combined-systemd/Dockerfile \
        /src/benchmark/runtime-action-worker-final-combined-systemd/SKILL.md
