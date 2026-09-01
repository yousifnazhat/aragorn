ARG V3_FORCE_BASE

# Exact retained proposal child; its rootfs is itself an additive child of the
# exact V3 force-policy parent supplied and rechecked by the capture recipe.
FROM sha256:601a0b582406193cf031b0f5512b564464452a60a00bc97098266182ccd13ff7

ARG V3_FORCE_BASE

COPY benchmark/runtime-action-worker-final-combined-v3-workshop-invalidation-systemd/ \
    /src/benchmark/runtime-action-worker-final-combined-v3-workshop-invalidation-systemd/
COPY scripts/capture_runtime_action_worker_final_combined_v3_workshop_invalidation_systemd.sh \
    scripts/materialize_openclaw_final_v3_workshop_invalidation_probe.py \
    scripts/runtime_action_worker_final_combined_v3_workshop_invalidation_systemd_probe.py \
    /src/scripts/

RUN set -eux; \
    test "$V3_FORCE_BASE" = \
        "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/protected-route-v3-probe.mjs | cut -d ' ' -f 1)" = \
        667dec03c90ff0df1567e8dcca9d4137f66d0de8e3f7f302f6fc279f311b2780; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/benchmark/admission/openclaw-v2026.7.1/protected-route-v3-probe.mjs)" = \
        'regular file:0:0:444:1:50175'; \
    test "$(sha256sum /src/scripts/materialize_openclaw_final_v3_workshop_invalidation_probe.py | cut -d ' ' -f 1)" = \
        d60da66234d68f180e19e61f74f16a8ce9422221015f726fa9b839549edd06fc; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/materialize_openclaw_final_v3_workshop_invalidation_probe.py)" = \
        'regular file:0:0:700:1:8612'; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_combined_v3_workshop_invalidation_systemd_probe.py | cut -d ' ' -f 1)" = \
        9fbb5203c42007d39be55603207e240a8e3f3a52055a69c3bd44677f794f44e4; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/runtime_action_worker_final_combined_v3_workshop_invalidation_systemd_probe.py)" = \
        'regular file:0:0:700:1:11916'; \
    test "$(sha256sum /src/scripts/capture_runtime_action_worker_final_combined_v3_workshop_invalidation_systemd.sh | cut -d ' ' -f 1)" = \
        0aab169f990453a1de2a3529ae63e598ae7ca355201dee1357a66f6bdddc6495; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' /src/scripts/capture_runtime_action_worker_final_combined_v3_workshop_invalidation_systemd.sh)" = \
        'regular file:0:0:700:1:2818'; \
    materialized=/tmp/workshop-invalidation-v3; \
    /usr/local/bin/python3.12 \
        /src/scripts/materialize_openclaw_final_v3_workshop_invalidation_probe.py \
        "$materialized"; \
    probe="$materialized/protected-workshop-invalidation-v3-probe.mjs"; \
    proposal="$materialized/PROPOSAL.md"; \
    test "$(sha256sum "$probe" | cut -d ' ' -f 1)" = \
        d987ab8e17caa527786486f8440d194bec6e8b441386fd0f85100e3d33459334; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' "$probe")" = \
        'regular file:0:0:444:1:48609'; \
    test "$(sha256sum "$proposal" | cut -d ' ' -f 1)" = \
        a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a; \
    test "$(stat -c '%F:%u:%g:%a:%h:%s' "$proposal")" = \
        'regular file:0:0:444:1:84'; \
    install -m 0444 "$probe" \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-workshop-invalidation-v3-probe.mjs; \
    find /route-input -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; \
    install -d -m 0555 /route-input/workshop-invalidation; \
    install -m 0444 "$proposal" \
        /route-input/workshop-invalidation/PROPOSAL.md; \
    install -m 0444 "$probe" \
        /route-input/workshop-invalidation/protected-workshop-invalidation-v3-probe.mjs; \
    rm -rf -- "$materialized"; \
    test "$(find /route-input -mindepth 1 -maxdepth 2 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'workshop-invalidation:d' \
            'workshop-invalidation/PROPOSAL.md:f' \
            'workshop-invalidation/protected-workshop-invalidation-v3-probe.mjs:f' \
            | sort)"; \
    test "$(sha256sum /route-input/workshop-invalidation/PROPOSAL.md | cut -d ' ' -f 1)" = \
        a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a; \
    test "$(sha256sum /route-input/workshop-invalidation/protected-workshop-invalidation-v3-probe.mjs | cut -d ' ' -f 1)" = \
        d987ab8e17caa527786486f8440d194bec6e8b441386fd0f85100e3d33459334; \
    /usr/local/bin/node --check \
        /route-input/workshop-invalidation/protected-workshop-invalidation-v3-probe.mjs; \
    chmod 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-workshop-invalidation-v3-probe.mjs \
        /route-input/workshop-invalidation/PROPOSAL.md \
        /route-input/workshop-invalidation/protected-workshop-invalidation-v3-probe.mjs \
        /src/benchmark/runtime-action-worker-final-combined-v3-workshop-invalidation-systemd/Dockerfile; \
    chmod 0555 \
        /src/scripts/capture_runtime_action_worker_final_combined_v3_workshop_invalidation_systemd.sh \
        /src/scripts/materialize_openclaw_final_v3_workshop_invalidation_probe.py \
        /src/scripts/runtime_action_worker_final_combined_v3_workshop_invalidation_systemd_probe.py; \
    find /route-input -type d -exec chmod 0555 {} +; \
    test -z "$(find /route-input -mindepth 1 ! -type d ! -type f -print -quit)"
