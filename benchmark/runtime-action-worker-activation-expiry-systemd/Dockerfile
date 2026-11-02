ARG P37B_BASE

FROM ${P37B_BASE}

ARG P37B_BASE

COPY packaging/activate-runtime-capability-host.sh \
    packaging/activate-runtime-action-worker-host.sh \
    packaging/install-runtime-action-worker-host.sh \
    /src/packaging/
COPY src/aragorn/runtime_action_broker_v4.py \
    src/aragorn/runtime_action_broker_v5.py \
    src/aragorn/runtime_action_service_v4.py \
    src/aragorn/runtime_action_service_v5.py \
    src/aragorn/runtime_action_worker.py \
    /src/src/aragorn/
COPY benchmark/runtime-action-worker-activation-expiry-systemd/ \
    /src/benchmark/runtime-action-worker-activation-expiry-systemd/
COPY scripts/runtime_action_worker_activation_expiry_systemd_probe.py \
    scripts/capture_runtime_action_worker_activation_expiry_systemd.sh \
    /src/scripts/

# P3.7c is one additive current-byte activation/expiry layer over the exact,
# separately retained P3.7b image. The inherited installer inputs remain bound
# by that parent; only these eight changed production sources are overlaid.
RUN set -eux; \
    test "$P37B_BASE" = \
        "sha256:1afab032375efbe87ac938c0993880e164d6dace2e37239a27c6def8e320e1db"; \
    test "$(sha256sum /src/packaging/activate-runtime-capability-host.sh | cut -d ' ' -f 1)" = \
        "6d8925e6195b1218d7dd81452707e88b89e1b68e41d3afa1d6211981a3bb203a"; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        "f474737ccc9cd52b91247d50604186adcde449f69df73ed03cdecdc0833c79b2"; \
    test "$(sha256sum /src/packaging/install-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        "885441b628298629cc07d5c68e52b852864c6a755bc10d0e7e5de406f17b4748"; \
    test "$(sha256sum /src/src/aragorn/runtime_action_broker_v4.py | cut -d ' ' -f 1)" = \
        "ab7d08105229ee3dd58f8dca5c20156d5e260e2b79f0ed2b4c08693c3cf6174a"; \
    test "$(sha256sum /src/src/aragorn/runtime_action_broker_v5.py | cut -d ' ' -f 1)" = \
        "35c17f92cca01ba064058f6d76223a03072138aa61d060538600f6799af7eca5"; \
    test "$(sha256sum /src/src/aragorn/runtime_action_service_v4.py | cut -d ' ' -f 1)" = \
        "8c3c70dc85dd8eaa8e8a2dcdbc2c8b0571b23f5901eb023cf146a916f49b49a7"; \
    test "$(sha256sum /src/src/aragorn/runtime_action_service_v5.py | cut -d ' ' -f 1)" = \
        "a3e829d2e60f26dd91cbb14967ddf2a747414ce8f125b4f207dbce7a5e1e86c7"; \
    test "$(sha256sum /src/src/aragorn/runtime_action_worker.py | cut -d ' ' -f 1)" = \
        "16e77024f715d1b7f2c600df16e5878e23f584753444fef998cf9b4742603d60"; \
    sh /src/packaging/install-runtime-action-worker-host.sh; \
    systemd-sysusers /usr/lib/sysusers.d/aragorn-runtime-action-worker.conf; \
    systemd-analyze verify \
        /usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service \
        /usr/lib/systemd/system/aragorn-runtime-lineage-capability-observation-publisher.service \
        /usr/lib/systemd/system/aragorn-runtime-action-worker.service \
        /usr/lib/systemd/system/aragorn-agent-gateway.service; \
    for name in \
        __init__.py \
        oci_worker_protocol.py \
        runtime_action_broker.py \
        runtime_action_broker_v2.py \
        runtime_action_broker_v3.py \
        runtime_action_broker_v4.py \
        runtime_action_broker_v5.py \
        runtime_action_decision.py \
        runtime_action_observation_publisher.py \
        runtime_action_observation_publisher_v2.py \
        runtime_action_observation_publisher_v3.py \
        runtime_action_observation_publisher_v4.py \
        runtime_action_service.py \
        runtime_action_service_v2.py \
        runtime_action_service_v4.py \
        runtime_action_service_v5.py \
        runtime_action_worker.py \
        runtime_active_skill_lineage.py \
        runtime_capability_grant.py \
        runtime_lineage_capability_issuer.py \
        runtime_observation_service.py \
        runtime_observation_service_v2.py \
        runtime_observation_service_v3.py \
        runtime_observation_service_v4.py \
        runtime_process_profile.py \
        runtime_revocation_service.py; \
    do \
        cmp "/src/src/aragorn/$name" "/usr/lib/aragorn/aragorn/$name"; \
    done; \
    for name in \
        activate-runtime-capability-host.sh \
        activate-runtime-action-worker-host.sh \
        aragorn-runtime-action-service-v5.py \
        aragorn-runtime-action-worker-service.py \
        aragorn-runtime-observation-service-v4.py \
        aragorn-runtime-revocation-service.py; \
    do \
        case "$name" in \
            activate-*) source="/src/packaging/$name" ;; \
            *) source="/src/packaging/libexec/$name" ;; \
        esac; \
        cmp "$source" "/usr/libexec/aragorn/$name"; \
    done; \
    for name in \
        aragorn-agent-gateway.service \
        aragorn-runtime-action-worker.service \
        aragorn-runtime-lineage-capability-action-broker.service \
        aragorn-runtime-lineage-capability-observation-publisher.service \
        aragorn-runtime-revocation-publisher.service; \
    do \
        cmp "/src/packaging/systemd/$name" "/usr/lib/systemd/system/$name"; \
    done; \
    cmp /src/packaging/systemd/aragorn-gateway.sysusers \
        /usr/lib/sysusers.d/aragorn-gateway.conf; \
    cmp /src/packaging/systemd/aragorn-runtime-action-worker.sysusers \
        /usr/lib/sysusers.d/aragorn-runtime-action-worker.conf; \
    cmp /src/packaging/systemd/aragorn-runtime-action.tmpfiles \
        /usr/lib/tmpfiles.d/aragorn-runtime-action.conf; \
    for name in index.js openclaw.plugin.json package.json; do \
        cmp \
            "/src/packaging/openclaw/aragorn-runtime-action-worker/$name" \
            "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/$name"; \
    done; \
    for name in \
        aragorn-runtime-action-service.py \
        aragorn-runtime-action-service-v2.py \
        aragorn-runtime-action-service-v3.py \
        aragorn-runtime-action-service-v4.py \
        aragorn-runtime-observation-service.py \
        aragorn-runtime-observation-service-v2.py \
        aragorn-runtime-observation-service-v3.py; \
    do \
        test ! -e "/usr/libexec/aragorn/$name"; \
    done; \
    chmod 0555 \
        /src/packaging/activate-runtime-capability-host.sh \
        /src/packaging/activate-runtime-action-worker-host.sh \
        /src/packaging/install-runtime-action-worker-host.sh \
        /src/scripts/runtime_action_worker_activation_expiry_systemd_probe.py \
        /src/scripts/capture_runtime_action_worker_activation_expiry_systemd.sh; \
    chmod 0444 \
        /src/benchmark/runtime-action-worker-activation-expiry-systemd/Dockerfile \
        /src/src/aragorn/runtime_action_broker_v4.py \
        /src/src/aragorn/runtime_action_broker_v5.py \
        /src/src/aragorn/runtime_action_service_v4.py \
        /src/src/aragorn/runtime_action_service_v5.py \
        /src/src/aragorn/runtime_action_worker.py
