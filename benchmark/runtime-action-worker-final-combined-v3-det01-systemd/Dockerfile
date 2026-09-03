ARG V3_FORCE_BASE

# Exact frozen V3 campaign parent. The capture recipe independently verifies
# its immutable image ID and this child's additive layer ancestry.
FROM sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f

ARG V3_FORCE_BASE

COPY benchmark/admission/openclaw-v2026.7.1/deterministic-authority-vectors-v1.json \
    /src/benchmark/admission/openclaw-v2026.7.1/deterministic-authority-vectors-v1.json
COPY benchmark/runtime-action-worker-final-combined-v3-det01-systemd/ \
    /src/benchmark/runtime-action-worker-final-combined-v3-det01-systemd/
COPY scripts/capture_runtime_action_worker_final_combined_v3_det01_systemd.sh \
    scripts/materialize_openclaw_final_v3_det01.py \
    scripts/run_admission_authority_replay.py \
    scripts/runtime_action_worker_final_combined_v3_det01_systemd_probe.py \
    /src/scripts/
COPY src/aragorn/__init__.py \
    src/aragorn/admission_decision.py \
    src/aragorn/analyze.py \
    src/aragorn/oci_worker_protocol.py \
    src/aragorn/policy.py \
    /src/src/aragorn/

RUN set -eux; \
    test "$V3_FORCE_BASE" = \
        "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"; \
    test "$(sha256sum /src/scripts/materialize_openclaw_final_v3_det01.py | cut -d ' ' -f 1)" = \
        42af9e1c895a2e63de4c5803b5fb0dfc9aedcef2b164e4d8bd53b4cbf1660081; \
    test "$(stat -c '%F:%u:%g:%s' /src/scripts/materialize_openclaw_final_v3_det01.py)" = \
        'regular file:0:0:6960'; \
    test "$(sha256sum /src/scripts/run_admission_authority_replay.py | cut -d ' ' -f 1)" = \
        43be1290771abc4c6664faa262a0c366e8078a3f8aa5143d05b747e01030b966; \
    test "$(stat -c '%F:%u:%g:%s' /src/scripts/run_admission_authority_replay.py)" = \
        'regular file:0:0:7330'; \
    test "$(sha256sum /src/benchmark/admission/openclaw-v2026.7.1/deterministic-authority-vectors-v1.json | cut -d ' ' -f 1)" = \
        1b611972663a9de166bc4de16e15bf4a05841a3dc895cc920e71094b55a16161; \
    test "$(stat -c '%F:%u:%g:%s' /src/benchmark/admission/openclaw-v2026.7.1/deterministic-authority-vectors-v1.json)" = \
        'regular file:0:0:11875'; \
    test "$(sha256sum /src/src/aragorn/__init__.py | cut -d ' ' -f 1)" = \
        4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01; \
    test "$(sha256sum /src/src/aragorn/admission_decision.py | cut -d ' ' -f 1)" = \
        6ff41b17d151b89043757c5d0537e1540bd0c964618a6ea4b77f8b8195ce79ca; \
    test "$(sha256sum /src/src/aragorn/analyze.py | cut -d ' ' -f 1)" = \
        43796b5fdbca1fd0968ca87c5e8f640e3517867d6eed229c40980451471255a6; \
    test "$(sha256sum /src/src/aragorn/oci_worker_protocol.py | cut -d ' ' -f 1)" = \
        0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b; \
    test "$(sha256sum /src/src/aragorn/policy.py | cut -d ' ' -f 1)" = \
        246a0f93c1c0e2ca803c8d1bda4e50a0bc4d3ab5855242532308396d6ad82d9b; \
    test "$(sha256sum /src/scripts/capture_runtime_action_worker_final_combined_v3_det01_systemd.sh | cut -d ' ' -f 1)" = \
        5ca0a724021d3fda46cef46e087ed3a698df8bb0fbe684824db0579b1559d2e1; \
    test "$(stat -c '%F:%u:%g:%s' /src/scripts/capture_runtime_action_worker_final_combined_v3_det01_systemd.sh)" = \
        'regular file:0:0:10878'; \
    test "$(sha256sum /src/scripts/runtime_action_worker_final_combined_v3_det01_systemd_probe.py | cut -d ' ' -f 1)" = \
        f3e94d951ded2cfd802bb6e7c3e0a4cb7ced5638778e14d90fd1223162dafb8a; \
    test "$(stat -c '%F:%u:%g:%s' /src/scripts/runtime_action_worker_final_combined_v3_det01_systemd_probe.py)" = \
        'regular file:0:0:32547'; \
    chmod 0555 \
        /src/scripts/capture_runtime_action_worker_final_combined_v3_det01_systemd.sh \
        /src/scripts/materialize_openclaw_final_v3_det01.py \
        /src/scripts/runtime_action_worker_final_combined_v3_det01_systemd_probe.py; \
    chmod 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/deterministic-authority-vectors-v1.json \
        /src/benchmark/runtime-action-worker-final-combined-v3-det01-systemd/Dockerfile \
        /src/scripts/run_admission_authority_replay.py \
        /src/src/aragorn/__init__.py \
        /src/src/aragorn/admission_decision.py \
        /src/src/aragorn/analyze.py \
        /src/src/aragorn/oci_worker_protocol.py \
        /src/src/aragorn/policy.py; \
    check=/tmp/aragorn-det01-build-check; \
    /usr/local/bin/python3.12 /src/scripts/materialize_openclaw_final_v3_det01.py "$check"; \
    PYTHONDONTWRITEBYTECODE=1 /usr/local/bin/python3.12 \
        "$check/run_admission_authority_replay.py" \
        >/tmp/aragorn-det01-build-check.json; \
    test "$(find "$check" -mindepth 1 -printf '%P:%y\n' | sort)" = \
        "$(printf '%s\n' \
            'aragorn:d' \
            'aragorn/__init__.py:f' \
            'aragorn/admission_decision.py:f' \
            'aragorn/analyze.py:f' \
            'aragorn/oci_worker_protocol.py:f' \
            'aragorn/policy.py:f' \
            'deterministic-authority-vectors-v1.json:f' \
            'run_admission_authority_replay.py:f' \
            | sort)"; \
    /usr/local/bin/python3.12 -c \
        'import json,sys; d=json.load(open(sys.argv[1])); assert d["schema"] == "aragorn/admission-authority-replay-evidence/v1" and [c["case_id"] for c in d["cases"]] == ["allow", "deny", "error", "review"]' \
        /tmp/aragorn-det01-build-check.json; \
    chmod -R u+w "$check"; \
    rm -rf -- "$check" /tmp/aragorn-det01-build-check.json; \
    rm -rf -- /campaign; \
    install -d -m 0755 /campaign; \
    test -z "$(find /campaign -mindepth 1 -maxdepth 1 -print -quit)"
