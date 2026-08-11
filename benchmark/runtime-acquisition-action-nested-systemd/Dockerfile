ARG P38C_BASE

FROM ${P38C_BASE}

ARG P38C_BASE

RUN set -eux; \
    snapshot=/opt/aragorn-p38c-overwritten-artifacts; \
    test "$P38C_BASE" = \
        "sha256:0f028d91f2215e6225bc4f5a30128edc56119cf9e2886b106bf18eb37f50fccb"; \
    test "$(sha256sum /src/src/aragorn/runtime_active_skill_lineage.py | cut -d ' ' -f 1)" = \
        7f5fc7aa979efd0a719904d14b2d8576b80af302572882de90dca464291db726; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/runtime_active_skill_lineage.py | cut -d ' ' -f 1)" = \
        7f5fc7aa979efd0a719904d14b2d8576b80af302572882de90dca464291db726; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        466261b94b832da010a2f27896335731cfcaeb3a87d8c15767b80c6aceb752bb; \
    test "$(sha256sum /usr/libexec/aragorn/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        466261b94b832da010a2f27896335731cfcaeb3a87d8c15767b80c6aceb752bb; \
    install -d -m 0755 "$snapshot/source" "$snapshot/installed"; \
    install -m 0444 /src/src/aragorn/runtime_active_skill_lineage.py \
        "$snapshot/source/runtime_active_skill_lineage.py"; \
    install -m 0644 /usr/lib/aragorn/aragorn/runtime_active_skill_lineage.py \
        "$snapshot/installed/runtime_active_skill_lineage.py"; \
    install -m 0555 /src/packaging/activate-runtime-action-worker-host.sh \
        "$snapshot/source/activate-runtime-action-worker-host.sh"; \
    install -m 0755 /usr/libexec/aragorn/activate-runtime-action-worker-host.sh \
        "$snapshot/installed/activate-runtime-action-worker-host.sh"; \
    chmod 0555 "$snapshot/source" "$snapshot/installed" "$snapshot"

COPY src/aragorn/runtime_active_skill_lineage.py \
    /src/src/aragorn/runtime_active_skill_lineage.py
COPY packaging/activate-runtime-action-worker-host.sh \
    /src/packaging/activate-runtime-action-worker-host.sh
COPY benchmark/runtime-acquisition-action-nested-systemd/ \
    /src/benchmark/runtime-acquisition-action-nested-systemd/
COPY scripts/capture_runtime_acquisition_action_nested_systemd.sh \
    scripts/runtime_acquisition_action_nested_systemd_probe.py \
    /src/scripts/

# P3.8d is one additive depth-one, two-file runtime-lineage layer over the
# exact retained P3.8c acquisition-to-action image. It updates the existing
# worker package in place; it does not add a service or alter the protected
# broker release identity.
RUN set -eux; \
    package=/opt/aragorn-broker-p36b; \
    identity=/etc/aragorn/protected-broker-release.json; \
    namespace=/var/lib/aragorn-quarantine/7337e37e9f58be9929650c0bbf09f72d96e68798ec59d9f9fe9c3b8c1d9670fc; \
    snapshot=/opt/aragorn-p38c-overwritten-artifacts; \
    test "$P38C_BASE" = \
        "sha256:0f028d91f2215e6225bc4f5a30128edc56119cf9e2886b106bf18eb37f50fccb"; \
    test "$(sha256sum "$identity" | cut -d ' ' -f 1)" = \
        08ce966f9523c211ddeea9d48f386c73491d69f685c6a83d09f42d5887144cda; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/runtime_active_skill_lineage.py | cut -d ' ' -f 1)" = \
        7f5fc7aa979efd0a719904d14b2d8576b80af302572882de90dca464291db726; \
    test "$(sha256sum /usr/libexec/aragorn/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        466261b94b832da010a2f27896335731cfcaeb3a87d8c15767b80c6aceb752bb; \
    test "$(sha256sum "$snapshot/source/runtime_active_skill_lineage.py" | cut -d ' ' -f 1)" = \
        7f5fc7aa979efd0a719904d14b2d8576b80af302572882de90dca464291db726; \
    test "$(sha256sum "$snapshot/installed/runtime_active_skill_lineage.py" | cut -d ' ' -f 1)" = \
        7f5fc7aa979efd0a719904d14b2d8576b80af302572882de90dca464291db726; \
    test "$(sha256sum "$snapshot/source/activate-runtime-action-worker-host.sh" | cut -d ' ' -f 1)" = \
        466261b94b832da010a2f27896335731cfcaeb3a87d8c15767b80c6aceb752bb; \
    test "$(sha256sum "$snapshot/installed/activate-runtime-action-worker-host.sh" | cut -d ' ' -f 1)" = \
        466261b94b832da010a2f27896335731cfcaeb3a87d8c15767b80c6aceb752bb; \
    test "$(stat -c '%u:%g:%a' "$snapshot/source/runtime_active_skill_lineage.py")" = \
        0:0:444; \
    test "$(stat -c '%u:%g:%a' "$snapshot/installed/runtime_active_skill_lineage.py")" = \
        0:0:644; \
    test "$(stat -c '%u:%g:%a' "$snapshot/source/activate-runtime-action-worker-host.sh")" = \
        0:0:555; \
    test "$(stat -c '%u:%g:%a' "$snapshot/installed/activate-runtime-action-worker-host.sh")" = \
        0:0:755; \
    test "$(sha256sum /src/src/aragorn/runtime_active_skill_lineage.py | cut -d ' ' -f 1)" = \
        6d1663d097410838d6c9b69644ffdfb2bd7ace30091d31544f31b04a7f6776d1; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        b395941f2ebfbb5593460e125cbcb4d9a1aea9a6ec63a09baa181dfd350a5ab2; \
    test "$(sha256sum /src/packaging/install-runtime-capability-host.sh | cut -d ' ' -f 1)" = \
        6a7b4ec084b4dee8d974a0acab183f850be57e0acff30b616040687b307d28d9; \
    test "$(sha256sum /src/packaging/install-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        885441b628298629cc07d5c68e52b852864c6a755bc10d0e7e5de406f17b4748; \
    test "$(sha256sum /src/scripts/capture_runtime_acquisition_action_nested_systemd.sh | cut -d ' ' -f 1)" = \
        6fc9e3069cd8278c55317ba5127a18b2fcff2b657a433d64d01ed611a662a2d1; \
    test "$(sha256sum /src/scripts/runtime_acquisition_action_nested_systemd_probe.py | cut -d ' ' -f 1)" = \
        659205bd5041b263028822609cce7d70a21da13b29ec0f4c81bb6cf9135160a0; \
    test ! -e "$namespace"; \
    test ! -e /var/lib/aragorn-protected/coordinator-active.json; \
    test -z "$(find /var/lib/aragorn-protected/skills -mindepth 1 -print -quit)"; \
    sh /src/packaging/install-runtime-action-worker-host.sh; \
    systemd-analyze verify \
        /usr/lib/systemd/system/aragorn-agent-gateway.service \
        /usr/lib/systemd/system/aragorn-runtime-action-worker.service \
        /usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service \
        /usr/lib/systemd/system/aragorn-runtime-lineage-capability-observation-publisher.service \
        /usr/lib/systemd/system/aragorn-runtime-revocation-publisher.service; \
    cmp /src/src/aragorn/runtime_active_skill_lineage.py \
        /usr/lib/aragorn/aragorn/runtime_active_skill_lineage.py; \
    cmp /src/packaging/activate-runtime-action-worker-host.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/runtime_active_skill_lineage.py | cut -d ' ' -f 1)" = \
        6d1663d097410838d6c9b69644ffdfb2bd7ace30091d31544f31b04a7f6776d1; \
    test "$(sha256sum /usr/libexec/aragorn/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        b395941f2ebfbb5593460e125cbcb4d9a1aea9a6ec63a09baa181dfd350a5ab2; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/acquire.py | cut -d ' ' -f 1)" = \
        56942e7c1b10c58f265615c8b7abf3f199c7f98bf016be50eb6d3a98d2bd0f8c; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/cas.py | cut -d ' ' -f 1)" = \
        c5642f910ac4b2d6172a59a02105b359cb43d3a2f2e2240368229d3436ad4859; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/runtime_process_profile.py | cut -d ' ' -f 1)" = \
        a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68; \
    test "$(sha256sum "$identity" | cut -d ' ' -f 1)" = \
        08ce966f9523c211ddeea9d48f386c73491d69f685c6a83d09f42d5887144cda; \
    tree_digest="$(/usr/local/bin/python3.12 -I -S -B -c 'import runpy; from pathlib import Path; module=runpy.run_path("/usr/libexec/aragorn/aragorn-protected-install-launcher.py", run_name="_aragorn_p38d_release_measurement"); print(module["_measure_package"](Path("/opt/aragorn-broker-p36b"), 0))')"; \
    test "$tree_digest" = \
        sha256:c4c2aec999a3731d0193c59114d52bfced1dca89163738a3400776f2bc42463d; \
    test ! -e "$namespace"; \
    test ! -e /var/lib/aragorn-protected/coordinator-active.json; \
    test -z "$(find /var/lib/aragorn-protected/skills -mindepth 1 -print -quit)"; \
    chmod 0555 \
        /src/packaging/activate-runtime-action-worker-host.sh \
        /src/scripts/capture_runtime_acquisition_action_nested_systemd.sh \
        /src/scripts/runtime_acquisition_action_nested_systemd_probe.py; \
    chmod 0444 \
        /src/benchmark/runtime-acquisition-action-nested-systemd/Dockerfile \
        /src/src/aragorn/runtime_active_skill_lineage.py
