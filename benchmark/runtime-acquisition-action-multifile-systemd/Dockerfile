ARG P38B_BASE

FROM ${P38B_BASE}

ARG P38B_BASE

COPY src/aragorn/acquire.py \
    src/aragorn/cas.py \
    src/aragorn/runtime_active_skill_lineage.py \
    src/aragorn/runtime_process_profile.py \
    /src/src/aragorn/
COPY packaging/activate-runtime-action-worker-host.sh \
    packaging/install-runtime-action-worker-host.sh \
    packaging/install-runtime-capability-host.sh \
    /src/packaging/
COPY benchmark/runtime-acquisition-action-multifile-systemd/ \
    /src/benchmark/runtime-acquisition-action-multifile-systemd/
COPY scripts/capture_runtime_acquisition_action_multifile_systemd.sh \
    scripts/runtime_acquisition_action_multifile_systemd_probe.py \
    /src/scripts/

# P3.8c is one additive, flat two-file runtime-lineage layer over the exact
# retained P3.8b acquisition-to-action image. It updates the existing runtime
# service package in place; it does not add a second service or alter the
# protected broker release identity.
RUN set -eux; \
    package=/opt/aragorn-broker-p36b; \
    identity=/etc/aragorn/protected-broker-release.json; \
    namespace=/var/lib/aragorn-quarantine/5ffeaf70a143fb51c781294ddc7ec1708f0bb7228f5850de78716b14244881cf; \
    test "$P38B_BASE" = \
        "sha256:d9c0da9a13a72d1c4d28749421840da13d79a93f748fb9de472a78962f1707d9"; \
    test "$(sha256sum "$identity" | cut -d ' ' -f 1)" = \
        08ce966f9523c211ddeea9d48f386c73491d69f685c6a83d09f42d5887144cda; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/runtime_active_skill_lineage.py | cut -d ' ' -f 1)" = \
        417314caf5ba62f7bd312a7e99930d206f8137ad90bb3f744c4957789b88febf; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/runtime_process_profile.py | cut -d ' ' -f 1)" = \
        5e321d90b1684e7cfe6dd4a9c02228e8018f330f54fe60e5c602e45939f453d3; \
    test "$(sha256sum /usr/libexec/aragorn/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        f474737ccc9cd52b91247d50604186adcde449f69df73ed03cdecdc0833c79b2; \
    test ! -e /usr/lib/aragorn/aragorn/acquire.py; \
    test ! -e /usr/lib/aragorn/aragorn/cas.py; \
    test "$(sha256sum /src/src/aragorn/acquire.py | cut -d ' ' -f 1)" = \
        56942e7c1b10c58f265615c8b7abf3f199c7f98bf016be50eb6d3a98d2bd0f8c; \
    test "$(sha256sum /src/src/aragorn/cas.py | cut -d ' ' -f 1)" = \
        c5642f910ac4b2d6172a59a02105b359cb43d3a2f2e2240368229d3436ad4859; \
    test "$(sha256sum /src/src/aragorn/runtime_active_skill_lineage.py | cut -d ' ' -f 1)" = \
        7f5fc7aa979efd0a719904d14b2d8576b80af302572882de90dca464291db726; \
    test "$(sha256sum /src/src/aragorn/runtime_process_profile.py | cut -d ' ' -f 1)" = \
        a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68; \
    test "$(sha256sum /src/packaging/install-runtime-capability-host.sh | cut -d ' ' -f 1)" = \
        6a7b4ec084b4dee8d974a0acab183f850be57e0acff30b616040687b307d28d9; \
    test "$(sha256sum /src/packaging/install-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        885441b628298629cc07d5c68e52b852864c6a755bc10d0e7e5de406f17b4748; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        466261b94b832da010a2f27896335731cfcaeb3a87d8c15767b80c6aceb752bb; \
    test "$(sha256sum /src/scripts/capture_runtime_acquisition_action_multifile_systemd.sh | cut -d ' ' -f 1)" = \
        053ce7d46cbd9a9c60e4516ce21e54e19e777f72b1ac46dce2f025107e73eb66; \
    test "$(sha256sum /src/scripts/runtime_acquisition_action_multifile_systemd_probe.py | cut -d ' ' -f 1)" = \
        c987f7c07e207c4716d056c2426f52f73cb787d77c72d26fc4e22da275adb2c9; \
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
    for name in \
        acquire.py \
        cas.py \
        runtime_active_skill_lineage.py \
        runtime_process_profile.py; \
    do \
        cmp "/src/src/aragorn/$name" "/usr/lib/aragorn/aragorn/$name"; \
    done; \
    cmp /src/packaging/activate-runtime-action-worker-host.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/acquire.py | cut -d ' ' -f 1)" = \
        56942e7c1b10c58f265615c8b7abf3f199c7f98bf016be50eb6d3a98d2bd0f8c; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/cas.py | cut -d ' ' -f 1)" = \
        c5642f910ac4b2d6172a59a02105b359cb43d3a2f2e2240368229d3436ad4859; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/runtime_active_skill_lineage.py | cut -d ' ' -f 1)" = \
        7f5fc7aa979efd0a719904d14b2d8576b80af302572882de90dca464291db726; \
    test "$(sha256sum /usr/lib/aragorn/aragorn/runtime_process_profile.py | cut -d ' ' -f 1)" = \
        a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68; \
    test "$(sha256sum /usr/libexec/aragorn/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        466261b94b832da010a2f27896335731cfcaeb3a87d8c15767b80c6aceb752bb; \
    test "$(sha256sum "$identity" | cut -d ' ' -f 1)" = \
        08ce966f9523c211ddeea9d48f386c73491d69f685c6a83d09f42d5887144cda; \
    tree_digest="$(/usr/local/bin/python3.12 -I -S -B -c 'import runpy; from pathlib import Path; module=runpy.run_path("/usr/libexec/aragorn/aragorn-protected-install-launcher.py", run_name="_aragorn_p38c_release_measurement"); print(module["_measure_package"](Path("/opt/aragorn-broker-p36b"), 0))')"; \
    test "$tree_digest" = \
        sha256:c4c2aec999a3731d0193c59114d52bfced1dca89163738a3400776f2bc42463d; \
    test ! -e "$namespace"; \
    test ! -e /var/lib/aragorn-protected/coordinator-active.json; \
    test -z "$(find /var/lib/aragorn-protected/skills -mindepth 1 -print -quit)"; \
    chmod 0555 \
        /src/packaging/activate-runtime-action-worker-host.sh \
        /src/packaging/install-runtime-action-worker-host.sh \
        /src/packaging/install-runtime-capability-host.sh \
        /src/scripts/capture_runtime_acquisition_action_multifile_systemd.sh \
        /src/scripts/runtime_acquisition_action_multifile_systemd_probe.py; \
    chmod 0444 \
        /src/benchmark/runtime-acquisition-action-multifile-systemd/Dockerfile \
        /src/src/aragorn/acquire.py \
        /src/src/aragorn/cas.py \
        /src/src/aragorn/runtime_active_skill_lineage.py \
        /src/src/aragorn/runtime_process_profile.py
