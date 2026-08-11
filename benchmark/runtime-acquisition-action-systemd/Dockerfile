ARG P37C_BASE

FROM ${P37C_BASE}

ARG P37C_BASE

COPY src/aragorn/protected_install_coordinator.py \
    /src/src/aragorn/
COPY packaging/libexec/aragorn-protected-install-coordinator.py \
    /src/packaging/libexec/
COPY packaging/systemd/aragorn-gateway.tmpfiles \
    packaging/systemd/aragorn-protected-install-coordinator.path \
    packaging/systemd/aragorn-protected-install-coordinator.service \
    /src/packaging/systemd/
COPY ["packaging/systemd/var-lib-aragorn\\\\x2dgateway.mount", "/src/packaging/systemd/"]
COPY benchmark/runtime-acquisition-action-systemd/ \
    /src/benchmark/runtime-acquisition-action-systemd/
COPY scripts/capture_runtime_acquisition_action_systemd.sh \
    scripts/runtime_acquisition_action_systemd_probe.py \
    /src/scripts/

# P3.8b is one additive live-ingress layer over the exact retained P3.7c
# image. The parent already contains the protected installer and runtime-action
# stack under an adapted Python 3.12 identity. This layer replaces the
# pre-ingress coordinator module and applies one measured fixture-only gateway
# backport for systemd 252, the Docker cgroup prefix, and Docker's embedded DNS.
# It is not the retained Phase 1 Python 3.14 release identity.
RUN set -eux; \
    package=/opt/aragorn-broker-p36b; \
    identity=/etc/aragorn/protected-broker-release.json; \
    launcher=/usr/libexec/aragorn/aragorn-protected-install-launcher.py; \
    coordinator=/usr/libexec/aragorn/aragorn-protected-install-coordinator.py; \
    install_unit=/usr/lib/systemd/system/aragorn-protected-install.service; \
    coordinator_unit=/usr/lib/systemd/system/aragorn-protected-install-coordinator.service; \
    coordinator_path=/usr/lib/systemd/system/aragorn-protected-install-coordinator.path; \
    gateway_mount='/usr/lib/systemd/system/var-lib-aragorn\x2dgateway.mount'; \
    install_drop_in=/etc/systemd/system/aragorn-protected-install.service.d/python312.conf; \
    coordinator_drop_in=/etc/systemd/system/aragorn-protected-install-coordinator.service.d/python312.conf; \
    gateway_preimage=/src/benchmark/runtime-acquisition-action-systemd/github-gateway-preimage.py; \
    inherited_namespace=/var/lib/aragorn-quarantine/918090c29df9d1dfc1f79e0534cb67d961403b4c89567c565ad4de52a042f0a1; \
    fresh_namespace=/var/lib/aragorn-quarantine/0cac984f8f4e1311fa166d8578b7ba77b4c87c1e96421ad403aeaaa0f9c6ee0f; \
    test "$P37C_BASE" = \
        "sha256:3c8321a7118684b8358876179406da6f12fb814dcfc3a1731a923c8bb5b3fe07"; \
    test "$(sha256sum "$identity" | cut -d ' ' -f 1)" = \
        017f725c026d7b651b561025d17fe762bc865ee83d17bb7eb63cab888359faf0; \
    test "$(sha256sum "$package/src/aragorn/protected_install_coordinator.py" | cut -d ' ' -f 1)" = \
        13f9e63037b80a19f30f793e90767e2d1e46b973caf2782166910c12b85d2616; \
    test "$(sha256sum "$package/src/aragorn/github_gateway.py" | cut -d ' ' -f 1)" = \
        21e3a74cb0927d1a160b089797cc169e1d1bfc8c68b7a2b5005904ee7aabe07c; \
    test "$(sha256sum /src/benchmark/runtime-acquisition-action-systemd/adapt-github-gateway.py | cut -d ' ' -f 1)" = \
        e13b2408655e1b1c2235bc7f8e511062547440ee73119a82bffd1f70f168fc30; \
    test "$(sha256sum /src/src/aragorn/protected_install_coordinator.py | cut -d ' ' -f 1)" = \
        402ab3e6d73e1ddcd79fbb5ceabe325661ceecca77e1d041e8940b7d03b50af4; \
    test "$(sha256sum /src/packaging/libexec/aragorn-protected-install-coordinator.py | cut -d ' ' -f 1)" = \
        93d509eb96ef350b0011c4c9fcb5837bd42a5a0560e02fa047e32061a31f0c19; \
    test "$(sha256sum /src/packaging/systemd/aragorn-protected-install-coordinator.path | cut -d ' ' -f 1)" = \
        b566debf0d7a9585168d19e8ff68ecc7691a2067c1e05dc2df10302945dac001; \
    test "$(sha256sum /src/packaging/systemd/aragorn-protected-install-coordinator.service | cut -d ' ' -f 1)" = \
        f86bd4abd3bb8815a66d404513d942bdae7839bcb66601f30c33f68f63162a97; \
    test "$(sha256sum /src/packaging/systemd/aragorn-gateway.tmpfiles | cut -d ' ' -f 1)" = \
        bbd0af0ca5f824d8e0a44689de5c8412dac6378c0fe3026778691c7f3527ad40; \
    test "$(sha256sum < '/src/packaging/systemd/var-lib-aragorn\x2dgateway.mount' | cut -d ' ' -f 1)" = \
        49e331166f7b6ebb6ece159270647f86c8a30290d030808a7d69bfa03cc886bc; \
    test "$(sha256sum /src/packaging/systemd/aragorn-gateway.sysusers | cut -d ' ' -f 1)" = \
        994234b5d509d33dff4448691591e7f30d965415ad18c8a4c01d1a31ed16bc04; \
    test "$(sha256sum /src/benchmark/runtime-acquisition-action-systemd/aragorn-protected-install-coordinator-python312.conf | cut -d ' ' -f 1)" = \
        b5eea137b7567be3265b54d55d2d888f70ae0cf880139be59464b6b064e91338; \
    test "$(sha256sum "$launcher" | cut -d ' ' -f 1)" = \
        e27b2ed1be6e24d758b148e9d6f9740d4e1c5cd74e87462d2fb2d9686dc5810b; \
    test "$(sha256sum "$install_unit" | cut -d ' ' -f 1)" = \
        7087601d0602d2ab64a7386b2c6a5da91c3cf6755b473a99b600ae78f5e95228; \
    test "$(sha256sum "$install_drop_in" | cut -d ' ' -f 1)" = \
        1c94aafb0211f72e2da694b055d8aa41e51d82dedf513ab71ee350e21313a74a; \
    test "$(sha256sum /usr/local/bin/python3.12 | cut -d ' ' -f 1)" = \
        7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57; \
    test -d "$inherited_namespace"; \
    test ! -e "$fresh_namespace"; \
    test ! -e /var/lib/aragorn-protected/coordinator-active.json; \
    test -z "$(find /var/lib/aragorn-protected/skills -mindepth 1 -print -quit)"; \
    test ! -e "$coordinator"; \
    test ! -e "$coordinator_unit"; \
    test ! -e "$coordinator_path"; \
    test ! -e "$gateway_mount"; \
    test ! -e /usr/bin/python3.14; \
    install -o root -g root -m 0444 \
        /src/src/aragorn/protected_install_coordinator.py \
        "$package/src/aragorn/protected_install_coordinator.py"; \
    install -o root -g root -m 0444 \
        "$package/src/aragorn/github_gateway.py" "$gateway_preimage"; \
    /usr/local/bin/python3.12 -I -S -B \
        /src/benchmark/runtime-acquisition-action-systemd/adapt-github-gateway.py \
        "$package/src/aragorn/github_gateway.py"; \
    test "$(sha256sum "$package/src/aragorn/github_gateway.py" | cut -d ' ' -f 1)" = \
        b31305c4555607a19a54a3ef08a61a243fd60ab1b5cacb38b1b04569ec3cac56; \
    test "$(sha256sum "$gateway_preimage" | cut -d ' ' -f 1)" = \
        21e3a74cb0927d1a160b089797cc169e1d1bfc8c68b7a2b5005904ee7aabe07c; \
    install -o root -g root -m 0555 \
        /src/packaging/libexec/aragorn-protected-install-coordinator.py \
        "$coordinator"; \
    install -o root -g root -m 0444 \
        /src/packaging/systemd/aragorn-protected-install-coordinator.service \
        "$coordinator_unit"; \
    install -o root -g root -m 0444 \
        /src/packaging/systemd/aragorn-protected-install-coordinator.path \
        "$coordinator_path"; \
    install -o root -g root -m 0644 \
        /src/packaging/systemd/aragorn-gateway.tmpfiles \
        /usr/lib/tmpfiles.d/aragorn-gateway.conf; \
    install -o root -g root -m 0444 \
        '/src/packaging/systemd/var-lib-aragorn\x2dgateway.mount' \
        "$gateway_mount"; \
    install -d -o root -g root -m 0755 \
        /etc/systemd/system/aragorn-protected-install-coordinator.service.d; \
    install -o root -g root -m 0444 \
        /src/benchmark/runtime-acquisition-action-systemd/aragorn-protected-install-coordinator-python312.conf \
        "$coordinator_drop_in"; \
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/aragorn-gateway.conf; \
    tree_digest="$(/usr/local/bin/python3.12 -I -S -B -c 'import runpy; from pathlib import Path; module=runpy.run_path("/usr/libexec/aragorn/aragorn-protected-install-launcher.py", run_name="_aragorn_p38b_release_measurement"); print(module["_measure_package"](Path("/opt/aragorn-broker-p36b"), 0))')"; \
    test "$tree_digest" = \
        sha256:c4c2aec999a3731d0193c59114d52bfced1dca89163738a3400776f2bc42463d; \
    python_digest="sha256:$(sha256sum /usr/local/bin/python3.12 | cut -d ' ' -f 1)"; \
    launcher_digest="sha256:$(sha256sum "$launcher" | cut -d ' ' -f 1)"; \
    broker_digest="sha256:$(sha256sum "$package/benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py" | cut -d ' ' -f 1)"; \
    temporary="$(mktemp /etc/aragorn/.protected-broker-release.p38b.XXXXXX)"; \
    printf '{"broker":{"digest":"%s","path":"benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py"},"launcher":{"digest":"%s","path":"/usr/libexec/aragorn/aragorn-protected-install-launcher.py"},"package":{"root":"/opt/aragorn-broker-p36b","tree_digest":"%s"},"python":{"digest":"%s","path":"/usr/local/bin/python3.12"},"schema":"aragorn/protected-broker-launch-identity/v1"}' \
        "$broker_digest" "$launcher_digest" "$tree_digest" "$python_digest" \
        > "$temporary"; \
    chown root:root "$temporary"; \
    chmod 0400 "$temporary"; \
    mv "$temporary" "$identity"; \
    test "$(sha256sum "$identity" | cut -d ' ' -f 1)" = \
        08ce966f9523c211ddeea9d48f386c73491d69f685c6a83d09f42d5887144cda; \
    /usr/local/bin/python3.12 -I -S -B -c 'import runpy; from pathlib import Path; module=runpy.run_path("/usr/libexec/aragorn/aragorn-protected-install-launcher.py", run_name="_aragorn_p38b_release_validation"); module["_validated_launch"](Path("/etc/aragorn/protected-broker-release.json"), (), expected_uid=0, launcher_path=Path("/usr/libexec/aragorn/aragorn-protected-install-launcher.py"))'; \
    /usr/local/bin/python3.12 -I -S -B -c 'import hashlib, runpy, sys; from pathlib import Path; entry=runpy.run_path("/usr/libexec/aragorn/aragorn-protected-install-coordinator.py", run_name="_aragorn_p38b_coordinator_validation"); root=entry["_verified_package_root"](); sys.path.insert(0, str(root / "src")); import aragorn.protected_install_coordinator as module; source=Path(module.__file__).resolve(strict=True); assert source == root / "src/aragorn/protected_install_coordinator.py"; assert hashlib.sha256(source.read_bytes()).hexdigest() == "402ab3e6d73e1ddcd79fbb5ceabe325661ceecca77e1d041e8940b7d03b50af4"; assert callable(module.submit_intent) and callable(module.coordinate_intent) and callable(module._run_submitted)'; \
    systemctl enable aragorn-protected-install-coordinator.path; \
    systemctl enable 'var-lib-aragorn\x2dgateway.mount'; \
    systemd-analyze verify \
        "$install_unit" \
        "$coordinator_unit" \
        "$coordinator_path" \
        "$gateway_mount"; \
    cmp /src/src/aragorn/protected_install_coordinator.py \
        "$package/src/aragorn/protected_install_coordinator.py"; \
    cmp /src/packaging/libexec/aragorn-protected-install-coordinator.py \
        "$coordinator"; \
    cmp /src/packaging/systemd/aragorn-protected-install-coordinator.service \
        "$coordinator_unit"; \
    cmp /src/packaging/systemd/aragorn-protected-install-coordinator.path \
        "$coordinator_path"; \
    cmp /src/packaging/systemd/aragorn-gateway.tmpfiles \
        /usr/lib/tmpfiles.d/aragorn-gateway.conf; \
    cmp '/src/packaging/systemd/var-lib-aragorn\x2dgateway.mount' \
        "$gateway_mount"; \
    cmp /src/packaging/systemd/aragorn-gateway.sysusers \
        /usr/lib/sysusers.d/aragorn-gateway.conf; \
    cmp /src/benchmark/runtime-acquisition-action-systemd/aragorn-protected-install-coordinator-python312.conf \
        "$coordinator_drop_in"; \
    cmp /src/packaging/systemd/aragorn-protected-install.service \
        "$install_unit"; \
    cmp /src/benchmark/runtime-producer-lineage-openclaw-systemd/aragorn-protected-install-python312.conf \
        "$install_drop_in"; \
    test "$(stat -c '%U:%G:%a' "$identity")" = root:root:400; \
    test "$(stat -c '%U:%G:%a' "$coordinator")" = root:root:555; \
    test "$(stat -c '%U:%G:%a' "$coordinator_unit")" = root:root:444; \
    test "$(stat -c '%U:%G:%a' "$coordinator_path")" = root:root:444; \
    test "$(stat -c '%U:%G:%a' "$coordinator_drop_in")" = root:root:444; \
    test "$(stat -c '%U:%G:%a' "$gateway_mount")" = root:root:444; \
    test "$(stat -c '%U:%G:%a' "$gateway_preimage")" = root:root:444; \
    test "$(stat -c '%U:%G:%a' /usr/lib/tmpfiles.d/aragorn-gateway.conf)" = root:root:644; \
    test "$(stat -c '%U:%G:%a' /var/lib/aragorn-gateway)" = aragorn-fetch:aragorn-fetch:700; \
    test "$(systemctl is-enabled aragorn-protected-install-coordinator.path)" = enabled; \
    test "$(systemctl is-enabled 'var-lib-aragorn\x2dgateway.mount')" = enabled; \
    test ! -e "$fresh_namespace"; \
    test ! -e /var/lib/aragorn-protected/coordinator-active.json; \
    test -z "$(find /var/lib/aragorn-protected/skills -mindepth 1 -print -quit)"; \
    chmod 0555 \
        /src/scripts/capture_runtime_acquisition_action_systemd.sh \
        /src/scripts/runtime_acquisition_action_systemd_probe.py; \
    chmod 0444 \
        /src/benchmark/runtime-acquisition-action-systemd/Dockerfile \
        /src/benchmark/runtime-acquisition-action-systemd/adapt-github-gateway.py \
        /src/benchmark/runtime-acquisition-action-systemd/aragorn-protected-install-coordinator-python312.conf \
        /src/packaging/libexec/aragorn-protected-install-coordinator.py \
        /src/packaging/systemd/aragorn-gateway.tmpfiles \
        '/src/packaging/systemd/var-lib-aragorn\x2dgateway.mount' \
        /src/packaging/systemd/aragorn-protected-install-coordinator.path \
        /src/packaging/systemd/aragorn-protected-install-coordinator.service \
        /src/src/aragorn/protected_install_coordinator.py
