# Baseline image candidates

These recipes package the pinned Phase 0 comparators. They are build and runtime
smoke inputs, not trusted efficacy baselines. `benchmark/baselines.lock.json`
remains authoritative, and `attestation_status` remains pending until Aragorn's
evidence runner launches an exact OCI image/platform digest with its hardened
runtime configuration retained and independently verified.

Current checked-in candidates and smoke evidence support Linux/arm64 only.
Verify their complete local OCI descriptor graphs against the lock with:

```console
python3.12 scripts/verify_baseline_images.py
```

Required vendor contexts:

- `cisco`: clean checkout at `605afdc5c7ea887c07e2afeb0fadc1452c07bfa7`
- `nvidia`: clean checkout at `a54947c307fe19a24a43db55f6148e181a987a67`

The Dockerfiles independently verify the exact build-input file set, dependency
lock, immutable base and frontend images, and any downloaded or derived package
artifact. They perform dependency installation during the image build only.
This establishes candidate byte identity; it is not a vulnerability audit,
reproducible-build proof, signature verification, or safety claim about the
scanner and its dependencies.
Inspection runs must add all of these controls:

```text
--pull=never
--network=none
--read-only
--cap-drop=ALL
--security-opt=no-new-privileges=true
--pids-limit=256
--memory=2g
--memory-swap=2g
--cpus=2
--ulimit=nofile=1024:1024
--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777
```

Mount only the materialized subject at `/workspace:ro`. Do not mount the suite,
labels, evidence CAS, Docker socket, credentials, or source repository. Use the
locked index digest plus explicit platform, never a mutable tag, when running it.
