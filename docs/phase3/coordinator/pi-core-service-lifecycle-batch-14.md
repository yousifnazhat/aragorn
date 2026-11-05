# Pi-core D2 batch 14: protected configuration and native service lifecycle

Date: 2026-11-05. Base: `4fdbc19e48e72a4f1f7f4ad0262c873726243726`.
Scope: source implementation, new/affected inert checks, a changed static image,
verified signed commit and normal branch push. No native service, target code,
VM, credential, provider request, live workload or acceptance run is authorized.

## Delivered and reused

Parallel lanes owned protected configuration and native lifecycle source/tests;
an independent lane reviewed both. Root owned channel integration, the existing
worker caller, successor pins, registry, evidence and release. The existing
installer/custody helpers, native supervisor, PIDFD/cgroup guards, service
wrappers, broker/grant recovery and authenticated channel codecs are reused.
No dependency, replacement security core or generic service manager was added.

`pi_core_service_configuration.py` validates exactly three canonical role files,
shared identities/grants/profile joins and independently pinned manifests. Its
absent-only installer leaves partial output intact and verifies named ancestry,
receipt, mode and byte custody. Sealed holders cover those configuration files
and the already-existing public provider profile/CA bundle, never credentials.
Held guards reject changed bytes/names and extended deadlines; context exit
rechecks custody before closing only newly owned handles.

`pi_core_service_lifecycle.py` owns exactly three fixed transient units. It uses
fresh absent-only root skeletons with read-only image/configuration mounts and
role-specific broker/admitted/listener paths. It does not change the image to
create mountpoints, mount host `/etc`/`run` wholesale, install keys or enable
provider networking. Existing broker/grant state must already be AVAILABLE;
root readiness is a read-only, nonblocking-lock snapshot, not initialization,
rotation or continued authority. The action handler retains its existing
role-local recovery and later effect-time guards.

Action starts first. Passive `/proc` LISTEN evidence joins the kernel socket to
the captured action process and retained directory descriptor; a path alone or
a probe connection cannot release the sensor. Post-exec accepted peers must
match captured PIDFD/start/cgroup/unit generations. Only then is the existing
channel holder minted, bound once to that exact lifecycle. Every channel guard
rechecks protected configuration/public inputs and immutable unit generations,
alongside the existing runtime-image and peer checks. A final guard detects
service death during an otherwise successful no-request worker bootstrap.

`run_native_pi_service_bootstrap` joins worker configuration, profile and grant
before service startup, then calls the existing native worker supervisor with
those exact held channels. Worker cleanup occurs inside the service lifetime;
channel authority is withdrawn before reverse-order service shutdown. SIGINT
allows wrapper finalizers to run within the original outer deadline; tighter
request/worker deadlines do not acquire fresh authority. Root never removes a
leftover child-owned action socket. Replaced resources, uncertain start/stop,
expired cleanup budgets and unresolved handles remain CLEANUP_HOLD, without
automatic retries. Frozen channel users without a lifecycle owner retain their
existing behavior, including independently authenticated provider retirement.
This new unavailable-provider profile expects all three services to remain live
until intentional shutdown; it does not enable that future provider dispatch.

The code-review skill and independent review drove the passive readiness join,
per-request custody, precise cleanup/deadline behavior and a real installed-path
correction: sensor configuration now accepts the existing `.aragorn-versions`
layout used by protected bundle launch, not the nonexistent `versions` layout.

## Environment and evidence limits

Each start/readback requires the system manager's exported environment to be
empty, plus empty unit environment, environment files, PAM and credential
properties. This uses the documented [systemd execution environment](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
and [Manager Environment property](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html).
Trusted root/manager stability remains part of the TCB; these checks are not an
atomic defense against adversarial root or proof of pre-Python loader behavior.

Static source/installed-byte hashes are not consumed-module identity or ABI
proof. Whole-image and unit readbacks may exceed existing short request/permit
budgets; no limit was widened and no timing feasibility is claimed. Native
START remains UNAVAILABLE, with no provider credentials, egress or dispatch.
The approved 29-requirement mapping and all final exit gates remain unchanged.

## Focused verification

**123 distinct checks passed once, with no failure or rerun.** Only these stages
were released through the existing pipeline and reviewed explicit closures:

| Stage | Checks | Successful fingerprint |
| --- | ---: | --- |
| `pi-core-service-configuration-offline` | 42 | `sha256:073e684feac2a9651d2196d094c81e52331dec34ea66e7ffad63c528a3b569b4` |
| `pi-core-service-lifecycle-offline` | 45 | `sha256:27699061e4d6a56aa337946a6eb10a943dc57c88dfb28f96dd0d0c1fde75a528` |
| `pi-core-managed-bootstrap-offline` | 31 | `sha256:28964e4c5e5286905691b40fe582d84f63cb7be14d033a87a1844dbb3d4cb431` |
| `pi-core-service-lifecycle-image-assemble` | 1 | `sha256:82fe17d941c809d8f32eebbcfd6f73c189166fbcc4e1e7bfa75622988a5bff66` |
| `pipeline-capacity` | 4 | `sha256:7ac0d7c110c37e8480b780115bcd681c5bfdfc5ea1e640dc920d9b716e214da2` |

Configuration/lifecycle checks are new. The integration stage contains 25 new
checks plus three selected affected entrypoint and three channel compatibility
checks, not their complete historical suites. The assembly checks only changed
successor bytes; capacity checks cover 172 accepted/173 refused stages and
duplicate/cycle refusal. Explicit stage closures contain 84/84/88/92 inputs.
Assembly reused all three exact successful prerequisites as SKIP_PASS. The
existing assembler and pipeline process cleanup remain intact. No old runtime,
historical capture, broad regression or final acceptance suite ran.

## Preserved predecessor and static successor

The existing v1 input record, artifact record and local image remain unchanged.
The [v2 input record](../../../packaging/pi-core/service-assembly-inputs-v2.json)
pins 82 reachable source modules: three additions follow the lifecycle-bound
channel import. The [v2 artifact checkpoint](../../../packaging/pi-core/service-artifact-v2.json)
records the new output from the same retained digest-pinned Python archive:

- Output: `.aragorn/pi-core-service-image/assembled-e76c24ccf0424aefaf3fba6c05bbb58e/`.
- 770 files, 54 directories, 41,465,539 root bytes; three wrappers, 69 native
  extensions, 27 library entries and 34 provenance files.
- Manifest: `sha256:a4a41a2215dcf4834f78775bf8e23ca79eb2b8979c0169cf35d37c0b685a564d`.
- Binding: `sha256:7e67a6701ac6845a3ba9585108f24a07a89c5fcba4966ff07778d9c02a8e2b6d`.
- Receipt: `sha256:402fa25f634652bf98637a569b03e335c21ba614c8dde5e18b671acaaf7abdff`.
- Status: PREPARED_NOT_INSTALLED_OR_EXECUTED. Four optional benchmark DSSE
  import sites remain explicitly unsupported, unchanged from v1.

The signed commit hash, signature verification and exact remote SHA readback
are recorded in ignored `.aragorn/pi-core-service-lifecycle-batch-14-release.json`
and the chat milestone. Only batch-owned source/docs/metadata are published to
the existing public repository; large images, local evidence and unrelated
drafts remain local. No release, service or deployment is published/activated.

## Remaining plan

1. **D2:** actual protected installation and consumed-code identity, native
   recovery and bounded timing; connect the explicit model/trust/key/egress
   deployment profile, then a separately authorized useful controlled pilot.
   This source/inert/static-artifact milestone is not D2 closure.
2. **D3:** remaining admission, RUN/sensor-health and workload/paired-task
   coverage on that same common deployment.
3. **D4:** executable 29-requirement mapping and independent verifiers; close
   prerequisites and freeze once.
4. **D5:** required fresh acceptance, measurements and verified cleanup; retain
   evidence for offline replay. Only then assess Phase 3 completion/Phase 4.
