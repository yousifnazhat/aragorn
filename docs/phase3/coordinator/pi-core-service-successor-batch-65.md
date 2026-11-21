# D2 batch 65 — join the trusted service runtime to the split guest

Signed input: `34dc6c7cc0ba960392b6c653ef08f4b5d8148e43`. Starting with
the retained B15 service image and B64 host/worker tree, this batch replaces
13 project sources, adds 20 required sources and renders the three fixed
service wrappers with the new inventory. All 103 project sources were checked.
The four pre-existing unsupported benchmark-helper import sites remain
explicitly unsupported. No interpreter, native extension, library or worker
bundle was rebuilt. This is static assembly, not an observed Linux import.

The 791-file service tree includes 685 retained files outside the project
sources and wrappers. The complete host, worker and service payload comprises
1,760 entries. The actual bytes and path modes were read back against the
[independently derived pins](../../../packaging/pi-core/service-successor-inputs-b65.json).
The [source review](../../../packaging/pi-core/service-source-successor-b65.json)
separately binds the signed tree, changes, rendered wrappers and unsupported sites.

The existing protected coordinator can use the `service_runtime` section
of the retained `outcome.json`: deployment at `/var/lib/aragorn/pi-service-runtime`,
two independent 0400 documents under `/etc/aragorn/service-runtime-inputs`,
and the expected layout receipt. These are **image contents**. Neither the
receipt nor the section proves a guest was installed or authorizes a service
to start. No capability grant, external approval, credential or sample was created.

Retained directory: `~/Library/Application Support/Aragorn-B65-Offline/`.
Full manifest SHA-256: `156c94630eec1fe9285e8732fd7574c14f2fd9926aa3dd6d0e5f95cb408ceb51`.
Local outcome SHA-256: `9eb990a693dc3e9e8ab9927ac04458383549b938cd831766cd94ee3203d3db4d`.

| Affected stage | Passed | Retained fingerprint |
|---|---:|---|
| `pi-core-service-successor-inputs` | 7 | `277efb331ee2d97385ebb223f4118efa99df27633a81c96b5ed1770830772560` |
| `pi-core-service-successor-preparation` | 1 | `297edee6596ee5d767a2822444c3d98ad8df7c4e6b4016da3effd22908070056` |
| `pipeline-capacity` | 4 | `b442565b0b2b82008c07825b89c51a04368fec67e4e11c333c28f89283efe61b` |

There are 298 registered stages. A fixed 320-entry parser limit leaves room
for reviewed additions without changing the runner fingerprint on every
batch. This does not register, select, or run any other tests, or change
the qualification contract.

1. **D2 open:** connect delivery of the short-lived service configuration
   and the protected storage topology. The three public config documents
   share four distinct role identities; action and sensor require the same
   real, current grant and admitted skill/profile. Do not bake an expiring
   grant into the image. Media/firmware, installed observation, health,
   recovery, full timing and the separately authorized useful pilot remain.
2. **D3 open:** complete connected admission, RUN/health and workload coverage.
3. **D4 not frozen:** complete independent coverage of all 29 requirements.
4. **D5 not authorized:** fresh admission, 100 attempts and 100 task pairs,
   cleanup, restoration and independent replay after freeze and approval.

B49 remains null. No VM boot, live service, provider requests or spending.
