"""B85: original-format inert archives, not a guest, capture authorization or pilot."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from aragorn import pi_core_mask_capture_entry as entry, pi_core_mask_capture_release as release
from aragorn import pi_core_restricted_profile as restricted
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts.prepare_pi_core_coordinator_host import host_contract
from scripts.verify_pi_core_joined_mask_receipts import verify_joined_masks
from test_pi_core_coordinator_entry import launch_document
from test_pi_core_sensor_state_entry import protected_plan
import test_pi_core_worker_walk_evidence as original


class OwnedWorkerViewReplay(unittest.TestCase):
    def setUp(self):
        self.spine = original.JoinedWorkerSpine()
        self.addCleanup(self.spine.doCleanups)
        self.spine.setUp()  # Reuse an original-format B58/B71 archive, not its historical tests.
        self.h = self.spine.archive
        self.b = self.h.base
        self.boot, self.invocation = self.b.head['boot_id'], 'd' * 32
        self.claim_mount = dict(dev='8:6', ino=339, mnt_id=32)
        self.evidence = '/var/lib/aragorn-capture-evidence'
        mgr = self.b.capture['roles']['manager']
        mgr['mountinfo'] = self.b.put(self.b.reader.read(mgr['mountinfo']) +
            b'31 2 259:4 / /run/aragorn-pi-config ro,nosuid,nodev,noexec - squashfs /dev/vda4 ro\n'
            b'32 1 8:6 / /var/lib/aragorn-capture-claims rw,nosuid,nodev,noexec - ext4 /dev/sda6 rw\n'
            b'33 1 8:7 / /var/lib/aragorn-capture-evidence rw,nosuid,nodev,noexec - ext4 /dev/sda7 rw\n')
        self.launch = launch_document(True)
        subject = self.b.head['subjects']['pi']
        self.launch.update(worker_uid=subject['uid'], worker_gid=subject['gid'], provider_route_digest=None)
        gate = json.loads((Path(__file__).parent/'fixtures/pi_core_b36_gate_receipt.json').read_bytes())
        receipt = restricted.runtime_receipt(gate | {'receipt_digest':'sha256:' + restricted.GATE_RECEIPT_SHA256})
        self.launch.update(compiled_receipt=receipt, compiled_receipt_digest=canonical_digest(receipt))
        source = self.launch['source_observation']
        source.update(schema=restricted.PROFILE_SCHEMA, required_sources=[restricted.ENTRY_PATH],
                      sources=[dict(path=restricted.ENTRY_PATH, digest='sha256:'+restricted.BUNDLE_SHA256)])
        source['pins'].update(gate_digest='sha256:'+restricted.GATE_SHA256, node_digest='sha256:'+restricted.NODE_SHA256)
        src = Path('/opt/aragorn/src/aragorn')
        self.host_files = {p:canonical_digest(str(p)) for p in {*host_contract._TOOLS, host_contract._LOADER,
                           src/'__init__.py', src/'pi_core_coordinator_entry.py', entry._PYTHON,
                           *(src/(n+'.py') for n in entry._CORE + entry._SPINE_CORE)}}
        for deployed, source_path in ((host_contract._WRAPPER, Path(host_contract.__file__)),
                                      (src/'pi_core_mask_capture_entry.py', Path(entry.__file__))):
            self.host_files[deployed] = 'sha256:' + sha256(source_path.read_bytes()).hexdigest()
        source['pins'].update(producer_digest=self.host_files[src/'pi_core_source_observer.py'],
                              node_observer_digest=self.host_files[src/'pi_core_node_source_observer.py'])
        self.profile_pin = self.launch['source_observation_digest'] = canonical_digest(source)
        self.interpreter_pin = self.host_files[entry._PYTHON]
        base = protected_plan()
        self.plan = {k:deepcopy(base[k]) for k in ('context','deployment','launch','service_configuration','cas_root',
                                                  'runtime_conformance_digest','revoked_context_ids')}
        self.plan.update(schema=entry.SPINE_PLAN, capture=dict(store=self.evidence+'/cas',
            receipt_directory=self.evidence+'/receipts', volume_device='253:7', backing_devices=['259:0'], fs_type='ext4'))
        self.plan['deployment']['digest'] = self.b.capture['deployment']
        self.plan['service_configuration']['configurations']['digest'] = self.b.capture['configuration']

    def put(self, doc, *, stdout=False):
        # Original wrapper stdout has one LF. Protected input members do not.
        return self.b.put(canonical_json(doc) + (b'\n' if stdout else b''))

    def hold(self, change_spine=None):
        manager_view = self.h.manager_view
        def bind(parts):
            manager_view(parts)
            parts['bindings'].update(profile=self.profile_pin, interpreter=self.interpreter_pin)
        with patch.object(self.h, 'manager_view', side_effect=bind):
            return self.spine.retain(change_spine)

    def assemble(self, retained, *, edit_plan=None, edit_release=None, edit_claim=None, edit_owner=None):
        std = '/opt/aragorn-cpython/lib/python3.12'
        host = dict(schema='aragorn/pi-core-coordinator-host/v1', target='linux-arm64-cpython312',
                    python_executable=str(entry._PYTHON), wrapper_path=str(host_contract._WRAPPER),
                    stdlib_roots=[std], sys_path=[std], absent_sys_path=[],
                    files=[dict(path=str(p), digest=d, size=24) for p,d in sorted(self.host_files.items())])
        plan = deepcopy(self.plan)
        attempt = plan['capture']['attempt_id'] = f'{self.h.attempt:032x}'
        plan['host_profile_digest'] = host_pin = self.put(host)
        plan['launch']['digest'] = self.put(self.launch)
        if edit_plan: edit_plan(plan)
        plan_pin = self.put(plan)
        grant = dict(schema='aragorn/pi-core-stopped-mask-release/v1', scope=release.SPINE_SCOPE, plan_digest=plan_pin,
                     host_profile_digest=host_pin, deployment_digest=plan['deployment']['digest'], attempt_id=attempt,
                     boot_id=self.boot, max_starts=1, claim_directory=self.claim_mount,
                     not_before_unix_ns=1_000_000_000, expires_unix_ns=31_000_000_000)
        if edit_release: edit_release(grant)
        release_pin = self.put(grant)
        claim = dict(schema='aragorn/pi-core-mask-start-claim/v1', status='SPENT', release_digest=release_pin,
                     plan_digest=plan_pin, boot_id=self.boot, attempt_id=attempt)
        if edit_claim: edit_claim(claim)
        claim_pin = self.put(claim)
        authority = dict(host_profile_digest=host_pin, plan_digest=plan_pin, release_digest=release_pin, claim_digest=claim_pin)
        public = host_contract._public_mask_capture(dict(schema='aragorn/pi-core-mask-capture-entry/v2',
            status='CAPTURE_RETAINED_ONLY', capture_authority=authority, capture_attempted=True, claim_confirmed=True,
            owned_inputs_closed=True, cleanup_verified=True, mask_consistent=True, capture_digest=retained['capture_pin'],
            receipt_digest=retained['receipt_pin'], activation_authorized=False, phase3_exit_eligible=False))
        public.update(status='CAPTURE_RETAINED_ONLY', wrapper_stage='POST_CALL_CUSTODY',
                      wrapper_cleanup={'source_loader':'CLOSED','host':'CLOSED'}, entry_call_attempted=True)
        if edit_owner: edit_owner(public)
        return self.h.keys() | retained | dict(require_owned_worker_spine=True, owner_pin=self.put(public,stdout=True),
            plan_pin=plan_pin, release_pin=release_pin, claim_pin=claim_pin, invocation_id=self.invocation,
            attempt_id=attempt, boot_id=self.boot)

    def test_original_public_projection_and_both_archives_join_but_grant_nothing(self):
        args = self.assemble(self.hold())
        result = verify_joined_masks(**args)
        self.assertEqual(result['mask_capture_owner'], args['owner_pin'])
        for k in ('owned_worker_spine_records_matched','worker_root_and_admitted_cwd_read_only',
                  'stopped_worker_handles_and_admitted_cwd_matched','manager_state_roots_and_targets_matched'):
            self.assertIs(result[k], True, k)
        for k in ('worker_permissions_verified','full_worker_namespace_walk_verified','independent_live_claim_verified',
                  'worker_socket_lookup_observed','worker_process_relative_links_verified','sensor_health_verified',
                  'same_capture_interval_verified','external_freshness_verified','installed_isolation_verified',
                  'activation_authorized','recovery_authorized','phase3_exit_eligible'):
            self.assertIs(result[k], False, k)

    def test_independent_attempt_boot_invocation_and_all_four_document_pins_are_required(self):
        args = self.assemble(self.hold())
        for field in ('plan_pin','release_pin','claim_pin','owner_pin','boot_id','invocation_id','attempt_id'):
            with self.subTest(removed=field), self.assertRaises(ValueError):
                verify_joined_masks(**(args | {field:None}))
        for field, other in (('boot_id','12345678-1234-4234-8234-123456789abc'),
                             ('invocation_id','9'*32),('attempt_id','a'*32)):
            with self.subTest(different=field), self.assertRaises(ValueError):
                verify_joined_masks(**(args | {field:other}))

    def test_owner_must_refer_to_this_claim_and_receipt_after_cleanup(self):
        retained = self.hold()
        def old(report):
            report.pop('capture_authority')
            report['schema'] = 'aragorn/pi-core-mask-capture-report/v1'
        for label, edit in [('legacy',old),('claim',lambda r:r['capture_authority'].update(claim_digest=canonical_digest('other'))),
                            ('receipt',lambda r:r.update(receipt_digest=canonical_digest('other'))),
                            ('incomplete close',lambda r:r['wrapper_cleanup'].update(host='UNKNOWN'))]:
            with self.subTest(label=label), self.assertRaises(ValueError):
                verify_joined_masks(**self.assemble(retained, edit_owner=edit))

    def test_resealed_wrong_plan_release_spend_and_worker_principal_are_rejected(self):
        retained = self.hold()
        for label, changes in [('plan',dict(edit_plan=lambda p:p.update(schema=entry.PLAN))),
                ('release',dict(edit_release=lambda r:r.update(scope=release.SCOPE))),
                ('claim',dict(edit_claim=lambda c:c.update(boot_id='12345678-1234-4234-8234-123456789abc')))]:
            with self.subTest(different=label), self.assertRaises(ValueError):
                verify_joined_masks(**self.assemble(retained, **changes))
        self.launch['worker_gid'] += 1
        with self.assertRaises(ValueError):
            verify_joined_masks(**self.assemble(retained))

    def test_old_producer_cannot_prove_v2_by_reformatting_its_output(self):
        retained = self.hold()
        for path in (host_contract._WRAPPER,Path('/opt/aragorn/src/aragorn/pi_core_mask_capture_entry.py')):
            with self.subTest(path=path), patch.dict(self.host_files,{path:canonical_digest('older-source')}), self.assertRaises(ValueError):
                verify_joined_masks(**self.assemble(retained))

    def test_both_agreeing_original_worker_tables_cannot_hide_writable_root(self):
        role = self.b.capture['roles']['pi']
        raw = self.b.reader.read(role['mountinfo'])
        token = b' / / ro - squashfs '
        self.assertEqual(raw.count(token), 1)
        role['mountinfo'] = self.b.put(raw.replace(token,b' / / rw - squashfs '))
        with self.assertRaisesRegex(ValueError, "matching read-only mounts"):
            verify_joined_masks(**self.assemble(self.hold()))

    def test_positive_owner_cannot_hide_state_backed_inherited_stdio(self):
        # Both the full walk and handle observation inherit this same forbidden object.
        self.h.outer.walk['fds']['0']['dev'] = self.b.capture['mapping']['device']
        with self.assertRaises(ValueError):
            verify_joined_masks(**self.assemble(self.hold()))
