"""Bind an inert firmware proposal to B112. Only ordinary files are ever read.

The raw boot request is a successor of B44's *denied* request; the actual
store identity, KEK/dbx policy baseline, authorization and B49 stay unbound.
Do not replay the multi-gigabyte B112 media check or manufacture a new ESL.
"""
import json
import struct
from pathlib import Path

from scripts.build_pi_core_linux import ROOT, regular_bytes, require, sha256
from scripts.prepare_pi_core_guest_firmware_trust import EFI_CERT_SHA256, OWNER


PARENT = ROOT / "packaging/pi-core"
HERE = PARENT / "immutable-host-b113"
TEMPLATE = PARENT / "immutable-host-b44/boot-request.json"
MEDIA = PARENT / "immutable-host-b112/media-output.json"
TEMPLATE_SHA = "6f6914e8bf0d0ca7819e1913d97bf7931824ae81695dc36e2f64fac86001762a"
MEDIA_SHA = "fac725f23b8a1d694ba89054859710786649693c53d23a9c19a01794938877f7"
RETAINED_ESL = Path.home() / "Library/Application Support/Aragorn-B112-Offline/b112-uki-sha256.esl"


def _bytes(doc):
    return (json.dumps(doc, indent=2, allow_nan=False) + "\n").encode("ascii")


def validate_public(template_raw, media_raw, request_raw, proposal_raw):
    """Validate exact public bytes from disk or a trusted Git tree. No I/O."""
    require(sha256(template_raw) == TEMPLATE_SHA and sha256(media_raw) == MEDIA_SHA,
            "foreign boot template or media catalog")
    request, media = json.loads(template_raw), json.loads(media_raw)
    # Change exactly five fields. All host constraints, eight empty private
    # bindings, read-only device graph, limits and denied permissions survive.
    request["guest"].update(disk_bytes=media["disk_bytes"], disk_sha256=media["disk_sha256"])
    fw = request["firmware"]
    fw.update(raw_uki_sha256=media["uki_sha256"],
              allow_image_authenticode_sha256=media["authenticode_sha256"],
              proposed_esl_sha256=media["esl_sha256"])
    require(request_raw == _bytes(request), "not the exact held B112 boot request")
    proposal = dict(schema="aragorn/b113-detached-firmware-proposal/v1", status="inert-proposal-only",
                    media_catalog_sha256=MEDIA_SHA, request_template_sha256=TEMPLATE_SHA,
                    boot_request_sha256=sha256(request_raw), disk_bytes=media["disk_bytes"],
                    disk_sha256=media["disk_sha256"], uki_bytes=media["uki_bytes"], uki_sha256=fw["raw_uki_sha256"],
                    authenticode_sha256=fw["allow_image_authenticode_sha256"], signature_type=str(EFI_CERT_SHA256),
                    signature_owner=str(OWNER), esl_bytes=media["esl_bytes"], esl_sha256=fw["proposed_esl_sha256"],
                    proposed_pk=fw["proposed_pk"], db_allow_sha256=[fw["allow_image_authenticode_sha256"]],
                    preserve_approved_revocations=fw["preserve_approved_revocations"],
                    broad_default_allow_signatures=fw["broad_default_allow_signatures"], private_store_identity=None,
                    private_store_sha256=None, approved_policy_sha256=None, enrollment_observed=False,
                    boot_authorized=False, boot_observed=False, phase3_exit_eligible=False)
    require(proposal_raw == _bytes(proposal), "not the exact held B112 firmware proposal")
    return proposal


def validate_esl(proposal, record):
    # Bind the ordinary detached B112 file to the *proposed* db entry. This
    # record has no authenticated update header, X.509 material or second list.
    require(len(record) == 76 == proposal["esl_bytes"] and sha256(record) == proposal["esl_sha256"],
            "foreign detached ESL")
    kind, total, header, entry, owner, digest = struct.unpack("<16sIII16s32s", record)
    require((kind, total, header, entry, owner) == (EFI_CERT_SHA256.bytes_le, 76, 0, 48, OWNER.bytes_le)
            and [digest.hex()] == proposal["db_allow_sha256"] == [proposal["authenticode_sha256"]],
            "ESL does not identify the single proposed EFI image hash")


def inspect():
    proposal = validate_public(*(regular_bytes(p, 16384) for p in (
        TEMPLATE, MEDIA, HERE / "boot-request.json", HERE / "firmware-proposal.json")))
    require(RETAINED_ESL.resolve(strict=True) == RETAINED_ESL, "linked detached proposal")
    validate_esl(proposal, regular_bytes(RETAINED_ESL, 76))
    return proposal


if __name__ == "__main__":
    print(json.dumps(inspect(), sort_keys=True))
