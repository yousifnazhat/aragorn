"""Check one pinned native denial path without executing or qualifying it."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from . import (
    admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture as semantic,
)
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_DIST = "/runtime/lib/node_modules/openclaw/dist/"
_MODULES = {
    "installed-plugin-index-records-NrU3hnwq.js": (
        4_686, "5500445dcd66876952758eec91019a3c4dcc4a852498f956022828f0f867d21f"
    ),
    "diagnostic-events-JZsXee1S.js": (
        22_651, "fa576a8a2881ff61f0f6bd67a289af6442c61f37b364a2e7923955348ed19994"
    ),
    "update-cli-DBeOm5kS.js": (
        162_369, "4883052d157512a0d1f8f5f60ca61efff8b80eaa11bd9e2745e36f172dc41309"
    ),
    "update-CM1QhIWo.js": (
        70_855, "7c74e15d9f9ecc8eca90f069619e346c793cb3b2a0ca502c05e89d9a6bf59597"
    ),
    "git-install-B1_qr0Ru.js": (
        13_036, "3ef38e48d69d2e8f3c580e99e081882db17cae5825d193435f32b2c26325ad82"
    ),
    "install-security-scan-BSpTdhul.js": (
        2_432, "79a3bb57e52b78b469a5ed609f5415004e03eaaa0a524d2697e43f46cc8fe43e"
    ),
    "install-security-scan.runtime.js": (
        61, "d24aec6df26f4027686a309cefe206f8e635e1a4a5a2e3918c8c3e4a268b2e6d"
    ),
    "install-security-scan.runtime-CMin9jbx.js": (
        39_967, "49efcd394780b9b65338e41121b1e14be6c4297aa3af232eb64d947364122f35"
    ),
    "install-policy-yA6T1vUH.js": (
        20_773, "fe85c45bb33191131662b161be2daf66270fa4f538cefbc807b16661cd9884e1"
    ),
    "install-BzCFXkWy.js": (
        87_117, "c0418807ee6a26e09b1cd878e5d68f87cdfe882786903449bde4ec1ec9c1da45"
    ),
}


def verify_core_updater_native_provenance(
    files: Mapping[str, bytes], original_document: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind source-backed native semantics to a recorded audit, not a route PASS.

    The caller must separately prove signed custody and membership of these bytes
    in the original read-only runtime. No selected JavaScript is executed here.
    """

    try:
        if not isinstance(files, Mapping) or set(files) != {
            _DIST + name for name in _MODULES
        }:
            raise AdmissionEvidenceError("native provenance module inventory changed")
        sources = {}
        for name, (size, digest) in _MODULES.items():
            raw = files[_DIST + name]
            if (
                type(raw) is not bytes
                or len(raw) != size
                or hashlib.sha256(raw).hexdigest() != digest
            ):
                raise AdmissionEvidenceError(f"native provenance module changed: {name}")
            sources[name] = raw.decode("utf-8")
        _verify_call_path(sources)
        semantic.verify_openclaw_final_v3_core_updater_plugin_replacement_semantic_compatibility(
            original_document
        )
        preflight = original_document["core_updater_preflight"]
        writer = preflight["installed_index"]["writer_module"]
        audit = preflight["trusted_policy_audit"]
        for module, name, alias in (
            (writer, "installed-plugin-index-records-NrU3hnwq.js", "s"),
            (audit["diagnostic_module"], "diagnostic-events-JZsXee1S.js", "g"),
        ):
            size, digest = _MODULES[name]
            if module != {
                "alias": alias, "bytes": size, "digest": "sha256:" + digest,
                "path": _DIST + name,
            }:
                raise AdmissionEvidenceError("native recorded module binding changed")
        commands = original_document["actions"][0]["commands"]
        previous_end = None
        for command in commands:
            start, end = _time(command["started_at"]), _time(command["completed_at"])
            if start > end or (previous_end is not None and start < previous_end):
                raise AdmissionEvidenceError("native command time ordering changed")
            previous_end = end
        repair = commands[1]
        event_time = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
            milliseconds=audit["event"]["ts"]
        )
        if not (
            _time(repair["started_at"]) <= event_time <= _time(repair["completed_at"])
            and previous_end <= _time(original_document["recorded_at"])
        ):
            raise AdmissionEvidenceError("native audit is outside the repair command")
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, OverflowError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(f"invalid native core-updater provenance: {exc}") from exc

    return {
        "schema": "aragorn/openclaw-final-v3-core-updater-native-provenance/v1",
        "authority": "PINNED_SOURCE_PATH_ONLY_NOT_ROUTE_PASS_OR_CAMPAIGN_AUTHORITY",
        "bindings": {
            "modules": [
                {"path": _DIST + name, "bytes": size, "digest": "sha256:" + digest}
                for name, (size, digest) in _MODULES.items()
            ],
            "observation_canonical_digest": canonical_digest(original_document),
            "writer_module": dict(writer),
            "diagnostic_module": dict(audit["diagnostic_module"]),
            "audit_event_id": audit["event"]["eventId"],
            "audit_timestamp_ms": audit["event"]["ts"],
            "repair_pid": repair["pid"],
        },
        "decision": {
            "status": "NATIVE_POLICY_DENIAL_SOURCE_PATH_VERIFIED_NOT_ROUTE_PASS_AUTHORITY",
            "route_pass_eligible": False,
            **{key: False for key in semantic._ELIGIBILITY_KEYS},
        },
        "source_backed_semantics": {
            "audit_within_repair_interval": True,
            "blocked_return_precedes_dependency_install_and_target_replacement": True,
            "native_cli_to_git_policy_call_path": True,
            "native_diagnostic_subscription_and_writer_aliases": True,
            "direct_policy_process_or_call_site_trace": False,
            "selected_modules_executed_by_verifier": False,
        },
        "limitations": [
            "CALLER_MUST_VERIFY_SIGNED_CUSTODY_AND_ORIGINAL_RUNTIME_MEMBERSHIP",
            "TEN_MODULE_SEMANTIC_CALL_SITE_SUBSET_NOT_FULL_IMPORT_CLOSURE",
            "NO_DIRECT_POLICY_PROCESS_OR_CALL_SITE_TRACE",
            "TRUSTED_METADATA_ALONE_IS_NOT_INDEPENDENT_CALL_SITE_PROVENANCE",
            "EPHEMERAL_WORKING_CONFIG_AND_SEEDED_INSTALLED_RECORD_FIXTURE",
            "NO_CAPTURE_FRESHNESS_DESTRUCTION_OR_INDEPENDENCE_VERIFICATION",
            "NO_ROUTE_PASS_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _time(value: Any) -> datetime:
    if type(value) is not str or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value
    ):
        raise AdmissionEvidenceError("native provenance requires exact UTC time")
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _ordered(source: str, *fragments: str) -> None:
    # These are reviewed relationships in fully pinned bytes, not a JS parser.
    offset = 0
    for fragment in fragments:
        offset = source.find(fragment, offset)
        if offset < 0:
            raise AdmissionEvidenceError("native source-backed call path changed")
        offset += len(fragment)


def _verify_call_path(sources: Mapping[str, str]) -> None:
    writer = sources["installed-plugin-index-records-NrU3hnwq.js"]
    _ordered(writer, "async function writePersistedInstalledPluginIndexInstallRecords(",
             "await refreshPersistedInstalledPluginIndex({", 'reason: "source-changed",',
             "installRecords: records", "return resolveInstalledPluginIndexRecordsStorePath(options);",
             "writePersistedInstalledPluginIndexInstallRecords as s")
    cli = sources["update-cli-DBeOm5kS.js"]
    _ordered(cli, "import { a as updateNpmInstalledPlugins,", 'from "./update-CM1QhIWo.js";')
    _ordered(cli, "async function updatePluginsAfterCoreUpdate(params)",
             "const npmResult = await updateNpmInstalledPlugins({", "config: pluginConfig,",
             "disableOnFailure: true,")
    _ordered(cli, "async function runPostCorePluginUpdate(params)",
             "return await updatePluginsAfterCoreUpdate({")
    _ordered(cli, "async function updateFinalizeCommand(opts)",
             "const pluginInstallRecords = await loadInstalledPluginIndexInstallRecords();",
             "return await runPostCorePluginUpdate({")
    _ordered(cli, "function registerUpdateFinalizationCommand(update, name, hidden)",
             "await updateFinalizeCommand({", 'registerUpdateFinalizationCommand(update, "repair", false);')
    update = sources["update-CM1QhIWo.js"]
    _ordered(update, 'import { t as installPluginFromGitSpec } from "./git-install-B1_qr0Ru.js";',
             "async function updateNpmInstalledPlugins(params)", "let result;",
             'record.source === "git" ? await installPluginFromGitSpec({',
             "config: params.config,", 'mode: "update",', "expectedPluginId: pluginId,")
    git = sources["git-install-B1_qr0Ru.js"]
    _ordered(git, 'import { n as preflightPluginGitInstallPolicy } from "./install-security-scan-BSpTdhul.js";',
             "s as emitPluginAuditSecurityEvent,", 'from "./install-BzCFXkWy.js";',
             "async function installPluginFromGitSpec(params)",
             'const effectiveMode = params.mode === "update" && await pathExists(persistentRepoDir) ? "update" : "install";',
             "const preflight = await preflightPluginGitInstallPolicy({", "mode: effectiveMode,",
             "pluginId: params.expectedPluginId ?? parsed.label,", "if (preflight?.blocked) {",
             "emitPluginAuditSecurityEvent({", "pluginId: params.expectedPluginId,",
             "mode: effectiveMode,", 'sourceFamily: "git"',
             "return buildBlockedGitInstallResult({ blocked: preflight.blocked });",
             "const install = await runCommandWithTimeout(",
             "const result = await installPluginFromInstalledPackageDir({",
             "const replaceResult = await replaceManagedGitRepo({")
    _ordered(sources["install-security-scan-BSpTdhul.js"],
             'return await import("./install-security-scan.runtime.js");',
             "async function preflightPluginGitInstallPolicy(params)",
             "const { preflightPluginGitInstallPolicyRuntime } = await loadInstallSecurityScanRuntime();",
             "return await preflightPluginGitInstallPolicyRuntime(params);")
    if sources["install-security-scan.runtime.js"] != (
        'export * from "./install-security-scan.runtime-CMin9jbx.js";\n'
    ):
        raise AdmissionEvidenceError("native lazy runtime bridge changed")
    runtime = sources["install-security-scan.runtime-CMin9jbx.js"]
    _ordered(runtime, 'import { n as runInstallPolicy } from "./install-policy-yA6T1vUH.js";',
             "async function runOperatorInstallPolicy(params)", "const result = await runInstallPolicy({",
             "config: params.config,", "targetName: params.targetName,", "kind: params.requestKind,",
             "mode: params.requestMode,", "return { blocked: result.blocked };")
    _ordered(runtime, "async function preflightPluginGitInstallPolicyRuntime(params)",
             "return await runOperatorInstallPolicy({", 'requestKind: "plugin-git",',
             'requestMode: params.mode ?? "install",')
    policy = sources["install-policy-yA6T1vUH.js"]
    _ordered(policy, "function blockedByPolicy(reason, findings)",
             'code: "security_scan_blocked",',
             "reason: `blocked by install policy: ${truncateText(reason, MAX_REASON_CHARS)}`")
    _ordered(policy, "function parsePolicyResponse(stdout)",
             'const decision = record.decision;', 'decision !== "allow" && decision !== "block"',
             "return blockedByPolicy(reason, normalizedFindings);", "async function runInstallPolicy(params)",
             "const policy = resolvePolicy(config, params.request.targetType);",
             "result = await runPolicyCommand({", "command: secureCommandPath,",
             "const parsed = parsePolicyResponse(result.stdout);", "if (parsed.blocked) return logBlocked(parsed);")
    install = sources["install-BzCFXkWy.js"]
    _ordered(install, 'import { c as emitTrustedSecurityEvent } from "./diagnostic-events-JZsXee1S.js";',
             "function emitPluginAuditSecurityEvent(params)", "emitTrustedSecurityEvent({",
             'action: "plugin.audit.failed",', 'decision: "deny",', "reason: params.reason",
             "source_family: params.sourceFamily", "mode: params.mode")
    diagnostic = sources["diagnostic-events-JZsXee1S.js"]
    _ordered(diagnostic, "function emitDiagnosticEventWithTrust(event, trusted, options = {})",
             'if (event.type === "security.event" && options.allowSecurityEvent !== true) return;',
             "createInternalDiagnosticMetadata(trusted) : { trusted }")
    _ordered(diagnostic, "function emitTrustedSecurityEvent(event)",
             "emitDiagnosticEventWithTrust({", 'type: "security.event",',
             "}, true, { allowSecurityEvent: true });", "function onTrustedInternalDiagnosticEvent(listener)",
             "state.trustedListeners.add(listener);", "emitTrustedSecurityEvent as c,",
             "onTrustedInternalDiagnosticEvent as g,")
