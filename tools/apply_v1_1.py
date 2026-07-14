#!/usr/bin/env python3
"""Apply the Hardening Lens 1.1 operational-trust release to the working tree.

This script is intentionally idempotent. It is used once by the release branch
workflow and removed before the branch is merged.
"""

from __future__ import annotations

import json
import re
import shutil
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "HardeningLens"
VERSION = "1.1.0"


def read(path: str | Path) -> str:
    return (ROOT / path).read_text(encoding="utf-8-sig")


def write(path: str | Path, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.replace("\r\n", "\n"), encoding="utf-8", newline="\n")


def load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(read(path))


def dump_json(path: str | Path, value: Any) -> None:
    write(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        if new in text:
            return text
        raise RuntimeError(f"Could not locate {label}")
    return text.replace(old, new, 1)


def resolve_action_sha(repository: str, tag: str, fallback: str) -> str:
    try:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/git/ref/tags/{tag}",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "hardening-lens-release"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.load(response)
        obj = payload["object"]
        if obj["type"] == "tag":
            request = urllib.request.Request(obj["url"], headers={"User-Agent": "hardening-lens-release"})
            with urllib.request.urlopen(request, timeout=20) as response:
                obj = json.load(response)["object"]
        sha = str(obj["sha"])
        if re.fullmatch(r"[0-9a-f]{40}", sha):
            return sha
    except Exception as exc:  # pragma: no cover - fallback protects release generation
        print(f"Warning: could not resolve {repository}@{tag}: {exc}")
    return fallback


CHECKOUT_SHA = resolve_action_sha(
    "actions/checkout", "v7", "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
)
UPLOAD_SHA = resolve_action_sha(
    "actions/upload-artifact", "v7", "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
)
ATTEST_SHA = resolve_action_sha(
    "actions/attest-build-provenance", "v3", "e8998f949152b193b063cb0ec769d69d929409be"
)


def reference_factory(catalog: dict[str, Any]):
    sample = None
    for control in catalog.get("controls", []):
        refs = control.get("references")
        if refs:
            sample = refs[0]
            break

    def make(items: list[tuple[str, str]]) -> list[Any]:
        if isinstance(sample, dict):
            result = []
            for title, url in items:
                keys = set(sample)
                entry: dict[str, str] = {}
                if "title" in keys:
                    entry["title"] = title
                if "name" in keys:
                    entry["name"] = title
                if "url" in keys:
                    entry["url"] = url
                if "uri" in keys:
                    entry["uri"] = url
                result.append(entry)
            return result
        return [url for _, url in items]

    return make


def choose_category(existing: set[str], preferred: str, contains: str) -> str:
    if preferred in existing:
        return preferred
    for category in sorted(existing):
        if contains.casefold() in category.casefold():
            return category
    return sorted(existing)[0]


def add_controls() -> list[str]:
    catalog_path = MODULE / "Data" / "control-catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8-sig"))
    catalog["catalogVersion"] = VERSION
    existing_ids = {str(control["id"]) for control in catalog["controls"]}
    categories = {str(control["category"]) for control in catalog["controls"]}
    refs = reference_factory(catalog)

    network = choose_category(categories, "Network Protection", "network")
    firewall = choose_category(categories, "Windows Firewall", "firewall")
    credential = choose_category(categories, "Credential Protection", "credential")
    privilege = choose_category(categories, "Privilege Management", "privilege")
    platform = choose_category(categories, "Platform Security", "platform")
    defender = choose_category(categories, "Endpoint Protection", "endpoint")
    logging = choose_category(categories, "Security Logging", "logging")
    remote = choose_category(categories, "Remote Administration", "remote")

    microsoft_tls = [("Microsoft TLS registry settings", "https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings")]
    microsoft_baseline = [("Windows Server security baseline", "https://learn.microsoft.com/windows-server/security/osconfig/osconfig-how-to-configure-security-baselines")]
    microsoft_firewall = [("Windows Firewall logging", "https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/configure-logging")]
    microsoft_defender = [("Configure Microsoft Defender Antivirus exclusions", "https://learn.microsoft.com/defender-endpoint/configure-exclusions-microsoft-defender-antivirus")]
    microsoft_rds = [("Remote Desktop Services policy settings", "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-terminalserver")]
    microsoft_audit = [("Advanced security audit policy settings", "https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings")]

    controls: list[dict[str, Any]] = [
        {
            "id": "HL-TLS-001",
            "title": "TLS 1.0 server protocol is explicitly disabled",
            "description": "Verifies the effective Schannel server configuration for TLS 1.0 instead of assuming an operating-system default.",
            "category": network,
            "severity": "High",
            "weight": 4,
            "probe": "TlsProtocol",
            "parameters": {"protocol": "TLS 1.0", "side": "Server", "expected": "Disabled"},
            "rationale": "Explicitly disabling legacy TLS reduces downgrade and weak-protocol exposure and makes the intended state auditable.",
            "remediation": "Disable TLS 1.0 server support through a tested policy rollout after validating application dependencies.",
            "references": refs(microsoft_tls),
        },
        {
            "id": "HL-TLS-002",
            "title": "TLS 1.1 server protocol is explicitly disabled",
            "description": "Verifies the effective Schannel server configuration for TLS 1.1.",
            "category": network,
            "severity": "High",
            "weight": 4,
            "probe": "TlsProtocol",
            "parameters": {"protocol": "TLS 1.1", "side": "Server", "expected": "Disabled"},
            "rationale": "TLS 1.1 is obsolete and should not remain available as an undocumented compatibility path.",
            "remediation": "Disable TLS 1.1 server support after dependency discovery and staged validation.",
            "references": refs(microsoft_tls),
        },
        {
            "id": "HL-TLS-003",
            "title": "TLS 1.2 server protocol is explicitly enabled",
            "description": "Verifies an explicit TLS 1.2 Schannel server configuration.",
            "category": network,
            "severity": "High",
            "weight": 4,
            "probe": "TlsProtocol",
            "parameters": {"protocol": "TLS 1.2", "side": "Server", "expected": "Enabled"},
            "rationale": "An explicit modern protocol configuration avoids relying on release-specific defaults.",
            "remediation": "Enable TLS 1.2 server support explicitly and validate the full certificate and application path.",
            "references": refs(microsoft_tls),
        },
        {
            "id": "HL-NETBIOS-001",
            "title": "NetBIOS over TCP/IP is disabled on active adapters",
            "description": "Evaluates every IP-enabled adapter and distinguishes explicit disablement from DHCP or default behavior.",
            "category": network,
            "severity": "Medium",
            "weight": 3,
            "probe": "NetBios",
            "parameters": {},
            "rationale": "Removing unnecessary legacy name-resolution paths reduces broadcast exposure and credential-relay opportunities.",
            "remediation": "Disable NetBIOS over TCP/IP on active adapters after confirming that legacy applications do not depend on it.",
            "references": refs(microsoft_baseline),
        },
        {
            "id": "HL-FW-003",
            "title": "Windows Firewall logs dropped packets",
            "description": "Checks dropped-packet logging on Domain, Private, and Public profiles in the active policy store.",
            "category": firewall,
            "severity": "Medium",
            "weight": 2,
            "probe": "FirewallLogging",
            "parameters": {"property": "LogBlocked"},
            "rationale": "Dropped-packet telemetry supports incident investigation and change validation.",
            "remediation": "Enable dropped-packet logging for every Windows Firewall profile and size the log for the expected event volume.",
            "references": refs(microsoft_firewall),
        },
        {
            "id": "HL-FW-004",
            "title": "Windows Firewall logs successful connections",
            "description": "Checks successful-connection logging on Domain, Private, and Public profiles in the active policy store.",
            "category": firewall,
            "severity": "Low",
            "weight": 1,
            "probe": "FirewallLogging",
            "parameters": {"property": "LogAllowed"},
            "rationale": "Allowed-connection telemetry provides evidence for segmentation tests and incident response.",
            "remediation": "Enable successful-connection logging where the operational log volume is acceptable and centrally retained.",
            "references": refs(microsoft_firewall),
        },
        {
            "id": "HL-UAC-003",
            "title": "Remote UAC token filtering is enabled",
            "description": "Checks LocalAccountTokenFilterPolicy and treats an undocumented value as unresolved evidence.",
            "category": privilege,
            "severity": "High",
            "weight": 4,
            "probe": "RegistrySecurityValue",
            "parameters": {
                "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "name": "LocalAccountTokenFilterPolicy",
                "operator": "Equals",
                "expected": 0,
                "missingStatus": "Pass"
            },
            "rationale": "Remote token filtering reduces the administrative reach of local accounts over the network.",
            "remediation": "Remove LocalAccountTokenFilterPolicy or set it to zero after validating remote-administration workflows.",
            "references": refs(microsoft_baseline),
        },
        {
            "id": "HL-CREDSSP-001",
            "title": "CredSSP Encryption Oracle Remediation is enforced",
            "description": "Checks the effective AllowEncryptionOracle policy and rejects vulnerable compatibility mode.",
            "category": credential,
            "severity": "High",
            "weight": 4,
            "probe": "RegistrySecurityValue",
            "parameters": {
                "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters",
                "name": "AllowEncryptionOracle",
                "operator": "LessThanOrEqual",
                "expected": 1,
                "missingStatus": "Pass"
            },
            "rationale": "CredSSP must not permit vulnerable clients as a compatibility fallback.",
            "remediation": "Configure Encryption Oracle Remediation to Force Updated Clients or Mitigated and update incompatible endpoints.",
            "references": refs(microsoft_baseline),
        },
        {
            "id": "HL-MSI-001",
            "title": "AlwaysInstallElevated is disabled",
            "description": "Checks machine policy and every loaded user policy hive for AlwaysInstallElevated.",
            "category": privilege,
            "severity": "Critical",
            "weight": 5,
            "probe": "AlwaysInstallElevated",
            "parameters": {},
            "rationale": "AlwaysInstallElevated can allow untrusted MSI packages to execute with elevated privileges.",
            "remediation": "Disable AlwaysInstallElevated in both computer and user policy and investigate systems where it was enabled.",
            "references": refs(microsoft_baseline),
        },
        {
            "id": "HL-DC-003",
            "title": "Print Spooler is disabled on domain controllers",
            "description": "Checks that the Print Spooler is disabled and not running when the detected role is DomainController.",
            "category": platform,
            "severity": "High",
            "weight": 4,
            "probe": "ServiceState",
            "parameters": {"name": "Spooler", "expected": "Disabled", "onlyRole": "DomainController"},
            "rationale": "Domain controllers rarely need print services and should minimize exposed privileged services.",
            "remediation": "Disable the Print Spooler on domain controllers unless a documented dependency is approved and compensated.",
            "references": refs(microsoft_baseline),
        },
        {
            "id": "HL-HVCI-001",
            "title": "Memory Integrity is running",
            "description": "Uses the Device Guard provider to verify that hypervisor-protected code integrity is running, not merely configured.",
            "category": platform,
            "severity": "High",
            "weight": 4,
            "probe": "HVCI",
            "parameters": {},
            "rationale": "Memory Integrity raises the trust boundary for kernel-mode code and reduces the impact of vulnerable drivers.",
            "remediation": "Enable Memory Integrity on supported hardware after driver compatibility testing and staged deployment.",
            "references": refs(microsoft_baseline),
        },
        {
            "id": "HL-DEF-006",
            "title": "Microsoft Defender exclusions are approved",
            "description": "Inventories path, process, extension, and IP exclusions and compares them with an explicit allowlist.",
            "category": defender,
            "severity": "High",
            "weight": 4,
            "probe": "DefenderExclusions",
            "parameters": {"allowedPatterns": []},
            "rationale": "Broad or undocumented exclusions create durable blind spots in endpoint protection.",
            "remediation": "Remove unnecessary exclusions or define narrowly scoped, reviewed patterns in a custom baseline.",
            "references": refs(microsoft_defender),
        },
        {
            "id": "HL-AUD-007",
            "title": "Sensitive Privilege Use auditing is enabled",
            "description": "Verifies Success and Failure auditing for Sensitive Privilege Use by subcategory GUID.",
            "category": logging,
            "severity": "Medium",
            "weight": 3,
            "probe": "AuditPolicy",
            "parameters": {
                "subcategoryName": "Sensitive Privilege Use",
                "subcategoryGuid": "{0CCE9228-69AE-11D9-BED3-505054503030}",
                "requiredFlags": ["Success", "Failure"]
            },
            "rationale": "Sensitive privilege telemetry supports investigation of high-impact administrative actions.",
            "remediation": "Enable Success and Failure auditing for Sensitive Privilege Use through advanced audit policy.",
            "references": refs(microsoft_audit),
        },
        {
            "id": "HL-AUD-008",
            "title": "System Integrity auditing is enabled",
            "description": "Verifies Success and Failure auditing for System Integrity by subcategory GUID.",
            "category": logging,
            "severity": "High",
            "weight": 4,
            "probe": "AuditPolicy",
            "parameters": {
                "subcategoryName": "System Integrity",
                "subcategoryGuid": "{0CCE9212-69AE-11D9-BED3-505054503030}",
                "requiredFlags": ["Success", "Failure"]
            },
            "rationale": "System Integrity events provide high-value evidence about security subsystem failures and tampering.",
            "remediation": "Enable Success and Failure auditing for System Integrity through advanced audit policy.",
            "references": refs(microsoft_audit),
        },
        {
            "id": "HL-RDS-001",
            "title": "AVD clipboard redirection is disabled",
            "description": "Checks the policy that prevents clipboard redirection in Remote Desktop sessions.",
            "category": remote,
            "severity": "Medium",
            "weight": 3,
            "probe": "RdsPolicy",
            "parameters": {"name": "fDisableClip", "operator": "Equals", "expected": 1, "missingStatus": "Fail"},
            "rationale": "Clipboard redirection can create an uncontrolled data-transfer channel between managed sessions and endpoints.",
            "remediation": "Disable clipboard redirection for AVD session hosts or record a scoped business exception.",
            "references": refs(microsoft_rds),
        },
        {
            "id": "HL-RDS-002",
            "title": "AVD drive redirection is disabled",
            "description": "Checks the policy that prevents client drive redirection in Remote Desktop sessions.",
            "category": remote,
            "severity": "Medium",
            "weight": 3,
            "probe": "RdsPolicy",
            "parameters": {"name": "fDisableCdm", "operator": "Equals", "expected": 1, "missingStatus": "Fail"},
            "rationale": "Drive redirection can bypass managed storage and data-loss controls.",
            "remediation": "Disable drive redirection for AVD session hosts or document a constrained exception.",
            "references": refs(microsoft_rds),
        },
        {
            "id": "HL-RDS-003",
            "title": "AVD idle-session timeout is configured",
            "description": "Checks that an explicit idle-session timeout of 30 minutes or less is configured.",
            "category": remote,
            "severity": "Medium",
            "weight": 2,
            "probe": "RdsPolicy",
            "parameters": {"name": "MaxIdleTime", "operator": "LessThanOrEqual", "expected": 1800000, "missingStatus": "Fail"},
            "rationale": "Idle-session limits reduce unattended session exposure and resource exhaustion.",
            "remediation": "Configure an AVD idle-session timeout aligned with business and security requirements.",
            "references": refs(microsoft_rds),
        },
    ]

    for control in controls:
        if control["id"] not in existing_ids:
            catalog["controls"].append(control)
    catalog["controls"] = sorted(catalog["controls"], key=lambda item: str(item["id"]))
    dump_json(catalog_path.relative_to(ROOT), catalog)
    return [control["id"] for control in controls]


def update_control_schema() -> None:
    path = MODULE / "Schema" / "control-catalog.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8-sig"))

    def find_probe_enum(node: Any) -> list[str] | None:
        if isinstance(node, dict):
            if "probe" in node.get("properties", {}) and isinstance(node["properties"]["probe"].get("enum"), list):
                return node["properties"]["probe"]["enum"]
            for value in node.values():
                found = find_probe_enum(value)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = find_probe_enum(value)
                if found is not None:
                    return found
        return None

    probe_enum = find_probe_enum(schema)
    if probe_enum is None:
        raise RuntimeError("Could not locate probe enum in control catalog schema")
    for name in [
        "TlsProtocol",
        "NetBios",
        "FirewallLogging",
        "RegistrySecurityValue",
        "AlwaysInstallElevated",
        "ServiceState",
        "HVCI",
        "DefenderExclusions",
        "RdsPolicy",
    ]:
        if name not in probe_enum:
            probe_enum.append(name)
    probe_enum.sort()
    dump_json(path.relative_to(ROOT), schema)


def update_baselines(new_ids: list[str]) -> None:
    baseline_root_candidates = [MODULE / "Data" / "Baselines", MODULE / "Data" / "baselines"]
    baseline_root = next((path for path in baseline_root_candidates if path.exists()), None)
    if baseline_root is None:
        raise RuntimeError("Could not locate baseline directory")

    common = [
        "HL-TLS-001", "HL-TLS-002", "HL-TLS-003", "HL-NETBIOS-001",
        "HL-FW-003", "HL-FW-004", "HL-UAC-003", "HL-CREDSSP-001",
        "HL-MSI-001", "HL-HVCI-001", "HL-DEF-006", "HL-AUD-007", "HL-AUD-008",
    ]
    role_specific = {
        "DomainController": ["HL-DC-003"],
        "AVDSessionHost": ["HL-RDS-001", "HL-RDS-002", "HL-RDS-003"],
    }

    for path in baseline_root.glob("*.json"):
        baseline = json.loads(path.read_text(encoding="utf-8-sig"))
        baseline["version"] = VERSION
        name = str(baseline.get("name", path.stem))
        ids = list(common)
        for role, extra in role_specific.items():
            if role.casefold() in name.casefold() or role in [str(x) for x in baseline.get("supportedRoles", [])]:
                ids.extend(extra)
        existing = {str(item["id"] if isinstance(item, dict) else item) for item in baseline["controls"]}
        sample = baseline["controls"][0]
        for control_id in ids:
            if control_id in existing:
                continue
            baseline["controls"].append({"id": control_id} if isinstance(sample, dict) else control_id)
        dump_json(path.relative_to(ROOT), baseline)


def update_result_schema() -> None:
    path = MODULE / "Schema" / "result.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8-sig"))
    scan = schema["properties"]["scan"]["properties"]
    scan.setdefault("assessmentMode", {"type": "string", "enum": ["Full", "Focused"]})
    scan.setdefault("baselineControlCount", {"type": "integer", "minimum": 0})
    dump_json(path.relative_to(ROOT), schema)


def update_manifest() -> None:
    path = MODULE / "HardeningLens.psd1"
    text = path.read_text(encoding="utf-8-sig")
    text = re.sub(r"(?m)^(\s*ModuleVersion\s*=\s*)'[^']+'", rf"\g<1>'{VERSION}'", text, count=1)
    exports = ["Test-HardeningLensResult", "Test-HardeningLensPolicy", "Invoke-HardeningLensFleet"]
    for function_name in exports:
        if re.search(rf"['\"]{re.escape(function_name)}['\"]", text):
            continue
        match = re.search(r"(?ms)(FunctionsToExport\s*=\s*@\()(.*?)(\n\s*\))", text)
        if not match:
            raise RuntimeError("Could not locate FunctionsToExport in module manifest")
        body = match.group(2).rstrip()
        comma = "," if body and not body.rstrip().endswith(",") else ""
        replacement = match.group(1) + body + comma + f"\n        '{function_name}'" + match.group(3)
        text = text[: match.start()] + replacement + text[match.end() :]
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_dispatcher() -> None:
    path = MODULE / "Private" / "ProbeDispatcher.ps1"
    text = path.read_text(encoding="utf-8-sig")
    if "'TlsProtocol'" in text:
        return
    cases = """            'TlsProtocol'           { return Invoke-HLTlsProtocolProbe -Control $Control }
            'NetBios'               { return Invoke-HLNetBiosProbe }
            'FirewallLogging'       { return Invoke-HLFirewallLoggingProbe -Control $Control }
            'RegistrySecurityValue' { return Invoke-HLRegistrySecurityValueProbe -Control $Control }
            'AlwaysInstallElevated' { return Invoke-HLAlwaysInstallElevatedProbe }
            'ServiceState'          { return Invoke-HLServiceStateProbe -Control $Control -SystemContext $SystemContext }
            'HVCI'                  { return Invoke-HLHVCIProbe }
            'DefenderExclusions'    { return Invoke-HLDefenderExclusionProbe -Control $Control }
            'RdsPolicy'             { return Invoke-HLRdsPolicyProbe -Control $Control }
"""
    text, count = re.subn(r"(?m)^(\s*)default\s+\{", lambda match: cases + match.group(0), text, count=1)
    if count != 1:
        raise RuntimeError("Could not patch probe dispatcher")
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_invoke() -> None:
    path = MODULE / "Public" / "Invoke-HardeningLens.ps1"
    text = path.read_text(encoding="utf-8-sig")
    if "$baselineControlCount" not in text:
        text, count = re.subn(
            r"(?m)^(\s*\$controls\s*=\s*@\(\$resolvedBaseline\.controls\)\s*)$",
            r"\1\n    $baselineControlCount = @($controls).Count",
            text,
            count=1,
        )
        if count != 1:
            raise RuntimeError("Could not capture baseline control count")

    if "assessmentMode" not in text:
        selected_line = re.search(r"(?m)^(\s*selectedControlCount\s*=.*)$", text)
        if not selected_line:
            raise RuntimeError("Could not locate selectedControlCount")
        indent = re.match(r"\s*", selected_line.group(1)).group(0)
        addition = (
            selected_line.group(1)
            + f"\n{indent}baselineControlCount = $baselineControlCount"
            + f"\n{indent}assessmentMode       = if (@($controls).Count -lt $baselineControlCount) {{ 'Focused' }} else {{ 'Full' }}"
        )
        text = text[: selected_line.start()] + addition + text[selected_line.end() :]

    # Only the baseline metadata count changes; selectedControlCount remains the evaluated scope.
    baseline_block = re.search(r"(?ms)(baseline\s*=\s*\[pscustomobject\]\[ordered\]@\{.*?\n\s*\})", text)
    if baseline_block:
        updated = re.sub(r"(?m)(controlCount\s*=\s*)@\(\$controls\)\.Count", r"\1$baselineControlCount", baseline_block.group(1))
        text = text[: baseline_block.start()] + updated + text[baseline_block.end() :]
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_comparison() -> None:
    private_path = MODULE / "Private" / "Comparison.ps1"
    text = private_path.read_text(encoding="utf-8-sig")
    text = text.replace("Evidence       = $Result.evidence", "Evidence       = ConvertTo-HLCanonicalObject -InputObject $Result.evidence")
    if "function Get-HLDriftChangeType" not in text:
        helper = r'''function Get-HLDriftChangeType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReferenceStatus,
        [Parameter(Mandatory)][string]$DifferenceStatus
    )

    $referenceFinding = $ReferenceStatus -in @('Fail', 'Warning', 'Excepted')
    $differenceFinding = $DifferenceStatus -in @('Fail', 'Warning', 'Excepted')
    $referenceEvidence = $ReferenceStatus -notin @('Unknown', 'Error')
    $differenceEvidence = $DifferenceStatus -notin @('Unknown', 'Error')

    if ($referenceEvidence -and -not $differenceEvidence) { return 'Changed' }
    if (-not $referenceEvidence -and $differenceEvidence) { return 'Changed' }
    if (-not $referenceFinding -and $differenceFinding) { return 'NewFinding' }
    if ($referenceFinding -and $DifferenceStatus -eq 'Pass') { return 'Resolved' }
    return 'Changed'
}

'''
        marker = "function Compare-HLScanResult"
        if marker not in text:
            raise RuntimeError("Could not locate comparison function")
        text = text.replace(marker, helper + marker, 1)

    old = """            if (-not $referenceOpen -and $differenceOpen) {
                $changeType = 'NewFinding'
            }
            elseif ($referenceOpen -and -not $differenceOpen) {
                $changeType = 'Resolved'
            }
            else {
                $changeType = 'Changed'
            }"""
    if old in text:
        text = text.replace(old, "            $changeType = Get-HLDriftChangeType -ReferenceStatus ([string]$referenceResult.status) -DifferenceStatus ([string]$differenceResult.status)", 1)
    private_path.write_text(text, encoding="utf-8", newline="\n")

    public_path = MODULE / "Public" / "Compare-HardeningLensResult.ps1"
    public = public_path.read_text(encoding="utf-8-sig")
    if "AllowRedactedComparison" not in public:
        anchor = re.search(r"(?m)^(\s*\[switch\]\$AllowCrossTarget)", public)
        if not anchor:
            raise RuntimeError("Could not locate AllowCrossTarget")
        public = public[: anchor.start()] + "    [switch]$AllowRedactedComparison,\n\n" + public[anchor.start() :]
        load_anchor = re.search(r"(?m)^\s*\$differenceResult\s*=.*$", public)
        if not load_anchor:
            raise RuntimeError("Could not locate loaded comparison inputs")
        guard = r'''

    if (-not $AllowRedactedComparison -and (
        ($null -ne $referenceResult.scan.redacted -and [bool]$referenceResult.scan.redacted) -or
        ($null -ne $differenceResult.scan.redacted -and [bool]$differenceResult.scan.redacted)
    )) {
        throw 'Target identity cannot be established safely for redacted results. Use -AllowRedactedComparison only after independently verifying both inputs.'
    }
'''
        public = public[: load_anchor.end()] + guard + public[load_anchor.end() :]
    public_path.write_text(public, encoding="utf-8", newline="\n")


def patch_exceptions() -> None:
    path = MODULE / "Private" / "Exceptions.ps1"
    text = path.read_text(encoding="utf-8-sig")
    if "Overlapping approved exception scopes" in text:
        return
    marker = "    return [pscustomobject][ordered]@{\n        IsValid"
    if marker not in text:
        raise RuntimeError("Could not locate exception validation return")
    governance = r'''    $approved = @($Document.exceptions | Where-Object { [string]$_.status -eq 'Approved' })
    $now = (Get-Date).ToUniversalTime()
    foreach ($exception in $approved) {
        if (@($exception.targets) -contains '*') {
            $warnings.Add("Approved exception '$($exception.id)' applies to every target.")
        }
        if ($null -ne $exception.expires) {
            $expires = ([datetime]$exception.expires).ToUniversalTime()
            if ($expires -gt $now -and $expires -le $now.AddDays(30)) {
                $warnings.Add("Approved exception '$($exception.id)' expires within 30 days.")
            }
        }
    }

    for ($leftIndex = 0; $leftIndex -lt $approved.Count; $leftIndex++) {
        for ($rightIndex = $leftIndex + 1; $rightIndex -lt $approved.Count; $rightIndex++) {
            $left = $approved[$leftIndex]
            $right = $approved[$rightIndex]
            if ([string]$left.controlId -ne [string]$right.controlId) { continue }
            $leftBaselines = if ($null -ne $left.baselines -and @($left.baselines).Count -gt 0) { @($left.baselines) } else { @('*') }
            $rightBaselines = if ($null -ne $right.baselines -and @($right.baselines).Count -gt 0) { @($right.baselines) } else { @('*') }
            if ((Test-HLWildcardScopeOverlap -Left @($left.targets) -Right @($right.targets)) -and
                (Test-HLWildcardScopeOverlap -Left $leftBaselines -Right $rightBaselines)) {
                $errors.Add("Overlapping approved exception scopes '$($left.id)' and '$($right.id)' match control '$($left.controlId)'.")
            }
        }
    }

'''
    text = text.replace(marker, governance + marker, 1)
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_report_export() -> None:
    path = MODULE / "Public" / "Export-HardeningLensReport.ps1"
    text = path.read_text(encoding="utf-8-sig")
    if "Add-HLAssessmentScopeBanner" in text:
        return
    pattern = re.compile(r"New-HLHtmlReport\s+-ScanResult\s+\$InputObject")
    text, count = pattern.subn("Add-HLAssessmentScopeBanner -Html (New-HLHtmlReport -ScanResult $InputObject) -ScanResult $InputObject", text, count=1)
    if count == 0:
        pattern = re.compile(r"New-HLHtmlReport\s+-Result\s+\$InputObject")
        text, count = pattern.subn("Add-HLAssessmentScopeBanner -Html (New-HLHtmlReport -Result $InputObject) -ScanResult $InputObject", text, count=1)
    if count == 0:
        raise RuntimeError("Could not patch HTML report generation")
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_cli() -> None:
    path = ROOT / "hardening-lens.ps1"
    text = path.read_text(encoding="utf-8-sig")
    if "$PolicyPath" not in text:
        marker = "    [switch]$PassThru"
        if marker not in text:
            raise RuntimeError("Could not locate PassThru parameter")
        text = text.replace(marker, "    [string]$PolicyPath,\n\n" + marker, 1)
    if "Test-HardeningLensPolicy" not in text:
        marker = "    if ($PassThru) {"
        if marker not in text:
            raise RuntimeError("Could not locate PassThru output block")
        policy = r'''    if (-not [string]::IsNullOrWhiteSpace($PolicyPath)) {
        $policyDecision = $scan | Test-HardeningLensPolicy -PolicyPath $PolicyPath
        if (-not $policyDecision.passed) {
            $failedNames = @($policyDecision.checks | Where-Object Passed -eq $false | ForEach-Object Name)
            Write-Warning ("Hardening Lens policy denied the assessment: {0}" -f ($failedNames -join ', '))
            if ($PassThru) { $PSCmdlet.WriteObject($policyDecision, $false) }
            exit 1
        }
    }

'''
        text = text.replace(marker, policy + marker, 1)
    path.write_text(text, encoding="utf-8", newline="\n")


def replace_fleet_script() -> None:
    content = r'''[CmdletBinding(DefaultParameterSetName = 'ComputerName')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ComputerName')]
    [string[]]$ComputerName,

    [Parameter(Mandatory, ParameterSetName = 'Inventory')]
    [string]$InventoryPath,

    [ValidateSet('Auto', 'Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
    [string]$Baseline = 'Auto',

    [string]$CustomBaselinePath,
    [string]$ExceptionsPath,

    [Parameter(Mandatory)]
    [string]$OutputDirectory,

    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 8,

    [ValidateRange(30, 3600)]
    [int]$TimeoutSeconds = 300,

    [ValidateRange(0, 5)]
    [int]$RetryCount = 1,

    [pscredential]$Credential,
    [switch]$Resume,
    [switch]$Redact
)

$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
Import-Module -Name (Join-Path $repositoryRoot 'src/HardeningLens/HardeningLens.psd1') -Force -ErrorAction Stop
Invoke-HardeningLensFleet @PSBoundParameters
'''
    write("scripts/Invoke-FleetAssessment.ps1", content)


def patch_validator() -> None:
    path = ROOT / "tools" / "validate_repository.py"
    text = path.read_text(encoding="utf-8-sig")
    text = re.sub(
        r"if\s+len\(controls\)\s*!=\s*58:\s*\n\s*errors\.append\([^\n]+\)",
        "if len(controls) < 75:\n        errors.append(f\"Expected at least 75 controls for catalog {catalog_version}; found {len(controls)}.\")",
        text,
        count=1,
    )
    text = text.replace("58 controls", "at least 75 controls")
    path.write_text(text, encoding="utf-8", newline="\n")


def update_docs() -> None:
    changelog_path = ROOT / "CHANGELOG.md"
    changelog = changelog_path.read_text(encoding="utf-8-sig")
    if "## [1.1.0]" not in changelog:
        entry = """## [1.1.0] - 2026-07-14

### Added

- Full versus focused assessment semantics with explicit baseline scope.
- Runtime result validation through `Test-HardeningLensResult`.
- Policy-as-code quality gates through `Test-HardeningLensPolicy` and automation-safe exit codes.
- Reliable fleet assessment with inventory files, retry, timeout, resume, and one manifest record per requested host.
- Seventeen curated controls for TLS, NetBIOS, firewall telemetry, Remote UAC, CredSSP, AlwaysInstallElevated, domain-controller spooler posture, Memory Integrity, Defender exclusions, advanced audit policy, and AVD redirection/session controls.
- Exception overlap detection and expiry warnings.
- Release metadata, SPDX SBOM generation, checksums, and artifact provenance attestation.
- Product roadmap for 1.2 interoperability and the 2.0 policy-and-evidence architecture.

### Changed

- Drift no longer treats evidence loss as remediation.
- Evidence fingerprints are canonicalized before comparison.
- Redacted result comparisons require explicit operator approval.
- HTML reports identify focused assessments and avoid presenting a scope score as a complete baseline score.
- GitHub Actions are pinned to immutable commit SHAs.

"""
        heading = re.search(r"(?m)^## ", changelog)
        changelog = changelog[: heading.start()] + entry + changelog[heading.start() :] if heading else changelog + "\n" + entry
    changelog_path.write_text(changelog, encoding="utf-8", newline="\n")

    readme_path = ROOT / "README.md"
    readme = readme_path.read_text(encoding="utf-8-sig")
    readme = readme.replace("1.0.0", VERSION)
    readme = re.sub(r"\b58\s+(?=curated|controls|Windows)", "75 ", readme)
    if "## Operational trust in 1.1" not in readme:
        section = r'''
## Operational trust in 1.1

Hardening Lens distinguishes a complete baseline assessment from a focused control selection. A focused run receives a scope score, not a complete-baseline claim. Runtime validation checks result integrity before policy or drift decisions are made.

```powershell
$result = Invoke-HardeningLens -Baseline MemberServer -NoConsole
$result | Test-HardeningLensResult
$result | Test-HardeningLensPolicy -PolicyPath .\examples\production-policy.json
```

Policy gates can require a full assessment, minimum evidence coverage, zero collection errors, severity thresholds, and controlled exception debt. The CLI exits with `0` for an allowed assessment, `1` for a policy denial, and `2` for an operational error.

```powershell
.\hardening-lens.ps1 `
    -Baseline MemberServer `
    -PolicyPath .\examples\production-policy.json `
    -OutputDirectory .\out
```

Fleet execution accounts for every requested host, including connection failures and timeouts:

```powershell
Invoke-HardeningLensFleet `
    -InventoryPath .\examples\fleet-inventory.json `
    -ExceptionsPath .\exceptions.json `
    -OutputDirectory .\fleet-results `
    -ThrottleLimit 8 `
    -TimeoutSeconds 300 `
    -RetryCount 2 `
    -Resume
```

The fleet output includes `run-manifest.json`, per-host results, explicit failure records, CSV summary, and a self-contained HTML report.

'''
        insertion = re.search(r"(?m)^## ", readme)
        readme = readme[: insertion.start()] + section + readme[insertion.start() :] if insertion else readme + section
    if "ROADMAP.md" not in readme:
        readme += "\n## Roadmap\n\nThe planned interoperability work for 1.2 and the schema/provider architecture for 2.0 are documented in [ROADMAP.md](ROADMAP.md).\n"
    readme_path.write_text(readme, encoding="utf-8", newline="\n")

    architecture_path = ROOT / "docs" / "ARCHITECTURE.md"
    if architecture_path.exists():
        architecture = architecture_path.read_text(encoding="utf-8-sig").replace("New-HLProbeResult", "Get-HLProbeResult")
        architecture_path.write_text(architecture, encoding="utf-8", newline="\n")

    write(
        "docs/OPERATIONAL_TRUST.md",
        """# Operational trust model\n\nHardening Lens 1.1 treats scope, evidence, policy, exceptions, and fleet execution as separate contracts.\n\n## Assessment scope\n\nA full assessment selects every control from the resolved baseline. A focused assessment selects a subset through `-ControlId`. The historical `summary.ScorePercent` remains the score for the evaluated scope for schema compatibility, while `scan.assessmentMode`, `scan.selectedControlCount`, and `scan.baselineControlCount` make the scope explicit. Policy gates reject focused results by default.\n\n## Evidence transitions\n\nA finding is resolved only when the new state is `Pass`. A transition from `Fail` or `Warning` to `Unknown` or `Error` is evidence loss and remains a changed state, never a resolution. Evidence is canonicalized before fingerprinting to remove remoting metadata and property-order noise.\n\n## Redaction and identity\n\nResult redaction is intended for controlled sharing, not durable asset identity. Comparisons involving redacted results require `-AllowRedactedComparison` because two different hosts can share the same redacted display name. Stable pseudonymous asset identity is planned for schema 2.0.\n\n## Policy gates\n\nPolicy decisions are deterministic and read-only. They can require full scope, evidence coverage, error and unknown limits, severity thresholds, and bounded exception exposure. A denied policy does not alter the underlying assessment.\n\n## Fleet accounting\n\nEvery requested target produces one run-manifest record: completed, connection failed, assessment failed, timed out, or skipped from resume. Failed hosts are never silently omitted from the fleet denominator.\n\n## Exceptions\n\nApproved exceptions remain `Excepted`, preserve `originalStatus`, and are not scored as passing. Overlapping approved exception scopes for the same control are rejected because JSON ordering is not an acceptable precedence mechanism.\n""",
    )


def write_workflows() -> None:
    quality = f'''name: Quality Gate

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: quality-${{{{ github.ref }}}}
  cancel-in-progress: true

jobs:
  repository-contract:
    name: Repository contract
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@{CHECKOUT_SHA} # v7
        with:
          show-progress: false
      - name: Install schema validator
        run: python3 -m pip install --disable-pip-version-check -r requirements-dev.txt
      - name: Validate generated documentation
        run: python3 tools/generate_control_reference.py --check
      - name: Validate schemas and repository invariants
        run: python3 tools/validate_repository.py

  powershell-core:
    name: PowerShell 7 / Linux
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@{CHECKOUT_SHA} # v7
        with:
          show-progress: false
      - name: Install test modules
        shell: pwsh
        run: |
          $ErrorActionPreference = 'Stop'
          Set-PSRepository PSGallery -InstallationPolicy Trusted
          if (-not (Get-Module -ListAvailable Pester | Where-Object Version -ge 5.6.1)) {{ Install-Module Pester -MinimumVersion 5.6.1 -Scope CurrentUser -Force -AllowClobber }}
          if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {{ Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber }}
      - name: Validate and test
        shell: pwsh
        run: |
          $logPath = Join-Path $PWD 'build-pwsh.log'
          try {{ & ./build.ps1 -Task Test *>&1 | Tee-Object -FilePath $logPath }}
          catch {{ $_ | Format-List * -Force | Out-String | Tee-Object -FilePath $logPath -Append | Write-Host; throw }}
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@{UPLOAD_SHA} # v7
        with:
          name: test-results-pwsh
          path: |
            build-pwsh.log
            TestResults.xml
            artifacts/coverage.xml
          if-no-files-found: ignore

  windows-powershell:
    name: Windows PowerShell 5.1
    runs-on: windows-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@{CHECKOUT_SHA} # v7
        with:
          show-progress: false
      - name: Install test modules
        shell: powershell
        run: |
          $ErrorActionPreference = 'Stop'
          [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
          Set-PSRepository PSGallery -InstallationPolicy Trusted
          if (-not (Get-Module -ListAvailable Pester | Where-Object Version -ge 5.6.1)) {{ Install-Module Pester -MinimumVersion 5.6.1 -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck }}
          if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {{ Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck }}
      - name: Validate and test
        shell: powershell
        run: |
          $logPath = Join-Path $PWD 'build-windows-powershell.log'
          try {{ & .\build.ps1 -Task Test *>&1 | Tee-Object -FilePath $logPath }}
          catch {{ $_ | Format-List * -Force | Out-String | Tee-Object -FilePath $logPath -Append | Write-Host; throw }}
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@{UPLOAD_SHA} # v7
        with:
          name: test-results-windows-powershell
          path: |
            build-windows-powershell.log
            TestResults.xml
            artifacts/coverage.xml
          if-no-files-found: ignore
'''
    write(".github/workflows/quality.yml", quality)

    release = f'''name: Release

on:
  push:
    tags:
      - "v*.*.*"

permissions:
  contents: write
  id-token: write
  attestations: write

jobs:
  release:
    runs-on: windows-latest
    timeout-minutes: 35
    steps:
      - uses: actions/checkout@{CHECKOUT_SHA} # v7
        with:
          fetch-depth: 0
      - name: Install validation dependencies
        run: python -m pip install --disable-pip-version-check -r requirements-dev.txt
      - name: Install PowerShell test modules
        shell: powershell
        run: |
          $ErrorActionPreference = 'Stop'
          [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
          Set-PSRepository PSGallery -InstallationPolicy Trusted
          if (-not (Get-Module -ListAvailable Pester | Where-Object Version -ge 5.6.1)) {{ Install-Module Pester -MinimumVersion 5.6.1 -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck }}
          if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {{ Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck }}
      - name: Verify release version
        shell: powershell
        run: |
          $manifest = Test-ModuleManifest .\src\HardeningLens\HardeningLens.psd1
          $tagVersion = '${{{{ github.ref_name }}}}'.TrimStart('v')
          if ($manifest.Version.ToString() -ne $tagVersion) {{ throw "Tag version $tagVersion does not match module version $($manifest.Version)." }}
      - name: Validate repository
        run: |
          python tools/generate_control_reference.py --check
          python tools/validate_repository.py
      - name: Test and package
        shell: powershell
        run: .\build.ps1 -Task All
      - name: Generate release metadata
        shell: powershell
        run: .\tools\New-ReleaseMetadata.ps1 -ArtifactsDirectory .\artifacts -SourceCommit '${{{{ github.sha }}}}'
      - name: Attest module archive
        uses: actions/attest-build-provenance@{ATTEST_SHA} # v3
        with:
          subject-path: artifacts/HardeningLens-*.zip
      - name: Publish GitHub release
        shell: powershell
        env:
          GH_TOKEN: ${{{{ github.token }}}}
        run: |
          $version = '${{{{ github.ref_name }}}}'.TrimStart('v')
          gh release create '${{{{ github.ref_name }}}}' `
            "artifacts/HardeningLens-$version.zip" `
            "artifacts/HardeningLens-$version.zip.sha256" `
            "artifacts/build-manifest.json" `
            "artifacts/sbom.spdx.json" `
            --title "Hardening Lens $version" `
            --generate-notes `
            --verify-tag
'''
    write(".github/workflows/release.yml", release)

    windows_live_path = ROOT / ".github" / "workflows" / "windows-live.yml"
    if windows_live_path.exists():
        text = windows_live_path.read_text(encoding="utf-8-sig")
        text = re.sub(r"actions/checkout@[^\s#]+", f"actions/checkout@{CHECKOUT_SHA}", text)
        text = re.sub(r"actions/upload-artifact@[^\s#]+", f"actions/upload-artifact@{UPLOAD_SHA}", text)
        windows_live_path.write_text(text, encoding="utf-8", newline="\n")


def write_release_metadata_script() -> None:
    write(
        "tools/New-ReleaseMetadata.ps1",
        r'''[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ArtifactsDirectory,

    [Parameter(Mandatory)]
    [string]$SourceCommit
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
$artifactRoot = [System.IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ArtifactsDirectory))
$manifest = Test-ModuleManifest -Path (Join-Path $repositoryRoot 'src/HardeningLens/HardeningLens.psd1')
$catalog = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src/HardeningLens/Data/control-catalog.json') -Raw | ConvertFrom-Json

$files = @(Get-ChildItem -LiteralPath (Join-Path $repositoryRoot 'src/HardeningLens') -File -Recurse | Sort-Object FullName | ForEach-Object {
    [pscustomobject][ordered]@{
        path   = $_.FullName.Substring($repositoryRoot.Length + 1).Replace('\', '/')
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes  = $_.Length
    }
})

$buildManifest = [pscustomobject][ordered]@{
    schemaVersion       = '1.0'
    moduleVersion       = $manifest.Version.ToString()
    sourceCommit        = $SourceCommit
    catalogVersion      = [string]$catalog.catalogVersion
    resultSchemaVersion = '1.0'
    builtAt             = (Get-Date).ToUniversalTime().ToString('o')
    files               = $files
}
$buildManifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $artifactRoot 'build-manifest.json') -Encoding UTF8

$packages = @($files | ForEach-Object {
    [pscustomobject][ordered]@{
        SPDXID           = 'SPDXRef-' + ($_.path -replace '[^A-Za-z0-9.-]', '-')
        fileName         = $_.path
        checksums        = @([pscustomobject][ordered]@{ algorithm = 'SHA256'; checksumValue = $_.sha256 })
        licenseConcluded = 'NOASSERTION'
        copyrightText    = 'NOASSERTION'
    }
})
$sbom = [pscustomobject][ordered]@{
    spdxVersion       = 'SPDX-2.3'
    dataLicense       = 'CC0-1.0'
    SPDXID            = 'SPDXRef-DOCUMENT'
    name              = "HardeningLens-$($manifest.Version)"
    documentNamespace = "https://github.com/xGreeny/hardening-lens/releases/tag/v$($manifest.Version)/sbom"
    creationInfo      = [pscustomobject][ordered]@{
        created  = (Get-Date).ToUniversalTime().ToString('o')
        creators = @('Tool: HardeningLens release workflow')
    }
    files             = $packages
}
$sbom | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $artifactRoot 'sbom.spdx.json') -Encoding UTF8
''',
    )


def write_tests() -> None:
    write(
        "tests/Unit/OperationalTrust.Tests.ps1",
        r'''BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path $script:RepositoryRoot 'src/HardeningLens/HardeningLens.psd1') -Force
    $script:Sample = Get-Content -LiteralPath (Join-Path $script:RepositoryRoot 'examples/sample-result.json') -Raw | ConvertFrom-Json
}

Describe 'Hardening Lens 1.1 operational trust' {
    It 'validates the shipped sample result' {
        $validation = $script:Sample | Test-HardeningLensResult
        $validation.IsValid | Should -BeTrue
    }

    It 'infers a focused assessment from selected and baseline counts' {
        $copy = $script:Sample | ConvertTo-Json -Depth 60 | ConvertFrom-Json
        $copy.scan | Add-Member -NotePropertyName selectedControlCount -NotePropertyValue 2 -Force
        $copy.scan | Add-Member -NotePropertyName baselineControlCount -NotePropertyValue 20 -Force
        $copy.scan | Add-Member -NotePropertyName assessmentMode -NotePropertyValue Focused -Force
        $copy.results = @($copy.results | Select-Object -First 2)
        InModuleScope HardeningLens -Parameters @{ Scan = $copy } {
            param($Scan)
            Get-HLAssessmentMode -ScanResult $Scan | Should -Be 'Focused'
        }
    }

    It 'rejects duplicate control identifiers' {
        $copy = $script:Sample | ConvertTo-Json -Depth 60 | ConvertFrom-Json
        $copy.results = @($copy.results[0], $copy.results[0])
        $copy.scan.selectedControlCount = 2
        ($copy | Test-HardeningLensResult).IsValid | Should -BeFalse
    }

    It 'does not classify evidence loss as resolved' {
        InModuleScope HardeningLens {
            Get-HLDriftChangeType -ReferenceStatus Fail -DifferenceStatus Unknown | Should -Be 'Changed'
            Get-HLDriftChangeType -ReferenceStatus Warning -DifferenceStatus Error | Should -Be 'Changed'
            Get-HLDriftChangeType -ReferenceStatus Fail -DifferenceStatus Pass | Should -Be 'Resolved'
            Get-HLDriftChangeType -ReferenceStatus Pass -DifferenceStatus Fail | Should -Be 'NewFinding'
        }
    }

    It 'rejects a focused assessment when full scope is required' {
        $copy = $script:Sample | ConvertTo-Json -Depth 60 | ConvertFrom-Json
        $copy.scan | Add-Member -NotePropertyName selectedControlCount -NotePropertyValue @($copy.results).Count -Force
        $copy.scan | Add-Member -NotePropertyName baselineControlCount -NotePropertyValue (@($copy.results).Count + 5) -Force
        $copy.scan | Add-Member -NotePropertyName assessmentMode -NotePropertyValue Focused -Force
        $policy = [pscustomobject]@{
            schemaVersion = '1.0'; requireFullAssessment = $true; minimumEvidenceCoverage = 0; maximumErrors = 999
            maximumUnknown = 999; maximumExceptedCritical = 999; maximumExpiringExceptions = 999
            maximumFindings = [pscustomobject]@{ Critical = 999; High = 999; Medium = 999; Low = 999; Info = 999 }
        }
        $decision = $copy | Test-HardeningLensPolicy -Policy $policy
        $decision.passed | Should -BeFalse
        @($decision.checks | Where-Object Name -eq 'Assessment completeness')[0].Passed | Should -BeFalse
    }

    It 'permits a valid result under a permissive policy' {
        $copy = $script:Sample | ConvertTo-Json -Depth 60 | ConvertFrom-Json
        $copy.scan | Add-Member -NotePropertyName selectedControlCount -NotePropertyValue @($copy.results).Count -Force
        $copy.scan | Add-Member -NotePropertyName baselineControlCount -NotePropertyValue @($copy.results).Count -Force
        $copy.scan | Add-Member -NotePropertyName assessmentMode -NotePropertyValue Full -Force
        $policy = [pscustomobject]@{
            schemaVersion = '1.0'; requireFullAssessment = $true; minimumEvidenceCoverage = 0; maximumErrors = 999
            maximumUnknown = 999; maximumExceptedCritical = 999; maximumExpiringExceptions = 999
            maximumFindings = [pscustomobject]@{ Critical = 999; High = 999; Medium = 999; Low = 999; Info = 999 }
        }
        ($copy | Test-HardeningLensPolicy -Policy $policy).passed | Should -BeTrue
    }
}
''',
    )

    write(
        "tests/Unit/V11Probes.Tests.ps1",
        r'''BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path $script:RepositoryRoot 'src/HardeningLens/HardeningLens.psd1') -Force
}

Describe 'Hardening Lens 1.1 probes' {
    InModuleScope HardeningLens {
        BeforeAll {
            function script:Get-NetFirewallProfile { }
            function script:Get-MpPreference { }
        }

        It 'passes explicitly disabled legacy TLS' {
            Mock Get-HLRegistrySecurityValue {
                if ($Name -eq 'Enabled') { [pscustomobject]@{ Present = $true; Value = 0; Error = $null } }
                else { [pscustomobject]@{ Present = $true; Value = 1; Error = $null } }
            }
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ protocol = 'TLS 1.0'; side = 'Server'; expected = 'Disabled' } }
            (Invoke-HLTlsProtocolProbe -Control $control).Status | Should -Be 'Pass'
        }

        It 'returns Unknown for an implicit TLS default' {
            Mock Get-HLRegistrySecurityValue { [pscustomobject]@{ Present = $false; Value = $null; Error = $null } }
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ protocol = 'TLS 1.1'; side = 'Server'; expected = 'Disabled' } }
            (Invoke-HLTlsProtocolProbe -Control $control).Status | Should -Be 'Unknown'
        }

        It 'fails when NetBIOS is enabled' {
            Mock Get-CimInstance { [pscustomobject]@{ Description = 'Adapter'; SettingID = '1'; TcpipNetbiosOptions = 1 } }
            (Invoke-HLNetBiosProbe).Status | Should -Be 'Fail'
        }

        It 'warns when NetBIOS inherits DHCP state' {
            Mock Get-CimInstance { [pscustomobject]@{ Description = 'Adapter'; SettingID = '1'; TcpipNetbiosOptions = 0 } }
            (Invoke-HLNetBiosProbe).Status | Should -Be 'Warning'
        }

        It 'passes firewall logging on every profile' {
            Mock Get-Command { [pscustomobject]@{ Name = 'Get-NetFirewallProfile' } } -ParameterFilter { $Name -eq 'Get-NetFirewallProfile' }
            Mock Get-NetFirewallProfile {
                @('Domain', 'Private', 'Public') | ForEach-Object { [pscustomobject]@{ Name = $_; LogBlocked = $true; LogAllowed = $true; LogFileName = 'x'; LogMaxSizeKilobytes = 4096 } }
            }
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ property = 'LogBlocked' } }
            (Invoke-HLFirewallLoggingProbe -Control $control).Status | Should -Be 'Pass'
        }

        It 'detects AlwaysInstallElevated in machine policy' {
            Mock Get-HLRegistrySecurityValue {
                if ($Path -like 'HKLM:*') { [pscustomobject]@{ Path = $Path; Present = $true; Value = 1; Error = $null } }
                else { [pscustomobject]@{ Path = $Path; Present = $false; Value = $null; Error = $null } }
            }
            Mock Get-ChildItem { @() }
            (Invoke-HLAlwaysInstallElevatedProbe).Status | Should -Be 'Fail'
        }

        It 'passes HVCI when service id 2 is running' {
            Mock Get-CimInstance { [pscustomobject]@{ VirtualizationBasedSecurityStatus = 2; SecurityServicesConfigured = @(2); SecurityServicesRunning = @(2) } }
            (Invoke-HLHVCIProbe).Status | Should -Be 'Pass'
        }

        It 'fails unapproved Defender exclusions' {
            Mock Get-Command { [pscustomobject]@{ Name = 'Get-MpPreference' } } -ParameterFilter { $Name -eq 'Get-MpPreference' }
            Mock Get-MpPreference { [pscustomobject]@{ ExclusionPath = @('C:\Unsafe'); ExclusionProcess = @(); ExclusionExtension = @(); ExclusionIpAddress = @() } }
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ allowedPatterns = @() } }
            (Invoke-HLDefenderExclusionProbe -Control $control).Status | Should -Be 'Fail'
        }

        It 'passes approved Defender exclusions' {
            Mock Get-Command { [pscustomobject]@{ Name = 'Get-MpPreference' } } -ParameterFilter { $Name -eq 'Get-MpPreference' }
            Mock Get-MpPreference { [pscustomobject]@{ ExclusionPath = @('C:\Approved\Cache'); ExclusionProcess = @(); ExclusionExtension = @(); ExclusionIpAddress = @() } }
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ allowedPatterns = @('C:\Approved\*') } }
            (Invoke-HLDefenderExclusionProbe -Control $control).Status | Should -Be 'Pass'
        }

        It 'returns NotApplicable for a role-scoped service check' {
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ name = 'Spooler'; expected = 'Disabled'; onlyRole = 'DomainController' } }
            $context = [pscustomobject]@{ DetectedRole = 'MemberServer' }
            (Invoke-HLServiceStateProbe -Control $control -SystemContext $context).Status | Should -Be 'NotApplicable'
        }
    }
}
''',
    )


def clean_temporary_files() -> None:
    export = ROOT / ".github" / "workflows" / "repository-export.yml"
    if export.exists():
        export.unlink()
    payload = ROOT / ".v1.1-payload"
    if payload.exists():
        shutil.rmtree(payload)


def main() -> None:
    new_ids = add_controls()
    update_control_schema()
    update_baselines(new_ids)
    update_result_schema()
    update_manifest()
    patch_dispatcher()
    patch_invoke()
    patch_comparison()
    patch_exceptions()
    patch_report_export()
    patch_cli()
    replace_fleet_script()
    patch_validator()
    update_docs()
    write_workflows()
    write_release_metadata_script()
    write_tests()
    clean_temporary_files()
    print(f"Applied Hardening Lens {VERSION} with {len(new_ids)} new controls.")


if __name__ == "__main__":
    main()
