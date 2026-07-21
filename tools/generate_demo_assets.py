#!/usr/bin/env python3
"""Generate deterministic, synthetic demo results and rendered report assets."""

from __future__ import annotations

import base64
import csv
import hashlib
import html
import io
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "src" / "HardeningLens" / "Data" / "control-catalog.json"
BASELINE_PATH = ROOT / "src" / "HardeningLens" / "Data" / "Baselines" / "MemberServer.json"
MANIFEST_PATH = ROOT / "src" / "HardeningLens" / "HardeningLens.psd1"
EXCEPTION_PATH = ROOT / "examples" / "exceptions.json"
EXAMPLES = ROOT / "examples"
COLLECTED_AT = "2026-07-12T09:42:18.4210000Z"
REPORT_SCRIPT = "(function(){const search=document.getElementById('search'),status=document.getElementById('statusFilter'),severity=document.getElementById('severityFilter'),rows=[...document.querySelectorAll('#controlRows tr')],count=document.getElementById('visibleCount');function filter(){const q=search.value.trim().toLowerCase();let visible=0;rows.forEach(r=>{const ok=(!q||r.dataset.search.includes(q))&&(!status.value||r.dataset.status===status.value)&&(!severity.value||r.dataset.severity===severity.value);r.classList.toggle('hidden',!ok);if(ok)visible++;});count.textContent=visible+' of '+rows.length+' controls';}search.addEventListener('input',filter);status.addEventListener('change',filter);severity.addEventListener('change',filter);filter();})();"


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def module_version() -> str:
    match = re.search(r"ModuleVersion\s*=\s*'([^']+)'", MANIFEST_PATH.read_text(encoding="utf-8"))
    if not match:
        raise RuntimeError("Unable to parse ModuleVersion from HardeningLens.psd1")
    return match.group(1)


def content_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    output = json.loads(json.dumps(base))
    if "severity" in override:
        output["severity"] = override["severity"]
    output["parameters"] = {**output.get("parameters", {}), **override.get("parameters", {})}
    return output


def expected_value(control: dict[str, Any]) -> Any:
    parameters = control.get("parameters", {})
    if "expected" in parameters:
        return parameters["expected"]
    if "minimumSizeBytes" in parameters:
        return f"At least {parameters['minimumSizeBytes']} bytes"
    if "maximumAgeDays" in parameters:
        return f"<= {parameters['maximumAgeDays']} days"
    if "maximumDays" in parameters:
        return f"<= {parameters['maximumDays']} days"
    if "requiredFlags" in parameters:
        return " and ".join(parameters["requiredFlags"])
    if control["probe"] == "FirewallProfiles":
        return "Enabled with default inbound Block"
    if control["probe"] == "WindowsOptionalFeature":
        return "Disabled or absent"
    if control["probe"] == "CredentialGuard":
        return "Credential Guard running"
    if control["probe"] == "DeviceGuardService":
        return f"{parameters.get('serviceName')} running"
    if control["probe"] == "LapsBackup":
        return "Microsoft Entra ID or Active Directory"
    if control["probe"] == "LapsAdEncryption":
        return "Enabled"
    if control["probe"] == "PowerShellModuleLogging":
        return "Enabled with at least one module pattern"
    if control["probe"] == "BitLocker":
        return "Protection On and FullyEncrypted"
    if control["probe"] == "SecureBoot":
        return "Enabled"
    if control["probe"] == "AutoRun":
        return "NoDriveTypeAutoRun=255 and NoAutorun=1"
    if control["probe"] == "LocalGuestAccount":
        return "Disabled"
    if control["probe"] == "Service":
        return "Disabled and stopped"
    if control["probe"] == "WinRM":
        return parameters.get("expected", False)
    if control["probe"] == "AsrRules":
        return f"{len(parameters.get('requiredRules', []))} required rules in approved enforcement modes"
    return "Baseline-compliant effective state"


def evidence_for_pass(control: dict[str, Any], expected: Any) -> dict[str, Any]:
    parameters = control.get("parameters", {})
    probe = control["probe"]
    evidence: dict[str, Any] = {
        "Source": "Synthetic demo fixture",
        "Probe": probe,
        "Resolved": True,
    }
    if probe == "RegistryValue":
        evidence.update({"Path": parameters.get("path"), "Name": parameters.get("name"), "Value": expected})
    elif probe in {"DefenderStatus", "DefenderPreference"}:
        evidence.update({"Property": parameters.get("property"), "Value": expected})
    elif probe == "EventLog":
        evidence.update({"LogName": parameters.get("logName"), "MaximumSizeBytes": parameters.get("minimumSizeBytes"), "IsEnabled": True})
    elif probe == "AuditPolicy":
        evidence.update({"SubcategoryName": parameters.get("subcategoryName"), "SubcategoryGuid": parameters.get("subcategoryGuid"), "RequiredFlags": parameters.get("requiredFlags")})
    return evidence


def status_overrides() -> dict[str, dict[str, Any]]:
    return {
        "HL-UAC-003": {
            "status": "Fail", "actual": 0,
            "message": "The built-in Administrator account is not running in Admin Approval Mode.",
            "evidence": {"Path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "Name": "FilterAdministratorToken", "Value": 0, "Kind": "DWord"},
        },
        "HL-LAPS-003": {
            "status": "Fail", "actual": "Disabled",
            "message": "Windows LAPS is backed up to Active Directory, but password encryption is disabled.",
            "evidence": {"PolicySource": "GroupPolicy", "BackupDirectory": 2, "ADPasswordEncryptionEnabled": 0, "PasswordAgeDays": 30},
        },
        "HL-SMB-003": {
            "status": "Fail", "actual": False,
            "message": "The SMB server accepts sessions without requiring packet signing.",
            "evidence": {"Side": "Server", "Property": "RequireSecuritySignature", "Value": False},
        },
        "HL-SVC-001": {
            "status": "Fail", "actual": "Automatic, Running",
            "message": "Remote Registry is configured for automatic startup and is currently running.",
            "evidence": {"Name": "RemoteRegistry", "DisplayName": "Remote Registry", "StartMode": "Auto", "State": "Running"},
        },
        "HL-ASR-001": {
            "status": "Fail", "actual": "5 pass, 1 audit-only, 1 fail",
            "message": "One required ASR rule is disabled and another remains in Audit mode.",
            "evidence": [
                {"Id": "56a863a9-875e-4185-98a7-b882c64b5ce5", "Name": "Block abuse of exploited vulnerable signed drivers", "Action": 1, "ActionName": "Block", "Result": "Pass"},
                {"Id": "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Name": "Block credential stealing from LSASS", "Action": 1, "ActionName": "Block", "Result": "Pass"},
                {"Id": "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Name": "Block Office applications from creating child processes", "Action": 2, "ActionName": "Audit", "Result": "Warning"},
                {"Id": "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Name": "Block Office applications from injecting code into other processes", "Action": 0, "ActionName": "Disabled", "Result": "Fail"},
            ],
        },
        "HL-PSLOG-002": {
            "status": "Fail", "actual": "Disabled or not configured",
            "message": "PowerShell Module Logging is not enabled through machine policy.",
            "evidence": {"Enabled": None, "ModulePatterns": [], "PolicyPath": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"},
        },
        "HL-BIT-001": {
            "status": "Fail", "actual": "Off, FullyDecrypted",
            "message": "The operating system volume is not protected by BitLocker.",
            "evidence": {"MountPoint": "C:", "VolumeStatus": "FullyDecrypted", "ProtectionStatus": "Off", "EncryptionMethod": "None", "KeyProtectorTypes": []},
        },
        "HL-DEF-006": {
            "status": "Warning", "actual": 2,
            "message": "Potentially unwanted application protection is configured in Audit mode rather than Block mode.",
            "evidence": {"Property": "PUAProtection", "Value": 2, "Mode": "Audit"},
        },
        "HL-DEF-009": {
            "status": "Warning", "actual": 2,
            "message": "Defender network protection is configured in Audit mode rather than Block mode.",
            "evidence": {"Property": "EnableNetworkProtection", "Value": 2, "Mode": "Audit"},
        },
        "HL-PS-001": {
            "status": "Warning", "actual": "Disable pending",
            "message": "Windows PowerShell 2.0 is pending disablement and requires a restart.",
            "evidence": [
                {"FeatureName": "MicrosoftWindowsPowerShellV2Root", "Present": True, "State": "DisablePending", "Evaluated": True},
                {"FeatureName": "MicrosoftWindowsPowerShellV2", "Present": True, "State": "Disabled", "Evaluated": True},
            ],
        },
        "HL-RA-001": {
            "status": "Excepted", "originalStatus": "Fail", "actual": 1,
            "message": "Solicited Remote Assistance is enabled for the approved support workflow.",
            "evidence": {"Path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance", "Name": "fAllowToGetHelp", "Value": 1, "Kind": "DWord"},
            "exception": {
                "id": "EXC-DEMO-REMOTE-ASSISTANCE",
                "owner": "Workplace Engineering",
                "reason": "The approved support workflow requires solicited Remote Assistance on this managed server group.",
                "ticket": "SEC-1842",
                "expires": "2027-06-30",
                "approvedBy": "Security Engineering",
                "compensatingControls": ["Access is restricted to the support group.", "Session activity is logged and reviewed."],
            },
        },
        "HL-CRED-002": {
            "status": "Unknown", "actual": None,
            "message": "The Device Guard WMI provider did not return Credential Guard state.",
            "evidence": {"Namespace": r"root\Microsoft\Windows\DeviceGuard", "ProviderAvailable": False},
        },
        "HL-AUD-007": {
            "status": "Error", "actual": None,
            "message": "AuditQuerySystemPolicy returned access denied while reading Audit Policy Change.",
            "evidence": {"SubcategoryName": "Audit Policy Change", "SubcategoryGuid": "0cce922f-69ae-11d9-bed3-505054503030", "Win32Error": 5},
        },
    }


def score_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = ["Pass", "Fail", "Warning", "Excepted", "Unknown", "Error", "NotApplicable"]
    counts = Counter(item["status"] for item in results)
    weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Informational": 0}
    ranks = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    applicable = [item for item in results if item["status"] != "NotApplicable"]
    covered = [item for item in applicable if item["status"] not in {"Unknown", "Error"}]
    weighted_total = sum(weights[item["severity"]] for item in applicable)
    weighted_pass = sum(weights[item["severity"]] for item in applicable if item["status"] == "Pass")
    open_items = [item for item in results if item["status"] in {"Fail", "Warning", "Excepted", "Error"}]
    return {
        "Total": len(results),
        "Applicable": len(applicable),
        **{status: counts[status] for status in statuses},
        "HardeningScore": round(weighted_pass / weighted_total * 100, 1) if weighted_total else None,
        "EvidenceCoverage": round(len(covered) / len(applicable) * 100, 1) if applicable else None,
        "HighestOpenSeverity": max(open_items, key=lambda item: ranks[item["severity"]])["severity"] if open_items else "None",
        "ScoringModel": "Severity-weighted pass percentage. Exceptions, unknowns, warnings, and errors receive no pass credit; not-applicable and informational controls are excluded.",
    }


def create_result(
    scan_id: str,
    collected_at: str,
    overrides: dict[str, dict[str, Any]],
    collection_duration_ms: int,
) -> dict[str, Any]:
    catalog = load(CATALOG_PATH)
    baseline = load(BASELINE_PATH)
    release_version = module_version()
    catalog_by_id = {item["id"]: item for item in catalog["controls"]}
    controls = [merge(catalog_by_id[item["id"]], item) for item in baseline["controls"]]
    logical_baseline = {
        name: baseline[name]
        for name in (
            "schemaVersion", "name", "displayName", "version", "description",
            "sourceBasis", "supportedRoles", "notes",
        )
    }
    logical_baseline["controls"] = controls
    results: list[dict[str, Any]] = []
    for index, control in enumerate(controls):
        expected = expected_value(control)
        item: dict[str, Any] = {
            "controlId": control["id"],
            "title": control["title"],
            "category": control["category"],
            "severity": control["severity"],
            "status": "Pass",
            "originalStatus": None,
            "expected": expected,
            "actual": expected,
            "message": "The effective state matches the selected baseline.",
            "evidence": evidence_for_pass(control, expected),
            "rationale": control["rationale"],
            "remediation": control["remediation"],
            "references": control["references"],
            "tags": control["tags"],
            "probe": control["probe"],
            "exception": None,
            "collectedAt": collected_at,
            "probeDurationMs": (index % 7) + 1,
        }
        if control["id"] in overrides:
            item.update(overrides[control["id"]])
            item.setdefault("originalStatus", None)
            item.setdefault("exception", None)
        results.append(item)

    return {
        "$schema": f"https://raw.githubusercontent.com/xGreeny/hardening-lens/v{release_version}/src/HardeningLens/Schema/result.schema.json",
        "schemaVersion": "1.1",
        "scan": {
            "id": scan_id,
            "collectedAt": collected_at,
            "moduleVersion": release_version,
            "redacted": False,
            "readOnly": True,
            "elevated": True,
            "partialCollection": False,
            "exceptionRegisterUsed": True,
            "selectedControlCount": len(results),
            "collectionDurationMs": collection_duration_ms,
        },
        "system": {
            "ComputerName": "SRV-DEMO-01",
            "Domain": "LAB.EXAMPLE.INVALID",
            "DomainJoined": True,
            "DetectedRole": "MemberServer",
            "ProductType": 3,
            "OSCaption": "Microsoft Windows Server 2025 Standard",
            "OSVersion": "10.0.26100",
            "BuildNumber": "26100",
            "OSArchitecture": "64-bit",
            "Manufacturer": "Demo Hypervisor",
            "Model": "Generation 2 Virtual Machine",
            "PowerShellVersion": "7.6.3",
            "PowerShellEdition": "Core",
            "CurrentUser": r"LAB\audit.runner",
            "IsElevated": True,
        },
        "baseline": {
            "name": baseline["name"],
            "displayName": baseline["displayName"],
            "version": baseline["version"],
            "description": baseline["description"],
            "source": "BuiltIn",
            "sourceBasis": baseline["sourceBasis"],
            "supportedRoles": baseline["supportedRoles"],
            "controlCount": len(results),
            "notes": baseline["notes"],
        },
        "provenance": {
            "catalogVersion": catalog["catalogVersion"],
            "catalogDigest": content_digest(catalog),
            "baselineDigest": content_digest(logical_baseline),
            "capabilities": [
                {"name": name, "available": True, "detail": "Synthetic demo fixture"}
                for name in sorted({control["probe"] for control in controls}, key=str.casefold)
            ],
            "exceptionDigest": content_digest(load(EXCEPTION_PATH)),
        },
        "summary": score_summary(results),
        "results": results,
    }


def display(value: Any) -> str:
    if value is None:
        return "<not set>"
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def render_html(result: dict[str, Any]) -> str:
    summary = result["summary"]
    score = "n/a" if summary["HardeningScore"] is None else f"{summary['HardeningScore']:.1f}%"
    coverage = "n/a" if summary["EvidenceCoverage"] is None else f"{summary['EvidenceCoverage']:.1f}%"
    status_class = {"Pass":"pass","Fail":"fail","Warning":"warning","Excepted":"excepted","Unknown":"unknown","Error":"error","NotApplicable":"na"}
    ranks = {"Critical":4,"High":3,"Medium":2,"Low":1,"Informational":0}
    findings = sorted((item for item in result["results"] if item["status"] in {"Fail","Warning","Error","Excepted"}), key=lambda item: (-ranks[item["severity"]], item["controlId"]))
    e = lambda value: html.escape(str(value), quote=True)

    metrics = [
        ("Hardening score", score, "score"), ("Evidence coverage", coverage, ""),
        ("Pass", summary["Pass"], "pass"), ("Fail", summary["Fail"], "fail"),
        ("Warning", summary["Warning"], "warning"), ("Excepted", summary["Excepted"], "excepted"),
        ("Unknown", summary["Unknown"], "unknown"), ("Error", summary["Error"], "error"),
    ]
    cards = "".join(f'<div class="card metric"><div class="value {cls}">{e(value)}</div><div class="label">{e(label)}</div></div>' for label,value,cls in metrics)
    meta = [
        ("Collected", "2026-07-12 09:42:18 UTC"),
        ("Operating system", f"{result['system']['OSCaption']} ({result['system']['BuildNumber']})"),
        ("Detected role", result["system"]["DetectedRole"]),
        ("Baseline", f"{result['baseline']['name']} {result['baseline']['version']}"),
        ("Module / catalog", f"{result['scan']['moduleVersion']} / {result['provenance']['catalogVersion']}"),
        ("Result schema", result["schemaVersion"]),
        ("Scan ID", result["scan"]["id"]),
        ("Redacted", result["scan"]["redacted"]),
    ]
    meta_html = "".join(f'<div class="card"><div class="small">{e(k)}</div><div class="mono">{e(v)}</div></div>' for k,v in meta)
    exception_digest = result["provenance"].get("exceptionDigest", "not used")
    capability_text = "; ".join(
        f"{item['name']}: available"
        if item["available"]
        else f"{item['name']}: unavailable ({item['detail']})"
        for item in result["provenance"]["capabilities"]
    )
    provenance_items = [
        ("Catalog digest", result["provenance"]["catalogDigest"]),
        ("Effective baseline digest", result["provenance"]["baselineDigest"]),
        ("Exception register digest", exception_digest),
        ("Collection duration", f"{result['scan']['collectionDurationMs']} ms"),
        ("Probe capabilities", capability_text),
    ]
    provenance_html = "".join(
        f"<div>{e(label)}</div><div class=\"mono\">{e(value)}</div>"
        for label, value in provenance_items
    )
    findings_html = []
    for finding in findings:
        allowed_references = [url for url in finding["references"] if url.startswith("https://learn.microsoft.com/")]
        refs = " | ".join(f'<a href="{e(url)}" target="_blank" rel="noopener noreferrer">Microsoft guidance</a>' for url in allowed_references)
        exception = ""
        if finding["exception"]:
            exc = finding["exception"]
            exception = f'<div>Exception</div><div><span class="mono">{e(exc["id"])}</span> | owner {e(exc["owner"])} | expires {e(exc["expires"])}<br>{e(exc["reason"])}</div>'
        evidence = e(json.dumps(finding["evidence"], indent=2))
        cls = status_class[finding["status"]]
        sev = finding["severity"].lower()
        findings_html.append(f'''<article class="finding {cls}"><div class="finding-head"><div><h3><span class="mono">{e(finding['controlId'])}</span> - {e(finding['title'])}</h3><div class="small">{e(finding['category'])}</div></div><div><span class="badge {cls}">{e(finding['status'])}</span> <span class="severity sev-{sev}">{e(finding['severity'])}</span></div></div>
<p>{e(finding['message'])}</p><div class="kv"><div>Expected</div><div class="mono">{e(display(finding['expected']))}</div><div>Actual</div><div class="mono">{e(display(finding['actual']))}</div><div>Why it matters</div><div>{e(finding['rationale'])}</div><div>Remediation</div><div>{e(finding['remediation'])}</div>{exception}</div><p class="small">References: {refs}</p><details><summary>Evidence</summary><pre>{evidence}</pre></details></article>''')

    rows = []
    for item in result["results"]:
        search = f"{item['controlId']} {item['title']} {item['category']} {item['status']} {item['severity']}".lower()
        cls = status_class[item["status"]]
        rows.append(f'<tr data-status="{e(item["status"])}" data-severity="{e(item["severity"])}" data-search="{e(search)}"><td><strong class="mono">{e(item["controlId"])}</strong><br>{e(item["title"])}</td><td><span class="badge {cls}">{e(item["status"])}</span></td><td class="severity sev-{e(item["severity"].lower())}">{e(item["severity"])}</td><td>{e(item["category"])}</td><td class="mono">{e(display(item["expected"]))}</td><td class="mono">{e(display(item["actual"]))}</td><td>{e(item["message"])}</td></tr>')

    script_hash = base64.b64encode(hashlib.sha256(REPORT_SCRIPT.encode("utf-8")).digest()).decode("ascii")
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'; img-src data:; base-uri 'none'; form-action 'none'">
<title>Hardening Lens Report</title>
<style>
:root{{--bg:#07110d;--panel:#0c1b14;--line:#244434;--text:#e7f3ec;--muted:#9eb7aa;--accent:#55e69d;--pass:#3ed598;--fail:#ff6b6b;--warn:#ffc857;--except:#b892ff;--unknown:#7ea7c9;--error:#ff8f5a;--na:#798b82}}*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 80% -10%,#123c28 0,transparent 32%),var(--bg);color:var(--text);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}a{{color:var(--accent)}}code,pre,.mono{{font-family:"Cascadia Code","SFMono-Regular",Consolas,monospace}}.wrap{{max-width:1500px;margin:0 auto;padding:32px}}.hero{{border:1px solid var(--line);background:linear-gradient(135deg,rgba(85,230,157,.09),rgba(12,27,20,.96));border-radius:18px;padding:28px;box-shadow:0 24px 80px rgba(0,0,0,.3)}}.eyebrow{{color:var(--accent);letter-spacing:.16em;text-transform:uppercase;font:700 12px/1.4 monospace}}.hero h1{{font-size:clamp(30px,5vw,52px);margin:7px 0 8px}}.subtitle{{color:var(--muted);margin:0}}.meta-grid,.metric-grid{{display:grid;gap:14px}}.meta-grid{{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin-top:22px}}.metric-grid{{grid-template-columns:repeat(auto-fit,minmax(135px,1fr));margin:22px 0}}.card{{border:1px solid var(--line);background:var(--panel);border-radius:14px;padding:16px}}.metric .value{{font:800 27px/1.1 monospace}}.metric .label{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin-top:6px}}.score{{color:var(--accent)}}.section{{margin-top:28px}}.section h2{{font-size:22px;margin:0 0 12px}}.toolbar{{display:flex;gap:10px;flex-wrap:wrap;padding:14px;border:1px solid var(--line);background:var(--panel);border-radius:14px;margin-bottom:12px}}.toolbar input,.toolbar select{{background:#07110d;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 11px;min-width:180px}}.table-wrap{{overflow:auto;border:1px solid var(--line);border-radius:14px;background:var(--panel)}}table{{width:100%;border-collapse:collapse;min-width:980px}}th,td{{padding:12px 13px;text-align:left;vertical-align:top;border-bottom:1px solid rgba(36,68,52,.72)}}th{{position:sticky;top:0;background:#0e2017;color:#bcd1c5;font-size:12px;text-transform:uppercase;letter-spacing:.06em;z-index:1}}tr:hover td{{background:rgba(85,230,157,.03)}}.badge{{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:2px 8px;font:700 11px/1.5 monospace;text-transform:uppercase}}.badge.pass{{color:var(--pass)}}.badge.fail{{color:var(--fail)}}.badge.warning{{color:var(--warn)}}.badge.excepted{{color:var(--except)}}.badge.unknown{{color:var(--unknown)}}.badge.error{{color:var(--error)}}.badge.na{{color:var(--na)}}.severity{{font-weight:700}}.sev-critical{{color:#ff5b77}}.sev-high{{color:#ff8f5a}}.sev-medium{{color:#ffc857}}.sev-low{{color:#8cb9dc}}.finding{{border:1px solid var(--line);border-left-width:5px;background:var(--panel);border-radius:12px;padding:16px;margin:10px 0}}.finding.fail{{border-left-color:var(--fail)}}.finding.warning{{border-left-color:var(--warn)}}.finding.error{{border-left-color:var(--error)}}.finding.excepted{{border-left-color:var(--except)}}.finding-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}}.finding h3{{margin:0 0 5px;font-size:17px}}.small{{font-size:12px;color:var(--muted)}}details{{margin-top:10px}}summary{{cursor:pointer;color:var(--accent)}}pre{{white-space:pre-wrap;word-break:break-word;background:#06100b;border:1px solid var(--line);border-radius:9px;padding:12px;color:#cce1d5;max-height:430px;overflow:auto}}.kv{{display:grid;grid-template-columns:minmax(150px,220px) 1fr;gap:7px 15px}}.kv div:nth-child(odd){{color:var(--muted)}}.method{{color:var(--muted)}}.hidden{{display:none!important}}.footer{{color:var(--muted);text-align:center;margin:28px 0 8px;font-size:12px}}@media(max-width:700px){{.wrap{{padding:16px}}.hero{{padding:20px}}.kv{{grid-template-columns:1fr}}.finding-head{{display:block}}}}@media print{{body{{background:#fff;color:#111}}.wrap{{max-width:none;padding:0}}.hero,.card,.toolbar,.table-wrap,.finding{{background:#fff;border-color:#bbb;box-shadow:none}}.toolbar{{display:none}}a{{color:#111}}.small,.method,.subtitle,.metric .label{{color:#444}}th{{position:static;background:#eee;color:#111}}pre{{background:#f5f5f5;color:#111;border-color:#ccc}}.badge{{border-color:#555;color:#111!important}}}}
</style></head><body><main class="wrap"><section class="hero"><div class="eyebrow">xGreeny / Windows Security Engineering</div><h1>Hardening Lens</h1><p class="subtitle">Read-only posture assessment for <strong>{e(result['system']['ComputerName'])}</strong> against <strong>{e(result['baseline']['displayName'])}</strong>.</p><div class="meta-grid">{meta_html}</div></section><section class="metric-grid">{cards}</section><section class="section"><h2>Prioritized findings</h2>{''.join(findings_html)}</section><section class="section"><h2>All controls</h2><div class="toolbar"><input id="search" type="search" placeholder="Search control, title, category..." aria-label="Search"><select id="statusFilter"><option value="">All statuses</option><option>Pass</option><option>Fail</option><option>Warning</option><option>Excepted</option><option>Unknown</option><option>Error</option><option>NotApplicable</option></select><select id="severityFilter"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option></select><span id="visibleCount" class="small"></span></div><div class="table-wrap"><table><thead><tr><th>Control</th><th>Status</th><th>Severity</th><th>Category</th><th>Expected</th><th>Actual</th><th>Message</th></tr></thead><tbody id="controlRows">{''.join(rows)}</tbody></table></div></section><section class="section card"><h2>Assessment provenance</h2><div class="kv">{provenance_html}</div></section><section class="section card"><h2>Assessment model</h2><p class="method">{e(summary['ScoringModel'])}</p><p class="method">Hardening Lens is a read-only technical posture assessment. It does not change the device, prove policy intent, replace risk assessment, or certify compliance with Microsoft, CIS, NIST, or another framework. Validate findings against application requirements and change-control procedures before remediation.</p></section><div class="footer mono">hardening-lens / xGreeny | report schema 1.1</div><script>{REPORT_SCRIPT}</script></main></body></html>\n'''


def flatten_csv(result: dict[str, Any]) -> str:
    output = io.StringIO(newline="")
    fields = ["ControlId","Title","Category","Severity","Status","OriginalStatus","Expected","Actual","Message","ExceptionId","ExceptionOwner","ExceptionExpiry","Remediation","References"]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for item in result["results"]:
        exc = item["exception"] or {}
        row = {
            "ControlId": item["controlId"], "Title": item["title"], "Category": item["category"], "Severity": item["severity"], "Status": item["status"],
            "OriginalStatus": item["originalStatus"] or "", "Expected": display(item["expected"]), "Actual": display(item["actual"]), "Message": item["message"],
            "ExceptionId": exc.get("id", ""), "ExceptionOwner": exc.get("owner", ""), "ExceptionExpiry": exc.get("expires", ""),
            "Remediation": item["remediation"], "References": "; ".join(item["references"]),
        }
        writer.writerow({key: ("'" + str(value) if str(value).startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else value) for key, value in row.items()})
    return output.getvalue()


def result_state_fingerprint(item: dict[str, Any]) -> str:
    """Return the effective assessment state used for drift classification."""
    state = {
        "Status": item.get("status"),
        "Severity": item.get("severity"),
        "Expected": item.get("expected"),
        "Actual": item.get("actual"),
        "Evidence": item.get("evidence"),
        "Exception": item.get("exception"),
    }
    return json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)


def state_snapshot(item: dict[str, Any] | None) -> dict[str, Any] | None:
    if item is None:
        return None
    return {
        "Status": item["status"],
        "Severity": item["severity"],
        "Expected": item["expected"],
        "Actual": item["actual"],
        "Evidence": item["evidence"],
        "Exception": item["exception"],
    }


def create_comparison(reference: dict[str, Any], difference: dict[str, Any]) -> dict[str, Any]:
    before = {item["controlId"]: item for item in reference["results"]}
    after = {item["controlId"]: item for item in difference["results"]}
    changes = []
    open_statuses = {"Fail","Warning","Excepted","Error"}
    for control_id in sorted(set(before) | set(after)):
        left, right = before.get(control_id), after.get(control_id)
        left_state = state_snapshot(left)
        right_state = state_snapshot(right)
        if left is None:
            changed_fields = ["Presence"]
            change = "AddedControl"
        elif right is None:
            changed_fields = ["Presence"]
            change = "RemovedControl"
        else:
            changed_fields = [
                field
                for field in ("Status", "Severity", "Expected", "Actual", "Evidence", "Exception")
                if json.dumps(left_state[field], sort_keys=True, separators=(",", ":"), default=str)
                != json.dumps(right_state[field], sort_keys=True, separators=(",", ":"), default=str)
            ]
            left_open, right_open = left["status"] in open_statuses, right["status"] in open_statuses
            if not left_open and right_open: change = "NewFinding"
            elif left_open and not right_open: change = "Resolved"
            elif changed_fields: change = "Changed"
            else: change = "Unchanged"
        source = right or left
        changes.append({
            "ControlId": control_id, "Title": source["title"], "Severity": source["severity"], "Category": source["category"], "ChangeType": change,
            "ChangedFields": changed_fields, "Before": left_state, "After": right_state,
            "BeforeStatus": left["status"] if left else None, "AfterStatus": right["status"] if right else None,
            "BeforeActual": left["actual"] if left else None, "AfterActual": right["actual"] if right else None,
        })
    counts = Counter(item["ChangeType"] for item in changes)
    ref_score, diff_score = reference["summary"]["HardeningScore"], difference["summary"]["HardeningScore"]
    ref_coverage = reference["summary"]["EvidenceCoverage"]
    diff_coverage = difference["summary"]["EvidenceCoverage"]
    ref_provenance = reference["provenance"]
    diff_provenance = difference["provenance"]
    reference_baseline = {
        "Name": reference["baseline"]["name"],
        "Version": reference["baseline"]["version"],
        "Digest": ref_provenance["baselineDigest"],
    }
    difference_baseline = {
        "Name": difference["baseline"]["name"],
        "Version": difference["baseline"]["version"],
        "Digest": diff_provenance["baselineDigest"],
    }
    reference_catalog = {
        "Version": ref_provenance["catalogVersion"],
        "Digest": ref_provenance["catalogDigest"],
    }
    difference_catalog = {
        "Version": diff_provenance["catalogVersion"],
        "Digest": diff_provenance["catalogDigest"],
    }
    return {
        "$schema":f"https://raw.githubusercontent.com/xGreeny/hardening-lens/v{difference['scan']['moduleVersion']}/src/HardeningLens/Schema/comparison.schema.json",
        "schemaVersion":"1.1", "comparedAt":"2026-07-12T10:06:04.0000000Z", "computerName":difference["system"]["ComputerName"], "baseline":difference["baseline"]["name"],
        "baselineContext": {
            "Reference": reference_baseline,
            "Difference": difference_baseline,
            "Changed": reference_baseline != difference_baseline,
        },
        "catalogContext": {
            "Reference": reference_catalog,
            "Difference": difference_catalog,
            "Changed": reference_catalog != difference_catalog,
        },
        "referenceScan":{
            "Id":reference["scan"]["id"],"CollectedAt":reference["scan"]["collectedAt"],
            "ResultSchemaVersion": reference["schemaVersion"], "ModuleVersion": reference["scan"]["moduleVersion"],
            "Score":ref_score, "EvidenceCoverage":ref_coverage,
            "CollectionDurationMs": reference["scan"]["collectionDurationMs"],
            "ExceptionDigest": ref_provenance.get("exceptionDigest"),
            "Capabilities": ref_provenance["capabilities"],
        },
        "differenceScan":{
            "Id":difference["scan"]["id"],"CollectedAt":difference["scan"]["collectedAt"],
            "ResultSchemaVersion": difference["schemaVersion"], "ModuleVersion": difference["scan"]["moduleVersion"],
            "Score":diff_score, "EvidenceCoverage":diff_coverage,
            "CollectionDurationMs": difference["scan"]["collectionDurationMs"],
            "ExceptionDigest": diff_provenance.get("exceptionDigest"),
            "Capabilities": diff_provenance["capabilities"],
        },
        "summary":{"ScoreDelta":round(diff_score-ref_score,1),"CoverageDelta":round(diff_coverage-ref_coverage,1),"NewFindings":counts["NewFinding"],"Resolved":counts["Resolved"],"Changed":counts["Changed"],"AddedControls":counts["AddedControl"],"RemovedControls":counts["RemovedControl"],"Unchanged":counts["Unchanged"]},
        "changes":changes,
    }


def drift_markdown(comparison: dict[str, Any]) -> str:
    s=comparison["summary"]
    baseline_context=comparison["baselineContext"]
    catalog_context=comparison["catalogContext"]
    lines=["# Hardening Lens drift report","",f"* **Host:** `{comparison['computerName']}`",f"* **Baseline:** `{comparison['baseline']}`",f"* **Reference:** `{comparison['referenceScan']['Id']}` ({comparison['referenceScan']['CollectedAt']})",f"* **Current:** `{comparison['differenceScan']['Id']}` ({comparison['differenceScan']['CollectedAt']})",f"* **Baseline provenance:** `{baseline_context['Reference']['Name']}` `{baseline_context['Reference']['Version']}` (`{baseline_context['Reference']['Digest']}`) -> `{baseline_context['Difference']['Name']}` `{baseline_context['Difference']['Version']}` (`{baseline_context['Difference']['Digest']}`)",f"* **Catalog provenance:** `{catalog_context['Reference']['Version']}` (`{catalog_context['Reference']['Digest']}`) -> `{catalog_context['Difference']['Version']}` (`{catalog_context['Difference']['Digest']}`)",f"* **Score delta:** {s['ScoreDelta']:+.1f} points",f"* **Evidence coverage delta:** {s['CoverageDelta']:+.1f} points","","| New findings | Resolved | Changed | Added controls | Removed controls |","|---:|---:|---:|---:|---:|",f"| {s['NewFindings']} | {s['Resolved']} | {s['Changed']} | {s['AddedControls']} | {s['RemovedControls']} |","","## Changes","","| Type | Control | Severity | Changed fields | Before | After |","|---|---|---|---|---|---|"]
    rank={"Critical":4,"High":3,"Medium":2,"Low":1,"Informational":0}
    relevant=sorted((x for x in comparison["changes"] if x["ChangeType"]!="Unchanged"),key=lambda x:(-rank[x["Severity"]],x["ControlId"]))
    for item in relevant:
        title=item["Title"].replace("|",r"\|")
        lines.append(f"| {item['ChangeType']} | `{item['ControlId']}` - {title} | {item['Severity']} | {', '.join(item['ChangedFields'])} | {item['BeforeStatus'] or ''} | {item['AfterStatus'] or ''} |")
    lines.extend(["","Generated by Hardening Lens. Review operational context before treating drift as a security incident or approved change.",""])
    return "\n".join(lines)


def build_outputs() -> dict[Path, str]:
    current_overrides=status_overrides()
    current=create_result("8fc7045c-a95e-4f23-bdb7-2bb858322c52",COLLECTED_AT,current_overrides,1432)
    reference_overrides=json.loads(json.dumps(current_overrides))
    reference_overrides["HL-SMB-003"]={"status":"Pass","actual":True,"message":"SMB server signing is required.","evidence":{"Side":"Server","Property":"RequireSecuritySignature","Value":True}}
    reference_overrides["HL-DEF-006"]={"status":"Pass","actual":1,"message":"Potentially unwanted application protection is enabled in Block mode.","evidence":{"Property":"PUAProtection","Value":1,"Mode":"Block"}}
    reference_overrides["HL-ASR-001"]={"status":"Warning","actual":"6 pass, 1 audit-only, 0 fail","message":"One required ASR rule remains in Audit mode.","evidence":[{"Name":"Block Office applications from creating child processes","Action":2,"ActionName":"Audit","Result":"Warning"}]}
    reference_overrides["HL-RDP-001"]={"status":"Fail","actual":0,"message":"Remote Desktop does not require Network Level Authentication.","evidence":{"Path":r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp","Name":"UserAuthentication","Value":0}}
    reference=create_result("e747bf2b-e9de-4e5a-bffe-514e51b86fe8","2026-06-12T09:38:02.1200000Z",reference_overrides,1298)
    comparison=create_comparison(reference,current)

    return {
        EXAMPLES/"sample-result.json": json.dumps(current,indent=2)+"\n",
        EXAMPLES/"sample-reference-result.json": json.dumps(reference,indent=2)+"\n",
        EXAMPLES/"sample-report.html": render_html(current),
        EXAMPLES/"sample-report.csv": flatten_csv(current),
        EXAMPLES/"sample-drift.json": json.dumps(comparison,indent=2)+"\n",
        EXAMPLES/"sample-drift.md": drift_markdown(comparison),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Generate deterministic synthetic demo assets.")
    parser.add_argument("--check", action="store_true", help="Verify that committed demo assets match the generator output.")
    args = parser.parse_args()

    outputs = build_outputs()
    if args.check:
        stale = []
        for path, content in outputs.items():
            committed = path.read_text(encoding="utf-8") if path.exists() else None
            if committed is None or committed.replace("\r\n", "\n") != content.replace("\r\n", "\n"):
                stale.append(str(path.relative_to(ROOT)))
        if stale:
            raise SystemExit("Demo assets are stale: " + ", ".join(sorted(stale)) + ". Run tools/generate_demo_assets.py.")
        print("Demo assets are current.")
        return

    EXAMPLES.mkdir(parents=True, exist_ok=True)
    for path, content in outputs.items():
        path.write_text(content, encoding="utf-8")
    print("Generated synthetic demo results, report, CSV, and drift artifacts.")


if __name__ == "__main__":
    main()
