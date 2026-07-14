#!/usr/bin/env python3
"""Run every 1.1 migration step independently and repair common repository-layout variants."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "HardeningLens"

spec = importlib.util.spec_from_file_location("hardening_lens_v11_apply", ROOT / "tools" / "apply_v1_1.py")
if spec is None or spec.loader is None:
    raise RuntimeError("Could not load release generator")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def robust_baselines(new_ids: list[str]) -> None:
    common = [
        "HL-TLS-001", "HL-TLS-002", "HL-TLS-003", "HL-NETBIOS-001", "HL-FW-003", "HL-FW-004",
        "HL-UAC-003", "HL-CREDSSP-001", "HL-MSI-001", "HL-HVCI-001", "HL-DEF-006", "HL-AUD-007", "HL-AUD-008",
    ]
    candidates = []
    for path in MODULE.rglob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            continue
        if isinstance(value, dict) and isinstance(value.get("controls"), list) and value.get("name") and value.get("version"):
            if "baseline" in path.as_posix().casefold() or value.get("supportedRoles"):
                candidates.append((path, value))
    if len(candidates) < 4:
        raise RuntimeError(f"Expected at least four baseline documents, found {len(candidates)}")

    for path, baseline in candidates:
        baseline["version"] = release.VERSION
        name = str(baseline.get("name", path.stem))
        roles = [str(item) for item in baseline.get("supportedRoles", [])]
        ids = list(common)
        if "domaincontroller" in re.sub(r"[^a-z]", "", name.casefold()) or "DomainController" in roles:
            ids.append("HL-DC-003")
        if "avdsessionhost" in re.sub(r"[^a-z]", "", name.casefold()) or "AVDSessionHost" in roles:
            ids.extend(["HL-RDS-001", "HL-RDS-002", "HL-RDS-003"])
        existing = {str(item.get("id") if isinstance(item, dict) else item) for item in baseline["controls"]}
        object_entries = not baseline["controls"] or isinstance(baseline["controls"][0], dict)
        for control_id in ids:
            if control_id not in existing:
                baseline["controls"].append({"id": control_id} if object_entries else control_id)
        path.write_text(json.dumps(baseline, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def robust_manifest() -> None:
    path = MODULE / "HardeningLens.psd1"
    text = path.read_text(encoding="utf-8-sig")
    text = re.sub(r"(?m)^(\s*ModuleVersion\s*=\s*)['\"][^'\"]+['\"]", rf"\g<1>'{release.VERSION}'", text, count=1)
    key = text.find("FunctionsToExport")
    if key < 0:
        raise RuntimeError("FunctionsToExport is missing")
    start = text.find("@(", key)
    if start < 0:
        raise RuntimeError("FunctionsToExport array is missing")
    depth = 0
    end = None
    for index in range(start + 1, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end is None:
        raise RuntimeError("FunctionsToExport array is unterminated")
    names = re.findall(r"['\"]([^'\"]+)['\"]", text[start + 2 : end])
    for name in ["Test-HardeningLensResult", "Test-HardeningLensPolicy", "Invoke-HardeningLensFleet"]:
        if name not in names:
            names.append(name)
    replacement = "@(\n" + "".join(f"        '{name}',\n" for name in names).rstrip(",\n") + "\n    )"
    text = text[:start] + replacement + text[end + 1 :]
    path.write_text(text, encoding="utf-8", newline="\n")


def robust_result_schema() -> None:
    path = MODULE / "Schema" / "result.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8-sig"))

    def locate_scan(node):
        if isinstance(node, dict):
            properties = node.get("properties")
            if isinstance(properties, dict) and "selectedControlCount" in properties:
                return properties
            for value in node.values():
                found = locate_scan(value)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = locate_scan(value)
                if found is not None:
                    return found
        return None

    scan = locate_scan(schema)
    if scan is None:
        raise RuntimeError("Could not locate scan schema")
    scan.setdefault("assessmentMode", {"type": "string", "enum": ["Full", "Focused"]})
    scan.setdefault("baselineControlCount", {"type": "integer", "minimum": 0})
    path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8", newline="\n")


def run_step(name, function, errors):
    try:
        function()
        print(f"ok: {name}")
    except Exception as exc:
        errors.append(f"{name}: {exc}")
        print(f"error: {name}: {exc}")


def main() -> None:
    errors: list[str] = []
    new_ids = release.add_controls()
    run_step("control schema", release.update_control_schema, errors)
    run_step("baselines", lambda: robust_baselines(new_ids), errors)
    run_step("result schema", robust_result_schema, errors)
    run_step("manifest", robust_manifest, errors)
    for name, function in [
        ("dispatcher", release.patch_dispatcher),
        ("assessment scope", release.patch_invoke),
        ("comparison", release.patch_comparison),
        ("exceptions", release.patch_exceptions),
        ("report", release.patch_report_export),
        ("cli", release.patch_cli),
        ("fleet wrapper", release.replace_fleet_script),
        ("validator", release.patch_validator),
        ("documentation", release.update_docs),
        ("workflows", release.write_workflows),
        ("release metadata", release.write_release_metadata_script),
        ("tests", release.write_tests),
    ]:
        run_step(name, function, errors)

    # The catalog, module manifest, dispatcher, result schema, and built-in baselines are release-critical.
    critical = [item for item in errors if item.split(":", 1)[0] in {"control schema", "baselines", "result schema", "manifest", "dispatcher", "assessment scope"}]
    if critical:
        raise RuntimeError("Critical release steps failed: " + " | ".join(critical))
    if errors:
        print("Non-critical migration warnings: " + " | ".join(errors))


if __name__ == "__main__":
    main()
