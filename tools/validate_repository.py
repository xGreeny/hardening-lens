#!/usr/bin/env python3
"""Validate schemas, cross-file contracts, examples, and repository hygiene."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import sys
import urllib.parse
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from generate_demo_assets import create_comparison

ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "src" / "HardeningLens"
SCHEMA_ROOT = MODULE_ROOT / "Schema"
DATA_ROOT = MODULE_ROOT / "Data"
BASELINE_ROOT = DATA_ROOT / "Baselines"

ERRORS: list[str] = []


def fail(message: str) -> None:
    ERRORS.append(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # validation utility should aggregate errors
        fail(f"{path.relative_to(ROOT)}: invalid JSON: {exc}")
        return None


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_schema(instance_path: Path, schema_path: Path) -> Any:
    instance = load_json(instance_path)
    schema = load_json(schema_path)
    if instance is None or schema is None:
        return instance
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path)):
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        fail(f"{instance_path.relative_to(ROOT)} [{location}]: {error.message}")
    return instance


def severity_weight(severity: str) -> int:
    return {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Informational": 0}[severity]


def expected_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = ["Pass", "Fail", "Warning", "Excepted", "Unknown", "Error", "NotApplicable"]
    counts = Counter(item["status"] for item in results)
    applicable = [item for item in results if item["status"] != "NotApplicable"]
    covered = [item for item in applicable if item["status"] not in {"Unknown", "Error"}]
    weighted_total = sum(severity_weight(item["severity"]) for item in applicable)
    weighted_pass = sum(severity_weight(item["severity"]) for item in applicable if item["status"] == "Pass")
    score = round(weighted_pass / weighted_total * 100, 1) if weighted_total else None
    coverage = round(len(covered) / len(applicable) * 100, 1) if applicable else None
    open_items = [item for item in results if item["status"] in {"Fail", "Warning", "Excepted", "Error"}]
    ranking = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    highest = max(open_items, key=lambda item: ranking[item["severity"]])["severity"] if open_items else "None"
    return {
        "Total": len(results),
        "Applicable": len(applicable),
        **{status: counts[status] for status in statuses},
        "HardeningScore": score,
        "EvidenceCoverage": coverage,
        "HighestOpenSeverity": highest,
    }


def resolve_effective_baseline(
    baseline_document: dict[str, Any],
    controls: list[dict[str, Any]],
) -> dict[str, Any]:
    catalog_by_id = {item["id"]: item for item in controls}
    effective_controls = []
    for baseline_control in baseline_document["controls"]:
        resolved = json.loads(json.dumps(catalog_by_id[baseline_control["id"]]))
        if "severity" in baseline_control:
            resolved["severity"] = baseline_control["severity"]
        resolved["parameters"] = {
            **resolved.get("parameters", {}),
            **baseline_control.get("parameters", {}),
        }
        effective_controls.append(resolved)

    logical_baseline = {
        name: baseline_document[name]
        for name in (
            "schemaVersion", "name", "displayName", "version", "description",
            "sourceBasis", "supportedRoles", "notes",
        )
    }
    logical_baseline["controls"] = effective_controls
    return logical_baseline


def validate_demo_scan(
    path: Path,
    module_version: str | None,
    catalog: dict[str, Any],
    controls: list[dict[str, Any]],
    catalog_ids: set[str],
    baseline_documents: dict[str, dict[str, Any]],
    exceptions: dict[str, Any] | None,
) -> dict[str, Any] | None:
    sample = validate_schema(path, SCHEMA_ROOT / "result.schema.json")
    if not sample:
        return sample

    label = path.relative_to(ROOT)
    scan = sample.get("scan", {})
    provenance = sample.get("provenance", {})
    if module_version and scan.get("moduleVersion") != module_version:
        fail(f"{label}: scan.moduleVersion does not match module version {module_version}.")

    expected_schema_uri = (
        f"https://raw.githubusercontent.com/xGreeny/hardening-lens/v{module_version}/"
        "src/HardeningLens/Schema/result.schema.json"
    )
    if module_version and sample.get("$schema") != expected_schema_uri:
        fail(f"{label}: $schema is not pinned to the module release.")

    if provenance.get("catalogVersion") != catalog.get("catalogVersion"):
        fail(f"{label}: provenance.catalogVersion does not match the catalog.")
    if provenance.get("catalogDigest") != canonical_digest(catalog):
        fail(f"{label}: provenance.catalogDigest does not match canonical catalog content.")

    sample_baseline_name = sample.get("baseline", {}).get("name")
    baseline_document = baseline_documents.get(sample_baseline_name)
    if baseline_document is None:
        fail(f"{label}: baseline {sample_baseline_name!r} is not a built-in baseline.")
    else:
        logical_baseline = resolve_effective_baseline(baseline_document, controls)
        if provenance.get("baselineDigest") != canonical_digest(logical_baseline):
            fail(f"{label}: provenance.baselineDigest does not match the effective baseline.")

    exception_register_used = bool(scan.get("exceptionRegisterUsed"))
    if exception_register_used and exceptions is not None:
        if provenance.get("exceptionDigest") != canonical_digest(exceptions):
            fail(f"{label}: provenance.exceptionDigest does not match examples/exceptions.json.")

        exception_by_id = {item["id"]: item for item in exceptions.get("exceptions", [])}
        try:
            collected_date = date.fromisoformat(str(scan.get("collectedAt"))[:10])
        except ValueError:
            collected_date = None
        computer_name = str(sample.get("system", {}).get("ComputerName", ""))
        baseline_name = str(sample.get("baseline", {}).get("name", ""))
        for result in sample.get("results", []):
            applied = result.get("exception")
            if applied is None:
                continue

            exception_id = applied.get("id")
            registered = exception_by_id.get(exception_id)
            if registered is None:
                fail(
                    f"{label}: applied exception {exception_id!r} is not present in "
                    "examples/exceptions.json."
                )
                continue
            if registered.get("controlId") != result.get("controlId"):
                fail(
                    f"{label}: applied exception {exception_id!r} does not match "
                    f"control {result.get('controlId')!r}."
                )
            if registered.get("status") != "Approved":
                fail(f"{label}: applied exception {exception_id!r} is not Approved.")
            if collected_date is not None and date.fromisoformat(str(registered.get("expires"))) < collected_date:
                fail(f"{label}: applied exception {exception_id!r} was expired when the sample was collected.")

            target_match = any(
                fnmatch.fnmatchcase(computer_name.casefold(), str(pattern).casefold())
                for pattern in registered.get("targets", [])
            )
            if not target_match:
                fail(f"{label}: applied exception {exception_id!r} does not target computer {computer_name!r}.")
            baselines = registered.get("baselines", [])
            if baselines and baseline_name.casefold() not in {
                str(value).casefold() for value in baselines
            }:
                fail(f"{label}: applied exception {exception_id!r} does not target baseline {baseline_name!r}.")

            registered_snapshot = {
                "id": registered["id"],
                "owner": registered["owner"],
                "reason": registered["reason"],
                "ticket": registered["ticket"],
                "expires": registered["expires"],
                "approvedBy": registered.get("approvedBy", ""),
                "compensatingControls": registered.get("compensatingControls", []),
            }
            if applied != registered_snapshot:
                fail(
                    f"{label}: applied exception {exception_id!r} does not match the reportable fields "
                    "in examples/exceptions.json."
                )

    capability_names = [item.get("name") for item in provenance.get("capabilities", [])]
    expected_capability_names = sorted(
        {item.get("probe") for item in sample.get("results", [])},
        key=str.casefold,
    )
    if capability_names != expected_capability_names:
        fail(f"{label}: provenance.capabilities does not match the selected probe set in sorted order.")

    result_ids = [item["controlId"] for item in sample.get("results", [])]
    if len(result_ids) != len(set(result_ids)):
        fail(f"{label}: duplicate result control IDs.")
    unknown = sorted(set(result_ids) - catalog_ids)
    if unknown:
        fail(f"{label}: unknown controls: {', '.join(unknown)}")
    if scan.get("selectedControlCount") != len(result_ids):
        fail(f"{label}: selectedControlCount does not match results length.")
    if sample.get("baseline", {}).get("controlCount") != len(result_ids):
        fail(f"{label}: baseline controlCount does not match results length.")

    computed = expected_summary(sample.get("results", []))
    for key, expected in computed.items():
        if sample.get("summary", {}).get(key) != expected:
            fail(f"{label}: summary.{key} is {sample.get('summary', {}).get(key)!r}; expected {expected!r}.")
    return sample


def validate_fleet_schema_contract(sample: dict[str, Any] | None) -> None:
    fleet_schema_path = SCHEMA_ROOT / "fleet-result.schema.json"
    result_schema_path = SCHEMA_ROOT / "result.schema.json"
    fleet_schema = load_json(fleet_schema_path)
    result_schema = load_json(result_schema_path)
    if fleet_schema is None or result_schema is None:
        return

    result_schema_id = result_schema.get("$id")
    assessment_contract = fleet_schema.get("$defs", {}).get("assessment")
    if assessment_contract != {"$ref": result_schema_id}:
        fail(
            "src/HardeningLens/Schema/fleet-result.schema.json: $defs.assessment must contain only "
            "a $ref equal to result.schema.json.$id."
        )
        return
    if sample is None or not isinstance(result_schema_id, str):
        fail("Fleet schema regression validation requires a valid sample result and result schema $id.")
        return

    registry = Registry().with_resource(result_schema_id, Resource.from_contents(result_schema))
    validator = Draft202012Validator(
        fleet_schema,
        registry=registry,
        format_checker=FormatChecker(),
    )
    scan = sample["scan"]
    summary = sample["summary"]
    fleet_fixture = {
        "$schema": fleet_schema["$id"],
        "schemaVersion": "1.1",
        "run": {
            "id": scan["id"],
            "startedAt": scan["collectedAt"],
            "completedAt": scan["collectedAt"],
            "moduleVersion": scan["moduleVersion"],
            "baselineSelection": sample["baseline"]["name"],
            "customBaseline": False,
            "redacted": scan["redacted"],
            "allowPartial": scan["partialCollection"],
            "throttleLimit": 1,
            "requestedCount": 1,
            "succeededCount": 1,
            "failedCount": 0,
        },
        "summary": {
            "requestedCount": 1,
            "succeededCount": 1,
            "failedCount": 0,
            "averageHardeningScore": summary["HardeningScore"],
            "averageEvidenceCoverage": summary["EvidenceCoverage"],
            "totalFail": summary["Fail"],
            "totalWarning": summary["Warning"],
            "totalExcepted": summary["Excepted"],
            "totalUnknown": summary["Unknown"],
            "totalError": summary["Error"],
        },
        "artifacts": {
            "outputDirectory": "fleet-results",
            "summaryPath": "fleet-results/fleet-summary.csv",
            "resultPath": "fleet-results/fleet-result.json",
            "manifestPath": "fleet-results/manifest.json",
            "commitMarkerPath": "fleet-results/commit.json",
        },
        "hosts": [{
            "ordinal": 1,
            "requestedComputerName": sample["system"]["ComputerName"],
            "computerName": sample["system"]["ComputerName"],
            "status": "Succeeded",
            "error": None,
            "assessment": sample,
            "artifactPath": "fleet-results/host-001.json",
        }],
    }
    valid_errors = list(validator.iter_errors(fleet_fixture))
    if valid_errors:
        fail(f"Fleet schema rejected the canonical sample result: {valid_errors[0].message}")

    invalid_fixture = json.loads(json.dumps(fleet_fixture))
    invalid_fixture["hosts"][0]["assessment"] = {
        "schemaVersion": "1.1",
        "scan": {},
        "system": {},
        "baseline": {},
        "summary": {},
        "results": [],
    }
    if not list(validator.iter_errors(invalid_fixture)):
        fail("Fleet schema accepted a minimal empty schema 1.1 assessment.")


def validate_demo_drift(
    reference: dict[str, Any] | None,
    difference: dict[str, Any] | None,
) -> None:
    drift_path = ROOT / "examples" / "sample-drift.json"
    drift = validate_schema(drift_path, SCHEMA_ROOT / "comparison.schema.json")
    if not drift or reference is None or difference is None:
        return

    expected = create_comparison(reference, difference)
    if drift != expected:
        sections = sorted(
            key
            for key in set(drift) | set(expected)
            if drift.get(key) != expected.get(key)
        )
        fail(
            "examples/sample-drift.json does not match a fresh comparison of the reference and "
            f"difference samples; differing sections: {', '.join(sections)}."
        )


def validate_contracts() -> None:
    for schema_path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        schema_document = load_json(schema_path)
        if schema_document is None:
            continue
        try:
            Draft202012Validator.check_schema(schema_document)
        except Exception as exc:
            fail(f"{schema_path.relative_to(ROOT)}: invalid JSON Schema: {exc}")

    catalog_path = DATA_ROOT / "control-catalog.json"
    catalog = validate_schema(catalog_path, SCHEMA_ROOT / "control-catalog.schema.json")
    if not catalog:
        return

    controls = catalog["controls"]
    ids = [item["id"] for item in controls]
    if len(controls) != 64:
        fail(f"Control catalog must contain 64 controls; found {len(controls)}.")
    duplicates = sorted(control_id for control_id, count in Counter(ids).items() if count > 1)
    if duplicates:
        fail(f"Duplicate control IDs: {', '.join(duplicates)}")
    catalog_ids = set(ids)

    manifest_text = (MODULE_ROOT / "HardeningLens.psd1").read_text(encoding="utf-8")
    version_match = re.search(r"ModuleVersion\s*=\s*'([^']+)'", manifest_text)
    if not version_match:
        fail("HardeningLens.psd1: ModuleVersion could not be parsed.")
        module_version = None
    else:
        module_version = version_match.group(1)
        if not re.fullmatch(r"\d+\.\d+\.\d+", module_version):
            fail(f"HardeningLens.psd1: ModuleVersion {module_version!r} is not semantic version form x.y.z.")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        if f"## [{module_version}]" not in changelog:
            fail(f"CHANGELOG.md has no release section for module version {module_version}.")

    for control in controls:
        for reference in control["references"]:
            if not reference.startswith("https://learn.microsoft.com/"):
                fail(f"{control['id']}: reference is not first-party Microsoft guidance: {reference}")

    baseline_documents: dict[str, dict[str, Any]] = {}
    for path in sorted(BASELINE_ROOT.glob("*.json")):
        baseline = validate_schema(path, SCHEMA_ROOT / "baseline.schema.json")
        if not baseline:
            continue
        baseline_documents[baseline["name"]] = baseline
        baseline_control_ids = [entry["id"] for entry in baseline["controls"]]
        if len(baseline_control_ids) < 50:
            fail(f"{path.name}: expected at least 50 controls; found {len(baseline_control_ids)}.")
        if len(set(baseline_control_ids)) != len(baseline_control_ids):
            fail(f"{path.name}: contains duplicate control IDs.")
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(baseline.get("version", ""))):
            fail(f"{path.name}: version {baseline.get('version')!r} is not semantic version form x.y.z.")
        unknown = sorted(set(baseline_control_ids) - catalog_ids)
        if unknown:
            fail(f"{path.name}: unknown controls: {', '.join(unknown)}")

    expected_baselines = {"Workstation", "MemberServer", "DomainController", "AVDSessionHost"}
    if set(baseline_documents) != expected_baselines:
        fail(f"Built-in baseline set differs from {sorted(expected_baselines)}.")

    custom_path = ROOT / "examples" / "custom-baseline.json"
    custom = validate_schema(custom_path, SCHEMA_ROOT / "baseline.schema.json")
    if custom:
        referenced = {entry["id"] for entry in custom["controls"]} | set(custom.get("excludedControls", []))
        unknown = sorted(referenced - catalog_ids)
        if unknown:
            fail(f"examples/custom-baseline.json: unknown controls: {', '.join(unknown)}")

    exception_path = ROOT / "examples" / "exceptions.json"
    exceptions = validate_schema(exception_path, SCHEMA_ROOT / "exception.schema.json")
    if exceptions:
        exception_ids = [item["id"] for item in exceptions["exceptions"]]
        if len(exception_ids) != len(set(exception_ids)):
            fail("examples/exceptions.json: duplicate exception IDs.")
        for item in exceptions["exceptions"]:
            if item["controlId"] not in catalog_ids:
                fail(f"{item['id']}: unknown control {item['controlId']}.")

    sample = validate_demo_scan(
        ROOT / "examples" / "sample-result.json",
        module_version,
        catalog,
        controls,
        catalog_ids,
        baseline_documents,
        exceptions,
    )
    reference = validate_demo_scan(
        ROOT / "examples" / "sample-reference-result.json",
        module_version,
        catalog,
        controls,
        catalog_ids,
        baseline_documents,
        exceptions,
    )
    validate_fleet_schema_contract(sample)
    validate_demo_drift(reference, sample)


def validate_repository_hygiene() -> None:
    required = [
        "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md",
        ".github/workflows/quality.yml", ".github/workflows/release.yml", ".github/workflows/windows-live.yml",
        "src/HardeningLens/HardeningLens.psd1", "src/HardeningLens/HardeningLens.psm1",
        "src/HardeningLens/Public/Invoke-HardeningLensFleet.ps1", "src/HardeningLens/Schema/fleet-result.schema.json",
        "docs/CONTROL_REFERENCE.md", "docs/assets/social-preview.png", "examples/sample-result.json", "examples/sample-report.html",
        "tests/Unit/Catalog.Tests.ps1",
    ]
    for relative in required:
        if not (ROOT / relative).exists():
            fail(f"Missing required repository file: {relative}")

    forbidden_terms = {
        "".join(("chat", "gpt")): "external authoring marker",
        "".join(("open", "ai")): "external authoring marker",
        "".join(("generated by ", "ai")): "external authoring marker",
    }
    text_extensions = {".md", ".ps1", ".psm1", ".psd1", ".json", ".yml", ".yaml", ".py", ".html", ".svg", ".txt"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in text_extensions:
            continue
        if any(part in {"dist", "artifacts", ".git"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lower = text.lower()
        for term, reason in forbidden_terms.items():
            if term in lower:
                fail(f"{path.relative_to(ROOT)} contains forbidden {reason}: {term}")
        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", text):
            fail(f"{path.relative_to(ROOT)} appears to contain a private key.")
        if re.search(r"(?i)(client[_-]?secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}", text):
            fail(f"{path.relative_to(ROOT)} appears to contain a secret assignment.")

    for path in list(ROOT.rglob("*.ps1")) + list(ROOT.rglob("*.psm1")) + list(ROOT.rglob("*.psd1")):
        if any(part in {"dist", "artifacts"} for part in path.parts):
            continue
        raw = path.read_bytes()
        if any(byte > 0x7F for byte in raw):
            fail(f"{path.relative_to(ROOT)} contains non-ASCII bytes; Windows PowerShell 5.1 source files must remain ASCII-safe.")
        if b"\t" in raw:
            fail(f"{path.relative_to(ROOT)} contains tab indentation.")

    html_path = ROOT / "examples" / "sample-report.html"
    if html_path.exists():
        html = html_path.read_text(encoding="utf-8")
        if "Content-Security-Policy" not in html:
            fail("examples/sample-report.html has no Content-Security-Policy.")
        for required_label in [
            "Result schema", "Assessment provenance", "Catalog digest",
            "Effective baseline digest", "Exception register digest",
            "Collection duration", "Probe capabilities",
        ]:
            if required_label not in html:
                fail(f"examples/sample-report.html is missing required v1.1 metadata: {required_label}")
        for pattern in [r"<script[^>]+src=", r"<link[^>]+rel=['\"]stylesheet", r"url\(https?://"]:
            if re.search(pattern, html, flags=re.IGNORECASE):
                fail(f"examples/sample-report.html is not self-contained; matched {pattern}.")

    readme = ROOT / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8")
        normalized_text = text.casefold()
        for required_phrase in ["64 controls", "read-only", "Workstation", "DomainController", "Exceptions", "Drift"]:
            if required_phrase.casefold() not in normalized_text:
                fail(f"README.md does not document required capability: {required_phrase}")

    markdown_link = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
    for path in ROOT.rglob("*.md"):
        if any(part in {"dist", "artifacts", ".git"} for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8")
        for match in markdown_link.finditer(text):
            target = match.group(1).strip()
            if ' "' in target:
                target = target.split(' "', 1)[0]
            if target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            relative_target = urllib.parse.unquote(target.split("#", 1)[0])
            if not relative_target:
                continue
            if not (path.parent / relative_target).resolve().exists():
                line = text.count("\n", 0, match.start()) + 1
                fail(f"{path.relative_to(ROOT)}:{line}: local Markdown link does not exist: {relative_target}")


def main() -> int:
    validate_contracts()
    validate_repository_hygiene()
    if ERRORS:
        print("Repository validation failed:", file=sys.stderr)
        for error in ERRORS:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("Repository validation passed: schemas, cross-file contracts, examples, and hygiene are consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
