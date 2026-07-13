#!/usr/bin/env python3
"""Validate schemas, cross-file contracts, examples, and repository hygiene."""

from __future__ import annotations

import json
import re
import sys
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

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


def validate_contracts() -> None:
    catalog_path = DATA_ROOT / "control-catalog.json"
    catalog = validate_schema(catalog_path, SCHEMA_ROOT / "control-catalog.schema.json")
    if not catalog:
        return

    controls = catalog["controls"]
    ids = [item["id"] for item in controls]
    if len(controls) != 58:
        fail(f"Control catalog must contain 58 controls; found {len(controls)}.")
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
        if catalog.get("catalogVersion") != module_version:
            fail(f"Control catalog version {catalog.get('catalogVersion')!r} does not match module version {module_version!r}.")
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
        if module_version and baseline.get("version") != module_version:
            fail(f"{path.name}: version {baseline.get('version')!r} does not match module version {module_version!r}.")
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

    sample_path = ROOT / "examples" / "sample-result.json"
    if sample_path.exists():
        sample = validate_schema(sample_path, SCHEMA_ROOT / "result.schema.json")
        if sample:
            result_ids = [item["controlId"] for item in sample["results"]]
            if len(result_ids) != len(set(result_ids)):
                fail("examples/sample-result.json: duplicate result control IDs.")
            unknown = sorted(set(result_ids) - catalog_ids)
            if unknown:
                fail(f"examples/sample-result.json: unknown controls: {', '.join(unknown)}")
            if sample["scan"]["selectedControlCount"] != len(sample["results"]):
                fail("examples/sample-result.json: selectedControlCount does not match results length.")
            if sample["baseline"]["controlCount"] != len(sample["results"]):
                fail("examples/sample-result.json: baseline controlCount does not match results length.")
            computed = expected_summary(sample["results"])
            for key, expected in computed.items():
                if sample["summary"].get(key) != expected:
                    fail(f"examples/sample-result.json: summary.{key} is {sample['summary'].get(key)!r}; expected {expected!r}.")

    drift_path = ROOT / "examples" / "sample-drift.json"
    if drift_path.exists():
        validate_schema(drift_path, SCHEMA_ROOT / "comparison.schema.json")


def validate_repository_hygiene() -> None:
    required = [
        "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md",
        ".github/workflows/quality.yml", ".github/workflows/release.yml", ".github/workflows/windows-live.yml",
        "src/HardeningLens/HardeningLens.psd1", "src/HardeningLens/HardeningLens.psm1",
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
        for pattern in [r"<script[^>]+src=", r"<link[^>]+rel=['\"]stylesheet", r"url\(https?://"]:
            if re.search(pattern, html, flags=re.IGNORECASE):
                fail(f"examples/sample-report.html is not self-contained; matched {pattern}.")

    readme = ROOT / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8")
        normalized_text = text.casefold()
        for required_phrase in ["58 controls", "read-only", "Workstation", "DomainController", "Exceptions", "Drift"]:
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
