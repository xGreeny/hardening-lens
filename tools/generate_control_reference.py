#!/usr/bin/env python3
"""Generate the committed control reference from the catalog and baselines."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "src" / "HardeningLens" / "Data" / "control-catalog.json"
BASELINE_ROOT = ROOT / "src" / "HardeningLens" / "Data" / "Baselines"
OUTPUT_PATH = ROOT / "docs" / "CONTROL_REFERENCE.md"
BASELINE_ORDER = ["Workstation", "MemberServer", "DomainController", "AVDSessionHost"]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def display_parameters(parameters: dict) -> str:
    if not parameters:
        return "No control-specific parameters."
    return f"```json\n{json.dumps(parameters, indent=2, sort_keys=True)}\n```"


def generate() -> str:
    catalog = load_json(CATALOG_PATH)
    controls = sorted(catalog["controls"], key=lambda item: (item["category"], item["id"]))
    baselines = {name: load_json(BASELINE_ROOT / f"{name}.json") for name in BASELINE_ORDER}
    baseline_ids = {
        name: {entry["id"] for entry in document["controls"]}
        for name, document in baselines.items()
    }
    categories = Counter(control["category"] for control in controls)
    by_category: dict[str, list[dict]] = defaultdict(list)
    for control in controls:
        by_category[control["category"]].append(control)

    lines: list[str] = [
        "# Control reference",
        "",
        f"Catalog version **{catalog['catalogVersion']}**, dated **{catalog['generatedOn']}**. "
        f"The catalog contains **{len(controls)}** read-only controls. Every control records expected state, "
        "effective state, status, evidence, rationale, remediation guidance, and first-party Microsoft references.",
        "",
        "> The catalog is an operational assessment model. It is not a verbatim Microsoft Security Baseline,",
        "> CIS Benchmark, certification, or replacement for workload-specific risk assessment.",
        "",
        "## Baseline coverage",
        "",
        "| Baseline | Controls | Intended role |",
        "|---|---:|---|",
    ]
    for name in BASELINE_ORDER:
        baseline = baselines[name]
        lines.append(
            f"| `{name}` | {len(baseline['controls'])} | {baseline['description']} |"
        )

    lines.extend([
        "",
        "## Category index",
        "",
        "| Category | Controls |",
        "|---|---:|",
    ])
    for category in sorted(categories):
        anchor = category.lower().replace(" ", "-")
        lines.append(f"| [{category}](#{anchor}) | {categories[category]} |")

    lines.extend([
        "",
        "## Baseline matrix",
        "",
        "| Control | Severity | Category | Workstation | Member Server | Domain Controller | AVD Session Host |",
        "|---|---|---|:---:|:---:|:---:|:---:|",
    ])
    for control in sorted(controls, key=lambda item: item["id"]):
        marks = ["✓" if control["id"] in baseline_ids[name] else "—" for name in BASELINE_ORDER]
        lines.append(
            f"| [`{control['id']}`](#{control['id'].lower()}) | {control['severity']} | "
            f"{control['category']} | {' | '.join(marks)} |"
        )

    for category in sorted(by_category):
        lines.extend(["", f"## {category}", ""])
        for control in by_category[category]:
            included = [name for name in BASELINE_ORDER if control["id"] in baseline_ids[name]]
            references = "\n".join(f"- [{url}]({url})" for url in control["references"])
            tags = ", ".join(f"`{tag}`" for tag in control["tags"])
            lines.extend([
                f"### {control['id']} — {control['title']}",
                "",
                f"**Severity:** {control['severity']}  ",
                f"**Probe:** `{control['probe']}`  ",
                f"**Baselines:** {', '.join(f'`{name}`' for name in included) or 'Custom only'}  ",
                f"**Tags:** {tags}",
                "",
                control["description"],
                "",
                f"**Why it matters.** {control['rationale']}",
                "",
                f"**Remediation.** {control['remediation']}",
                "",
                "**Parameters**",
                "",
                display_parameters(control["parameters"]),
                "",
                "**Microsoft guidance**",
                "",
                references,
                "",
            ])

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail when the committed file differs.")
    args = parser.parse_args()
    content = generate()

    if args.check:
        if not OUTPUT_PATH.exists() or OUTPUT_PATH.read_text(encoding="utf-8") != content:
            print("docs/CONTROL_REFERENCE.md is out of date. Run tools/generate_control_reference.py.", file=sys.stderr)
            return 1
        print("Control reference is current.")
        return 0

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(content, encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
