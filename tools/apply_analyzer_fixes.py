#!/usr/bin/env python3
"""Apply one-time PSScriptAnalyzer cleanup to PowerShell sources."""

from pathlib import Path

RENAMES = [
    ("New-HLComparisonMarkdown", "ConvertTo-HLComparisonMarkdown"),
    ("New-HLComparison", "Compare-HLScanResult"),
    ("New-HLValueProbeResult", "Get-HLValueProbeResult"),
    ("New-HLHtmlReport", "ConvertTo-HLHtmlReport"),
    ("New-HLProbeResult", "Get-HLProbeResult"),
    ("Get-HLRegistryKeyValues", "Get-HLRegistryKeyValueMap"),
    ("Get-HLBuiltinBaselineNames", "Get-HLBuiltinBaselineName"),
    ("Invoke-Tests", "Invoke-TestSuite"),
]

WRITE_OBJECT_REPLACEMENTS = {
    "src/HardeningLens/Public/Invoke-HardeningLens.ps1": (
        "    Write-Output -NoEnumerate $scanResult\n",
        "    $PSCmdlet.WriteObject($scanResult, $false)\n",
    ),
    "src/HardeningLens/Public/Compare-HardeningLensResult.ps1": (
        "    Write-Output -NoEnumerate $comparison\n",
        "    $PSCmdlet.WriteObject($comparison, $false)\n",
    ),
    "hardening-lens.ps1": (
        "        Write-Output -NoEnumerate $scan\n",
        "        $PSCmdlet.WriteObject($scan, $false)\n",
    ),
}

SUPPRESSION_TARGET = "    [CmdletBinding(DefaultParameterSetName = 'Named')]\n"
SUPPRESSION_REPLACEMENT = (
    "    [CmdletBinding(DefaultParameterSetName = 'Named')]\n"
    "    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', "
    "Justification = 'Hardening Lens is the singular product name.')]\n"
)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    powershell_files = sorted(
        path
        for path in root.rglob("*.ps1")
        if not any(part in {"artifacts", "dist"} for part in path.parts)
    )

    rename_counts = {old: 0 for old, _ in RENAMES}
    changed: set[Path] = set()

    for path in powershell_files:
        text = path.read_text(encoding="utf-8")
        original = text
        for old, new in RENAMES:
            count = text.count(old)
            if count:
                rename_counts[old] += count
                text = text.replace(old, new)
        if text != original:
            path.write_text(text, encoding="utf-8", newline="\n")
            changed.add(path)

    missing = [name for name, count in rename_counts.items() if count == 0]
    if missing:
        raise RuntimeError(f"Expected identifiers were not found: {', '.join(missing)}")

    for relative_path, (old, new) in WRITE_OBJECT_REPLACEMENTS.items():
        path = root / relative_path
        text = path.read_text(encoding="utf-8")
        if old not in text:
            raise RuntimeError(f"Expected Write-Output call not found in {relative_path}")
        path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")
        changed.add(path)

    public_command = root / "src/HardeningLens/Public/Invoke-HardeningLens.ps1"
    text = public_command.read_text(encoding="utf-8")
    if SUPPRESSION_TARGET not in text:
        raise RuntimeError("Invoke-HardeningLens CmdletBinding declaration was not found")
    public_command.write_text(
        text.replace(SUPPRESSION_TARGET, SUPPRESSION_REPLACEMENT, 1),
        encoding="utf-8",
        newline="\n",
    )
    changed.add(public_command)

    print(f"Updated {len(changed)} PowerShell file(s).")
    for path in sorted(changed):
        print(f"- {path.relative_to(root)}")


if __name__ == "__main__":
    main()
