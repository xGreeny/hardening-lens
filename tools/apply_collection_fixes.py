#!/usr/bin/env python3
"""Apply one-time PowerShell collection materialization fixes."""

from pathlib import Path

REPLACEMENTS: dict[str, list[tuple[str, str]]] = {
    "src/HardeningLens/Private/Common.ps1": [
        ("    $baseline.controls = @($resolvedControls)\n", "    $baseline.controls = $resolvedControls.ToArray()\n"),
        ("    $baseline | Add-Member -NotePropertyName controlCount -NotePropertyValue @($resolvedControls).Count -Force\n", "    $baseline | Add-Member -NotePropertyName controlCount -NotePropertyValue $resolvedControls.Count -Force\n"),
        ("        return @($items)\n", "        return $items.ToArray()\n"),
    ],
    "src/HardeningLens/Private/AuditPolicy.ps1": [
        ("    $actual = @($actualFlags) -join ' and '\n", "    $actual = $actualFlags.ToArray() -join ' and '\n"),
        ("    return New-HLProbeResult -Status Fail -Expected $expected -Actual $actual -Message ('Missing required audit flags: {0}.' -f (@($missing) -join ', ')) -Evidence $evidence\n", "    return New-HLProbeResult -Status Fail -Expected $expected -Actual $actual -Message ('Missing required audit flags: {0}.' -f ($missing.ToArray() -join ', ')) -Evidence $evidence\n"),
    ],
    "src/HardeningLens/Private/Comparison.ps1": [
        ("        changes       = @($changes)\n", "        changes       = $changes.ToArray()\n"),
        ("    return ($lines -join [Environment]::NewLine)\n", "    return ($lines.ToArray() -join [Environment]::NewLine)\n"),
    ],
    "src/HardeningLens/Private/Exceptions.ps1": [
        ("        return [pscustomobject][ordered]@{ IsValid = $false; Errors = @($errors); Warnings = @($warnings); ExceptionCount = 0 }\n", "        return [pscustomobject][ordered]@{ IsValid = $false; Errors = $errors.ToArray(); Warnings = $warnings.ToArray(); ExceptionCount = 0 }\n"),
        ("        Errors         = @($errors)\n", "        Errors         = $errors.ToArray()\n"),
        ("        Warnings       = @($warnings)\n", "        Warnings       = $warnings.ToArray()\n"),
    ],
    "src/HardeningLens/Private/Probes.System.ps1": [
        ("('Unable to query one or more optional features: {0}' -f (@($queryErrors) -join ' | '))", "('Unable to query one or more optional features: {0}' -f ($queryErrors.ToArray() -join ' | '))"),
        ("-Evidence @($evidence)", "-Evidence $evidence.ToArray()"),
    ],
    "src/HardeningLens/Private/Probes.Network.ps1": [
        ("('Non-compliant: {0}' -f (@($nonCompliant) -join ', '))", "('Non-compliant: {0}' -f ($nonCompliant.ToArray() -join ', '))"),
        ("('Unresolved: {0}' -f (@($unresolved) -join ', '))", "('Unresolved: {0}' -f ($unresolved.ToArray() -join ', '))"),
        ("-Evidence @($evidence)", "-Evidence $evidence.ToArray()"),
    ],
    "src/HardeningLens/Private/Probes.Defender.ps1": [
        ("-Evidence @($evidence)", "-Evidence $evidence.ToArray()"),
    ],
    "src/HardeningLens/Public/Export-HardeningLensReport.ps1": [
        ("        return @($written)\n", "        return $written.ToArray()\n"),
    ],
    "src/HardeningLens/Public/Invoke-HardeningLens.ps1": [
        ("        summary = Get-HLSummary -Results @($results)\n", "        summary = Get-HLSummary -Results $results.ToArray()\n"),
        ("        results = @($results)\n", "        results = $results.ToArray()\n"),
    ],
}


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    changed: list[str] = []

    for relative_path, replacements in REPLACEMENTS.items():
        path = root / relative_path
        text = path.read_text(encoding="utf-8")
        original = text

        for old, new in replacements:
            occurrences = text.count(old)
            if occurrences == 0:
                raise RuntimeError(f"Expected text not found in {relative_path}: {old!r}")
            text = text.replace(old, new)

        if text != original:
            path.write_text(text, encoding="utf-8", newline="\n")
            changed.append(relative_path)

    print(f"Updated {len(changed)} file(s).")
    for path in changed:
        print(f"- {path}")


if __name__ == "__main__":
    main()
