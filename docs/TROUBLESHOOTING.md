# Troubleshooting

## Live collection requires Windows

```text
Live Hardening Lens collection requires Windows.
```

Run `Invoke-HardeningLens` on the Windows endpoint. Catalog inspection, exception validation, report export from JSON, and drift comparison can run cross-platform.

## Elevation required

```text
Run Hardening Lens from an elevated PowerShell session...
```

Start Windows PowerShell or PowerShell as Administrator. Use `-AllowPartial` only when incomplete evidence is intentional and review `EvidenceCoverage`.

## A control is Unknown

`Unknown` means the state could not be resolved, not that it is compliant. Check:

- whether the cmdlet or Windows feature exists on the edition;
- whether the endpoint protection provider is Microsoft Defender;
- whether the session architecture can access the 64-bit registry view;
- whether the provider is healthy;
- whether the control is appropriate for the selected role;
- verbose output with `-Verbose`.

```powershell
Invoke-HardeningLens -Baseline MemberServer -ControlId HL-CRED-002 -Verbose
```

## A control is Error

`Error` records a collection failure such as access denied, a provider exception, or malformed state. Review the `message` and `evidence`, rerun the single control, and confirm elevation. Do not convert recurring collection errors into exceptions merely to improve the score.

## Defender controls fail on a third-party protected host

The Defender cmdlets may be unavailable or non-authoritative. Confirm the organization's endpoint-protection architecture. Keep the finding visible or use a narrowly scoped, approved exception that names the authoritative protection, its monitoring, and its review date.

## Windows LAPS appears disabled

Hardening Lens checks current Windows LAPS policy locations in precedence order and identifies legacy Microsoft LAPS separately. Confirm:

- policy has reached the device;
- `BackupDirectory` is configured;
- the expected policy delivery mechanism is authoritative;
- the endpoint supports Windows LAPS;
- legacy policy is not the only configuration present.

## Optional feature query fails

`Get-WindowsOptionalFeature` can require elevation and DISM provider health. A feature that is genuinely absent is treated differently from a query error. Review the evidence for `NotPresent` versus `QueryError`.

## Secure Boot reports unsupported

Confirm that the system boots in UEFI mode and that virtual hardware exposes Secure Boot. Unsupported firmware is a failed platform-security expectation in built-in profiles, not `NotApplicable`.

## Report export fails

Confirm the destination is writable and the JSON result uses schema version `1.0`.

```powershell
Export-HardeningLensReport `
    -Path .\examples\sample-result.json `
    -OutputDirectory .\out
```

## Exception register is rejected

```powershell
Test-HardeningLensExceptionFile -Path .\exceptions.json | Format-List
```

Common causes:

- unknown control ID;
- duplicate exception ID;
- invalid `yyyy-MM-dd` date;
- Approved status without approver, approval date, or compensating controls;
- approval date after expiry;
- empty target pattern.

## Fleet results include remoting metadata

Use `Invoke-HardeningLensFleet`. It removes `PSComputerName`, `RunspaceId`, and `PSShowComputerName` before writing result JSON so the output remains schema-compatible. The legacy `scripts/Invoke-FleetAssessment.ps1` wrapper uses the same implementation.
