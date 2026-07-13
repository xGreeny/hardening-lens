# Operations guide

## Local assessment

Run from an elevated Windows PowerShell 5.1 or PowerShell 7 session:

```powershell
.\hardening-lens.ps1 `
    -Baseline Auto `
    -OutputDirectory .\out
```

The wrapper imports the module from `src`, runs the assessment, exports HTML/JSON/CSV, prints report paths, and returns a process exit code suitable for automation.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | No finding at or above `-FailOnSeverity`, or threshold is `None` |
| `1` | At least one `Fail` or `Error` meets the configured severity threshold |
| `2` | Invocation, validation, baseline, or report error |

`Warning` and `Excepted` do not trigger exit code 1. Review them through report policy rather than treating them as an execution failure.

```powershell
.\hardening-lens.ps1 -Baseline MemberServer -FailOnSeverity Critical
```

## Partial collection

Elevation is the expected operating mode. `-AllowPartial` permits collection without elevation and preserves unavailable evidence as `Unknown` or `Error`:

```powershell
Invoke-HardeningLens -Baseline Workstation -AllowPartial
```

Do not interpret a partial result without its evidence-coverage metric.

## Focused checks

Run selected controls while troubleshooting or validating a change:

```powershell
Invoke-HardeningLens `
    -Baseline MemberServer `
    -ControlId HL-SMB-001, HL-SMB-003, HL-SMB-004 `
    -NoConsole
```

A requested control must be present in the resolved baseline.

## Report handling

```powershell
$result = Invoke-HardeningLens -Baseline MemberServer -NoConsole
$result | Export-HardeningLensReport `
    -Format Html, Json, Csv `
    -OutputDirectory .\out `
    -FileNamePrefix 'change-CHG-0042-after'
```

- **HTML** is self-contained, filterable, printable, and protected by a restrictive Content Security Policy.
- **JSON** preserves full evidence for automation and drift comparison.
- **CSV** supports finding registers and spreadsheet review.

Reports contain sensitive configuration evidence. Restrict access and retention according to local policy.

## Redaction

```powershell
Invoke-HardeningLens -Baseline MemberServer -Redact
```

Redaction replaces the detected computer name, domain, and current-user identity throughout the result. It does not claim to anonymize arbitrary values returned by every Windows provider. Review reports before external sharing.

## Fleet assessment

`scripts/Invoke-FleetAssessment.ps1` transfers the module to temporary directories on remote hosts, runs locally through PowerShell remoting, removes transport metadata, writes one schema-compatible JSON result per host, and produces a fleet summary CSV.

```powershell
.\scripts\Invoke-FleetAssessment.ps1 `
    -ComputerName SRV-APP-01, SRV-FILE-01, SRV-WEB-01 `
    -Baseline MemberServer `
    -ExceptionsPath .\exceptions.json `
    -OutputDirectory .\fleet-results `
    -ThrottleLimit 8
```

Prerequisites:

- WinRM connectivity and authorization;
- an account permitted to collect the required evidence;
- matching PowerShell remoting architecture;
- secure handling of generated result files.

The helper does not install the module permanently on remote systems.

## Drift comparison

```powershell
Compare-HardeningLensResult `
    -Reference .\before.json `
    -Difference .\after.json `
    -Format Markdown `
    -OutputPath .\drift.md
```

Change types:

- `NewFinding`
- `Resolved`
- `Changed`
- `AddedControl`
- `RemovedControl`
- `Unchanged`

A drift record is evidence of changed observed state, not proof that a change was malicious or unauthorized.

## Installation

Install the versioned module for the current user:

```powershell
.\scripts\Install-HardeningLens.ps1 -Scope CurrentUser
Import-Module HardeningLens
```

Use `-Scope AllUsers` from an elevated session for a machine-wide installation. Versioned module folders permit side-by-side releases.

## Scheduling

For scheduled collection:

- use a managed service identity or dedicated service account with the minimum required rights;
- write to an access-controlled local or network path;
- use the CLI exit code for pipeline state, not as the sole incident signal;
- rotate and retain reports according to evidence policy;
- compare both hardening score and evidence coverage;
- update baselines through a reviewed release process.
