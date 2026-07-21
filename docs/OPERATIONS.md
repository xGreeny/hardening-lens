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

`Invoke-HardeningLensFleet` transfers the module to temporary directories on remote hosts, runs locally through PowerShell remoting, removes transport metadata, and preserves exactly one ordered outcome for every requested host.

```powershell
Invoke-HardeningLensFleet `
    -ComputerName SRV-APP-01, SRV-FILE-01, SRV-WEB-01 `
    -Baseline MemberServer `
    -ExceptionPath .\exceptions.json `
    -OutputDirectory .\fleet-results `
    -ThrottleLimit 8
```

Every invocation creates a run ID and builds host results, failure JSON, summary CSV, manifest, consolidated fleet-result JSON, and `commit.json` inside a private staging directory. The completed directory is then published as one committed run. A colliding run is rejected unless `-Force` is explicit; forced replacement keeps the previous committed directory until the new run is complete and restores it if publication fails. Consumers should treat the commit marker as the signal that the run is complete. Transport errors, empty remote output, and invalid scan results become explicit failed host entries. Use `-FailOnHostError` to throw only after all artifacts have been committed. `scripts/Invoke-FleetAssessment.ps1` remains available as a compatibility wrapper and writes its latest-summary alias atomically.

Prerequisites:

- WinRM connectivity and authorization;
- an account permitted to collect the required evidence;
- matching PowerShell remoting architecture;
- secure handling of generated result files.

The command does not install the module permanently on remote systems.

### Aggregated fleet report

`Export-HardeningLensFleetReport` renders one self-contained HTML page for a fleet run: per-host scores, status counts, failed collections with their recorded errors, and the controls affecting the most hosts.

```powershell
Invoke-HardeningLensFleet -ComputerName SRV-APP-01, SRV-FILE-01 -Baseline MemberServer -OutputDirectory .\fleet-results |
    Export-HardeningLensFleetReport -OutputDirectory .\fleet-results

Export-HardeningLensFleetReport -Path .\fleet-results\<run-id>\fleet-result.json -OutputDirectory .\reports
```

The report embeds no external scripts, styles, fonts, or images, uses a restrictive Content Security Policy, and encodes all values. It inherits the redaction state of the fleet run; review it like any other assessment artifact before sharing.

## Automation policy

Use the result object rather than console text as the automation contract:

```powershell
$evaluation = Test-HardeningLensPolicy `
    -Path .\out\hardening-lens-result.json `
    -MaxFailed 0 `
    -MaxWarning 2 `
    -MinimumScore 85 `
    -MinimumCoverage 95 `
    -DisallowPartialCollection `
    -DisallowExpiredExceptions

if (-not $evaluation.Passed) {
    $evaluation.Violations | Format-Table Rule, Actual, Expected, Message
    exit $evaluation.ExitCode
}
```

`-FailOnViolation` emits a terminating error with ID `HardeningLens.PolicyViolation`. All thresholds are opt-in, so an omitted rule is not evaluated.

## Provenance and reproducibility

Schema 1.1 results distinguish three release identities:

- `scan.moduleVersion`: assessment engine version;
- `provenance.catalogVersion`: shipped control-content version;
- `baseline.version`: selected baseline-content version.

The provenance object hashes the full catalog, effective resolved baseline before any `-ControlId` filter, and the exception register when used. Compare these values before interpreting drift; a state change and an assessment-input change are different operational events.

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
