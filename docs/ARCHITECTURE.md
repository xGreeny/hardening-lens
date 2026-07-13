# Architecture

Hardening Lens separates **security intent**, **evidence collection**, **governance**, and **presentation**. This keeps probes reusable and allows the same result contract to support local operations, fleet collection, reports, and drift analysis.

```mermaid
flowchart LR
    CLI[CLI / Module command] --> Context[System context]
    CLI --> Baseline[Baseline resolver]
    Catalog[Control catalog] --> Baseline
    Baseline --> Engine[Assessment engine]
    Context --> Engine
    Exceptions[Exception register] --> Engine
    Engine --> Probes[Read-only probes]
    Probes --> Windows[Registry / CIM / Windows APIs / Cmdlets]
    Engine --> Result[Result schema 1.0]
    Result --> Reports[HTML / JSON / CSV]
    Result --> Drift[Drift comparison]
    Result --> Fleet[Fleet summary]
```

## Module layout

```text
src/HardeningLens/
├── Data/
│   ├── Baselines/
│   └── control-catalog.json
├── Private/
│   ├── probe implementations
│   ├── baseline and scoring logic
│   ├── exception matching
│   ├── report rendering
│   └── drift comparison
├── Public/
│   └── exported commands
├── Schema/
│   └── JSON contracts
├── HardeningLens.psd1
└── HardeningLens.psm1
```

## Assessment flow

1. Confirm the platform is Windows and collect system context.
2. Enforce elevation unless partial collection is explicitly allowed.
3. Resolve a built-in or custom baseline against the catalog.
4. Validate the exception register before evaluating controls.
5. Dispatch each control to a named read-only probe.
6. Normalize the probe result to expected, actual, status, message, and evidence.
7. Apply a matching Approved exception to `Fail` or `Warning` only.
8. Calculate score and evidence coverage.
9. Optionally redact stable host identifiers.
10. Return one schema-versioned result object.

## Control contract

A catalog control defines:

```text
identity          id, title, category, tags
risk context      severity, rationale
assessment        probe, parameters, expected state
operations        remediation
traceability      Microsoft references
```

A probe returns only:

```text
Status
Expected
Actual
Message
Evidence
```

The engine adds catalog metadata, collection time, exception data, and scan context. This prevents probe implementations from inventing inconsistent result structures.

## Read-only boundary

No public or private assessment function contains a remediation path. State-changing operations are limited to:

- writing report and comparison files;
- creating an exception-register file;
- installing a copy of the module when the dedicated installer is invoked;
- creating temporary module files during fleet collection.

Windows security configuration itself is never modified.

## Cross-platform boundary

Live collection requires Windows. The following operations remain cross-platform:

- catalog and baseline inspection;
- custom baseline resolution;
- exception validation;
- report generation from existing JSON;
- result comparison;
- repository tests that use synthetic fixtures.

This split allows CI on both Windows PowerShell 5.1 and current PowerShell without pretending Windows evidence APIs exist on Linux.

## Extension model

A new probe requires:

1. a private function returning `New-HLProbeResult`;
2. a dispatcher entry in `Invoke-HLProbe`;
3. one or more catalog controls;
4. role placement in built-in baselines where appropriate;
5. Pester coverage and synthetic fixtures;
6. first-party documentation references;
7. regenerated control documentation.

Arbitrary probe code cannot be embedded in JSON baselines or exception files.
