# Hardening Lens Roadmap

This roadmap records the intended product direction after the 1.1 operational-trust release. It is directional rather than a promise of dates. Security semantics, backward compatibility, and evidence quality take priority over raw control count.

## Product principles

Hardening Lens remains read-only by default. Its job is to collect, assess, explain, govern, and prove Windows security posture. It does not silently remediate production systems.

The project separates posture from observability. A system with missing evidence must not appear secure merely because collection failed. Approved exceptions remain visible exposure, not passing controls.

## Version 1.2 — Interoperability Preview

Version 1.2 extends the 1.x result contract without replacing the local Windows collector.

### Desired-state source adapters

- Read-only import of Windows Server 2025 OSConfig security-baseline compliance.
- Import of Microsoft Security Compliance Toolkit and GPO snapshot data.
- Source attribution for local observation, GPO intent, OSConfig intent, and imported assessment results.
- Conflict reporting when multiple desired-state sources configure incompatible values.

### Trend and portfolio reporting

- Build a time series from directories of Hardening Lens result files.
- Track recurring findings, evidence loss, exception debt, and remediation age.
- Generate fleet trend reports without requiring a database or persistent agent.
- Add stable operator-supplied asset identifiers for reliable correlation of redacted reports.

### App Control readiness

- Read App Control for Business policy mode, base policies, supplemental policies, and policy version.
- Summarize Code Integrity and AppLocker audit events over a configurable observation window.
- Report unsigned binaries, unresolved publishers, and enforcement blockers.
- Remain audit-first; no policy deployment or enforcement action is performed.

### Operational hardening

- Expand Windows live-smoke coverage by provider family.
- Add signed release metadata and verification documentation.
- Evaluate PowerShell Gallery publication after reproducible package validation.
- Continue adding narrowly scoped controls only where Hardening Lens provides evidence or governance value beyond native Microsoft baseline tooling.

### Exit criteria

Version 1.2 is complete when imported desired state can be reconciled against a local observation without changing result schema 1.0, trend reports can consume existing 1.x results, and App Control readiness can be demonstrated safely in audit mode.

## Version 2.0 — Policy and Evidence Engine

Version 2.0 is a deliberate major release. It introduces a new result contract and provider model instead of merely adding more registry checks.

### Result schema 2.0

Separate policy decision from evidence state.

Policy decisions:

- `Compliant`
- `NonCompliant`
- `Transitional`
- `Excepted`
- `NotApplicable`
- `NotEvaluated`

Evidence states:

- `Observed`
- `Partial`
- `Unsupported`
- `Unavailable`
- `CollectionError`

Every assessment records start and finish time, duration, source commit, tool version, catalog digest, resolved-policy digest, exception-register digest, control revision, and evidence-source authority.

### Provider registry

Replace the fixed probe enumeration with registered, trusted providers. Policy data may select a provider and parameters but may never embed arbitrary PowerShell code.

Initial provider families:

- Windows registry values
- CIM and Windows services
- Windows Firewall
- SMB and WinRM
- Microsoft Defender and ASR
- Windows LAPS
- Advanced Audit Policy and event-log configuration
- BitLocker, Secure Boot, Device Guard, and App Control
- OSConfig compliance
- Security Compliance Toolkit or GPO snapshot import
- Hardening Lens result import

### Composable policy packs

Move from four monolithic baselines to composable packs and overlays:

- Windows core
- Workstation
- Server core
- Windows Server 2019, 2022, and 2025
- Domain controller
- Azure Virtual Desktop session host
- Microsoft Defender
- ASR
- Windows LAPS
- App Control readiness

The resolver exposes every override and rejects ambiguous policy conflicts. It never relies on silent last-file-wins behavior.

### Desired versus observed reconciliation

Version 2 identifies four distinct conditions:

1. Secure desired state and secure observed state: compliant.
2. Secure desired state and insecure observed state: enforcement drift.
3. Insecure desired state and insecure observed state: policy-design finding.
4. Conflicting desired-state sources: management-plane conflict.

### Transition-aware drift

Drift events become explicit operational events:

- Regression
- Improvement
- Evidence lost
- Evidence restored
- Exception added, revoked, or expired
- Desired state changed
- Observed state changed
- Source conflict detected
- Assessment scope changed
- Control added, revised, or retired

### Scoring model 2.0

Expose three independent measures:

- Posture score
- Evidence coverage
- Exception debt

Category-balanced weights prevent a policy pack with many atomic controls from dominating the score solely because of its size. ASR rules become individual controls with a group roll-up rather than one composite result.

### Evidence bundles

Introduce a portable `.hlbundle` format containing:

- Result document
- Resolved policy
- Exception register
- Normalized evidence files
- Hash manifest
- Build and assessment provenance

Bundles support integrity verification and controlled redaction without requiring a central service.

### Compatibility and migration

- Provide a deterministic converter from result schema 1.0 to 2.0.
- Keep a documented support window for the 1.x module.
- Never reinterpret an old result as more complete than it originally was.
- Preserve control lineage through explicit control revisions and replacement metadata.

### Explicit non-goals

Version 2 does not become a vulnerability scanner, SIEM, network scanner, persistent endpoint agent, or automatic remediation platform. Microsoft 365 tenant assessment and FSLogix troubleshooting remain separate projects with their own trust boundaries.
