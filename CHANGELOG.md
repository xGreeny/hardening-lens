# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-07-14

### Added

- Record catalog, effective-baseline, and exception-register SHA-256 provenance in result schema 1.1.
- Report collection and per-probe durations plus a deterministic capability snapshot.
- Cache shared provider snapshots within one assessment and dispatch probes through an explicit parameter-aware registry.
- Expose `Invoke-HardeningLensFleet` as a pipeline-capable module command with unambiguous host correlation and transactionally committed run directories.
- Add automation policy gates for findings, score, evidence coverage, partial collection, and expired exceptions.
- Add structured baseline validation plus serialized, atomic exception lifecycle updates that require re-approval after material changes.
- Explain drift through field-level before/after snapshots, baseline provenance, catalog provenance, and evidence-coverage delta.

### Changed

- Accept schema 1.0 scan inputs as a controlled legacy format while emitting schema 1.1 for new scans and comparisons.
- Decouple the module release from catalog and baseline content versions; module 1.1.0 continues to ship catalog and baseline content 1.0.1.
- Keep the legacy fleet script as a compatibility wrapper over the public module API.

## [1.0.1] - 2026-07-14

### Security

- Validate imported scan results before report generation and drift comparison.
- Harden HTML attributes and reference links, and neutralize spreadsheet formulas in CSV exports.

### Fixed

- Prevent public catalog objects from mutating the module's internal cache.
- Canonicalize structured evidence for deterministic drift comparisons and reject duplicate result IDs.
- Preserve every requested fleet target, including transport and collection failures.
- Prevent report and fleet artifact collisions from silently overwriting earlier output.
- Fail the quality gate on Pester discovery, block, or container failures.

### Changed

- Pin emitted schema identifiers to the immutable `v1.0.1` release.
- Verify the packaged module during the release workflow.

## [1.0.0] - 2026-07-12

### Added

- 58 curated, read-only Windows security posture controls.
- Role-aware baselines for Workstation, Member Server, Domain Controller, and Azure Virtual Desktop Session Host.
- Evidence collection across registry policy, Windows Firewall, SMB, WinRM, Windows LAPS, Microsoft Defender, ASR, advanced audit policy, event logs, BitLocker, Secure Boot, optional features, services, and PowerShell logging.
- Severity-weighted hardening score and independent evidence-coverage metric.
- Governed exception register with target and baseline scope, approval metadata, expiry, and compensating controls.
- Custom baseline inheritance, control exclusion, parameter override, and severity override.
- Drift comparison for status, severity, expected state, observed state, evidence, and exception governance, with same-target and same-baseline safeguards plus JSON and Markdown output.
- Self-contained HTML, JSON, and CSV reports.
- Redaction of computer, domain, and current-user identifiers.
- Fleet collection helper for PowerShell remoting.
- JSON Schemas, Pester tests, PSScriptAnalyzer policy, dual-edition CI, scheduled Windows live-collection smoke tests, release packaging, and SHA-256 checksums.
