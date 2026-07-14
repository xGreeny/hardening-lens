# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

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
