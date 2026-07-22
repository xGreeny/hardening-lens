# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [1.2.2] - 2026-07-21

### Fixed

- Resolve relative output paths against the PowerShell location instead of the process working directory. `Compare-HardeningLensResult -OutputPath .\drift.md`, `New-HardeningLensExceptionFile`, and the atomic register writer previously created files in the directory where the PowerShell process started rather than the caller's current directory.

## [1.2.1] - 2026-07-21

### Fixed

- Evaluate the domain built-in Guest account (RID 501) on domain controllers instead of returning `Unknown`; domain controllers have no local SAM. The Unknown path now records search evidence instead of null.
- Report a server without the installed BitLocker feature as `Fail` ('BitLocker feature not installed') instead of `Unknown`; on server SKUs the absent optional feature proves the volume is unprotected. Client SKUs keep `Unknown` as a collection gap.
- Give `HL-FW-002` its own expected state and message when firewall profiles are disabled, instead of repeating the profile-enablement wording of `HL-FW-001`.

### Changed

- Resolve every optional-feature control from one cached `Get-WindowsOptionalFeature` listing per scan instead of separate per-feature DISM queries, roughly halving collection time on typical servers. The per-feature query path remains as fallback when the listing itself fails.
- Retry fleet run directory moves within a small bounded window when antivirus or indexing services briefly lock freshly written files. Genuine permission errors and missing directories still fail immediately, and the transactional commit guarantees are unchanged.
- Explain Defender status failures that occur while `AMRunningMode` is `Normal`: the checked protection is switched off rather than superseded by a third-party platform.

## [1.2.0] - 2026-07-21

### Added

- Classify collection failures through exception types and locale-independent error codes instead of English message text. Missing elevation and privileges become explainable `Unknown` results for Secure Boot and advanced audit policy, and a stopped Microsoft Defender service (0x800106BA) is reported as `Unknown` with explicit guidance instead of a generic error.
- Record third-party antivirus registrations from the Security Center and the Defender running mode as evidence, so a passive or disabled Defender can be judged against the actually authoritative endpoint protection platform.
- Add `Export-HardeningLensFleetReport`: one aggregated, self-contained fleet HTML report with per-host scores, failed collections, and the controls affecting the most hosts, under the same encoding and Content Security Policy rules as the single-host report.
- Ship control catalog 1.1.0 with six new controls (64 total): memory integrity (HVCI), Sudo for Windows, domain-controller Print Spooler exposure, and session clipboard redirection, drive redirection, and screen capture protection for AVD session hosts. Baselines: Workstation 56, MemberServer 54, DomainController 57, AVDSessionHost 58 controls, all versioned 1.1.0.
- Publish tagged releases to the PowerShell Gallery when a gallery API key is configured.

### Changed

- Extend the scheduled Windows live smoke test to collect the full member-server baseline and fail when robust probe classes return `Error`.
- Verify generated demo assets in the quality gate (`tools/generate_demo_assets.py --check`) and refresh the committed examples from the current generator.

## [1.1.1] - 2026-07-21

### Fixed

- Marshal the advanced audit policy structure inside the embedded native helper. The Windows PowerShell 5.1 method binder could select the `PtrToStructure(IntPtr, object)` overload and fail every `HL-AUD-*` control with "The specified structure must be blittable or have layout information."
- Treat an optional feature that the operating system no longer ships as absent instead of a collection error. Windows 11 24H2 removes the Windows PowerShell 2.0 features entirely, which previously turned `HL-PS-001` into `Error` even though absence satisfies the control.

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
