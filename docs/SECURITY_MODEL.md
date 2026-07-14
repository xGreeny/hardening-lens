# Security model

## Design objective

Hardening Lens is designed to answer:

> What security-relevant Windows state can be observed on this device, against this explicit baseline, with what evidence and what governed exceptions?

It is not designed to enforce settings, bypass endpoint controls, discover arbitrary network assets, or certify compliance.

## Privilege model

Many security providers expose incomplete data to standard users. The default command therefore requires elevation. `-AllowPartial` is explicit and preserves evidence gaps instead of silently treating them as pass.

Elevation increases the sensitivity of both the process and its output. Run from a trusted source path, verify releases, and protect report destinations.

## Input trust

| Input | Trust consideration |
|---|---|
| Built-in catalog | Versioned with module source and reviewed in CI |
| Built-in baselines | Versioned role contracts resolved only to catalog controls |
| Custom baseline | Can alter scope, severity, and expected parameters; requires review |
| Exception register | Can convert failures to accepted exposure; requires strict approval control |
| Existing result JSON | Used for reports, policy, and drift; validated by the module before consumption and still treated as untrusted data |

JSON inputs cannot embed executable PowerShell. Baselines reference known control IDs and named probes only.

## Collection behavior

Probes use documented local sources such as:

- 64-bit registry views;
- CIM classes;
- Windows networking and security cmdlets;
- Microsoft Defender cmdlets;
- Windows LAPS policy locations;
- Windows advanced audit APIs;
- event-log metadata;
- BitLocker and Secure Boot cmdlets.

Every probe catches operational failures and returns an explicit `Unknown` or `Error` result. A missing provider does not become a pass unless the control explicitly defines a secure operating-system default for an absent value.

Repeated controls can share a provider snapshot only within one in-memory collection context. The cache is discarded after the scan; it neither writes Windows state nor survives into another assessment. Probe dispatch is restricted to a built-in registry with explicit parameter allowlists.

## Provenance boundary

Schema 1.1 hashes the full catalog, effective resolved baseline, and optional exception register through edition-independent canonical JSON and SHA-256. These digests identify assessment inputs; they are not signatures and do not prove publisher authenticity. Verify release archives and source trust separately.

Capability and timing fields explain missing providers and collection cost without turning an unavailable provider into a passing result.

## Data sensitivity

Assessment output can disclose:

- host and domain identity;
- operating-system and security-product state;
- hardening gaps;
- service and protocol configuration;
- exception ownership and rationale;
- recovery or support workflow details.

Use access control, encryption at rest, retention limits, and approved transfer channels. `-Redact` replaces the detected computer name, domain, and current-user identity, but consumers must still inspect arbitrary evidence fields before external distribution.

## Report security

HTML reports are self-contained and do not fetch scripts, styles, fonts, or images from external hosts. Dynamic filtering uses inline JavaScript under a restrictive Content Security Policy. All control and evidence values are HTML-encoded before rendering.

The report contains links to first-party Microsoft guidance. Opening a link is a user action and occurs outside the report's local execution context.

## Exception risk

Exception files are high-impact security inputs. An attacker who can approve broad exceptions can reduce visible posture without changing the underlying device. Mitigations:

- restrict write access;
- require pull-request approval;
- narrow target and baseline scopes;
- require expiry and compensating controls;
- monitor exception-file changes;
- retain `originalStatus` in results;
- review `Excepted` findings separately from `Pass`.

## Known limitations

- Effective state can differ from management-plane intent or pending policy.
- Some providers are unavailable on specific Windows editions or when third-party security products are authoritative.
- A local privileged attacker can tamper with both configuration and collected evidence.
- A point-in-time scan cannot prove continuous enforcement.
- Application compatibility and business impact remain outside the assessment engine.
- Redaction is targeted, not a general-purpose anonymization system.
