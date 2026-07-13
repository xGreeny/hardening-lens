# Security policy

## Supported version

Security fixes are applied to the latest released major version. The current supported line is `1.x`.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, assessment evidence, host identifiers, or a method to bypass control evaluation.

Report the issue through **GitHub Security Advisories** in this repository. Include:

- the affected version and PowerShell edition;
- the control, probe, or report path involved;
- a minimal reproduction using synthetic data;
- the security impact;
- any suggested mitigation.

Reports are acknowledged as soon as practical. A fix, advisory, and release are coordinated before public disclosure when the report is confirmed.

## Assessment data

Hardening Lens reports can reveal security configuration, computer names, domain names, software state, and exception details. Treat reports as security-sensitive operational data. Use `-Redact` before sharing outside the administrative boundary, review the output manually, and store reports according to the organization's evidence-retention policy.

## Trust boundaries

Hardening Lens is read-only by design, but it executes with the privileges of the calling process and reads local security configuration. Run source and releases only from a trusted location. Verify release checksums, review custom baselines and exception registers through change control, and do not run unreviewed forks in privileged sessions.
