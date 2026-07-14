# Baselines

Module, catalog, and baseline versions have independent lifecycles. Hardening Lens 1.1.0 ships catalog and built-in baseline content 1.0.1; a module update does not imply that control intent changed. Scan provenance records each identity and the effective baseline digest separately.

Validate custom content before deployment with:

```powershell
Test-HardeningLensBaseline -Path .\custom-baseline.json
```

Hardening Lens ships four role-aware profiles. They are deliberately opinionated operational checks built from current Microsoft security guidance and common Windows engineering requirements. They are not copied vendor baselines and do not establish compliance by themselves.

| Baseline | Controls | Selection | Primary emphasis |
|---|---:|---|---|
| `Workstation` | 54 | Automatic for `ProductType=1` | Endpoint protection, BitLocker, SmartScreen, credential protection, PowerShell logging |
| `MemberServer` | 53 | Automatic for `ProductType=3` | Server attack surface, remote administration, signing, audit, event retention |
| `DomainController` | 55 | Automatic for `ProductType=2` | LDAP protection, DSRM management, credential exposure, high-value audit telemetry |
| `AVDSessionHost` | 53 | Explicit selection | Multi-session endpoint protection, AVD-compatible logging, session-host hardening |

## Selection behavior

`-Baseline Auto` resolves the role from `Win32_OperatingSystem.ProductType`:

```text
1  Workstation
2  DomainController
3  MemberServer
```

`AVDSessionHost` is never inferred because Windows does not expose a reliable local product role that distinguishes an AVD host from another workstation or member server. Select it explicitly:

```powershell
Invoke-HardeningLens -Baseline AVDSessionHost
```

An explicitly selected baseline is retained even when the detected role differs. Hardening Lens emits a warning so the mismatch remains visible.

## Baseline composition

A baseline stores control IDs plus optional parameter or severity overrides. The catalog owns the control's title, rationale, remediation, probe, tags, and references. This separation keeps control meaning stable while allowing role-specific thresholds.

Example: the Security log capacity is role-specific.

```json
{
  "id": "HL-LOG-001",
  "parameters": {
    "minimumSizeBytes": 1073741824
  }
}
```

## Role-specific decisions

### Workstation

The Workstation profile includes BitLocker, SmartScreen, Credential Guard, and endpoint controls suitable for managed user devices. It does not assume a specific MDM or Group Policy delivery mechanism; probes inspect effective local state.

### Member Server

The Member Server profile emphasizes secure remote administration, SMB signing, service reduction, Windows LAPS, Microsoft Defender, advanced auditing, and sufficient log retention. Application servers can require reviewed exceptions for authentication, services, or remote-management settings.

### Domain Controller

The Domain Controller profile adds controls for LDAP server signing, LDAP channel binding, LM hash storage, and Windows LAPS DSRM backup. BitLocker is not included by default because encryption architecture and recovery ownership for domain controllers require an explicit organizational decision; it can be added through a custom baseline.

### AVD Session Host

The AVD profile uses the endpoint-oriented control set but avoids assuming that every workstation-specific feature is appropriate for multi-session operation. Remote support and line-of-business application requirements should be represented through scoped, expiring exceptions rather than silent exclusions.

## Versioning

Baseline versions follow semantic versioning:

- **Patch:** wording, references, or probe fixes that do not intentionally change expected posture.
- **Minor:** additive controls or backward-compatible parameters.
- **Major:** removed controls, changed default expectations, or scoring behavior that can materially change results.

Scan results record the baseline name and version so drift can be interpreted against the correct assessment contract.

## Full matrix

The generated [control reference](CONTROL_REFERENCE.md#baseline-matrix) shows every control and its built-in baseline membership.
