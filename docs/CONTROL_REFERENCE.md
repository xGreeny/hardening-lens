# Control reference

Catalog version **1.0.1**, dated **2026-07-14**. The catalog contains **58** read-only controls. Every control records expected state, effective state, status, evidence, rationale, remediation guidance, and first-party Microsoft references.

> The catalog is an operational assessment model. It is not a verbatim Microsoft Security Baseline,
> CIS Benchmark, certification, or replacement for workload-specific risk assessment.

## Baseline coverage

| Baseline | Controls | Intended role |
|---|---:|---|
| `Workstation` | 54 | Opinionated posture profile for enterprise Windows 10/11 workstations managed through Group Policy, Intune, or equivalent controls. |
| `MemberServer` | 53 | Posture profile for domain-joined or centrally managed Windows member servers. |
| `DomainController` | 55 | Role-aware posture profile for Active Directory domain controllers with stricter identity, LDAP, LAPS, audit, and log-retention checks. |
| `AVDSessionHost` | 53 | Posture profile for pooled or personal Azure Virtual Desktop session hosts, balancing endpoint controls with multi-session operations. |

## Category index

| Category | Controls |
|---|---:|
| [Advanced Auditing](#advanced-auditing) | 7 |
| [Attack Surface Reduction](#attack-surface-reduction) | 2 |
| [Credential Protection](#credential-protection) | 7 |
| [Data Protection](#data-protection) | 1 |
| [Domain Controller](#domain-controller) | 4 |
| [Endpoint Protection](#endpoint-protection) | 10 |
| [Identity](#identity) | 3 |
| [Network Protection](#network-protection) | 8 |
| [Platform Security](#platform-security) | 1 |
| [Privilege Management](#privilege-management) | 3 |
| [Remote Administration](#remote-administration) | 5 |
| [Scripting Security](#scripting-security) | 1 |
| [Security Logging](#security-logging) | 6 |

## Baseline matrix

| Control | Severity | Category | Workstation | Member Server | Domain Controller | AVD Session Host |
|---|---|---|:---:|:---:|:---:|:---:|
| [`HL-ACC-001`](#hl-acc-001) | High | Identity | ✓ | ✓ | ✓ | ✓ |
| [`HL-ANON-001`](#hl-anon-001) | High | Identity | ✓ | ✓ | ✓ | ✓ |
| [`HL-ANON-002`](#hl-anon-002) | Medium | Identity | ✓ | ✓ | ✓ | ✓ |
| [`HL-ASR-001`](#hl-asr-001) | High | Attack Surface Reduction | ✓ | ✓ | ✓ | ✓ |
| [`HL-AUD-001`](#hl-aud-001) | High | Advanced Auditing | ✓ | ✓ | ✓ | ✓ |
| [`HL-AUD-002`](#hl-aud-002) | Medium | Advanced Auditing | ✓ | ✓ | ✓ | ✓ |
| [`HL-AUD-003`](#hl-aud-003) | High | Advanced Auditing | ✓ | ✓ | ✓ | ✓ |
| [`HL-AUD-004`](#hl-aud-004) | High | Advanced Auditing | ✓ | ✓ | ✓ | ✓ |
| [`HL-AUD-005`](#hl-aud-005) | High | Advanced Auditing | ✓ | ✓ | ✓ | ✓ |
| [`HL-AUD-006`](#hl-aud-006) | Medium | Advanced Auditing | ✓ | ✓ | ✓ | ✓ |
| [`HL-AUD-007`](#hl-aud-007) | High | Advanced Auditing | ✓ | ✓ | ✓ | ✓ |
| [`HL-AUTORUN-001`](#hl-autorun-001) | Medium | Attack Surface Reduction | ✓ | ✓ | ✓ | ✓ |
| [`HL-BIT-001`](#hl-bit-001) | High | Data Protection | ✓ | ✓ | — | — |
| [`HL-BOOT-001`](#hl-boot-001) | Medium | Platform Security | ✓ | ✓ | ✓ | ✓ |
| [`HL-CRED-001`](#hl-cred-001) | High | Credential Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-CRED-002`](#hl-cred-002) | High | Credential Protection | ✓ | ✓ | — | ✓ |
| [`HL-DC-001`](#hl-dc-001) | Critical | Domain Controller | — | — | ✓ | — |
| [`HL-DC-002`](#hl-dc-002) | High | Domain Controller | — | — | ✓ | — |
| [`HL-DC-003`](#hl-dc-003) | High | Domain Controller | — | — | ✓ | — |
| [`HL-DC-004`](#hl-dc-004) | High | Domain Controller | — | — | ✓ | — |
| [`HL-DEF-001`](#hl-def-001) | Critical | Endpoint Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-DEF-002`](#hl-def-002) | High | Endpoint Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-DEF-003`](#hl-def-003) | High | Endpoint Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-DEF-004`](#hl-def-004) | High | Endpoint Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-DEF-005`](#hl-def-005) | Medium | Endpoint Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-DEF-006`](#hl-def-006) | High | Endpoint Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-DEF-007`](#hl-def-007) | High | Endpoint Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-DEF-008`](#hl-def-008) | High | Endpoint Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-DEF-009`](#hl-def-009) | High | Endpoint Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-FW-001`](#hl-fw-001) | Critical | Network Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-FW-002`](#hl-fw-002) | High | Network Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-LAPS-001`](#hl-laps-001) | High | Credential Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-LAPS-002`](#hl-laps-002) | Medium | Credential Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-LAPS-003`](#hl-laps-003) | High | Credential Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-LOG-001`](#hl-log-001) | Medium | Security Logging | ✓ | ✓ | ✓ | ✓ |
| [`HL-LOG-002`](#hl-log-002) | Low | Security Logging | ✓ | ✓ | ✓ | ✓ |
| [`HL-LOG-003`](#hl-log-003) | Medium | Security Logging | ✓ | ✓ | ✓ | ✓ |
| [`HL-LSA-001`](#hl-lsa-001) | High | Credential Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-NET-001`](#hl-net-001) | Medium | Network Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-NTLM-001`](#hl-ntlm-001) | High | Credential Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-PS-001`](#hl-ps-001) | High | Scripting Security | ✓ | ✓ | ✓ | ✓ |
| [`HL-PSLOG-001`](#hl-pslog-001) | High | Security Logging | ✓ | ✓ | ✓ | ✓ |
| [`HL-PSLOG-002`](#hl-pslog-002) | Medium | Security Logging | ✓ | ✓ | ✓ | ✓ |
| [`HL-PSLOG-003`](#hl-pslog-003) | High | Security Logging | ✓ | ✓ | ✓ | ✓ |
| [`HL-RA-001`](#hl-ra-001) | Low | Remote Administration | ✓ | ✓ | ✓ | ✓ |
| [`HL-RDP-001`](#hl-rdp-001) | High | Remote Administration | ✓ | ✓ | ✓ | ✓ |
| [`HL-SMART-001`](#hl-smart-001) | Medium | Endpoint Protection | ✓ | — | — | ✓ |
| [`HL-SMB-001`](#hl-smb-001) | Critical | Network Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-SMB-002`](#hl-smb-002) | High | Network Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-SMB-003`](#hl-smb-003) | High | Network Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-SMB-004`](#hl-smb-004) | High | Network Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-SMB-005`](#hl-smb-005) | High | Network Protection | ✓ | ✓ | ✓ | ✓ |
| [`HL-SVC-001`](#hl-svc-001) | Medium | Remote Administration | ✓ | ✓ | ✓ | ✓ |
| [`HL-UAC-001`](#hl-uac-001) | Critical | Privilege Management | ✓ | ✓ | ✓ | ✓ |
| [`HL-UAC-002`](#hl-uac-002) | High | Privilege Management | ✓ | ✓ | ✓ | ✓ |
| [`HL-UAC-003`](#hl-uac-003) | Medium | Privilege Management | ✓ | ✓ | ✓ | ✓ |
| [`HL-WINRM-001`](#hl-winrm-001) | High | Remote Administration | ✓ | ✓ | ✓ | ✓ |
| [`HL-WINRM-002`](#hl-winrm-002) | High | Remote Administration | ✓ | ✓ | ✓ | ✓ |

## Advanced Auditing

### HL-AUD-001 — Credential Validation auditing captures success and failure

**Severity:** High  
**Probe:** `AuditPolicy`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `audit`, `authentication`

Reads the effective system audit policy through the native AuditQuerySystemPolicy API.

**Why it matters.** Credential validation events provide visibility into authentication attempts and failures.

**Remediation.** Configure Advanced Audit Policy: Account Logon > Credential Validation to Success and Failure.

**Parameters**

```json
{
  "requiredFlags": [
    "Success",
    "Failure"
  ],
  "subcategoryGuid": "0cce923f-69ae-11d9-bed3-505054503030",
  "subcategoryName": "Credential Validation"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)
- [https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy](https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)

### HL-AUD-002 — Security Group Management auditing captures success

**Severity:** Medium  
**Probe:** `AuditPolicy`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `audit`, `groups`

Reads effective auditing for changes to security groups.

**Why it matters.** Changes to privileged and access-control groups are high-value identity events.

**Remediation.** Configure Advanced Audit Policy: Account Management > Security Group Management to include Success.

**Parameters**

```json
{
  "requiredFlags": [
    "Success"
  ],
  "subcategoryGuid": "0cce9237-69ae-11d9-bed3-505054503030",
  "subcategoryName": "Security Group Management"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)
- [https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy](https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)

### HL-AUD-003 — User Account Management auditing captures success and failure

**Severity:** High  
**Probe:** `AuditPolicy`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `audit`, `accounts`

Reads effective auditing for user account lifecycle and modification events.

**Why it matters.** User account creation, deletion, enablement, and password changes require reliable audit visibility.

**Remediation.** Configure Advanced Audit Policy: Account Management > User Account Management to Success and Failure.

**Parameters**

```json
{
  "requiredFlags": [
    "Success",
    "Failure"
  ],
  "subcategoryGuid": "0cce9235-69ae-11d9-bed3-505054503030",
  "subcategoryName": "User Account Management"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)
- [https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy](https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)

### HL-AUD-004 — Process Creation auditing captures success

**Severity:** High  
**Probe:** `AuditPolicy`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `audit`, `process`

Reads effective auditing for process creation.

**Why it matters.** Process creation telemetry is foundational for Windows detection engineering and incident response.

**Remediation.** Configure Advanced Audit Policy: Detailed Tracking > Process Creation to include Success.

**Parameters**

```json
{
  "requiredFlags": [
    "Success"
  ],
  "subcategoryGuid": "0cce922b-69ae-11d9-bed3-505054503030",
  "subcategoryName": "Process Creation"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)
- [https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy](https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)

### HL-AUD-005 — Logon auditing captures success and failure

**Severity:** High  
**Probe:** `AuditPolicy`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `audit`, `logon`

Reads effective auditing for interactive and network logons.

**Why it matters.** Successful and failed logon events support authentication monitoring, investigation, and anomaly detection.

**Remediation.** Configure Advanced Audit Policy: Logon/Logoff > Logon to Success and Failure.

**Parameters**

```json
{
  "requiredFlags": [
    "Success",
    "Failure"
  ],
  "subcategoryGuid": "0cce9215-69ae-11d9-bed3-505054503030",
  "subcategoryName": "Logon"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)
- [https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy](https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)

### HL-AUD-006 — Special Logon auditing captures success

**Severity:** Medium  
**Probe:** `AuditPolicy`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `audit`, `privilege`

Reads effective auditing for logons assigned sensitive privileges.

**Why it matters.** Special logon events identify sessions receiving administrator-equivalent privileges.

**Remediation.** Configure Advanced Audit Policy: Logon/Logoff > Special Logon to include Success.

**Parameters**

```json
{
  "requiredFlags": [
    "Success"
  ],
  "subcategoryGuid": "0cce921b-69ae-11d9-bed3-505054503030",
  "subcategoryName": "Special Logon"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)
- [https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy](https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)

### HL-AUD-007 — Audit Policy Change auditing captures success

**Severity:** High  
**Probe:** `AuditPolicy`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `audit`, `policy-change`

Reads effective auditing for security audit policy changes.

**Why it matters.** Changes to audit policy can reduce visibility and should themselves be observable.

**Remediation.** Configure Advanced Audit Policy: Policy Change > Audit Policy Change to include Success.

**Parameters**

```json
{
  "requiredFlags": [
    "Success"
  ],
  "subcategoryGuid": "0cce922f-69ae-11d9-bed3-505054503030",
  "subcategoryName": "Audit Policy Change"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)
- [https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy](https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)


## Attack Surface Reduction

### HL-ASR-001 — Core Attack Surface Reduction rules are enforced

**Severity:** High  
**Probe:** `AsrRules`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `asr`, `defender`

Evaluates a curated set of ASR rules and reports missing, disabled, audit-only, warn, and block states per rule.

**Why it matters.** ASR rules disrupt common malware behaviors such as credential theft, malicious Office child processes, and ransomware activity.

**Remediation.** Pilot non-standard rules in Audit mode, tune legitimate impact, and move approved rules to Block or Warn. Avoid broad exclusions.

**Parameters**

```json
{
  "requiredRules": [
    {
      "allowedActions": [
        1,
        6
      ],
      "id": "56a863a9-875e-4185-98a7-b882c64b5ce5",
      "name": "Block abuse of exploited vulnerable signed drivers"
    },
    {
      "allowedActions": [
        1
      ],
      "id": "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
      "name": "Block credential stealing from LSASS"
    },
    {
      "allowedActions": [
        1,
        6
      ],
      "id": "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
      "name": "Block Office applications from creating child processes"
    },
    {
      "allowedActions": [
        1
      ],
      "id": "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
      "name": "Block Office applications from injecting code into other processes"
    },
    {
      "allowedActions": [
        1,
        6
      ],
      "id": "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
      "name": "Block execution of potentially obfuscated scripts"
    },
    {
      "allowedActions": [
        1,
        6
      ],
      "id": "d3e037e1-3eb8-44c8-a917-57927947596d",
      "name": "Block JavaScript or VBScript from launching downloaded executable content"
    },
    {
      "allowedActions": [
        1,
        6
      ],
      "id": "c1db55ab-c21a-4637-bb3f-a12568109d35",
      "name": "Use advanced protection against ransomware"
    }
  ]
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
- [https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-overview](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-overview)

### HL-AUTORUN-001 — AutoRun and AutoPlay are disabled

**Severity:** Medium  
**Probe:** `AutoRun`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `autorun`, `removable-media`

Checks machine policy values that disable AutoRun commands and AutoPlay behavior.

**Why it matters.** Automatic execution from removable media increases malware delivery risk.

**Remediation.** Disable AutoPlay for all drives and disable AutoRun commands through Group Policy or Intune.

**Parameters**

No control-specific parameters.

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)


## Credential Protection

### HL-CRED-001 — WDigest credential caching is disabled

**Severity:** High  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `wdigest`, `credentials`

Checks that WDigest does not retain reusable plaintext credentials in LSASS.

**Why it matters.** Enabling WDigest credential caching can expose plaintext credentials to memory-access attacks.

**Remediation.** Set UseLogonCredential to 0 under the WDigest security provider policy. A missing value is treated as the secure modern default.

**Parameters**

```json
{
  "expected": 0,
  "missingIsPass": true,
  "name": "UseLogonCredential",
  "operator": "Equals",
  "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)

### HL-CRED-002 — Credential Guard is running

**Severity:** High  
**Probe:** `CredentialGuard`  
**Baselines:** `Workstation`, `MemberServer`, `AVDSessionHost`  
**Tags:** `credential-guard`, `vbs`

Queries the Windows Device Guard provider and verifies that Credential Guard is active, not merely configured.

**Why it matters.** Credential Guard uses virtualization-based security to isolate secrets from the normal operating system.

**Remediation.** Enable virtualization-based security and Credential Guard with the deployment mode appropriate for the device. Validate VPN, Wi-Fi, delegation, and legacy authentication dependencies first.

**Parameters**

No control-specific parameters.

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/identity-protection/credential-guard/configure](https://learn.microsoft.com/windows/security/identity-protection/credential-guard/configure)

### HL-LAPS-001 — Windows LAPS password backup is configured

**Severity:** High  
**Probe:** `LapsBackup`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `laps`, `local-admin`

Evaluates the active Windows LAPS policy root and verifies that password backup targets Microsoft Entra ID or Active Directory.

**Why it matters.** Unique, rotated local administrator passwords reduce lateral movement and shared-password risk.

**Remediation.** Configure Windows LAPS BackupDirectory through Intune CSP or Group Policy and validate permissions to retrieve passwords.

**Parameters**

No control-specific parameters.

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings](https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings)

### HL-LAPS-002 — Windows LAPS password age is 30 days or less

**Severity:** Medium  
**Probe:** `LapsPasswordAge`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `laps`, `rotation`

Evaluates the effective PasswordAgeDays value from the active Windows LAPS policy root.

**Why it matters.** Regular rotation limits the useful lifetime of a disclosed local administrator password.

**Remediation.** Configure PasswordAgeDays to 30 or fewer days, balancing rotation with operational recovery requirements.

**Parameters**

```json
{
  "maximumDays": 30
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings](https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings)

### HL-LAPS-003 — Windows LAPS AD password encryption is enabled

**Severity:** High  
**Probe:** `LapsAdEncryption`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `laps`, `active-directory`

When LAPS backs up to Active Directory, verifies that password encryption is enabled. Entra-backed devices are marked not applicable.

**Why it matters.** AD password encryption narrows exposure of stored LAPS secrets and enables stronger authorization controls.

**Remediation.** Enable ADPasswordEncryptionEnabled for Active Directory-backed Windows LAPS after confirming the domain functional level and authorized decryptors.

**Parameters**

No control-specific parameters.

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings](https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings)

### HL-LSA-001 — LSA protection is enabled

**Severity:** High  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `lsa`, `credentials`

Checks whether LSASS is configured to run as a protected process.

**Why it matters.** LSA protection raises the bar for credential theft and blocks untrusted code from loading into LSASS.

**Remediation.** Enable "Configure LSASS to run as a protected process" in policy. Test authentication and security software compatibility before broad enforcement.

**Parameters**

```json
{
  "expected": [
    1,
    2
  ],
  "name": "RunAsPPL",
  "operator": "In",
  "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

### HL-NTLM-001 — LAN Manager authentication level refuses LM and NTLMv1

**Severity:** High  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `ntlm`, `legacy-auth`

Checks that only NTLMv2 responses are sent and LM/NTLM are refused.

**Why it matters.** LM and NTLMv1 provide materially weaker authentication than NTLMv2 or Kerberos.

**Remediation.** Set "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM" after auditing legacy dependencies.

**Parameters**

```json
{
  "expected": 5,
  "name": "LmCompatibilityLevel",
  "operator": "GreaterOrEqual",
  "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)


## Data Protection

### HL-BIT-001 — Operating system volume is protected by BitLocker

**Severity:** High  
**Probe:** `BitLocker`  
**Baselines:** `Workstation`, `MemberServer`  
**Tags:** `bitlocker`, `encryption`

Checks BitLocker protection and encryption state for the operating system volume.

**Why it matters.** Full-volume encryption protects data at rest when storage media or devices are lost or removed.

**Remediation.** Enable BitLocker using an approved protector and escrow recovery information in the organization-approved directory.

**Parameters**

```json
{
  "mountPoint": "SystemDrive"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/](https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/)


## Domain Controller

### HL-DC-001 — LDAP server signing is required

**Severity:** Critical  
**Probe:** `RegistryValue`  
**Baselines:** `DomainController`  
**Tags:** `ldap`, `domain-controller`

Checks the LDAPServerIntegrity policy on a domain controller.

**Why it matters.** Required LDAP signing helps prevent modification and relay of unsigned LDAP traffic.

**Remediation.** Set "Domain controller: LDAP server signing requirements" to Require signing after auditing unsigned binds.

**Parameters**

```json
{
  "expected": 2,
  "name": "LDAPServerIntegrity",
  "operator": "Equals",
  "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)

### HL-DC-002 — LDAP channel binding is enforced

**Severity:** High  
**Probe:** `RegistryValue`  
**Baselines:** `DomainController`  
**Tags:** `ldap`, `channel-binding`

Checks the LdapEnforceChannelBinding policy.

**Why it matters.** LDAP channel binding strengthens protection against credential relay over TLS.

**Remediation.** Audit compatibility, then set LdapEnforceChannelBinding to 2 (Always) through policy on domain controllers.

**Parameters**

```json
{
  "expected": 2,
  "name": "LdapEnforceChannelBinding",
  "operator": "Equals",
  "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)

### HL-DC-003 — LM password hashes are not stored

**Severity:** High  
**Probe:** `RegistryValue`  
**Baselines:** `DomainController`  
**Tags:** `lm-hash`, `domain-controller`

Checks the NoLMHash security option.

**Why it matters.** LM hashes are cryptographically weak and should not be generated for future password changes.

**Remediation.** Enable "Network security: Do not store LAN Manager hash value on next password change." Existing hashes disappear when passwords are changed.

**Parameters**

```json
{
  "expected": 1,
  "missingIsPassOnBuildAtLeast": 26100,
  "name": "NoLMHash",
  "operator": "Equals",
  "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)

### HL-DC-004 — Windows LAPS backs up DSRM passwords

**Severity:** High  
**Probe:** `LapsDsrmBackup`  
**Baselines:** `DomainController`  
**Tags:** `laps`, `dsrm`, `domain-controller`

For AD-backed Windows LAPS on domain controllers, verifies that DSRM password backup is enabled.

**Why it matters.** Managed and rotated DSRM passwords improve recoverability without retaining shared static secrets.

**Remediation.** Enable ADBackupDSRMPassword in Windows LAPS Group Policy and validate authorized recovery procedures.

**Parameters**

No control-specific parameters.

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings](https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings)


## Endpoint Protection

### HL-DEF-001 — Microsoft Defender real-time protection is enabled

**Severity:** Critical  
**Probe:** `DefenderStatus`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `defender`, `real-time`

Checks the live Defender real-time protection state.

**Why it matters.** Real-time protection inspects activity as files and processes are accessed.

**Remediation.** Enable real-time protection or document an approved third-party endpoint protection exception.

**Parameters**

```json
{
  "expected": true,
  "operator": "Equals",
  "property": "RealTimeProtectionEnabled"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)

### HL-DEF-002 — Cloud-delivered protection is enabled

**Severity:** High  
**Probe:** `DefenderPreference`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `defender`, `cloud`

Checks Defender MAPS reporting configuration.

**Why it matters.** Cloud-delivered protection improves detection of new and rapidly changing threats.

**Remediation.** Enable cloud-delivered protection at the organization-approved membership level.

**Parameters**

```json
{
  "expected": [
    1,
    2
  ],
  "operator": "In",
  "property": "MAPSReporting"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)

### HL-DEF-003 — Behavior monitoring is enabled

**Severity:** High  
**Probe:** `DefenderStatus`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `defender`, `behavior`

Checks the live Defender behavior monitoring state.

**Why it matters.** Behavior monitoring detects suspicious runtime activity that static signatures can miss.

**Remediation.** Enable behavior monitoring in Microsoft Defender Antivirus policy.

**Parameters**

```json
{
  "expected": true,
  "operator": "Equals",
  "property": "BehaviorMonitorEnabled"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)

### HL-DEF-004 — Downloaded files and attachments are scanned

**Severity:** High  
**Probe:** `DefenderStatus`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `defender`, `ioav`

Checks IOAV protection state.

**Why it matters.** Scanning downloaded files and attachments reduces exposure from common delivery channels.

**Remediation.** Enable IOAV protection in Microsoft Defender Antivirus policy.

**Parameters**

```json
{
  "expected": true,
  "operator": "Equals",
  "property": "IoavProtectionEnabled"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)

### HL-DEF-005 — Automatic sample submission is enabled

**Severity:** Medium  
**Probe:** `DefenderPreference`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `defender`, `samples`

Checks that Defender is allowed to submit safe or all samples automatically.

**Why it matters.** Sample submission improves cloud analysis and response time for unknown files.

**Remediation.** Configure sample submission according to organizational privacy requirements; avoid Never Send unless formally accepted.

**Parameters**

```json
{
  "expected": [
    1,
    3
  ],
  "operator": "In",
  "property": "SubmitSamplesConsent"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)

### HL-DEF-006 — Potentially unwanted application protection is enabled

**Severity:** High  
**Probe:** `DefenderPreference`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `defender`, `pua`

Checks that PUA protection is configured to block.

**Why it matters.** PUA blocking reduces adware, bundlers, and software that weakens device security.

**Remediation.** Set potentially unwanted application protection to Block.

**Parameters**

```json
{
  "expected": 1,
  "operator": "Equals",
  "property": "PUAProtection",
  "warningValues": [
    2
  ]
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)

### HL-DEF-007 — Microsoft Defender tamper protection is enabled

**Severity:** High  
**Probe:** `DefenderStatus`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `defender`, `tamper-protection`

Checks the Defender-reported tamper protection state.

**Why it matters.** Tamper protection helps prevent unauthorized changes to core endpoint protection settings.

**Remediation.** Enable tamper protection through the Microsoft Defender portal or supported management channel.

**Parameters**

```json
{
  "expected": true,
  "operator": "Equals",
  "property": "IsTamperProtected"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)

### HL-DEF-008 — Defender signatures are recent

**Severity:** High  
**Probe:** `DefenderSignatureAge`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `defender`, `signatures`

Calculates the age of the active antivirus signature update.

**Why it matters.** Stale signatures reduce detection coverage, particularly when cloud protection is unavailable.

**Remediation.** Restore update connectivity and investigate update channel, proxy, or platform health issues.

**Parameters**

```json
{
  "maximumAgeDays": 3
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)

### HL-DEF-009 — Defender network protection is enabled

**Severity:** High  
**Probe:** `DefenderPreference`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `defender`, `network-protection`

Checks the Defender network protection mode.

**Why it matters.** Network protection blocks connections to malicious or low-reputation destinations from supported processes.

**Remediation.** Deploy network protection in audit mode first, review impact, then enable block mode.

**Parameters**

```json
{
  "expected": 1,
  "operator": "Equals",
  "property": "EnableNetworkProtection",
  "warningValues": [
    2
  ]
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)

### HL-SMART-001 — Microsoft Defender SmartScreen is enforced

**Severity:** Medium  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `AVDSessionHost`  
**Tags:** `smartscreen`, `reputation`

Checks the machine policy that enables SmartScreen.

**Why it matters.** SmartScreen helps block malicious and low-reputation downloads and sites.

**Remediation.** Enable Microsoft Defender SmartScreen through Windows security baseline or Intune policy.

**Parameters**

```json
{
  "expected": 1,
  "name": "EnableSmartScreen",
  "operator": "Equals",
  "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/](https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/)


## Identity

### HL-ACC-001 — Built-in Guest account is disabled

**Severity:** High  
**Probe:** `LocalGuestAccount`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `account`, `local-security`

Checks the local account identified by the well-known RID 501 rather than relying on a localized account name.

**Why it matters.** An enabled guest account provides an unnecessary logon path with weak accountability.

**Remediation.** Disable the built-in Guest account through Group Policy, Intune, or local security policy and verify that no application depends on it.

**Parameters**

No control-specific parameters.

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)

### HL-ANON-001 — Anonymous SAM enumeration is restricted

**Severity:** High  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `anonymous`, `sam`

Checks the RestrictAnonymousSAM security option.

**Why it matters.** Anonymous enumeration can disclose account information useful for reconnaissance.

**Remediation.** Set "Network access: Do not allow anonymous enumeration of SAM accounts" to Enabled.

**Parameters**

```json
{
  "expected": 1,
  "name": "RestrictAnonymousSAM",
  "operator": "Equals",
  "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)

### HL-ANON-002 — Anonymous access is restricted

**Severity:** Medium  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `anonymous`, `network`

Checks the RestrictAnonymous security option.

**Why it matters.** Restricting anonymous access reduces unauthenticated information disclosure and legacy null-session behavior.

**Remediation.** Set "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to Enabled where compatible.

**Parameters**

```json
{
  "expected": 1,
  "name": "RestrictAnonymous",
  "operator": "GreaterOrEqual",
  "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)


## Network Protection

### HL-FW-001 — Windows Firewall is enabled for every profile

**Severity:** Critical  
**Probe:** `FirewallProfiles`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `firewall`

Checks Domain, Private, and Public firewall profile state.

**Why it matters.** Host firewalls limit lateral movement and provide protection when network controls are absent or bypassed.

**Remediation.** Enable Windows Firewall for all profiles and deploy explicit allow rules for required management and application traffic.

**Parameters**

```json
{
  "requireDefaultInboundBlock": false,
  "requireEnabled": true
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring)

### HL-FW-002 — Default inbound firewall action is Block

**Severity:** High  
**Probe:** `FirewallProfiles`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `firewall`, `default-deny`

Checks the default inbound action for every firewall profile.

**Why it matters.** A default-deny inbound posture limits unplanned exposure when no explicit rule exists.

**Remediation.** Set the default inbound action to Block for Domain, Private, and Public profiles, then maintain explicit allow rules.

**Parameters**

```json
{
  "requireDefaultInboundBlock": true,
  "requireEnabled": true
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring)

### HL-NET-001 — LLMNR is disabled

**Severity:** Medium  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `llmnr`, `name-resolution`

Checks the policy that disables multicast name resolution.

**Why it matters.** LLMNR can enable name-resolution poisoning and credential relay when DNS resolution fails.

**Remediation.** Enable "Turn off multicast name resolution" after validating name-resolution dependencies.

**Parameters**

```json
{
  "expected": 0,
  "name": "EnableMulticast",
  "operator": "Equals",
  "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)

### HL-SMB-001 — SMBv1 server component is disabled

**Severity:** Critical  
**Probe:** `WindowsOptionalFeature`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `smb`, `legacy`

Checks all known SMBv1 server feature names.

**Why it matters.** SMBv1 is obsolete and lacks modern security protections.

**Remediation.** Remove or disable the SMB 1.0/CIFS server component after identifying legacy dependencies.

**Parameters**

```json
{
  "evaluationMode": "FirstPresent",
  "expectedState": "Disabled",
  "features": [
    "SMB1Protocol-Server",
    "SMB1Protocol"
  ]
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3](https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)

### HL-SMB-002 — SMBv1 client component is disabled

**Severity:** High  
**Probe:** `WindowsOptionalFeature`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `smb`, `legacy`

Checks all known SMBv1 client feature names.

**Why it matters.** An SMBv1 client can be coerced into using an obsolete protocol against malicious or legacy servers.

**Remediation.** Remove or disable the SMB 1.0/CIFS client component after identifying legacy dependencies.

**Parameters**

```json
{
  "evaluationMode": "FirstPresent",
  "expectedState": "Disabled",
  "features": [
    "SMB1Protocol-Client",
    "SMB1Protocol"
  ]
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3](https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)

### HL-SMB-003 — SMB server signing is required

**Severity:** High  
**Probe:** `SmbServer`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `smb`, `signing`

Checks RequireSecuritySignature on the local SMB server.

**Why it matters.** Required signing helps protect SMB traffic from tampering and relay attacks.

**Remediation.** Require SMB server signing through Group Policy or the SMB server configuration. Validate legacy clients before rollout.

**Parameters**

```json
{
  "expected": true,
  "property": "RequireSecuritySignature"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/storage/file-server/smb-signing](https://learn.microsoft.com/windows-server/storage/file-server/smb-signing)

### HL-SMB-004 — SMB client signing is required

**Severity:** High  
**Probe:** `SmbClient`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `smb`, `signing`

Checks RequireSecuritySignature on the local SMB client.

**Why it matters.** Required client signing helps prevent downgrade and relay scenarios when connecting to file services.

**Remediation.** Require SMB client signing through Group Policy or SMB client configuration. Validate legacy appliances first.

**Parameters**

```json
{
  "expected": true,
  "property": "RequireSecuritySignature"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/storage/file-server/smb-signing](https://learn.microsoft.com/windows-server/storage/file-server/smb-signing)

### HL-SMB-005 — Insecure SMB guest authentication is disabled

**Severity:** High  
**Probe:** `SmbClient`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `smb`, `guest`

Checks EnableInsecureGuestLogons on the SMB client.

**Why it matters.** Guest SMB authentication removes identity assurance and does not support normal signing and encryption guarantees.

**Remediation.** Disable insecure guest logons and provide authenticated access to file services.

**Parameters**

```json
{
  "expected": false,
  "property": "EnableInsecureGuestLogons"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/storage/file-server/smb-signing](https://learn.microsoft.com/windows-server/storage/file-server/smb-signing)


## Platform Security

### HL-BOOT-001 — Secure Boot is enabled

**Severity:** Medium  
**Probe:** `SecureBoot`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `secure-boot`, `firmware`

Queries the firmware Secure Boot state.

**Why it matters.** Secure Boot helps prevent untrusted boot components from loading before Windows.

**Remediation.** Enable UEFI Secure Boot after validating firmware, operating system, and virtualization support.

**Parameters**

No control-specific parameters.

**Microsoft guidance**

- [https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot](https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot)


## Privilege Management

### HL-UAC-001 — User Account Control is enabled

**Severity:** Critical  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `uac`, `privilege`

Verifies that all administrators run in Admin Approval Mode.

**Why it matters.** Disabling UAC removes an important privilege boundary and weakens multiple Windows security features.

**Remediation.** Set "User Account Control: Run all administrators in Admin Approval Mode" to Enabled and restart the device.

**Parameters**

```json
{
  "expected": 1,
  "name": "EnableLUA",
  "operator": "Equals",
  "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration](https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration)

### HL-UAC-002 — Administrator elevation prompts require consent

**Severity:** High  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `uac`, `privilege`

Checks that administrator elevation is not configured to occur silently.

**Why it matters.** Silent elevation makes malicious or accidental privileged execution harder to detect and contain.

**Remediation.** Configure the administrator elevation prompt to "Prompt for consent for non-Windows binaries" or a stricter credential prompt.

**Parameters**

```json
{
  "expected": [
    1,
    2,
    3,
    4,
    5
  ],
  "name": "ConsentPromptBehaviorAdmin",
  "operator": "In",
  "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration](https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration)

### HL-UAC-003 — Built-in Administrator uses Admin Approval Mode

**Severity:** Medium  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `uac`, `privilege`

Checks Admin Approval Mode for the built-in Administrator account.

**Why it matters.** The built-in Administrator otherwise runs with a full token without UAC consent.

**Remediation.** Set "User Account Control: Admin Approval Mode for the Built-in Administrator account" to Enabled.

**Parameters**

```json
{
  "expected": 1,
  "name": "FilterAdministratorToken",
  "operator": "Equals",
  "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration](https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration)


## Remote Administration

### HL-RA-001 — Solicited Remote Assistance is disabled

**Severity:** Low  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `remote-assistance`

Checks whether users can request Remote Assistance.

**Why it matters.** Remote Assistance adds an interactive remote-access path that should be explicitly justified.

**Remediation.** Disable "Configure Solicited Remote Assistance" unless the support model requires it; use a documented exception when enabled.

**Parameters**

```json
{
  "expected": 0,
  "name": "fAllowToGetHelp",
  "operator": "Equals",
  "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)

### HL-RDP-001 — Remote Desktop requires Network Level Authentication

**Severity:** High  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `rdp`, `nla`

Checks that RDP requires authentication before creating a full interactive session.

**Why it matters.** NLA reduces pre-authentication attack surface and resource consumption.

**Remediation.** Enable "Require user authentication for remote connections by using Network Level Authentication."

**Parameters**

```json
{
  "expected": 1,
  "name": "UserAuthentication",
  "operator": "Equals",
  "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access](https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access)

### HL-SVC-001 — Remote Registry service is disabled

**Severity:** Medium  
**Probe:** `Service`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `service`, `remote-registry`

Checks that the Remote Registry service is disabled and not running.

**Why it matters.** Remote Registry expands the remote administration surface and is unnecessary for many systems.

**Remediation.** Disable the Remote Registry service unless a documented management dependency exists.

**Parameters**

```json
{
  "name": "RemoteRegistry",
  "requireStopped": true,
  "startupType": "Disabled"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)

### HL-WINRM-001 — WinRM Basic authentication is disabled

**Severity:** High  
**Probe:** `WinRM`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `winrm`, `authentication`

Checks Basic authentication on both WinRM client and service configuration.

**Why it matters.** Basic authentication relies on transport protection and is unnecessary in most domain-managed environments.

**Remediation.** Disable Basic authentication for WinRM client and service. Use Kerberos, certificate authentication, or another approved mechanism.

**Parameters**

```json
{
  "expected": false,
  "property": "Basic",
  "targets": [
    "Client",
    "Service"
  ]
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management](https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)

### HL-WINRM-002 — WinRM unencrypted traffic is disabled

**Severity:** High  
**Probe:** `WinRM`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `winrm`, `encryption`

Checks AllowUnencrypted on both WinRM client and service configuration.

**Why it matters.** Allowing unencrypted WinRM traffic can expose management data and credentials.

**Remediation.** Disable unencrypted WinRM traffic and use HTTPS or message-level protection provided by supported authentication protocols.

**Parameters**

```json
{
  "expected": false,
  "property": "AllowUnencrypted",
  "targets": [
    "Client",
    "Service"
  ]
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management](https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)


## Scripting Security

### HL-PS-001 — Windows PowerShell 2.0 is disabled

**Severity:** High  
**Probe:** `WindowsOptionalFeature`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `powershell`, `legacy`

Checks known Windows PowerShell 2.0 optional feature names.

**Why it matters.** PowerShell 2.0 lacks modern logging and security capabilities and can be abused for downgrade attacks.

**Remediation.** Remove the Windows PowerShell 2.0 optional feature after validating legacy script compatibility.

**Parameters**

```json
{
  "evaluationMode": "AllDisabled",
  "expectedState": "Disabled",
  "features": [
    "MicrosoftWindowsPowerShellV2Root",
    "MicrosoftWindowsPowerShellV2"
  ]
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5)


## Security Logging

### HL-LOG-001 — Security event log has sufficient capacity

**Severity:** Medium  
**Probe:** `EventLog`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `event-log`, `security`

Checks the configured maximum Security log size.

**Why it matters.** Undersized logs can overwrite evidence before it is collected or investigated.

**Remediation.** Increase the Security log maximum size and forward relevant events to centralized storage.

**Parameters**

```json
{
  "logName": "Security",
  "minimumSizeBytes": 536870912
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)

### HL-LOG-002 — System event log has sufficient capacity

**Severity:** Low  
**Probe:** `EventLog`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `event-log`, `system`

Checks the configured maximum System log size.

**Why it matters.** Adequate retention supports troubleshooting and incident reconstruction.

**Remediation.** Increase the System log maximum size based on event volume and forwarding latency.

**Parameters**

```json
{
  "logName": "System",
  "minimumSizeBytes": 134217728
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)

### HL-LOG-003 — PowerShell Operational log has sufficient capacity

**Severity:** Medium  
**Probe:** `EventLog`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `event-log`, `powershell`

Checks the Microsoft-Windows-PowerShell/Operational log size and enabled state.

**Why it matters.** PowerShell telemetry can be high volume and valuable evidence can be lost if the log is too small.

**Remediation.** Enable the PowerShell Operational log and increase its maximum size based on script activity and forwarding latency.

**Parameters**

```json
{
  "logName": "Microsoft-Windows-PowerShell/Operational",
  "minimumSizeBytes": 67108864,
  "requireEnabled": true
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5)

### HL-PSLOG-001 — PowerShell Script Block Logging is enabled

**Severity:** High  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `powershell`, `logging`

Checks policy-backed Script Block Logging.

**Why it matters.** Script Block Logging records de-obfuscated PowerShell content and provides high-value investigation telemetry.

**Remediation.** Enable "Turn on PowerShell Script Block Logging." Protect and forward the PowerShell Operational log.

**Parameters**

```json
{
  "expected": 1,
  "name": "EnableScriptBlockLogging",
  "operator": "Equals",
  "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5)

### HL-PSLOG-002 — PowerShell Module Logging is enabled

**Severity:** Medium  
**Probe:** `PowerShellModuleLogging`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `powershell`, `logging`

Checks module logging and verifies that at least one module pattern is configured.

**Why it matters.** Module logging adds pipeline and command visibility that complements Script Block Logging.

**Remediation.** Enable PowerShell Module Logging and configure approved module patterns, commonly "*" for broad visibility after sizing log collection.

**Parameters**

No control-specific parameters.

**Microsoft guidance**

- [https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5)

### HL-PSLOG-003 — Process creation events include command lines

**Severity:** High  
**Probe:** `RegistryValue`  
**Baselines:** `Workstation`, `MemberServer`, `DomainController`, `AVDSessionHost`  
**Tags:** `process-creation`, `logging`

Checks whether event 4688 includes process command-line data.

**Why it matters.** Command-line context substantially improves investigation and detection quality for process creation events.

**Remediation.** Enable "Include command line in process creation events." Restrict Security log access because arguments can contain sensitive data.

**Parameters**

```json
{
  "expected": 1,
  "name": "ProcessCreationIncludeCmdLine_Enabled",
  "operator": "Equals",
  "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"
}
```

**Microsoft guidance**

- [https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)
