# Governed exceptions

Hardening exceptions are security decisions, not scan suppressions. Hardening Lens therefore requires ownership, rationale, scope, expiry, approval metadata, and compensating controls before an exception can change a result to `Excepted`.

## Lifecycle

| Status | Applied during assessment | Intended use |
|---|:---:|---|
| `Draft` | No | Proposed exception under review |
| `Approved` | Yes, when valid and in scope | Time-bounded accepted exposure |
| `Revoked` | No | Approval withdrawn or superseded |

An Approved exception is ignored after its expiry date. The original result status is retained in `originalStatus`.

## Required approval data

Approved entries require:

- a catalog control ID;
- owner and business/technical rationale;
- change, risk, or incident ticket;
- one or more host target patterns;
- optional baseline scope;
- approver and approval date;
- expiry date;
- at least one compensating control.

```json
{
  "id": "EXC-AVD-REMOTE-ASSISTANCE",
  "controlId": "HL-RA-001",
  "status": "Approved",
  "owner": "Workplace Engineering",
  "reason": "The approved support workflow uses solicited Remote Assistance on pilot session hosts.",
  "ticket": "SEC-1842",
  "expires": "2027-06-30",
  "targets": ["AVD-PILOT-*"],
  "baselines": ["AVDSessionHost"],
  "approvedBy": "Security Engineering",
  "approvedOn": "2026-07-01",
  "compensatingControls": [
    "Access is restricted to the support group.",
    "Session activity is logged and reviewed."
  ]
}
```

## Matching order

An exception applies only when all conditions match:

1. `status` is `Approved`;
2. `controlId` equals the evaluated control;
3. `expires` is today or later;
4. the computer name matches at least one PowerShell wildcard in `targets`;
5. when `baselines` is present, the selected baseline name is listed.

The first matching exception is applied. Keep scopes non-overlapping to avoid ambiguous ownership.

## Creating and validating registers

Create an empty register:

```powershell
New-HardeningLensExceptionFile -Path .\exceptions.json
```

Create one approved entry:

```powershell
New-HardeningLensExceptionFile `
    -Path .\exceptions.json `
    -ControlId HL-RA-001 `
    -Target 'AVD-PILOT-*' `
    -Baseline AVDSessionHost `
    -Status Approved `
    -Owner 'Workplace Engineering' `
    -Reason 'Approved support workflow requires solicited Remote Assistance.' `
    -Ticket 'SEC-1842' `
    -Expires (Get-Date '2027-06-30') `
    -ApprovedBy 'Security Engineering' `
    -CompensatingControl 'Access is restricted to the support group.', 'Session activity is logged.'
```

Validate before use:

```powershell
Test-HardeningLensExceptionFile -Path .\exceptions.json
```

A register with missing approval metadata, unknown controls, invalid dates, duplicate IDs, or empty compensating controls is rejected. A global `*` target is accepted but produces a warning because narrower scopes are preferable.

## Review practice

Store exception registers in a restricted repository or configuration-management system. Require pull-request review from both the service owner and security owner. Expiry should trigger reassessment, not automatic renewal. Report exports contain exception rationale and ownership; handle them as security-sensitive evidence.
