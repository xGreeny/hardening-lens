# Scoring and evidence coverage

Hardening Lens reports two separate metrics: **hardening score** and **evidence coverage**. Keeping them separate prevents an inaccessible setting from looking secure and prevents a high score from hiding collection gaps.

## Hardening score

Each applicable control receives a severity weight:

| Severity | Weight |
|---|---:|
| Critical | 10 |
| High | 7 |
| Medium | 4 |
| Low | 1 |
| Informational | 0 |

Only `Pass` receives pass credit. The score is:

```text
sum(weights of passing controls)
-------------------------------- × 100
sum(weights of applicable controls)
```

`Fail`, `Warning`, `Excepted`, `Unknown`, and `Error` receive no pass credit. `NotApplicable` and `Informational` controls are excluded from the denominator.

This intentionally conservative model means an approved exception remains visible as accepted exposure rather than being counted as equivalent to a secure configuration.

## Evidence coverage

Evidence coverage measures whether the tool could resolve an applicable control:

```text
applicable controls excluding Unknown and Error
------------------------------------------------ × 100
applicable controls
```

A device can therefore have:

- a **high score and low coverage**, indicating insufficient evidence;
- a **low score and high coverage**, indicating well-evidenced weaknesses;
- a **high score and high coverage**, indicating strong observed posture;
- a **low score and low coverage**, requiring both remediation and collection troubleshooting.

## Status semantics

| Status | Meaning |
|---|---|
| `Pass` | Effective state satisfies the control. |
| `Fail` | Effective state is resolved and does not satisfy the control. |
| `Warning` | State is transitional or audit-only and is not fully enforced. |
| `Excepted` | A failing or warning state matches an Approved, unexpired exception. |
| `Unknown` | The platform, provider, or evidence source cannot resolve the state. |
| `Error` | The probe encountered an operational error while collecting evidence. |
| `NotApplicable` | The control does not apply to the detected role or selected configuration. |

## Interpreting trends

Compare score and coverage together. A score improvement caused by controls becoming `Unknown` is not a security improvement; coverage will fall. A baseline version change can also alter the denominator. Drift reports record both scan IDs and baseline context, but reviewers remain responsible for distinguishing intentional policy changes from regressions.

## What the score is not

The score is not a breach probability, risk rating, compliance percentage, maturity score, or substitute for threat modeling. It is a deterministic summary of the selected technical control set on the assessed device.
