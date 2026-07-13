# Contributing

Hardening Lens accepts focused changes that preserve three invariants:

1. **Collection remains read-only.** A probe may inspect effective configuration but must not modify it.
2. **A control is evidence-driven.** Every result must expose expected state, actual state, a clear message, and useful evidence or an explicit evidence gap.
3. **Security claims are traceable.** New controls require current first-party Microsoft guidance and must not imply certification.

## Development setup

```powershell
Install-Module Pester -MinimumVersion 5.6.1 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser
python -m pip install -r requirements-dev.txt

./build.ps1 -Task All
python ./tools/validate_repository.py
```

The test suite runs on Windows PowerShell 5.1 and current PowerShell on Linux. Live Windows probe tests are opt-in and excluded from the default quality gate.

## Proposing a control

A control proposal should define:

- a stable ID in the form `HL-<AREA>-NNN`;
- a narrowly scoped title and category;
- severity with operational justification;
- the effective configuration source to inspect;
- expected, failure, warning, unknown, and not-applicable behavior;
- remediation guidance that includes rollout or compatibility considerations;
- at least one `learn.microsoft.com` reference;
- role applicability and baseline placement;
- synthetic test evidence.

Use the **Control proposal** issue form before implementing broad or high-impact additions.

## Pull requests

Keep pull requests small enough to review. Update tests, JSON Schema, generated control documentation, examples, and changelog when the contract changes. Run:

```powershell
./build.ps1 -Task All
python ./tools/generate_control_reference.py --check
python ./tools/validate_repository.py
```

Do not commit production exports, customer names, tenant IDs, internal hostnames, addresses, secrets, or unredacted screenshots.
