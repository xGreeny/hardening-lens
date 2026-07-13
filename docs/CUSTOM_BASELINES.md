# Custom baselines

Custom baselines adapt the curated catalog without forking probe logic. A custom document can extend one built-in baseline, exclude controls, add catalog controls, override parameters, and adjust severity.

## Inheritance example

```json
{
  "$schema": "../src/HardeningLens/Schema/baseline.schema.json",
  "schemaVersion": "1.0",
  "name": "NorthstarMemberServer",
  "displayName": "Northstar Member Server",
  "version": "1.0.0",
  "description": "Organization-specific member-server posture profile.",
  "extends": "MemberServer",
  "excludedControls": ["HL-BIT-001"],
  "controls": [
    {
      "id": "HL-LOG-001",
      "parameters": {
        "minimumSizeBytes": 2147483648
      }
    },
    {
      "id": "HL-SVC-001",
      "severity": "Low"
    }
  ],
  "sourceBasis": [
    "Hardening Lens MemberServer baseline",
    "Organization infrastructure security standard"
  ],
  "supportedRoles": ["MemberServer"],
  "notes": [
    "BitLocker ownership is handled by a separate storage-encryption standard."
  ]
}
```

Run it with:

```powershell
Invoke-HardeningLens -BaselinePath .\custom-baseline.json
```

## Resolution rules

1. The built-in `extends` profile is loaded.
2. Metadata supplied by the custom document replaces inherited metadata.
3. `excludedControls` removes matching IDs.
4. Entries in `controls` update an inherited control or add a catalog control.
5. `enabled: false` removes a control.
6. Parameter objects are merged at the first property level.
7. Every final control is resolved against the catalog.

Unknown or duplicate control IDs stop resolution. A custom baseline cannot provide arbitrary probe code; all controls must exist in the curated catalog.

## Parameter overrides

Use overrides for measurable thresholds or role-specific approved modes. Examples include:

- event-log capacity;
- maximum Defender signature age;
- Windows LAPS password age;
- ASR rule sets and allowed actions;
- role-specific registry expectations.

Do not use parameter overrides to obscure a known exception. When a workload intentionally deviates from the organization's baseline, retain the control and use a governed exception so the exposure remains visible.

## Severity overrides

Severity is organizational context, not a technical probe behavior. A custom baseline may lower or raise a control severity, but the decision should be documented in `sourceBasis` or `notes` and reviewed through change control.

## Schema support

The JSON Schema at `src/HardeningLens/Schema/baseline.schema.json` provides editor validation and completion. Commit custom baselines with their assessment consumers, version them semantically, and preserve old versions needed to interpret historical results.
