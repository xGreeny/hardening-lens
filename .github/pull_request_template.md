## Purpose

Describe the problem and the resulting behavior.

## Security and operational impact

- [ ] Collection remains read-only.
- [ ] No production data, credentials, tenant identifiers, or internal hostnames are included.
- [ ] New or changed security claims cite first-party Microsoft guidance.
- [ ] Compatibility and rollout considerations are documented.

## Validation

- [ ] `./build.ps1 -Task All`
- [ ] `python ./tools/generate_control_reference.py --check`
- [ ] `python ./tools/validate_repository.py`
- [ ] Sample output or fixtures updated where required.
