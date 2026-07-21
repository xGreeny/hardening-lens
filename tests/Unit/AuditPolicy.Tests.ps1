BeforeDiscovery {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
}

Describe 'Advanced audit policy probe' {
    InModuleScope HardeningLens {
        BeforeAll {
            $script:auditControl = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    subcategoryName = 'Credential Validation'
                    subcategoryGuid = '0cce923f-69ae-11d9-bed3-505054503030'
                    requiredFlags   = @('Success', 'Failure')
                }
            }
        }

        It 'returns Pass when every required flag is effective' {
            Mock Get-HLAuditPolicySetting {
                [pscustomobject]@{
                    SubcategoryGuid = '0cce923f-69ae-11d9-bed3-505054503030'
                    RawValue        = [uint32]3
                    Success         = $true
                    Failure         = $true
                    None            = $false
                }
            }

            $result = Invoke-HLAuditPolicyProbe -Control $script:auditControl
            $result.Status | Should -Be 'Pass'
            $result.Actual | Should -Be 'Success and Failure'
            $result.Evidence.SubcategoryName | Should -Be 'Credential Validation'
            $result.Evidence.RawValue | Should -Be 3
        }

        It 'returns Fail and names every missing flag when auditing is off' {
            Mock Get-HLAuditPolicySetting {
                [pscustomobject]@{
                    SubcategoryGuid = '0cce923f-69ae-11d9-bed3-505054503030'
                    RawValue        = [uint32]4
                    Success         = $false
                    Failure         = $false
                    None            = $true
                }
            }

            $result = Invoke-HLAuditPolicyProbe -Control $script:auditControl
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be 'No Auditing'
            $result.Message | Should -Match 'Success'
            $result.Message | Should -Match 'Failure'
        }

        It 'returns Fail when only part of the required flags is effective' {
            Mock Get-HLAuditPolicySetting {
                [pscustomobject]@{
                    SubcategoryGuid = '0cce923f-69ae-11d9-bed3-505054503030'
                    RawValue        = [uint32]1
                    Success         = $true
                    Failure         = $false
                    None            = $false
                }
            }

            $result = Invoke-HLAuditPolicyProbe -Control $script:auditControl
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be 'Success'
            $result.Message | Should -Match 'Failure'
            $result.Message | Should -Not -Match 'Success,'
        }
    }
}

Describe 'Audit policy native interop contract' {
    InModuleScope HardeningLens {
        It 'compiles the native helper with the C#-side marshalling entry point' {
            Initialize-HLAuditNativeType
            $type = 'HardeningLens.NativeAuditPolicy2' -as [type]
            $type | Should -Not -BeNullOrEmpty
            $method = $type.GetMethod('QuerySinglePolicy')
            $method | Should -Not -BeNullOrEmpty
            $method.ReturnType.Name | Should -Be 'AUDIT_POLICY_INFORMATION'
            $method.ReturnType.IsLayoutSequential | Should -BeTrue
        }
    }

    It 'never marshals the audit policy structure from PowerShell' {
        # Regression guard: the PowerShell 5.1 binder can select the
        # PtrToStructure(IntPtr, object) overload, which fails at runtime.
        $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
        $auditSource = Get-Content -LiteralPath (Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/Private/AuditPolicy.ps1') -Raw
        $auditSource | Should -Not -Match '\[(System\.)?Runtime\.InteropServices\.Marshal\]::PtrToStructure'
    }
}
