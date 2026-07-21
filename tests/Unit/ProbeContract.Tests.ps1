BeforeDiscovery {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
}

Describe 'ASR probe normalization' {
    InModuleScope HardeningLens {
        BeforeAll {
            if ($null -eq (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
                Set-Item -Path Function:Get-MpPreference -Value {
                    throw 'The test stub must be replaced by a Pester mock.'
                }
            }
        }

        BeforeEach {
            Mock Get-Command {
                [pscustomobject]@{ Name = 'Get-MpPreference' }
            } -ParameterFilter { $Name -eq 'Get-MpPreference' }
        }

        It 'returns Pass when every required rule uses an approved action' {
            Mock Get-MpPreference {
                [pscustomobject]@{
                    AttackSurfaceReductionRules_Ids = @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2')
                    AttackSurfaceReductionRules_Actions = @(1)
                }
            }
            $control = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    requiredRules = @(
                        [pscustomobject]@{
                            id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
                            name = 'Block credential stealing from LSASS'
                            allowedActions = @(1)
                        }
                    )
                }
            }

            $result = Invoke-HLAsrRulesProbe -Control $control
            $result.Status | Should -Be 'Pass'
        }

        It 'returns Warning for audit-only state' {
            Mock Get-MpPreference {
                [pscustomobject]@{
                    AttackSurfaceReductionRules_Ids = @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2')
                    AttackSurfaceReductionRules_Actions = @(2)
                }
            }
            $control = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    requiredRules = @(
                        [pscustomobject]@{
                            id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
                            name = 'Block credential stealing from LSASS'
                            allowedActions = @(1)
                        }
                    )
                }
            }

            $result = Invoke-HLAsrRulesProbe -Control $control
            $result.Status | Should -Be 'Warning'
        }

        It 'returns Fail for missing or disabled required rules' {
            Mock Get-MpPreference {
                [pscustomobject]@{
                    AttackSurfaceReductionRules_Ids = @()
                    AttackSurfaceReductionRules_Actions = @()
                }
            }
            $control = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    requiredRules = @(
                        [pscustomobject]@{
                            id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
                            name = 'Block credential stealing from LSASS'
                            allowedActions = @(1)
                        }
                    )
                }
            }

            $result = Invoke-HLAsrRulesProbe -Control $control
            $result.Status | Should -Be 'Fail'
        }
    }
}

Describe 'Windows optional feature probe normalization' {
    InModuleScope HardeningLens {
        BeforeAll {
            if ($null -eq (Get-Command -Name Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
                Set-Item -Path Function:Get-WindowsOptionalFeature -Value {
                    [CmdletBinding()]
                    param(
                        [switch]$Online,
                        [string]$FeatureName
                    )
                    throw 'The test stub must be replaced by a Pester mock.'
                }
            }

            $script:featureControl = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    features       = @('RetiredFeatureRoot', 'RetiredFeature')
                    expectedState  = 'Disabled'
                    evaluationMode = 'AllDisabled'
                }
            }
        }

        BeforeEach {
            Mock Get-Command {
                [pscustomobject]@{ Name = 'Get-WindowsOptionalFeature' }
            } -ParameterFilter { $Name -eq 'Get-WindowsOptionalFeature' }
        }

        It 'treats a feature removed from the operating system as compliant' {
            Mock Get-WindowsOptionalFeature { $null }

            $result = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl
            $result.Status | Should -Be 'Pass'
            $result.Actual | Should -Be 'Feature not present'
            foreach ($entry in @($result.Evidence)) {
                $entry.Present | Should -BeFalse
                $entry.State | Should -Be 'NotPresent'
                $entry.Error | Should -BeNullOrEmpty
            }
        }

        It 'evaluates only present features when others are absent' {
            Mock Get-WindowsOptionalFeature { $null } -ParameterFilter { $FeatureName -eq 'RetiredFeatureRoot' }
            Mock Get-WindowsOptionalFeature {
                [pscustomobject]@{ FeatureName = 'RetiredFeature'; State = 'Disabled' }
            } -ParameterFilter { $FeatureName -eq 'RetiredFeature' }

            $result = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl
            $result.Status | Should -Be 'Pass'
            $result.Actual | Should -Be 'Disabled'
            @($result.Evidence | Where-Object { $_.FeatureName -eq 'RetiredFeatureRoot' }).Evaluated | Should -BeFalse
            @($result.Evidence | Where-Object { $_.FeatureName -eq 'RetiredFeature' }).Evaluated | Should -BeTrue
        }

        It 'fails when a present feature is enabled' {
            Mock Get-WindowsOptionalFeature { $null } -ParameterFilter { $FeatureName -eq 'RetiredFeatureRoot' }
            Mock Get-WindowsOptionalFeature {
                [pscustomobject]@{ FeatureName = 'RetiredFeature'; State = 'Enabled' }
            } -ParameterFilter { $FeatureName -eq 'RetiredFeature' }

            $result = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be 'RetiredFeature=Enabled'
        }

        It 'keeps unexpected query failures as collection errors' {
            Mock Get-WindowsOptionalFeature { throw 'The service cannot be started.' }

            $result = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl
            $result.Status | Should -Be 'Error'
            $result.Message | Should -Match 'Unable to query one or more optional features'
        }
    }
}

Describe 'Device Guard service probe normalization' {
    InModuleScope HardeningLens {
        BeforeAll {
            if ($null -eq (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
                Set-Item -Path Function:Get-CimInstance -Value {
                    [CmdletBinding()]
                    param(
                        [string]$Namespace,
                        [string]$ClassName,
                        [string]$Filter
                    )
                    throw 'The test stub must be replaced by a Pester mock.'
                }
            }

            $script:hvciControl = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    serviceId   = 2
                    serviceName = 'Memory integrity (HVCI)'
                }
            }
        }

        It 'returns Pass when the requested security service is running' {
            Mock Get-CimInstance {
                [pscustomobject]@{
                    VirtualizationBasedSecurityStatus = 2
                    SecurityServicesConfigured        = @(1, 2)
                    SecurityServicesRunning           = @(1, 2)
                }
            } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }

            $result = Invoke-HLDeviceGuardServiceProbe -Control $script:hvciControl -CollectionContext $null
            $result.Status | Should -Be 'Pass'
            $result.Evidence.ServiceId | Should -Be 2
        }

        It 'distinguishes configured-but-not-running from unconfigured' {
            Mock Get-CimInstance {
                [pscustomobject]@{
                    VirtualizationBasedSecurityStatus = 1
                    SecurityServicesConfigured        = @(2)
                    SecurityServicesRunning           = @()
                }
            } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }

            $result = Invoke-HLDeviceGuardServiceProbe -Control $script:hvciControl -CollectionContext $null
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be 'Configured but not running'
        }

        It 'returns Unknown when the Device Guard provider is unavailable' {
            Mock Get-CimInstance {
                throw 'Ungueltiger Namespace.'
            } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }

            $result = Invoke-HLDeviceGuardServiceProbe -Control $script:hvciControl -CollectionContext $null
            $result.Status | Should -Be 'Unknown'
        }
    }
}
