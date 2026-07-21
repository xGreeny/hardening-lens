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
            Mock Get-WindowsOptionalFeature {
                @([pscustomobject]@{ FeatureName = 'UnrelatedFeature'; State = 'Enabled' })
            } -ParameterFilter { [string]::IsNullOrWhiteSpace($FeatureName) }

            $result = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl -CollectionContext $null
            $result.Status | Should -Be 'Pass'
            $result.Actual | Should -Be 'Feature not present'
            foreach ($entry in @($result.Evidence)) {
                $entry.Present | Should -BeFalse
                $entry.State | Should -Be 'NotPresent'
                $entry.Error | Should -BeNullOrEmpty
            }
        }

        It 'evaluates only present features when others are absent' {
            Mock Get-WindowsOptionalFeature {
                @([pscustomobject]@{ FeatureName = 'RetiredFeature'; State = 'Disabled' })
            } -ParameterFilter { [string]::IsNullOrWhiteSpace($FeatureName) }

            $result = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl -CollectionContext $null
            $result.Status | Should -Be 'Pass'
            $result.Actual | Should -Be 'Disabled'
            @($result.Evidence | Where-Object { $_.FeatureName -eq 'RetiredFeatureRoot' }).Evaluated | Should -BeFalse
            @($result.Evidence | Where-Object { $_.FeatureName -eq 'RetiredFeature' }).Evaluated | Should -BeTrue
        }

        It 'fails when a present feature is enabled' {
            Mock Get-WindowsOptionalFeature {
                @([pscustomobject]@{ FeatureName = 'RetiredFeature'; State = 'Enabled' })
            } -ParameterFilter { [string]::IsNullOrWhiteSpace($FeatureName) }

            $result = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl -CollectionContext $null
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be 'RetiredFeature=Enabled'
        }

        It 'resolves every optional-feature control from one cached listing' {
            Mock Get-WindowsOptionalFeature {
                @([pscustomobject]@{ FeatureName = 'RetiredFeature'; State = 'Disabled' })
            } -ParameterFilter { [string]::IsNullOrWhiteSpace($FeatureName) }

            $context = New-HLCollectionContext
            $first = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl -CollectionContext $context
            $second = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl -CollectionContext $context
            $first.Status | Should -Be 'Pass'
            $second.Status | Should -Be 'Pass'
            Should -Invoke Get-WindowsOptionalFeature -Times 1 -Exactly
        }

        It 'falls back to per-feature queries when the listing fails' {
            Mock Get-WindowsOptionalFeature { throw 'Listing requires elevation.' } -ParameterFilter { [string]::IsNullOrWhiteSpace($FeatureName) }
            Mock Get-WindowsOptionalFeature { $null } -ParameterFilter { $FeatureName -eq 'RetiredFeatureRoot' }
            Mock Get-WindowsOptionalFeature {
                [pscustomobject]@{ FeatureName = 'RetiredFeature'; State = 'Disabled' }
            } -ParameterFilter { $FeatureName -eq 'RetiredFeature' }

            $result = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl -CollectionContext $null
            $result.Status | Should -Be 'Pass'
            $result.Actual | Should -Be 'Disabled'
        }

        It 'keeps unexpected query failures as collection errors' {
            Mock Get-WindowsOptionalFeature { throw 'The service cannot be started.' }

            $result = Invoke-HLWindowsOptionalFeatureProbe -Control $script:featureControl -CollectionContext $null
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

Describe 'Guest account probe role awareness' {
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

            $script:dcContext = [pscustomobject]@{ DetectedRole = 'DomainController'; Domain = 'contoso.example' }
            $script:memberContext = [pscustomobject]@{ DetectedRole = 'MemberServer'; Domain = 'contoso.example' }
        }

        It 'evaluates the domain built-in Guest on a domain controller' {
            Mock Get-CimInstance {
                @([pscustomobject]@{ Name = 'Gast'; Domain = 'CONTOSO'; SID = 'S-1-5-21-1-2-3-501'; Disabled = $true; Status = 'Degraded' })
            } -ParameterFilter { $ClassName -eq 'Win32_UserAccount' -and $Filter -like "*-501*" }

            $result = Invoke-HLLocalGuestAccountProbe -SystemContext $script:dcContext
            $result.Status | Should -Be 'Pass'
            $result.Evidence.Domain | Should -Be 'CONTOSO'
            $result.Evidence.Scope | Should -Match 'Domain accounts'
        }

        It 'fails when the domain built-in Guest is enabled' {
            Mock Get-CimInstance {
                @([pscustomobject]@{ Name = 'Guest'; Domain = 'CONTOSO'; SID = 'S-1-5-21-1-2-3-501'; Disabled = $false; Status = 'OK' })
            } -ParameterFilter { $ClassName -eq 'Win32_UserAccount' -and $Filter -like "*-501*" }

            $result = Invoke-HLLocalGuestAccountProbe -SystemContext $script:dcContext
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be 'Enabled'
        }

        It 'falls back to the only RID 501 hit when the NetBIOS domain differs' {
            Mock Get-CimInstance {
                @([pscustomobject]@{ Name = 'Guest'; Domain = 'CONTOSO-NB'; SID = 'S-1-5-21-1-2-3-501'; Disabled = $true; Status = 'OK' })
            } -ParameterFilter { $ClassName -eq 'Win32_UserAccount' -and $Filter -like "*-501*" }

            $result = Invoke-HLLocalGuestAccountProbe -SystemContext $script:dcContext
            $result.Status | Should -Be 'Pass'
            $result.Evidence.Domain | Should -Be 'CONTOSO-NB'
        }

        It 'returns Unknown with search evidence when no Guest account is found' {
            Mock Get-CimInstance { @() } -ParameterFilter { $ClassName -eq 'Win32_UserAccount' }

            $result = Invoke-HLLocalGuestAccountProbe -SystemContext $script:dcContext
            $result.Status | Should -Be 'Unknown'
            $result.Evidence | Should -Not -BeNullOrEmpty
            $result.Evidence.SidSuffix | Should -Be '-501'
            $result.Evidence.AccountsExamined | Should -Be 0
            $result.Evidence.DetectedRole | Should -Be 'DomainController'
        }

        It 'keeps the local account path for non domain controllers' {
            Mock Get-CimInstance {
                @([pscustomobject]@{ Name = 'Gast'; Domain = 'HOST01'; SID = 'S-1-5-21-9-9-9-501'; Disabled = $true; Status = 'Degraded' })
            } -ParameterFilter { $ClassName -eq 'Win32_UserAccount' -and $Filter -eq 'LocalAccount=True' }

            $result = Invoke-HLLocalGuestAccountProbe -SystemContext $script:memberContext
            $result.Status | Should -Be 'Pass'
            $result.Evidence.Scope | Should -Be 'Local accounts'
            Should -Invoke Get-CimInstance -Times 1 -Exactly -ParameterFilter { $Filter -eq 'LocalAccount=True' }
        }
    }
}

Describe 'Firewall profile probe messaging' {
    InModuleScope HardeningLens {
        BeforeAll {
            if ($null -eq (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
                Set-Item -Path Function:Get-NetFirewallProfile -Value {
                    [CmdletBinding()]
                    param([string]$PolicyStore)
                    throw 'The test stub must be replaced by a Pester mock.'
                }
            }

            function New-TestFirewallProfileSet {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory test fixture only.')]
                param([string]$Enabled, [string]$InboundAction = 'Block')

                @('Domain', 'Private', 'Public') | ForEach-Object {
                    [pscustomobject]@{ Name = $_; Enabled = $Enabled; DefaultInboundAction = $InboundAction; DefaultOutboundAction = 'Allow' }
                }
            }
        }

        BeforeEach {
            Mock Get-Command {
                [pscustomobject]@{ Name = 'Get-NetFirewallProfile' }
            } -ParameterFilter { $Name -eq 'Get-NetFirewallProfile' }
        }

        It 'names the inbound-block requirement when profiles are disabled' {
            Mock Get-NetFirewallProfile { New-TestFirewallProfileSet -Enabled 'False' }
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ requireEnabled = $true; requireDefaultInboundBlock = $true } }

            $result = Invoke-HLFirewallProfilesProbe -Control $control -CollectionContext $null
            $result.Status | Should -Be 'Fail'
            $result.Expected | Should -Be 'Default inbound action Block on every enabled profile'
            $result.Message | Should -Match 'cannot take effect'
        }

        It 'keeps the profile-enablement wording for the enablement control' {
            Mock Get-NetFirewallProfile { New-TestFirewallProfileSet -Enabled 'False' }
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ requireEnabled = $true } }

            $result = Invoke-HLFirewallProfilesProbe -Control $control -CollectionContext $null
            $result.Status | Should -Be 'Fail'
            $result.Expected | Should -Be 'All firewall profiles enabled'
            $result.Message | Should -Match 'profiles are disabled'
        }

        It 'still fails enabled profiles without a default inbound Block' {
            Mock Get-NetFirewallProfile { New-TestFirewallProfileSet -Enabled 'True' -InboundAction 'Allow' }
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ requireEnabled = $true; requireDefaultInboundBlock = $true } }

            $result = Invoke-HLFirewallProfilesProbe -Control $control -CollectionContext $null
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Match 'Not blocking'
        }
    }
}

Describe 'BitLocker probe platform awareness' {
    InModuleScope HardeningLens {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-BitLockerVolume' }
        }

        It 'fails a server without the BitLocker feature installed' -ForEach @(
            @{ ProductType = 2 }
            @{ ProductType = 3 }
        ) {
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ mountPoint = 'SystemDrive' } }
            $context = [pscustomobject]@{ ProductType = $ProductType }

            $result = Invoke-HLBitLockerProbe -Control $control -SystemContext $context
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be 'BitLocker feature not installed'
            $result.Evidence.BitLockerFeatureInstalled | Should -BeFalse
        }

        It 'keeps Unknown for client SKUs where the cmdlet should exist' {
            $control = [pscustomobject]@{ parameters = [pscustomobject]@{ mountPoint = 'SystemDrive' } }
            $context = [pscustomobject]@{ ProductType = 1 }

            $result = Invoke-HLBitLockerProbe -Control $control -SystemContext $context
            $result.Status | Should -Be 'Unknown'
        }
    }
}
