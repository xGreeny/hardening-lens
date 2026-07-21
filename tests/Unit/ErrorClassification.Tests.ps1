BeforeDiscovery {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
}

Describe 'Locale-independent error classification' {
    InModuleScope HardeningLens {
        It 'matches Win32 error codes regardless of the localized message' {
            $exception = New-Object System.ComponentModel.Win32Exception 1314, 'Dem Client fehlt ein erforderliches Recht.'
            Test-HLErrorMatchesCode -Exception $exception -Code 1314 | Should -BeTrue
            Test-HLErrorMatchesCode -Exception $exception -Code 0x800f080c | Should -BeFalse
        }

        It 'matches HResults through wrapped inner exceptions' {
            $inner = New-Object System.Runtime.InteropServices.COMException 'Der Funktionsname ist unbekannt.', 0x800F080C
            $outer = New-Object System.InvalidOperationException 'Wrapper', $inner
            Test-HLErrorMatchesCode -Exception $outer -Code 0x800f080c | Should -BeTrue
        }

        It 'falls back to hexadecimal codes embedded in localized messages' {
            $exception = New-Object System.Exception 'Fehler beim Vorgang: 0x800106ba'
            Test-HLErrorMatchesCode -Exception $exception -Code 0x800106BA | Should -BeTrue
        }

        It 'never matches short codes against message text' {
            $exception = New-Object System.Exception 'Vorgang 0x00000522 fehlgeschlagen'
            Test-HLErrorMatchesCode -Exception $exception -Code 1314 | Should -BeFalse
        }
    }
}

Describe 'Secure Boot probe classification' {
    InModuleScope HardeningLens {
        BeforeAll {
            if ($null -eq (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
                Set-Item -Path Function:Confirm-SecureBootUEFI -Value {
                    [CmdletBinding()]
                    param()
                    throw 'The test stub must be replaced by a Pester mock.'
                }
            }
        }

        BeforeEach {
            Mock Get-Command {
                [pscustomobject]@{ Name = 'Confirm-SecureBootUEFI' }
            } -ParameterFilter { $Name -eq 'Confirm-SecureBootUEFI' }
        }

        It 'classifies an unsupported platform as Fail on a localized system' {
            Mock Confirm-SecureBootUEFI {
                throw (New-Object System.PlatformNotSupportedException 'Das Cmdlet wird auf dieser Plattform nicht unterstuetzt: 0xC0000002')
            }

            $result = Invoke-HLSecureBootProbe
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be 'Unsupported by current firmware or virtual hardware'
        }

        It 'classifies missing elevation as Unknown instead of Error' {
            Mock Confirm-SecureBootUEFI {
                throw (New-Object System.UnauthorizedAccessException 'Der Zugriff wurde verweigert.')
            }

            $result = Invoke-HLSecureBootProbe
            $result.Status | Should -Be 'Unknown'
            $result.Message | Should -Match 'elevation'
        }

        It 'keeps unrecognized failures as collection errors' {
            Mock Confirm-SecureBootUEFI {
                throw (New-Object System.Exception 'Unerwarteter Firmwarefehler.')
            }

            $result = Invoke-HLSecureBootProbe
            $result.Status | Should -Be 'Error'
        }
    }
}

Describe 'Audit policy privilege classification' {
    InModuleScope HardeningLens {
        It 'reports missing SeSecurityPrivilege as Unknown with guidance' {
            Mock Get-HLAuditPolicySetting {
                throw (New-Object System.ComponentModel.Win32Exception 1314, 'Dem Client fehlt ein erforderliches Recht.')
            }
            $control = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    subcategoryName = 'Credential Validation'
                    subcategoryGuid = '0cce923f-69ae-11d9-bed3-505054503030'
                    requiredFlags   = @('Success', 'Failure')
                }
            }

            $result = Invoke-HLAuditPolicyProbe -Control $control
            $result.Status | Should -Be 'Unknown'
            $result.Message | Should -Match 'SeSecurityPrivilege'
        }
    }
}

Describe 'Optional feature localized error classification' {
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
        }

        BeforeEach {
            Mock Get-Command {
                [pscustomobject]@{ Name = 'Get-WindowsOptionalFeature' }
            } -ParameterFilter { $Name -eq 'Get-WindowsOptionalFeature' }
        }

        It 'treats the unknown-feature error code as absent on a localized system' {
            Mock Get-WindowsOptionalFeature {
                throw (New-Object System.Runtime.InteropServices.COMException 'Der Funktionsname ist unbekannt.', 0x800F080C)
            }
            $control = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    features       = @('RetiredFeature')
                    expectedState  = 'Disabled'
                    evaluationMode = 'AllDisabled'
                }
            }

            $result = Invoke-HLWindowsOptionalFeatureProbe -Control $control
            $result.Status | Should -Be 'Pass'
            @($result.Evidence)[0].State | Should -Be 'NotPresent'
        }
    }
}

Describe 'Defender service unavailability classification' {
    InModuleScope HardeningLens {
        BeforeAll {
            foreach ($stub in @('Get-MpPreference', 'Get-MpComputerStatus')) {
                if ($null -eq (Get-Command -Name $stub -ErrorAction SilentlyContinue)) {
                    Set-Item -Path ('Function:{0}' -f $stub) -Value {
                        [CmdletBinding()]
                        param()
                        throw 'The test stub must be replaced by a Pester mock.'
                    }
                }
            }
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

            $script:defenderControl = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    property = 'DisableRealtimeMonitoring'
                    operator = 'Equals'
                    expected = $false
                }
            }
        }

        BeforeEach {
            Mock Get-Command {
                [pscustomobject]@{ Name = 'Get-MpPreference' }
            } -ParameterFilter { $Name -eq 'Get-MpPreference' }
            Mock Get-Command {
                [pscustomobject]@{ Name = 'Get-MpComputerStatus' }
            } -ParameterFilter { $Name -eq 'Get-MpComputerStatus' }
            Mock Get-Command {
                [pscustomobject]@{ Name = 'Get-CimInstance' }
            } -ParameterFilter { $Name -eq 'Get-CimInstance' }
        }

        It 'reports the stopped Defender service as Unknown with third-party context' {
            Mock Get-MpPreference {
                throw (New-Object System.Runtime.InteropServices.COMException 'Fehler beim Vorgang: 0x800106ba', 0x800106BA)
            }
            Mock Get-CimInstance {
                [pscustomobject]@{ displayName = 'Acme Endpoint Security'; productState = 397568 }
            } -ParameterFilter { $Namespace -eq 'root/SecurityCenter2' }

            $result = Invoke-HLDefenderPreferenceProbe -Control $script:defenderControl -CollectionContext $null
            $result.Status | Should -Be 'Unknown'
            $result.Message | Should -Match '0x800106BA'
            $result.Evidence.DefenderServiceAvailable | Should -BeFalse
            @($result.Evidence.ThirdPartyAntivirus)[0].DisplayName | Should -Be 'Acme Endpoint Security'
        }

        It 'keeps other Defender failures as collection errors' {
            Mock Get-MpPreference {
                throw (New-Object System.Exception 'Unerwarteter WMI-Fehler.')
            }

            $result = Invoke-HLDefenderPreferenceProbe -Control $script:defenderControl -CollectionContext $null
            $result.Status | Should -Be 'Error'
        }

        It 'adds running mode and third-party evidence to the status probe' {
            Mock Get-MpComputerStatus {
                [pscustomobject]@{
                    RealTimeProtectionEnabled = $false
                    AntivirusEnabled          = $false
                    AMRunningMode             = 'Passive Mode'
                }
            }
            Mock Get-CimInstance {
                [pscustomobject]@{ displayName = 'Acme Endpoint Security'; productState = 397568 }
            } -ParameterFilter { $Namespace -eq 'root/SecurityCenter2' }
            $control = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    property = 'RealTimeProtectionEnabled'
                    operator = 'Equals'
                    expected = $true
                }
            }

            $result = Invoke-HLDefenderStatusProbe -Control $control -CollectionContext $null
            $result.Status | Should -Be 'Fail'
            $result.Evidence.AMRunningMode | Should -Be 'Passive Mode'
            @($result.Evidence.ThirdPartyAntivirus)[0].DisplayName | Should -Be 'Acme Endpoint Security'
            $result.Message | Should -Not -Match 'active antimalware engine'
        }

        It 'explains a switched-off protection while Defender runs in normal mode' {
            Mock Get-MpComputerStatus {
                [pscustomobject]@{
                    RealTimeProtectionEnabled = $false
                    AntivirusEnabled          = $true
                    AMRunningMode             = 'Normal'
                }
            }
            $control = [pscustomobject]@{
                parameters = [pscustomobject]@{
                    property = 'RealTimeProtectionEnabled'
                    operator = 'Equals'
                    expected = $true
                }
            }

            $result = Invoke-HLDefenderStatusProbe -Control $control -CollectionContext $null
            $result.Status | Should -Be 'Fail'
            $result.Message | Should -Match 'active antimalware engine'
        }
    }
}
