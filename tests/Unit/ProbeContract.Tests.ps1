BeforeAll {
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
