BeforeAll {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
}

Describe 'Value evaluation' {
    InModuleScope HardeningLens {
        It 'evaluates scalar operators' {
            Test-HLValue -Actual 1 -Expected 1 -Operator Equals | Should -BeTrue
            Test-HLValue -Actual 1 -Expected 2 -Operator NotEquals | Should -BeTrue
            Test-HLValue -Actual 2 -Expected @(1, 2, 3) -Operator In | Should -BeTrue
            Test-HLValue -Actual 4 -Expected @(1, 2, 3) -Operator NotIn | Should -BeTrue
            Test-HLValue -Actual 8 -Expected 7 -Operator GreaterOrEqual | Should -BeTrue
            Test-HLValue -Actual 2 -Expected 3 -Operator LessOrEqual | Should -BeTrue
        }

        It 'evaluates collection containment without order dependence' {
            Test-HLValue -Actual @('Failure', 'Success') -Expected @('Success', 'Failure') -Operator ContainsAll | Should -BeTrue
            Test-HLValue -Actual @('Success') -Expected @('Success', 'Failure') -Operator ContainsAll | Should -BeFalse
        }

        It 'converts configured warning values to Warning rather than Pass' {
            $result = New-HLValueProbeResult -Actual 2 -Expected 1 -Operator Equals -WarningValues @(2)
            $result.Status | Should -Be 'Warning'
        }

        It 'preserves actual and expected values in failure results' {
            $result = New-HLValueProbeResult -Actual $false -Expected $true -Operator Equals
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -BeFalse
            $result.Expected | Should -BeTrue
        }
    }
}
