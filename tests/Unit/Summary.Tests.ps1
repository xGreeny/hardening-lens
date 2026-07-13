BeforeAll {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
}

Describe 'Assessment summary' {
    InModuleScope HardeningLens {
        It 'keeps hardening score and evidence coverage independent' {
            $results = @(
                [pscustomobject]@{ status = 'Pass'; severity = 'Critical' }
                [pscustomobject]@{ status = 'Fail'; severity = 'High' }
                [pscustomobject]@{ status = 'Excepted'; severity = 'Medium' }
                [pscustomobject]@{ status = 'Unknown'; severity = 'Low' }
                [pscustomobject]@{ status = 'NotApplicable'; severity = 'Medium' }
                [pscustomobject]@{ status = 'Pass'; severity = 'Informational' }
            )

            $summary = Get-HLSummary -Results $results
            $summary.Total | Should -Be 6
            $summary.Applicable | Should -Be 5
            $summary.Pass | Should -Be 2
            $summary.Fail | Should -Be 1
            $summary.Excepted | Should -Be 1
            $summary.Unknown | Should -Be 1
            $summary.NotApplicable | Should -Be 1
            $summary.HardeningScore | Should -Be 45.5
            $summary.EvidenceCoverage | Should -Be 80.0
            $summary.HighestOpenSeverity | Should -Be 'High'
        }

        It 'returns null metrics when no controls are applicable' {
            $summary = Get-HLSummary -Results @([pscustomobject]@{ status = 'NotApplicable'; severity = 'High' })
            $summary.HardeningScore | Should -BeNullOrEmpty
            $summary.EvidenceCoverage | Should -BeNullOrEmpty
            $summary.HighestOpenSeverity | Should -Be 'None'
        }
    }
}
