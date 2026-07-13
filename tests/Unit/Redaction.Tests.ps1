BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
    $script:Sample = Get-Content -LiteralPath (Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/sample-result.json') -Raw | ConvertFrom-Json
}

Describe 'Targeted result redaction' {
    InModuleScope HardeningLens -Parameters @{ SampleResult = $script:Sample } {
        param($SampleResult)

        It 'replaces the longest overlapping identifiers first' {
            $redacted = Protect-HLResult -ScanResult $SampleResult
            $serialized = $redacted | ConvertTo-Json -Depth 40

            $redacted.scan.redacted | Should -BeTrue
            $redacted.system.ComputerName | Should -Be 'HOST-REDACTED'
            $redacted.system.Domain | Should -Be 'DOMAIN.REDACTED'
            $redacted.system.CurrentUser | Should -Be 'USER-REDACTED'
            $serialized | Should -Not -Match 'SRV-DEMO-01'
            $serialized | Should -Not -Match 'LAB\.EXAMPLE\.INVALID'
            $serialized | Should -Not -Match 'audit\.runner'
        }
    }
}
