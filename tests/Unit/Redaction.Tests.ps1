BeforeDiscovery {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $modulePath = Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1'
    $samplePath = Join-Path -Path $repositoryRoot -ChildPath 'examples/sample-result.json'
    $script:SampleResult = Get-Content -LiteralPath $samplePath -Raw | ConvertFrom-Json
    Import-Module -Name $modulePath -Force
}

Describe 'Targeted result redaction' {
    InModuleScope HardeningLens -Parameters @{ SampleResult = $script:SampleResult } {
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
