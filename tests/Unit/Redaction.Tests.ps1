BeforeDiscovery {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $script:ModulePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1'
    $script:SamplePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/sample-result.json'
    Import-Module -Name $script:ModulePath -Force
}

BeforeAll {
    Import-Module -Name $script:ModulePath -Force
}

Describe 'Targeted result redaction' {
    InModuleScope HardeningLens -Parameters @{ SamplePath = $script:SamplePath } {
        param($SamplePath)

        BeforeAll {
            $sampleResult = Get-Content -LiteralPath $SamplePath -Raw | ConvertFrom-Json
        }

        It 'replaces the longest overlapping identifiers first' {
            $redacted = Protect-HLResult -ScanResult $sampleResult
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
