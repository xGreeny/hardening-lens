BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
    $script:Module = Get-Module HardeningLens
    $script:BaselinePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/custom-baseline.json'
}

Describe 'Baseline governance validation' {
    It 'returns a structured valid result for a resolvable custom baseline' {
        $result = & $script:Module {
            param($InputPath)
            Test-HardeningLensBaseline -Path $InputPath
        } $script:BaselinePath

        $result.IsValid | Should -BeTrue
        @($result.Errors).Count | Should -Be 0
        $result.Name | Should -Not -BeNullOrEmpty
        $result.Version | Should -Match '^\d+\.\d+\.\d+$'
        $result.ControlCount | Should -BeGreaterThan 0
        $result.Path | Should -Be (Resolve-Path -LiteralPath $script:BaselinePath).Path
    }

    It 'returns validation errors instead of throwing for malformed input' {
        $document = Get-Content -LiteralPath $script:BaselinePath -Raw | ConvertFrom-Json
        $document.controls = @($document.controls) + @($document.controls[0])
        $result = & $script:Module {
            param($InputDocument)
            Test-HardeningLensBaseline -InputObject $InputDocument
        } $document

        $result.IsValid | Should -BeFalse
        @($result.Errors -join ' ') | Should -Match 'duplicate control'
    }

    It 'does not mutate baseline input objects' {
        $document = Get-Content -LiteralPath $script:BaselinePath -Raw | ConvertFrom-Json
        $before = $document | ConvertTo-Json -Depth 30 -Compress
        $null = & $script:Module {
            param($InputDocument)
            Test-HardeningLensBaseline -InputObject $InputDocument
        } $document

        ($document | ConvertTo-Json -Depth 30 -Compress) | Should -BeExactly $before
    }

    It 'detects ineffective exclusions and missing files with structured failures' {
        $document = Get-Content -LiteralPath $script:BaselinePath -Raw | ConvertFrom-Json
        $document.excludedControls = @('HL-DC-001')
        $ineffective = & $script:Module {
            param($InputDocument)
            Test-HardeningLensBaseline -InputObject $InputDocument
        } $document
        $ineffective.IsValid | Should -BeFalse
        @($ineffective.Errors -join ' ') | Should -Match 'not present'

        $missingPath = Join-Path -Path $TestDrive -ChildPath 'missing-baseline.json'
        $missing = & $script:Module {
            param($InputPath)
            Test-HardeningLensBaseline -Path $InputPath
        } $missingPath
        $missing.IsValid | Should -BeFalse
        @($missing.Errors).Count | Should -Be 1
        $missing.Path | Should -Be $missingPath
    }
}
