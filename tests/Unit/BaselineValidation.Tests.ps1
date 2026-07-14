BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $script:ModulePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1'
    $script:ExamplePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/custom-baseline.json'
    Import-Module -Name $script:ModulePath -Force
}

Describe 'Custom baseline runtime validation' {
    BeforeEach {
        $script:Document = Get-Content -LiteralPath $script:ExamplePath -Raw | ConvertFrom-Json
    }

    It 'rejects duplicate control overrides before merge' {
        $script:Document.controls = @($script:Document.controls) + @($script:Document.controls[0])
        $path = Join-Path -Path $TestDrive -ChildPath 'duplicate.json'
        $script:Document | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $path -Encoding UTF8

        { Get-HardeningLensBaseline -Path $path -IncludeControls } | Should -Throw '*duplicate control*'
    }

    It 'rejects unknown and ineffective exclusions' {
        $script:Document.excludedControls = @('HL-NOT-999')
        $unknownPath = Join-Path -Path $TestDrive -ChildPath 'unknown-exclusion.json'
        $script:Document | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $unknownPath -Encoding UTF8
        { Get-HardeningLensBaseline -Path $unknownPath -IncludeControls } | Should -Throw '*unknown control*'

        $script:Document.excludedControls = @('HL-DC-001')
        $ineffectivePath = Join-Path -Path $TestDrive -ChildPath 'ineffective-exclusion.json'
        $script:Document | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $ineffectivePath -Encoding UTF8
        { Get-HardeningLensBaseline -Path $ineffectivePath -IncludeControls } | Should -Throw '*not present*'
    }

    It 'rejects unknown parameters and incompatible types' {
        $script:Document.controls[0].parameters | Add-Member -NotePropertyName typoSizeBytes -NotePropertyValue 42
        $unknownPath = Join-Path -Path $TestDrive -ChildPath 'unknown-parameter.json'
        $script:Document | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $unknownPath -Encoding UTF8
        { Get-HardeningLensBaseline -Path $unknownPath -IncludeControls } | Should -Throw '*unknown parameter*'

        $script:Document = Get-Content -LiteralPath $script:ExamplePath -Raw | ConvertFrom-Json
        $script:Document.controls[0].parameters.minimumSizeBytes = 'large'
        $typePath = Join-Path -Path $TestDrive -ChildPath 'wrong-type.json'
        $script:Document | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $typePath -Encoding UTF8
        { Get-HardeningLensBaseline -Path $typePath -IncludeControls } | Should -Throw '*incompatible type*'
    }

    It 'rejects unsupported root properties' {
        $script:Document | Add-Member -NotePropertyName execute -NotePropertyValue 'ignored'
        $path = Join-Path -Path $TestDrive -ChildPath 'unsupported-property.json'
        $script:Document | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $path -Encoding UTF8

        { Get-HardeningLensBaseline -Path $path -IncludeControls } | Should -Throw '*unsupported property*'
    }
}
