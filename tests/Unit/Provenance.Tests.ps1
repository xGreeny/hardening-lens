BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $script:ResultSchemaPath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/Schema/result.schema.json'
    $script:ComparisonSchemaPath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/Schema/comparison.schema.json'
    Import-Module -Name (Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
}

Describe 'Canonical provenance serialization' {
    It 'uses edition-independent minimal JSON string escaping' {
        InModuleScope HardeningLens {
            $value = [pscustomobject][ordered]@{
                Text    = 'A & B < C > D'
                Control = "prefix$([char]1)suffix"
            }

            (ConvertTo-HLCanonicalJson -Value $value) | Should -Be '{"Control":"prefix\u0001suffix","Text":"A & B < C > D"}'
        }
    }
}

Describe 'Schema 1.1 provenance contracts' {
    It 'requires stable scan provenance and timing fields' {
        $schema = Get-Content -LiteralPath $script:ResultSchemaPath -Raw | ConvertFrom-Json

        $schema.properties.schemaVersion.const | Should -Be '1.1'
        @($schema.required) | Should -Contain 'provenance'
        @($schema.properties.scan.required) | Should -Contain 'collectionDurationMs'
        @($schema.'$defs'.result.required) | Should -Contain 'probeDurationMs'
        @($schema.properties.provenance.required) | Should -Contain 'catalogVersion'
        @($schema.properties.provenance.required) | Should -Contain 'catalogDigest'
        @($schema.properties.provenance.required) | Should -Contain 'baselineDigest'
        @($schema.properties.provenance.required) | Should -Contain 'capabilities'
        @($schema.properties.provenance.required) | Should -Not -Contain 'exceptionDigest'
        $schema.'$defs'.sha256Digest.pattern | Should -Be '^[a-f0-9]{64}$'
        @($schema.'$defs'.capability.required) -join ',' | Should -Be 'name,available,detail'
    }

    It 'requires explainable drift state and provenance context' {
        $schema = Get-Content -LiteralPath $script:ComparisonSchemaPath -Raw | ConvertFrom-Json
        $changeSchema = $schema.properties.changes.items

        $schema.properties.schemaVersion.const | Should -Be '1.1'
        @($schema.required) | Should -Contain 'baselineContext'
        @($schema.required) | Should -Contain 'catalogContext'
        @($schema.properties.summary.required) | Should -Contain 'CoverageDelta'
        @($changeSchema.required) | Should -Contain 'ChangedFields'
        @($changeSchema.required) | Should -Contain 'Before'
        @($changeSchema.required) | Should -Contain 'After'
        @($changeSchema.properties.ChangedFields.items.enum) | Should -Contain 'Evidence'
        @($changeSchema.properties.ChangedFields.items.enum) | Should -Contain 'Exception'
        @($schema.'$defs'.scanRef.required) | Should -Contain 'ResultSchemaVersion'
        @($schema.'$defs'.scanRef.required) | Should -Contain 'Capabilities'
    }
}
