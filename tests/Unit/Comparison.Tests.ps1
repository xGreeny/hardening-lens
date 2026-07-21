BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
    $script:ReferencePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/sample-reference-result.json'
    $script:DifferencePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/sample-result.json'
}

Describe 'Posture drift comparison' {
    It 'classifies new, resolved, and changed findings' {
        $comparison = Compare-HardeningLensResult -Reference $script:ReferencePath -Difference $script:DifferencePath

        $comparison.summary.NewFindings | Should -Be 2
        $comparison.summary.Resolved | Should -Be 1
        $comparison.summary.Changed | Should -Be 1
        $comparison.summary.ScoreDelta | Should -Be -2
        $comparison.summary.CoverageDelta | Should -Be 0
        @($comparison.changes | Where-Object ChangeType -eq 'NewFinding').ControlId | Should -Contain 'HL-SMB-003'
        @($comparison.changes | Where-Object ChangeType -eq 'Resolved').ControlId | Should -Contain 'HL-RDP-001'

        $newFinding = @($comparison.changes | Where-Object ControlId -eq 'HL-SMB-003')[0]
        @($newFinding.ChangedFields) | Should -Contain 'Status'
        $newFinding.Before.Status | Should -Be 'Pass'
        $newFinding.After.Status | Should -Be 'Fail'
    }


    It 'detects evidence-only changes without treating collection time as drift' {
        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $target = @($difference.results | Where-Object controlId -eq 'HL-SMB-001')[0]
        $target.evidence = [pscustomobject]@{ FeatureState = 'Disabled'; Source = 'Synthetic verification' }
        $target.collectedAt = (Get-Date).ToUniversalTime().ToString('o')

        $comparison = Compare-HardeningLensResult -Reference $reference -Difference $difference
        $change = @($comparison.changes | Where-Object ControlId -eq 'HL-SMB-001')[0]
        $change.ChangeType | Should -Be 'Changed'
        (@($change.ChangedFields) -join ',') | Should -Be 'Evidence'
        $change.Before.Evidence.Source | Should -Not -Be 'Synthetic verification'
        $change.After.Evidence.Source | Should -Be 'Synthetic verification'
    }

    It 'ignores recursive object property order but preserves array order' {
        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $referenceTarget = @($reference.results | Where-Object controlId -eq 'HL-SMB-001')[0]
        $differenceTarget = @($difference.results | Where-Object controlId -eq 'HL-SMB-001')[0]

        $referenceTarget.evidence = [pscustomobject][ordered]@{
            Source = 'Synthetic verification'
            Nested = [pscustomobject][ordered]@{ Alpha = 1; Beta = 2 }
            Values = @(1, 2, 3)
        }
        $differenceTarget.evidence = [pscustomobject][ordered]@{
            Values = @(1, 2, 3)
            Nested = [pscustomobject][ordered]@{ Beta = 2; Alpha = 1 }
            Source = 'Synthetic verification'
        }

        $comparison = Compare-HardeningLensResult -Reference $reference -Difference $difference
        $change = @($comparison.changes | Where-Object ControlId -eq 'HL-SMB-001')[0]
        $change.ChangeType | Should -Be 'Unchanged'
        @($change.ChangedFields).Count | Should -Be 0

        $differenceTarget.evidence.Values = @(3, 2, 1)
        $comparison = Compare-HardeningLensResult -Reference $reference -Difference $difference
        $change = @($comparison.changes | Where-Object ControlId -eq 'HL-SMB-001')[0]
        $change.ChangeType | Should -Be 'Changed'
        (@($change.ChangedFields) -join ',') | Should -Be 'Evidence'
    }

    It 'rejects duplicate and empty control IDs in either input' {
        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $reference.results += $reference.results[0]
        { Compare-HardeningLensResult -Reference $reference -Difference $difference } | Should -Throw '*Reference*duplicate controlId*'

        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference.results += $difference.results[0]
        { Compare-HardeningLensResult -Reference $reference -Difference $difference } | Should -Throw '*Difference*duplicate controlId*'

        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $reference.results[0].controlId = '  '
        { Compare-HardeningLensResult -Reference $reference -Difference $difference } | Should -Throw '*Reference*empty controlId*'

        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference.results[0].controlId = ''
        { Compare-HardeningLensResult -Reference $reference -Difference $difference } | Should -Throw '*Difference*empty controlId*'
    }

    It 'rejects unsupported schemas and malformed minimal contracts' {
        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $reference.schemaVersion = '2.0'
        { Compare-HardeningLensResult -Reference $reference -Difference $difference } | Should -Throw '*Reference*unsupported schemaVersion*'

        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $reference.PSObject.Properties.Remove('results')
        { Compare-HardeningLensResult -Reference $reference -Difference $difference } | Should -Throw "*Reference*missing required property 'results'*"
    }

    It 'compares schema 1.1 provenance and exposes collection context' {
        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $catalogDigestA = 'a' * 64
        $catalogDigestB = 'b' * 64
        $baselineDigestA = 'c' * 64
        $baselineDigestB = 'd' * 64

        foreach ($fixture in @($reference, $difference)) {
            $fixture.schemaVersion = '1.1'
            $fixture.scan.moduleVersion = '1.1.0'
            $fixture.scan.collectionDurationMs = 125
            foreach ($result in @($fixture.results)) {
                $result.probeDurationMs = 2
            }
        }
        $reference.provenance = [pscustomobject][ordered]@{
            catalogVersion = '1.0.1'
            catalogDigest  = $catalogDigestA
            baselineDigest = $baselineDigestA
            exceptionDigest = 'f' * 64
            capabilities   = @([pscustomobject][ordered]@{ name = 'Elevation'; available = $true; detail = 'Elevated token' })
        }
        $difference.provenance = [pscustomobject][ordered]@{
            catalogVersion = '1.1.0'
            catalogDigest  = $catalogDigestB
            baselineDigest = $baselineDigestB
            exceptionDigest = 'e' * 64
            capabilities   = @([pscustomobject][ordered]@{ name = 'Elevation'; available = $true; detail = 'Elevated token' })
        }

        $comparison = Compare-HardeningLensResult -Reference $reference -Difference $difference

        $comparison.schemaVersion | Should -Be '1.1'
        $comparison.referenceScan.ResultSchemaVersion | Should -Be '1.1'
        $comparison.referenceScan.CollectionDurationMs | Should -Be 125
        @($comparison.referenceScan.Capabilities).Count | Should -Be 1
        $comparison.catalogContext.Changed | Should -BeTrue
        $comparison.catalogContext.Reference.Digest | Should -Be $catalogDigestA
        $comparison.catalogContext.Difference.Digest | Should -Be $catalogDigestB
        $comparison.baselineContext.Changed | Should -BeTrue
        $comparison.differenceScan.ExceptionDigest | Should -Be ('e' * 64)
    }

    It 'accepts legacy schema 1.0 results with explicit unavailable provenance' {
        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:DifferencePath -Raw | ConvertFrom-Json
        foreach ($fixture in @($reference, $difference)) {
            $fixture.schemaVersion = '1.0'
            $fixture.PSObject.Properties.Remove('provenance')
            $fixture.scan.PSObject.Properties.Remove('collectionDurationMs')
            foreach ($result in @($fixture.results)) {
                $result.PSObject.Properties.Remove('probeDurationMs')
            }
        }

        $comparison = Compare-HardeningLensResult -Reference $reference -Difference $difference

        $comparison.schemaVersion | Should -Be '1.1'
        $comparison.referenceScan.ResultSchemaVersion | Should -Be '1.0'
        $comparison.referenceScan.CollectionDurationMs | Should -BeNullOrEmpty
        @($comparison.referenceScan.Capabilities).Count | Should -Be 0
        $comparison.baselineContext.Reference.Digest | Should -BeNullOrEmpty
        $comparison.catalogContext.Reference.Version | Should -BeNullOrEmpty
    }

    It 'normalizes parsed timestamps to edition-independent ISO 8601 values' {
        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:DifferencePath -Raw | ConvertFrom-Json
        $referenceJson = Get-Content -LiteralPath $script:ReferencePath -Raw
        $differenceJson = Get-Content -LiteralPath $script:DifferencePath -Raw
        $referenceMatch = [regex]::Match($referenceJson, '"collectedAt"\s*:\s*"([^"]+)"')
        $differenceMatch = [regex]::Match($differenceJson, '"collectedAt"\s*:\s*"([^"]+)"')
        $referenceMatch.Success | Should -BeTrue
        $differenceMatch.Success | Should -BeTrue
        $expectedReferenceTimestamp = $referenceMatch.Groups[1].Value
        $expectedDifferenceTimestamp = $differenceMatch.Groups[1].Value

        $comparison = Compare-HardeningLensResult -Reference $reference -Difference $difference

        $comparison.referenceScan.CollectedAt | Should -Be $expectedReferenceTimestamp
        $comparison.differenceScan.CollectedAt | Should -Be $expectedDifferenceTimestamp
    }

    It 'rejects accidental cross-target and cross-baseline comparisons' {
        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:DifferencePath -Raw | ConvertFrom-Json
        $difference.system.ComputerName = 'SRV-OTHER-01'

        { Compare-HardeningLensResult -Reference $reference -Difference $difference } | Should -Throw '*different targets*'
        { Compare-HardeningLensResult -Reference $reference -Difference $difference -AllowCrossTargetComparison } | Should -Not -Throw

        $difference.system.ComputerName = $reference.system.ComputerName
        $difference.baseline.name = 'Workstation'
        { Compare-HardeningLensResult -Reference $reference -Difference $difference } | Should -Throw '*different baselines*'
        { Compare-HardeningLensResult -Reference $reference -Difference $difference -AllowCrossBaselineComparison } | Should -Not -Throw
    }

    It 'writes deterministic Markdown and JSON contracts' {
        $markdownPath = Join-Path -Path $TestDrive -ChildPath 'drift.md'
        $jsonPath = Join-Path -Path $TestDrive -ChildPath 'drift.json'

        $null = Compare-HardeningLensResult -Reference $script:ReferencePath -Difference $script:DifferencePath -Format Markdown -OutputPath $markdownPath
        $null = Compare-HardeningLensResult -Reference $script:ReferencePath -Difference $script:DifferencePath -Format Json -OutputPath $jsonPath

        (Get-Content -LiteralPath $markdownPath -Raw) | Should -Match 'HL-SMB-003'
        $json = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
        $json.schemaVersion | Should -Be '1.1'
        @($json.changes).Count | Should -Be 54
        @($json.changes[0].PSObject.Properties.Name) | Should -Contain 'ChangedFields'
        @($json.changes[0].PSObject.Properties.Name) | Should -Contain 'Before'
        @($json.changes[0].PSObject.Properties.Name) | Should -Contain 'After'
    }
}
