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
        $comparison.summary.ScoreDelta | Should -Be -2.1
        @($comparison.changes | Where-Object ChangeType -eq 'NewFinding').ControlId | Should -Contain 'HL-SMB-003'
        @($comparison.changes | Where-Object ChangeType -eq 'Resolved').ControlId | Should -Contain 'HL-RDP-001'
    }


    It 'detects evidence-only changes without treating collection time as drift' {
        $reference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $difference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json
        $target = @($difference.results | Where-Object controlId -eq 'HL-SMB-001')[0]
        $target.evidence = [pscustomobject]@{ FeatureState = 'Disabled'; Source = 'Synthetic verification' }
        $target.collectedAt = (Get-Date).ToUniversalTime().ToString('o')

        $comparison = Compare-HardeningLensResult -Reference $reference -Difference $difference
        @($comparison.changes | Where-Object ControlId -eq 'HL-SMB-001')[0].ChangeType | Should -Be 'Changed'
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
        $json.schemaVersion | Should -Be '1.0'
        @($json.changes).Count | Should -Be 53
    }
}
