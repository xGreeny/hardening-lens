BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
    $script:Module = Get-Module HardeningLens
    $script:SamplePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/sample-result.json'

    function Get-HLPolicyTestResult {
        return Get-Content -LiteralPath $script:SamplePath -Raw | ConvertFrom-Json
    }
}

Describe 'Policy governance' {
    It 'returns deterministic threshold violations and metrics' {
        $scan = Get-HLPolicyTestResult
        $evaluation = & $script:Module {
            param($InputScan)
            Test-HardeningLensPolicy -InputObject $InputScan -MaxFailed 6 -MaxWarning 2 -MinimumScore 80 -MinimumCoverage 97
        } $scan

        $evaluation.Passed | Should -BeFalse
        $evaluation.ExitCode | Should -Be 1
        @($evaluation.Violations).Code | Should -Be @(
            'MaxFailedExceeded',
            'MaxWarningExceeded',
            'MinimumScoreNotMet',
            'MinimumCoverageNotMet'
        )
        $evaluation.Metrics.Failed | Should -Be 7
        $evaluation.Metrics.Warning | Should -Be 3
        $evaluation.Metrics.HardeningScore | Should -Be 77.1
        $evaluation.Metrics.EvidenceCoverage | Should -Be 96.2
    }

    It 'passes when supplied thresholds are met and leaves input unchanged' {
        $scan = Get-HLPolicyTestResult
        $before = $scan | ConvertTo-Json -Depth 40 -Compress
        $evaluation = & $script:Module {
            param($InputScan)
            Test-HardeningLensPolicy -InputObject $InputScan -MaxFailed 7 -MaxWarning 3 -MinimumScore 77 -MinimumCoverage 96
        } $scan

        $evaluation.Passed | Should -BeTrue
        $evaluation.ExitCode | Should -Be 0
        @($evaluation.Violations).Count | Should -Be 0
        ($scan | ConvertTo-Json -Depth 40 -Compress) | Should -BeExactly $before
    }

    It 'gates partial collection and expired exceptions against an explicit date' {
        $scan = Get-HLPolicyTestResult
        $scan.scan.partialCollection = $true
        $exceptedResult = $scan.results | Where-Object { $null -ne $_.exception } | Select-Object -First 1
        $exceptedResult.exception.expires = '2026-01-31'

        $evaluation = & $script:Module {
            param($InputScan)
            Test-HardeningLensPolicy -InputObject $InputScan -DisallowPartialCollection -DisallowExpiredExceptions -AsOf ([datetime]'2026-07-14')
        } $scan

        @($evaluation.Violations).Code | Should -Be @('PartialCollectionDisallowed', 'ExpiredException')
        $evaluation.Metrics.PartialCollection | Should -BeTrue
        $evaluation.Metrics.ExpiredExceptionCount | Should -Be 1
        $evaluation.EvaluatedAsOf | Should -Be '2026-07-14'
    }

    It 'supports JSON input and a terminating FailOnViolation contract' {
        $evaluation = & $script:Module {
            param($InputPath)
            Test-HardeningLensPolicy -Path $InputPath -MaxFailed 7
        } $script:SamplePath
        $evaluation.Passed | Should -BeTrue

        $caught = try {
            & $script:Module {
                param($InputPath)
                Test-HardeningLensPolicy -Path $InputPath -MaxFailed 0 -FailOnViolation
            } $script:SamplePath
            $null
        }
        catch {
            $_
        }
        $caught | Should -Not -BeNullOrEmpty
        $caught.FullyQualifiedErrorId | Should -Match '^HardeningLens\.PolicyViolation'
        $caught.TargetObject.Passed | Should -BeFalse
        $caught.TargetObject.ExitCode | Should -Be 1
    }
}
