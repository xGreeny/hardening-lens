#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Clean', 'Validate', 'Test', 'Build', 'Package', 'All')]
    [string]$Task = 'All',

    [switch]$SkipAnalyzer,

    [ValidateRange(0, 100)]
    [double]$MinimumCoveragePercent = 45.0
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$moduleSource = Join-Path -Path (Join-Path -Path $root -ChildPath 'src') -ChildPath 'HardeningLens'
$manifestPath = Join-Path -Path $moduleSource -ChildPath 'HardeningLens.psd1'
$dist = Join-Path -Path $root -ChildPath 'dist'
$artifacts = Join-Path -Path $root -ChildPath 'artifacts'

function Invoke-Clean {
    foreach ($path in @($dist, $artifacts, (Join-Path -Path $root -ChildPath 'TestResults.xml'))) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
}

function Invoke-Validation {
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
    Write-Host ("Validated module manifest: HardeningLens {0}" -f $manifest.Version) -ForegroundColor Green

    $jsonFiles = Get-ChildItem -Path $root -Filter '*.json' -File -Recurse | Where-Object {
        $_.FullName -notmatch '[\\/]artifacts[\\/]|[\\/]dist[\\/]'
    }
    foreach ($jsonFile in $jsonFiles) {
        $null = Get-Content -LiteralPath $jsonFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
    }
    Write-Host ("Validated JSON syntax in {0} files." -f @($jsonFiles).Count) -ForegroundColor Green

    Import-Module -Name $manifestPath -Force -ErrorAction Stop
    $catalog = @(Get-HardeningLensControl)
    if ($catalog.Count -ne 64) {
        throw "Expected 64 controls, found $($catalog.Count)."
    }
    $uniqueIds = @($catalog.id | Sort-Object -Unique)
    if ($uniqueIds.Count -ne $catalog.Count) {
        throw 'The control catalog contains duplicate IDs.'
    }
    foreach ($control in $catalog) {
        if (@($control.references).Count -eq 0) {
            throw "Control '$($control.id)' has no reference."
        }
        foreach ($reference in @($control.references)) {
            if ([string]$reference -notmatch '^https://learn\.microsoft\.com/') {
                throw "Control '$($control.id)' uses a non-Microsoft reference: $reference"
            }
        }
    }

    foreach ($baseline in Get-HardeningLensBaseline) {
        if ($baseline.ControlCount -lt 50) {
            throw "Baseline '$($baseline.Name)' unexpectedly contains fewer than 50 controls."
        }
    }

    $exceptionExample = Join-Path -Path (Join-Path -Path $root -ChildPath 'examples') -ChildPath 'exceptions.json'
    $exceptionValidation = Test-HardeningLensExceptionFile -Path $exceptionExample
    if (-not $exceptionValidation.IsValid) {
        throw ('Example exception register is invalid: {0}' -f (@($exceptionValidation.Errors) -join ' '))
    }

    if (-not $SkipAnalyzer) {
        $analyzer = Get-Module -ListAvailable -Name PSScriptAnalyzer | Sort-Object Version -Descending | Select-Object -First 1
        if ($null -eq $analyzer) {
            throw 'PSScriptAnalyzer is required. Install-Module PSScriptAnalyzer -Scope CurrentUser'
        }

        Import-Module PSScriptAnalyzer -MinimumVersion $analyzer.Version -Force
        $settings = Join-Path -Path $root -ChildPath '.psscriptanalyzer.psd1'
        $analysisPaths = @(
            $moduleSource,
            (Join-Path -Path $root -ChildPath 'scripts'),
            (Join-Path -Path $root -ChildPath 'tests'),
            (Join-Path -Path $root -ChildPath 'build.ps1'),
            (Join-Path -Path $root -ChildPath 'hardening-lens.ps1')
        )
        $analysis = New-Object System.Collections.Generic.List[object]
        foreach ($analysisPath in $analysisPaths) {
            if (-not (Test-Path -LiteralPath $analysisPath)) { continue }
            foreach ($finding in @(Invoke-ScriptAnalyzer -Path $analysisPath -Recurse -Settings $settings -Severity Warning,Error)) {
                $analysis.Add($finding)
            }
        }
        if ($analysis.Count -gt 0) {
            $analysis | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize | Out-String | Write-Host
            throw "PSScriptAnalyzer found $($analysis.Count) warning(s) or error(s)."
        }
        Write-Host 'PSScriptAnalyzer completed without warnings or errors.' -ForegroundColor Green
    }
}

function Invoke-TestSuite {
    $pester = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $pester -or $pester.Version -lt [version]'5.6.1') {
        throw 'Pester 5.6.1 or later is required. Install-Module Pester -MinimumVersion 5.6.1 -Scope CurrentUser'
    }

    Import-Module Pester -MinimumVersion 5.6.1 -Force
    [void](New-Item -Path $artifacts -ItemType Directory -Force)
    $coverageFiles = @(Get-ChildItem -Path @(
        (Join-Path -Path $moduleSource -ChildPath 'Private'),
        (Join-Path -Path $moduleSource -ChildPath 'Public')
    ) -Filter '*.ps1' -File -Recurse | ForEach-Object { $_.FullName })

    $configuration = New-PesterConfiguration
    $configuration.Run.Path = Join-Path -Path $root -ChildPath 'tests'
    $configuration.Filter.ExcludeTag = @('WindowsLive')
    $configuration.Run.PassThru = $true
    $configuration.Output.Verbosity = 'Detailed'
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputPath = Join-Path -Path $root -ChildPath 'TestResults.xml'
    $configuration.TestResult.OutputFormat = 'NUnitXml'
    $configuration.CodeCoverage.Enabled = $true
    $configuration.CodeCoverage.Path = $coverageFiles
    $configuration.CodeCoverage.OutputPath = Join-Path -Path $artifacts -ChildPath 'coverage.xml'
    $configuration.CodeCoverage.OutputFormat = 'JaCoCo'
    $configuration.CodeCoverage.CoveragePercentTarget = $MinimumCoveragePercent

    $result = Invoke-Pester -Configuration $configuration
    $runFailed = [string]$result.Result -ne 'Passed' -or
        $result.FailedCount -gt 0 -or
        $result.FailedBlocksCount -gt 0 -or
        $result.FailedContainersCount -gt 0
    if ($runFailed) {
        throw ('Pester run failed: result={0}, tests={1}, blocks={2}, containers={3}.' -f
            $result.Result,
            $result.FailedCount,
            $result.FailedBlocksCount,
            $result.FailedContainersCount)
    }

    if ($null -eq $result.CodeCoverage -or $null -eq $result.CodeCoverage.CoveragePercent) {
        throw 'Pester did not return a code coverage result.'
    }
    $coveragePercent = [double]$result.CodeCoverage.CoveragePercent
    if ($coveragePercent -lt $MinimumCoveragePercent) {
        throw ('Code coverage {0:N2}% is below the required {1:N2}%.' -f $coveragePercent, $MinimumCoveragePercent)
    }

    Write-Host ("Pester passed: {0} tests, {1} skipped, {2:N2}% coverage (minimum {3:N2}%)." -f $result.PassedCount, $result.SkippedCount, $coveragePercent, $MinimumCoveragePercent) -ForegroundColor Green
}

function Invoke-Build {
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
    $versionRoot = Join-Path -Path (Join-Path -Path $dist -ChildPath 'HardeningLens') -ChildPath $manifest.Version.ToString()
    if (Test-Path -LiteralPath $versionRoot) {
        Remove-Item -LiteralPath $versionRoot -Recurse -Force
    }
    [void](New-Item -Path $versionRoot -ItemType Directory -Force)
    Copy-Item -Path (Join-Path -Path $moduleSource -ChildPath '*') -Destination $versionRoot -Recurse -Force
    Write-Host "Built module at $versionRoot" -ForegroundColor Green
    return $versionRoot
}

function Invoke-Package {
    $null = Invoke-Build
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
    [void](New-Item -Path $artifacts -ItemType Directory -Force)
    $zipPath = Join-Path -Path $artifacts -ChildPath ("HardeningLens-{0}.zip" -f $manifest.Version)
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }

    Compress-Archive -Path (Join-Path -Path $dist -ChildPath 'HardeningLens') -DestinationPath $zipPath -CompressionLevel Optimal
    $hash = Get-FileHash -LiteralPath $zipPath -Algorithm SHA256
    $hashPath = $zipPath + '.sha256'
    [IO.File]::WriteAllText(
        $hashPath,
        ("{0}  {1}{2}" -f $hash.Hash, [IO.Path]::GetFileName($zipPath), [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
    Write-Host "Packaged $zipPath" -ForegroundColor Green
}

switch ($Task) {
    'Clean' { Invoke-Clean }
    'Validate' { Invoke-Validation }
    'Test' { Invoke-Validation; Invoke-TestSuite }
    'Build' { $null = Invoke-Build }
    'Package' { Invoke-Package }
    'All' { Invoke-Clean; Invoke-Validation; Invoke-TestSuite; Invoke-Package }
}
