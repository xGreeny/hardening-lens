function Compare-HardeningLensResult {
    <#
    .SYNOPSIS
    Compares two Hardening Lens scan results and identifies security posture drift.

    .PARAMETER Reference
    Earlier scan object or JSON file path.

    .PARAMETER Difference
    Current scan object or JSON file path.

    .PARAMETER OutputPath
    Optional output file path.

    .PARAMETER Format
    Output format when OutputPath is specified.

    .PARAMETER AllowCrossTargetComparison
    Allows results from different computer names to be compared. By default, a mismatch is rejected to prevent accidental cross-target drift reports.

    .PARAMETER AllowCrossBaselineComparison
    Allows results from different baseline names to be compared. Baseline version changes with the same name remain supported by default.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Reference,

        [Parameter(Mandatory)]
        [object]$Difference,

        [string]$OutputPath,

        [ValidateSet('Json', 'Markdown')]
        [string]$Format = 'Markdown',

        [switch]$AllowCrossTargetComparison,

        [switch]$AllowCrossBaselineComparison
    )

    $referenceResult = Read-HLScanResult -InputObject $Reference
    $differenceResult = Read-HLScanResult -InputObject $Difference

    $referenceComputer = [string]$referenceResult.system.ComputerName
    $differenceComputer = [string]$differenceResult.system.ComputerName
    if (-not $AllowCrossTargetComparison -and
        -not [string]::IsNullOrWhiteSpace($referenceComputer) -and
        -not [string]::IsNullOrWhiteSpace($differenceComputer) -and
        $referenceComputer -ine $differenceComputer) {
        throw "Cannot compare results from different targets ('$referenceComputer' and '$differenceComputer'). Use -AllowCrossTargetComparison only for an intentional cross-target comparison."
    }

    $referenceBaseline = [string]$referenceResult.baseline.name
    $differenceBaseline = [string]$differenceResult.baseline.name
    if (-not $AllowCrossBaselineComparison -and
        -not [string]::IsNullOrWhiteSpace($referenceBaseline) -and
        -not [string]::IsNullOrWhiteSpace($differenceBaseline) -and
        $referenceBaseline -ine $differenceBaseline) {
        throw "Cannot compare results from different baselines ('$referenceBaseline' and '$differenceBaseline'). Use -AllowCrossBaselineComparison only for an intentional cross-baseline comparison."
    }

    $comparison = New-HLComparison -Reference $referenceResult -Difference $differenceResult

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $parent = Split-Path -Path $OutputPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
            [void](New-Item -Path $parent -ItemType Directory -Force)
        }
        $content = if ($Format -eq 'Json') { ($comparison | ConvertTo-Json -Depth 30) + [Environment]::NewLine } else { (New-HLComparisonMarkdown -Comparison $comparison) + [Environment]::NewLine }
        Write-HLUtf8File -Path ([IO.Path]::GetFullPath($OutputPath)) -Content $content
    }

    Write-Output -NoEnumerate $comparison
}
