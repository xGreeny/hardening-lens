#requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'BuiltIn')]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = 'BuiltIn')]
    [ValidateSet('Auto', 'Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
    [string]$Baseline = 'MemberServer',

    [Parameter(Mandatory, ParameterSetName = 'Custom')]
    [ValidateNotNullOrEmpty()]
    [string]$CustomBaselinePath,

    [ValidateNotNullOrEmpty()]
    [string[]]$ControlId,

    [string]$ExceptionsPath,

    [switch]$Redact,

    [switch]$AllowPartial,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location).Path -ChildPath 'fleet-results'),

    [ValidateRange(1, 1024)]
    [int]$ThrottleLimit = 12,

    [pscredential]$Credential,

    [switch]$Force,

    [switch]$FailOnHostError
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repositoryRoot = Join-Path -Path $PSScriptRoot -ChildPath '..'
$moduleRoot = Join-Path -Path (Join-Path -Path $repositoryRoot -ChildPath 'src') -ChildPath 'HardeningLens'
$modulePath = Join-Path -Path $moduleRoot -ChildPath 'HardeningLens.psd1'
$resolvedModulePath = (Resolve-Path -LiteralPath $modulePath -ErrorAction Stop).Path
$resolvedModuleRoot = (Resolve-Path -LiteralPath $moduleRoot -ErrorAction Stop).Path
$module = Get-Module -Name HardeningLens | Where-Object { $_.ModuleBase -eq $resolvedModuleRoot } | Select-Object -First 1
if ($null -eq $module) {
    Import-Module -Name $resolvedModulePath -Force -ErrorAction Stop
    $module = Get-Module -Name HardeningLens | Where-Object { $_.ModuleBase -eq $resolvedModuleRoot } | Select-Object -First 1
}
if ($null -eq $module) {
    throw 'Hardening Lens could not be loaded.'
}

$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$latestSummaryPath = Join-Path -Path $outputRoot -ChildPath 'fleet-summary.csv'
if ((Test-Path -LiteralPath $latestSummaryPath) -and -not $Force) {
    throw "Legacy fleet summary already exists: $latestSummaryPath. Use -Force to replace it."
}

$parameters = @{
    ComputerName    = $ComputerName
    ExceptionPath   = $ExceptionsPath
    Redact          = $Redact
    AllowPartial    = $AllowPartial
    OutputDirectory = $outputRoot
    ThrottleLimit   = $ThrottleLimit
    Force           = $Force
}
if ($PSCmdlet.ParameterSetName -eq 'Custom') {
    $parameters.CustomBaselinePath = $CustomBaselinePath
}
else {
    $parameters.Baseline = $Baseline
}
if ($null -ne $ControlId -and @($ControlId).Count -gt 0) {
    $parameters.ControlId = $ControlId
}
if ($null -ne $Credential) {
    $parameters.Credential = $Credential
}

$fleetResult = & $module {
    param($FleetParameters)
    Invoke-HardeningLensFleet @FleetParameters
} $parameters

$baselineSelection = if ($PSCmdlet.ParameterSetName -eq 'Custom') { 'Custom' } else { $Baseline }
$summaryRows = @($fleetResult.hosts | ForEach-Object {
    $assessment = $_.assessment
    [pscustomobject][ordered]@{
        RunId                 = [string]$fleetResult.run.id
        RequestedComputerName = [string]$_.requestedComputerName
        ComputerName          = [string]$_.computerName
        Status                = [string]$_.status
        Error                 = if ($null -ne $_.error) { [string]$_.error.message } else { '' }
        ErrorCategory         = if ($null -ne $_.error) { [string]$_.error.category } else { '' }
        Baseline              = if ($null -ne $assessment) { [string]$assessment.baseline.name } else { $baselineSelection }
        Score                 = if ($null -ne $assessment) { $assessment.summary.HardeningScore } else { $null }
        Coverage              = if ($null -ne $assessment) { $assessment.summary.EvidenceCoverage } else { $null }
        Fail                  = if ($null -ne $assessment) { $assessment.summary.Fail } else { $null }
        Warning               = if ($null -ne $assessment) { $assessment.summary.Warning } else { $null }
        Excepted              = if ($null -ne $assessment) { $assessment.summary.Excepted } else { $null }
        Unknown               = if ($null -ne $assessment) { $assessment.summary.Unknown } else { $null }
        ErrorCount            = if ($null -ne $assessment) { $assessment.summary.Error } else { 1 }
        ArtifactPath          = [string]$_.artifactPath
    }
})

if ((Test-Path -LiteralPath $latestSummaryPath) -and -not $Force) {
    throw "Legacy fleet summary already exists: $latestSummaryPath. Use -Force to replace it."
}
$summaryContent = (@($summaryRows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine) + [Environment]::NewLine
& $module {
    param($Path,$Content,$AllowOverwrite)
    try {
        Write-HLAtomicUtf8File -Path $Path -Content $Content -NoClobber:(-not $AllowOverwrite)
    }
    catch [System.IO.IOException] {
        if (-not $AllowOverwrite -and (Test-Path -LiteralPath $Path)) {
            throw "Legacy fleet summary already exists: $Path. Use -Force to replace it."
        }
        throw
    }
} $latestSummaryPath $summaryContent ([bool]$Force)

$PSCmdlet.WriteObject($summaryRows, $true)
if ($FailOnHostError -and $fleetResult.summary.failedCount -gt 0) {
    throw "Fleet assessment $($fleetResult.run.id) failed on $($fleetResult.summary.failedCount) of $($fleetResult.summary.requestedCount) requested host(s)."
}
