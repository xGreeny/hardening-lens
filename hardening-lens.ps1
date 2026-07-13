#requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Named')]
param(
    [Parameter(ParameterSetName = 'Named')]
    [ValidateSet('Auto', 'Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
    [string]$Baseline = 'Auto',

    [Parameter(Mandatory, ParameterSetName = 'Path')]
    [string]$BaselinePath,

    [string[]]$ControlId,

    [string]$ExceptionsPath,

    [string]$OutputDirectory = (Join-Path -Path $PSScriptRoot -ChildPath 'out'),

    [ValidateSet('Html', 'Json', 'Csv')]
    [string[]]$Format = @('Html', 'Json', 'Csv'),

    [ValidateSet('None', 'Low', 'Medium', 'High', 'Critical')]
    [string]$FailOnSeverity = 'High',

    [switch]$AllowPartial,

    [switch]$Redact,

    [switch]$NoConsole,

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path -Path (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath 'src') -ChildPath 'HardeningLens') -ChildPath 'HardeningLens.psd1'

try {
    Import-Module -Name $modulePath -Force -ErrorAction Stop

    $scanParameters = @{
        AllowPartial = $AllowPartial
        Redact       = $Redact
        NoConsole    = $NoConsole
    }
    if ($null -ne $ControlId -and @($ControlId).Count -gt 0) { $scanParameters.ControlId = $ControlId }
    if (-not [string]::IsNullOrWhiteSpace($ExceptionsPath)) { $scanParameters.ExceptionsPath = $ExceptionsPath }
    if ($PSCmdlet.ParameterSetName -eq 'Path') { $scanParameters.BaselinePath = $BaselinePath } else { $scanParameters.Baseline = $Baseline }

    $scan = Invoke-HardeningLens @scanParameters
    $files = Export-HardeningLensReport -InputObject $scan -Format $Format -OutputDirectory $OutputDirectory

    if (-not $NoConsole) {
        Write-Host 'Reports:' -ForegroundColor Cyan
        foreach ($file in @($files)) { Write-Host ('  [{0}] {1}' -f $file.Format, $file.Path) }
        Write-Host ''
    }

    if ($PassThru) {
        $PSCmdlet.WriteObject($scan, $false)
    }

    if ($FailOnSeverity -eq 'None') { exit 0 }
    $rank = @{ Low = 1; Medium = 2; High = 3; Critical = 4 }
    $threshold = $rank[$FailOnSeverity]
    $blocking = @($scan.results | Where-Object {
        $_.status -in @('Fail', 'Error') -and $rank[[string]$_.severity] -ge $threshold
    })
    if ($blocking.Count -gt 0) { exit 1 }
    exit 0
}
catch {
    Write-Error -ErrorRecord $_
    exit 2
}
