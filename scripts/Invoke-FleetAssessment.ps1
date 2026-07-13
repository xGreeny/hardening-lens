#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$ComputerName,

    [ValidateSet('Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
    [string]$Baseline = 'MemberServer',

    [string]$ExceptionsPath,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location).Path -ChildPath 'fleet-results'),

    [int]$ThrottleLimit = 12,

    [pscredential]$Credential
)

$ErrorActionPreference = 'Stop'
$moduleSource = Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'src/HardeningLens'
$moduleFiles = Get-ChildItem -LiteralPath $moduleSource -File -Recurse | ForEach-Object {
    [pscustomobject]@{ RelativePath = $_.FullName.Substring($moduleSource.Length).TrimStart('\'); Content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($_.FullName)) }
}
$exceptionContent = if (-not [string]::IsNullOrWhiteSpace($ExceptionsPath)) { Get-Content -LiteralPath $ExceptionsPath -Raw -ErrorAction Stop } else { $null }
[void](New-Item -Path $OutputDirectory -ItemType Directory -Force)

$sessionOptions = @{ ComputerName = $ComputerName; ThrottleLimit = $ThrottleLimit; ErrorAction = 'Continue' }
if ($null -ne $Credential) { $sessionOptions.Credential = $Credential }

$results = Invoke-Command @sessionOptions -ArgumentList $moduleFiles,$Baseline,$exceptionContent -ScriptBlock {
    param($Files,$SelectedBaseline,$ExceptionJson)
    $tempRoot = Join-Path -Path $env:TEMP -ChildPath ('HardeningLens-' + [guid]::NewGuid().ToString('N'))
    $moduleRoot = Join-Path -Path $tempRoot -ChildPath 'HardeningLens'
    try {
        foreach ($file in @($Files)) {
            $target = Join-Path -Path $moduleRoot -ChildPath ([string]$file.RelativePath)
            [void](New-Item -Path (Split-Path -Path $target -Parent) -ItemType Directory -Force)
            [IO.File]::WriteAllBytes($target, [Convert]::FromBase64String([string]$file.Content))
        }
        Import-Module -Name (Join-Path -Path $moduleRoot -ChildPath 'HardeningLens.psd1') -Force
        $parameters = @{ Baseline = $SelectedBaseline; AllowPartial = $true; Redact = $false; NoConsole = $true }
        if (-not [string]::IsNullOrWhiteSpace($ExceptionJson)) {
            $exceptionPath = Join-Path -Path $tempRoot -ChildPath 'exceptions.json'
            [IO.File]::WriteAllText($exceptionPath, $ExceptionJson)
            $parameters.ExceptionsPath = $exceptionPath
        }
        Invoke-HardeningLens @parameters
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

$cleanResults = New-Object System.Collections.Generic.List[object]
foreach ($result in @($results)) {
    if ($null -eq $result.schemaVersion) { continue }

    # PowerShell remoting adds transport metadata to deserialized objects. Remove it
    # before exporting so the result remains compatible with result.schema.json.
    foreach ($propertyName in @('PSComputerName', 'RunspaceId', 'PSShowComputerName')) {
        [void]$result.PSObject.Properties.Remove($propertyName)
    }
    $cleanResults.Add($result)

    $safeName = ([string]$result.system.ComputerName) -replace '[^A-Za-z0-9._-]','-'
    $path = Join-Path -Path $OutputDirectory -ChildPath ("$safeName.json")
    [IO.File]::WriteAllText($path, (($result | ConvertTo-Json -Depth 40) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
}

$summary = @($cleanResults | ForEach-Object {
    [pscustomobject]@{
        ComputerName = $_.system.ComputerName
        Baseline = $_.baseline.name
        Score = $_.summary.HardeningScore
        Coverage = $_.summary.EvidenceCoverage
        Fail = $_.summary.Fail
        Warning = $_.summary.Warning
        Excepted = $_.summary.Excepted
        Unknown = $_.summary.Unknown
        Error = $_.summary.Error
    }
})
$summaryPath = Join-Path -Path $OutputDirectory -ChildPath 'fleet-summary.csv'
$summary | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8
$summary
