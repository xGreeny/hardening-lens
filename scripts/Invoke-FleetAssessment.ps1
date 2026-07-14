#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$ComputerName,

    [ValidateSet('Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
    [string]$Baseline = 'MemberServer',

    [string]$ExceptionsPath,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location).Path -ChildPath 'fleet-results'),

    [ValidateRange(1, 1024)]
    [int]$ThrottleLimit = 12,

    [pscredential]$Credential,

    [switch]$FailOnHostError
)

$ErrorActionPreference = 'Stop'

function ConvertTo-HLFleetSafeName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $safe = $Value -replace '[^A-Za-z0-9._-]', '-'
    $safe = $safe -replace '-{2,}', '-'
    $safe = $safe.Trim('-')
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return 'unknown-host'
    }
    return $safe
}

function Test-HLFleetHostNameMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Requested,

        [AllowNull()]
        [string]$Candidate
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return $false
    }

    $requestedName = $Requested.Trim().TrimEnd('.').ToLowerInvariant()
    $candidateName = $Candidate.Trim().TrimEnd('.').ToLowerInvariant()
    if ($requestedName -ceq $candidateName) {
        return $true
    }

    $requestedIsIp = $requestedName -match '^\d{1,3}(?:\.\d{1,3}){3}$'
    $candidateIsIp = $candidateName -match '^\d{1,3}(?:\.\d{1,3}){3}$'
    if ($requestedIsIp -or $candidateIsIp) {
        return $false
    }

    $requestedShort = @($requestedName -split '\.')[0]
    $candidateShort = @($candidateName -split '\.')[0]
    return -not [string]::IsNullOrWhiteSpace($requestedShort) -and $requestedShort -ceq $candidateShort
}

function Test-HLFleetResultHostMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Requested,

        [Parameter(Mandatory)]
        [object]$Result
    )

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($null -ne $Result.PSObject.Properties['PSComputerName']) {
        $candidates.Add([string]$Result.PSComputerName)
    }
    if ($null -ne $Result.PSObject.Properties['system'] -and
        $null -ne $Result.system -and
        $null -ne $Result.system.PSObject.Properties['ComputerName']) {
        $candidates.Add([string]$Result.system.ComputerName)
    }

    foreach ($candidate in $candidates) {
        if (Test-HLFleetHostNameMatch -Requested $Requested -Candidate $candidate) {
            return $true
        }
    }
    return $false
}

function Get-HLFleetErrorHostName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ErrorRecord
    )

    if ($null -ne $ErrorRecord.PSObject.Properties['OriginInfo'] -and
        $null -ne $ErrorRecord.OriginInfo -and
        $null -ne $ErrorRecord.OriginInfo.PSObject.Properties['PSComputerName']) {
        return [string]$ErrorRecord.OriginInfo.PSComputerName
    }
    if ($null -ne $ErrorRecord.PSObject.Properties['TargetObject'] -and $null -ne $ErrorRecord.TargetObject) {
        return [string]$ErrorRecord.TargetObject
    }
    return ''
}

function ConvertTo-HLFleetErrorDetail {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$ErrorRecord,

        [string]$FallbackMessage = 'The remote host returned no assessment result.'
    )

    if ($null -eq $ErrorRecord) {
        return [pscustomobject][ordered]@{
            Message               = $FallbackMessage
            Category              = 'RemoteResultMissing'
            FullyQualifiedErrorId = 'HardeningLens.Fleet.RemoteResultMissing'
        }
    }

    $message = if ($null -ne $ErrorRecord.PSObject.Properties['Exception'] -and $null -ne $ErrorRecord.Exception) {
        [string]$ErrorRecord.Exception.Message
    }
    else {
        [string]$ErrorRecord
    }
    $category = if ($null -ne $ErrorRecord.PSObject.Properties['CategoryInfo'] -and $null -ne $ErrorRecord.CategoryInfo) {
        [string]$ErrorRecord.CategoryInfo.Category
    }
    else {
        'RemoteExecutionError'
    }
    $errorId = if ($null -ne $ErrorRecord.PSObject.Properties['FullyQualifiedErrorId']) {
        [string]$ErrorRecord.FullyQualifiedErrorId
    }
    else {
        'HardeningLens.Fleet.RemoteExecutionError'
    }

    return [pscustomobject][ordered]@{
        Message               = $message
        Category              = $category
        FullyQualifiedErrorId = $errorId
    }
}

function Test-HLFleetScanResult {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Result
    )

    if ($null -eq $Result) {
        return $false
    }
    foreach ($requiredProperty in @('schemaVersion', 'scan', 'system', 'baseline', 'summary', 'results')) {
        if ($null -eq $Result.PSObject.Properties[$requiredProperty] -or $null -eq $Result.$requiredProperty) {
            return $false
        }
    }
    return [string]$Result.schemaVersion -eq '1.0'
}

function ConvertTo-HLFleetResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result
    )

    foreach ($propertyName in @('PSComputerName', 'RunspaceId', 'PSShowComputerName')) {
        [void]$Result.PSObject.Properties.Remove($propertyName)
    }
    return $Result
}

function Write-HLFleetJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [object]$InputObject
    )

    $content = ($InputObject | ConvertTo-Json -Depth 40) + [Environment]::NewLine
    [IO.File]::WriteAllText($Path, $content, (New-Object Text.UTF8Encoding($false)))
}

$requestedComputers = @($ComputerName | ForEach-Object {
    if ([string]::IsNullOrWhiteSpace([string]$_)) {
        throw 'ComputerName must not contain empty entries.'
    }
    ([string]$_).Trim()
})
if ($requestedComputers.Count -eq 0) {
    throw 'At least one ComputerName is required.'
}

$startedAt = (Get-Date).ToUniversalTime()
$runId = [guid]::NewGuid().ToString()
$runTimestamp = $startedAt.ToString('yyyyMMddTHHmmssfffZ')
$runKey = '{0}-{1}' -f $runTimestamp, $runId.Substring(0, 12)
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
[void](New-Item -Path $outputRoot -ItemType Directory -Force)

$moduleSource = Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'src/HardeningLens'
$moduleFiles = Get-ChildItem -LiteralPath $moduleSource -File -Recurse | ForEach-Object {
    [pscustomobject]@{
        RelativePath = $_.FullName.Substring($moduleSource.Length).TrimStart('\')
        Content      = [Convert]::ToBase64String([IO.File]::ReadAllBytes($_.FullName))
    }
}
$exceptionContent = if (-not [string]::IsNullOrWhiteSpace($ExceptionsPath)) {
    Get-Content -LiteralPath $ExceptionsPath -Raw -ErrorAction Stop
}
else {
    $null
}

$remoteErrors = @()
$sessionOptions = @{
    ComputerName  = $requestedComputers
    ThrottleLimit = $ThrottleLimit
    ErrorAction   = 'Continue'
    ErrorVariable = 'remoteErrors'
}
if ($null -ne $Credential) {
    $sessionOptions.Credential = $Credential
}

$remoteResults = @(Invoke-Command @sessionOptions -ArgumentList $moduleFiles,$Baseline,$exceptionContent -ScriptBlock {
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
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
})

$usedResultIndexes = @{}
$usedErrorIndexes = @{}
$summary = New-Object System.Collections.Generic.List[object]
$hostArtifacts = New-Object System.Collections.Generic.List[object]

for ($requestIndex = 0; $requestIndex -lt $requestedComputers.Count; $requestIndex++) {
    $requestedComputer = [string]$requestedComputers[$requestIndex]
    $matchedResult = $null
    $matchedResultIndex = -1
    for ($resultIndex = 0; $resultIndex -lt $remoteResults.Count; $resultIndex++) {
        if ($usedResultIndexes.ContainsKey($resultIndex)) {
            continue
        }
        if (Test-HLFleetResultHostMatch -Requested $requestedComputer -Result $remoteResults[$resultIndex]) {
            $matchedResult = $remoteResults[$resultIndex]
            $matchedResultIndex = $resultIndex
            break
        }
    }

    $matchedError = $null
    if ($null -eq $matchedResult) {
        for ($errorIndex = 0; $errorIndex -lt @($remoteErrors).Count; $errorIndex++) {
            if ($usedErrorIndexes.ContainsKey($errorIndex)) {
                continue
            }
            $errorHost = Get-HLFleetErrorHostName -ErrorRecord $remoteErrors[$errorIndex]
            if (Test-HLFleetHostNameMatch -Requested $requestedComputer -Candidate $errorHost) {
                $matchedError = $remoteErrors[$errorIndex]
                $usedErrorIndexes[$errorIndex] = $true
                break
            }
        }
    }

    $safeName = ConvertTo-HLFleetSafeName -Value $requestedComputer
    $artifactPrefix = 'fleet-{0}-{1:D3}-{2}' -f $runKey, ($requestIndex + 1), $safeName
    if ($null -ne $matchedResult -and (Test-HLFleetScanResult -Result $matchedResult)) {
        $usedResultIndexes[$matchedResultIndex] = $true
        $matchedResult = ConvertTo-HLFleetResult -Result $matchedResult
        $artifactPath = Join-Path -Path $outputRoot -ChildPath ($artifactPrefix + '.json')
        Write-HLFleetJson -Path $artifactPath -InputObject $matchedResult
        $summary.Add([pscustomobject][ordered]@{
            RunId                 = $runId
            RequestedComputerName = $requestedComputer
            ComputerName          = [string]$matchedResult.system.ComputerName
            Status                = 'Succeeded'
            Error                 = ''
            ErrorCategory         = ''
            Baseline              = [string]$matchedResult.baseline.name
            Score                 = $matchedResult.summary.HardeningScore
            Coverage              = $matchedResult.summary.EvidenceCoverage
            Fail                  = $matchedResult.summary.Fail
            Warning               = $matchedResult.summary.Warning
            Excepted              = $matchedResult.summary.Excepted
            Unknown               = $matchedResult.summary.Unknown
            ErrorCount            = $matchedResult.summary.Error
            ArtifactPath          = $artifactPath
        })
        $hostArtifacts.Add([pscustomobject][ordered]@{
            RequestedComputerName = $requestedComputer
            Status                = 'Succeeded'
            Path                  = $artifactPath
        })
        continue
    }

    if ($matchedResultIndex -ge 0) {
        $usedResultIndexes[$matchedResultIndex] = $true
        $errorDetails = ConvertTo-HLFleetErrorDetail -ErrorRecord $null -FallbackMessage 'The remote host returned an invalid Hardening Lens result.'
    }
    else {
        $errorDetails = ConvertTo-HLFleetErrorDetail -ErrorRecord $matchedError
    }
    $artifactPath = Join-Path -Path $outputRoot -ChildPath ($artifactPrefix + '.error.json')
    $failureArtifact = [pscustomobject][ordered]@{
        fleetSchemaVersion     = '1.0'
        artifactType          = 'HardeningLens.FleetHostFailure'
        runId                 = $runId
        recordedAt            = (Get-Date).ToUniversalTime().ToString('o')
        requestedComputerName = $requestedComputer
        status                = 'Failed'
        error                 = $errorDetails
    }
    Write-HLFleetJson -Path $artifactPath -InputObject $failureArtifact
    $summary.Add([pscustomobject][ordered]@{
        RunId                 = $runId
        RequestedComputerName = $requestedComputer
        ComputerName          = $requestedComputer
        Status                = 'Failed'
        Error                 = [string]$errorDetails.Message
        ErrorCategory         = [string]$errorDetails.Category
        Baseline              = $Baseline
        Score                 = $null
        Coverage              = $null
        Fail                  = $null
        Warning               = $null
        Excepted              = $null
        Unknown               = $null
        ErrorCount            = 1
        ArtifactPath          = $artifactPath
    })
    $hostArtifacts.Add([pscustomobject][ordered]@{
        RequestedComputerName = $requestedComputer
        Status                = 'Failed'
        Path                  = $artifactPath
    })
}

$summaryArray = $summary.ToArray()
$summaryPath = Join-Path -Path $outputRoot -ChildPath ("fleet-summary-$runKey.csv")
$latestSummaryPath = Join-Path -Path $outputRoot -ChildPath 'fleet-summary.csv'
$summaryArray | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8
$summaryArray | Export-Csv -LiteralPath $latestSummaryPath -NoTypeInformation -Encoding UTF8

$completedAt = (Get-Date).ToUniversalTime()
$succeededCount = @($summaryArray | Where-Object Status -eq 'Succeeded').Count
$failedCount = @($summaryArray | Where-Object Status -eq 'Failed').Count
$manifestPath = Join-Path -Path $outputRoot -ChildPath ("fleet-run-$runKey.json")
$manifest = [pscustomobject][ordered]@{
    fleetSchemaVersion = '1.0'
    artifactType       = 'HardeningLens.FleetRun'
    runId              = $runId
    startedAt          = $startedAt.ToString('o')
    completedAt        = $completedAt.ToString('o')
    baseline           = $Baseline
    requestedCount     = $requestedComputers.Count
    succeededCount     = $succeededCount
    failedCount        = $failedCount
    summaryPath        = $summaryPath
    latestSummaryPath  = $latestSummaryPath
    hostArtifacts      = $hostArtifacts.ToArray()
    unassignedResults  = $remoteResults.Count - $usedResultIndexes.Count
    unassignedErrors   = @($remoteErrors).Count - $usedErrorIndexes.Count
}
Write-HLFleetJson -Path $manifestPath -InputObject $manifest

if ($failedCount -gt 0) {
    Write-Warning ("Fleet assessment $runId completed with $failedCount failed host(s). See $manifestPath.")
}

$PSCmdlet.WriteObject($summaryArray, $true)
if ($FailOnHostError -and $failedCount -gt 0) {
    throw "Fleet assessment $runId failed on $failedCount of $($requestedComputers.Count) requested host(s)."
}
