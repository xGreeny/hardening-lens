function Get-HLFleetUtcNow {
    [CmdletBinding()]
    param()

    return (Get-Date).ToUniversalTime()
}

function Get-HLFleetRunId {
    [CmdletBinding()]
    param()

    return [guid]::NewGuid().ToString()
}

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

function Get-HLFleetNormalizedHostName {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }
    return $Value.Trim().TrimEnd('.').ToLowerInvariant()
}

function Test-HLFleetIpAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $parsed = $null
    return [net.ipaddress]::TryParse($Value, [ref]$parsed)
}

function Test-HLFleetQualifiedHostName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $normalized = Get-HLFleetNormalizedHostName -Value $Value
    return $normalized.Contains('.') -and -not (Test-HLFleetIpAddress -Value $normalized)
}

function Get-HLFleetShortHostName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $normalized = Get-HLFleetNormalizedHostName -Value $Value
    if ([string]::IsNullOrWhiteSpace($normalized) -or (Test-HLFleetIpAddress -Value $normalized)) {
        return $normalized
    }
    return @($normalized -split '\.')[0]
}

function Test-HLFleetHostNameExactMatch {
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
    return (Get-HLFleetNormalizedHostName -Value $Requested) -ceq (Get-HLFleetNormalizedHostName -Value $Candidate)
}

function Test-HLFleetHostNameMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Requested,

        [AllowNull()]
        [string]$Candidate,

        [switch]$AllowShortName
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return $false
    }

    $requestedName = Get-HLFleetNormalizedHostName -Value $Requested
    $candidateName = Get-HLFleetNormalizedHostName -Value $Candidate
    if (Test-HLFleetHostNameExactMatch -Requested $requestedName -Candidate $candidateName) {
        return $true
    }
    if (-not $AllowShortName) {
        return $false
    }

    if ((Test-HLFleetIpAddress -Value $requestedName) -or (Test-HLFleetIpAddress -Value $candidateName)) {
        return $false
    }
    if ((Test-HLFleetQualifiedHostName -Value $requestedName) -and (Test-HLFleetQualifiedHostName -Value $candidateName)) {
        return $false
    }

    $requestedShort = Get-HLFleetShortHostName -Value $requestedName
    $candidateShort = Get-HLFleetShortHostName -Value $candidateName
    return -not [string]::IsNullOrWhiteSpace($requestedShort) -and $requestedShort -ceq $candidateShort
}

function Test-HLFleetResultHostMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Requested,

        [Parameter(Mandatory)]
        [object]$Result,

        [switch]$AllowShortName
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
        if (Test-HLFleetHostNameExactMatch -Requested $Requested -Candidate $candidate) {
            return $true
        }
    }
    if (-not $AllowShortName) {
        return $false
    }

    if (Test-HLFleetQualifiedHostName -Value $Requested) {
        $conflictingQualifiedName = @($candidates | Where-Object {
            (Test-HLFleetQualifiedHostName -Value $_) -and
            -not (Test-HLFleetHostNameExactMatch -Requested $Requested -Candidate $_)
        }).Count -gt 0
        if ($conflictingQualifiedName) {
            return $false
        }
    }

    foreach ($candidate in $candidates) {
        if (Test-HLFleetHostNameMatch -Requested $Requested -Candidate $candidate -AllowShortName) {
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
            message               = $FallbackMessage
            category              = 'RemoteResultMissing'
            fullyQualifiedErrorId = 'HardeningLens.Fleet.RemoteResultMissing'
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
        message               = $message
        category              = $category
        fullyQualifiedErrorId = $errorId
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

    try {
        Assert-HLScanResult -ScanResult $Result
        return $true
    }
    catch {
        return $false
    }
}

function ConvertTo-HLFleetCleanResult {
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

function Write-HLFleetJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [object]$InputObject
    )

    $content = ($InputObject | ConvertTo-Json -Depth 50) + [Environment]::NewLine
    Write-HLAtomicUtf8File -Path $Path -Content $content
}

function Write-HLFleetCsvFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $content = (@($InputObject | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine) + [Environment]::NewLine
    Write-HLAtomicUtf8File -Path $Path -Content $content
}

function Move-HLFleetDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal transaction primitive controlled by the public command Force contract.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Destination,

        [ValidateRange(1, 20)]
        [int]$MaximumAttempts = 5,

        [ValidateRange(0, 5000)]
        [int]$RetryDelayMilliseconds = 250
    )

    for ($attempt = 1; $attempt -le $MaximumAttempts; $attempt++) {
        try {
            [IO.Directory]::Move($Path, $Destination)
            return
        }
        catch [IO.DirectoryNotFoundException] {
            # A missing source or destination parent never becomes movable.
            throw
        }
        catch [IO.IOException], [UnauthorizedAccessException] {
            # Antivirus and indexing services briefly lock freshly written
            # files; retry within a small bounded window before failing.
            if ($attempt -ge $MaximumAttempts) {
                throw
            }
        }
        Start-Sleep -Milliseconds $RetryDelayMilliseconds
    }
}

function Publish-HLFleetRunDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal transaction commit controlled by the public command Force contract.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$StagingPath,

        [Parameter(Mandatory)]
        [string]$DestinationPath,

        [switch]$Force
    )

    $stagingFullPath = [IO.Path]::GetFullPath($StagingPath)
    $destinationFullPath = [IO.Path]::GetFullPath($DestinationPath)
    $parentPath = [IO.Path]::GetFullPath((Split-Path -Path $destinationFullPath -Parent))
    if ([IO.Path]::GetFullPath((Split-Path -Path $stagingFullPath -Parent)) -cne $parentPath) {
        throw 'Fleet staging and destination directories must share the same parent directory.'
    }
    if (-not (Test-Path -LiteralPath $stagingFullPath -PathType Container)) {
        throw "Fleet staging directory does not exist: $stagingFullPath"
    }

    if (-not (Test-Path -LiteralPath $destinationFullPath)) {
        Move-HLFleetDirectory -Path $stagingFullPath -Destination $destinationFullPath
        return
    }
    if (-not $Force) {
        throw "Fleet run already exists: $destinationFullPath. Use -Force to replace the complete run."
    }

    $backupPath = Join-Path -Path $parentPath -ChildPath ('.{0}.backup-{1}' -f [IO.Path]::GetFileName($destinationFullPath), [guid]::NewGuid().ToString('N'))
    Move-HLFleetDirectory -Path $destinationFullPath -Destination $backupPath
    try {
        try {
            Move-HLFleetDirectory -Path $stagingFullPath -Destination $destinationFullPath
        }
        catch {
            $publishError = $_
            if ((Test-Path -LiteralPath $backupPath -PathType Container) -and -not (Test-Path -LiteralPath $destinationFullPath)) {
                Move-HLFleetDirectory -Path $backupPath -Destination $destinationFullPath
            }
            throw $publishError
        }

        if (Test-Path -LiteralPath $backupPath -PathType Container) {
            try {
                Remove-Item -LiteralPath $backupPath -Recurse -Force -ErrorAction Stop
            }
            catch {
                Write-Warning "Fleet run was committed, but its transaction backup could not be removed: $backupPath"
            }
        }
    }
    catch {
        if ((Test-Path -LiteralPath $backupPath -PathType Container) -and -not (Test-Path -LiteralPath $destinationFullPath)) {
            Move-HLFleetDirectory -Path $backupPath -Destination $destinationFullPath
        }
        throw
    }
}

function Get-HLFleetJsonContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Description
    )

    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $content = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop
    try {
        $null = $content | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "$Description '$resolvedPath' is not valid JSON: $($_.Exception.Message)"
    }
    return $content
}

function Get-HLFleetModulePayload {
    [CmdletBinding()]
    param()

    $moduleFiles = New-Object System.Collections.Generic.List[object]
    foreach ($file in @(Get-ChildItem -LiteralPath $script:HLModuleRoot -File -Recurse | Sort-Object FullName)) {
        $relativePath = $file.FullName.Substring($script:HLModuleRoot.Length).TrimStart([char[]]@('\', '/'))
        $moduleFiles.Add([pscustomobject][ordered]@{
            RelativePath = $relativePath
            Content      = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))
        })
    }
    return $moduleFiles.ToArray()
}

function Get-HLFleetRemoteScriptBlock {
    [CmdletBinding()]
    param()

    return {
        param($Files,$SelectedBaseline,$CustomBaselineJson,$ControlIds,$ExceptionJson,$PermitPartial,$UseRedaction)

        $ErrorActionPreference = 'Stop'
        $tempRoot = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ('HardeningLens-' + [guid]::NewGuid().ToString('N'))
        $moduleRoot = Join-Path -Path $tempRoot -ChildPath 'HardeningLens'
        [void](New-Item -Path $moduleRoot -ItemType Directory -Force)
        try {
            foreach ($file in $Files) {
                $relativePath = [string]$file.RelativePath -replace '[\\/]', [IO.Path]::DirectorySeparatorChar
                $target = Join-Path -Path $moduleRoot -ChildPath $relativePath
                [void](New-Item -Path (Split-Path -Path $target -Parent) -ItemType Directory -Force)
                [IO.File]::WriteAllBytes($target, [Convert]::FromBase64String([string]$file.Content))
            }

            $manifestPath = Join-Path -Path $moduleRoot -ChildPath 'HardeningLens.psd1'
            Import-Module -Name $manifestPath -Force -ErrorAction Stop
            $parameters = @{
                AllowPartial = [bool]$PermitPartial
                Redact       = [bool]$UseRedaction
                NoConsole    = $true
            }

            if (-not [string]::IsNullOrWhiteSpace([string]$CustomBaselineJson)) {
                $customBaselinePath = Join-Path -Path $tempRoot -ChildPath 'custom-baseline.json'
                [IO.File]::WriteAllText($customBaselinePath, [string]$CustomBaselineJson, (New-Object Text.UTF8Encoding($false)))
                $parameters.BaselinePath = $customBaselinePath
            }
            else {
                $parameters.Baseline = [string]$SelectedBaseline
            }

            if ($null -ne $ControlIds -and @($ControlIds).Count -gt 0) {
                $parameters.ControlId = @($ControlIds)
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$ExceptionJson)) {
                $exceptionPath = Join-Path -Path $tempRoot -ChildPath 'exceptions.json'
                [IO.File]::WriteAllText($exceptionPath, [string]$ExceptionJson, (New-Object Text.UTF8Encoding($false)))
                $parameters.ExceptionsPath = $exceptionPath
            }

            Invoke-HardeningLens @parameters
        }
        finally {
            if (Test-Path -LiteralPath $tempRoot) {
                Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function ConvertTo-HLFleetSummaryRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RunId,

        [Parameter(Mandatory)]
        [object]$HostResult,

        [Parameter(Mandatory)]
        [string]$BaselineSelection
    )

    $assessment = $HostResult.assessment
    return [pscustomobject][ordered]@{
        RunId                 = $RunId
        RequestedComputerName = [string]$HostResult.requestedComputerName
        ComputerName          = [string]$HostResult.computerName
        Status                = [string]$HostResult.status
        Error                 = if ($null -ne $HostResult.error) { [string]$HostResult.error.message } else { '' }
        ErrorCategory         = if ($null -ne $HostResult.error) { [string]$HostResult.error.category } else { '' }
        Baseline              = if ($null -ne $assessment) { [string]$assessment.baseline.name } else { $BaselineSelection }
        Score                 = if ($null -ne $assessment) { $assessment.summary.HardeningScore } else { $null }
        Coverage              = if ($null -ne $assessment) { $assessment.summary.EvidenceCoverage } else { $null }
        Fail                  = if ($null -ne $assessment) { $assessment.summary.Fail } else { $null }
        Warning               = if ($null -ne $assessment) { $assessment.summary.Warning } else { $null }
        Excepted              = if ($null -ne $assessment) { $assessment.summary.Excepted } else { $null }
        Unknown               = if ($null -ne $assessment) { $assessment.summary.Unknown } else { $null }
        ErrorCount            = if ($null -ne $assessment) { $assessment.summary.Error } else { 1 }
        ArtifactPath          = [string]$HostResult.artifactPath
    }
}

function Get-HLFleetAggregateSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$HostResults
    )

    $succeeded = @($HostResults | Where-Object status -eq 'Succeeded')
    $failed = @($HostResults | Where-Object status -eq 'Failed')
    $scores = @($succeeded | ForEach-Object { $_.assessment.summary.HardeningScore } | Where-Object { $null -ne $_ })
    $coverage = @($succeeded | ForEach-Object { $_.assessment.summary.EvidenceCoverage } | Where-Object { $null -ne $_ })

    $averageScore = if ($scores.Count -gt 0) {
        [math]::Round([double](($scores | Measure-Object -Average).Average), 2)
    }
    else {
        $null
    }
    $averageCoverage = if ($coverage.Count -gt 0) {
        [math]::Round([double](($coverage | Measure-Object -Average).Average), 2)
    }
    else {
        $null
    }

    return [pscustomobject][ordered]@{
        requestedCount          = $HostResults.Count
        succeededCount          = $succeeded.Count
        failedCount             = $failed.Count
        averageHardeningScore   = $averageScore
        averageEvidenceCoverage = $averageCoverage
        totalFail               = [int](($succeeded | ForEach-Object { $_.assessment.summary.Fail } | Measure-Object -Sum).Sum)
        totalWarning            = [int](($succeeded | ForEach-Object { $_.assessment.summary.Warning } | Measure-Object -Sum).Sum)
        totalExcepted           = [int](($succeeded | ForEach-Object { $_.assessment.summary.Excepted } | Measure-Object -Sum).Sum)
        totalUnknown            = [int](($succeeded | ForEach-Object { $_.assessment.summary.Unknown } | Measure-Object -Sum).Sum)
        totalError              = [int](($succeeded | ForEach-Object { $_.assessment.summary.Error } | Measure-Object -Sum).Sum) + $failed.Count
    }
}

function Invoke-HLFleetAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerName,

        [ValidateSet('Auto', 'Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
        [string]$Baseline = 'Auto',

        [string]$CustomBaselinePath,

        [string[]]$ControlId,

        [string]$ExceptionPath,

        [switch]$AllowPartial,

        [switch]$Redact,

        [pscredential]$Credential,

        [ValidateRange(1, 1024)]
        [int]$ThrottleLimit = 12,

        [Parameter(Mandatory)]
        [string]$OutputDirectory,

        [switch]$Force
    )

    $requestedComputers = @($ComputerName | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace([string]$_)) {
            throw 'ComputerName must not contain empty entries.'
        }
        ([string]$_).Trim()
    })
    if ($requestedComputers.Count -eq 0) {
        throw 'At least one ComputerName is required.'
    }

    $customBaselineJson = if (-not [string]::IsNullOrWhiteSpace($CustomBaselinePath)) {
        Get-HLFleetJsonContent -Path $CustomBaselinePath -Description 'Custom baseline'
    }
    else {
        $null
    }
    $exceptionJson = if (-not [string]::IsNullOrWhiteSpace($ExceptionPath)) {
        Get-HLFleetJsonContent -Path $ExceptionPath -Description 'Exception register'
    }
    else {
        $null
    }

    $startedAt = Get-HLFleetUtcNow
    $runId = Get-HLFleetRunId
    $runTimestamp = $startedAt.ToString('yyyyMMddTHHmmssfffZ')
    $runKey = '{0}-{1}' -f $runTimestamp, $runId.Substring(0, 12)
    $outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
    [void](New-Item -Path $outputRoot -ItemType Directory -Force)

    $runDirectoryName = "fleet-run-$runKey"
    $runRoot = Join-Path -Path $outputRoot -ChildPath $runDirectoryName
    if ((Test-Path -LiteralPath $runRoot) -and -not (Test-Path -LiteralPath $runRoot -PathType Container)) {
        throw "Fleet run path exists but is not a directory: $runRoot"
    }
    if ((Test-Path -LiteralPath $runRoot -PathType Container) -and -not $Force) {
        throw "Fleet run already exists: $runRoot. Use -Force to replace the complete run."
    }

    $stagingRoot = Join-Path -Path $outputRoot -ChildPath ('.{0}.staging-{1}' -f $runDirectoryName, [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $stagingRoot -ItemType Directory -ErrorAction Stop)
    $summaryPath = Join-Path -Path $runRoot -ChildPath 'fleet-summary.csv'
    $resultPath = Join-Path -Path $runRoot -ChildPath 'fleet-result.json'
    $manifestPath = Join-Path -Path $runRoot -ChildPath 'manifest.json'
    $commitMarkerPath = Join-Path -Path $runRoot -ChildPath 'commit.json'
    $stagingSummaryPath = Join-Path -Path $stagingRoot -ChildPath 'fleet-summary.csv'
    $stagingResultPath = Join-Path -Path $stagingRoot -ChildPath 'fleet-result.json'
    $stagingManifestPath = Join-Path -Path $stagingRoot -ChildPath 'manifest.json'
    $stagingCommitMarkerPath = Join-Path -Path $stagingRoot -ChildPath 'commit.json'
    $artifactPlan = New-Object System.Collections.Generic.List[object]
    for ($requestIndex = 0; $requestIndex -lt $requestedComputers.Count; $requestIndex++) {
        $safeName = ConvertTo-HLFleetSafeName -Value ([string]$requestedComputers[$requestIndex])
        $prefix = 'host-{0:D3}-{1}' -f ($requestIndex + 1), $safeName
        $artifactPlan.Add([pscustomobject][ordered]@{
            SuccessPath        = Join-Path -Path $runRoot -ChildPath ($prefix + '.json')
            ErrorPath          = Join-Path -Path $runRoot -ChildPath ($prefix + '.error.json')
            StagingSuccessPath = Join-Path -Path $stagingRoot -ChildPath ($prefix + '.json')
            StagingErrorPath   = Join-Path -Path $stagingRoot -ChildPath ($prefix + '.error.json')
        })
    }

    try {
        $moduleFiles = Get-HLFleetModulePayload
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

    $invocationError = $null
    try {
        $remoteResults = @(Invoke-Command @sessionOptions -ArgumentList @(
            $moduleFiles,
            $Baseline,
            $customBaselineJson,
            @($ControlId),
            $exceptionJson,
            [bool]$AllowPartial,
            [bool]$Redact
        ) -ScriptBlock (Get-HLFleetRemoteScriptBlock))
    }
    catch {
        $invocationError = $_
        $remoteResults = @()
    }

    $usedResultIndexes = @{}
    $usedErrorIndexes = @{}
    $hostResults = New-Object System.Collections.Generic.List[object]
    $summaryRows = New-Object System.Collections.Generic.List[object]
    $baselineSelection = if ($null -ne $customBaselineJson) { 'Custom' } else { $Baseline }

    for ($requestIndex = 0; $requestIndex -lt $requestedComputers.Count; $requestIndex++) {
        $requestedComputer = [string]$requestedComputers[$requestIndex]
        $requestedShortName = Get-HLFleetShortHostName -Value $requestedComputer
        $sameShortNameRequestCount = @($requestedComputers | Where-Object {
            (Get-HLFleetShortHostName -Value ([string]$_)) -ceq $requestedShortName
        }).Count
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
        if ($null -eq $matchedResult -and $sameShortNameRequestCount -eq 1) {
            $fallbackResultIndexes = New-Object System.Collections.Generic.List[int]
            for ($resultIndex = 0; $resultIndex -lt $remoteResults.Count; $resultIndex++) {
                if ($usedResultIndexes.ContainsKey($resultIndex)) {
                    continue
                }
                if (Test-HLFleetResultHostMatch -Requested $requestedComputer -Result $remoteResults[$resultIndex] -AllowShortName) {
                    $fallbackResultIndexes.Add($resultIndex)
                }
            }
            if ($fallbackResultIndexes.Count -eq 1) {
                $matchedResultIndex = $fallbackResultIndexes[0]
                $matchedResult = $remoteResults[$matchedResultIndex]
            }
        }

        $matchedError = $null
        if ($null -eq $matchedResult) {
            for ($errorIndex = 0; $errorIndex -lt @($remoteErrors).Count; $errorIndex++) {
                if ($usedErrorIndexes.ContainsKey($errorIndex)) {
                    continue
                }
                $errorHost = Get-HLFleetErrorHostName -ErrorRecord $remoteErrors[$errorIndex]
                if (Test-HLFleetHostNameExactMatch -Requested $requestedComputer -Candidate $errorHost) {
                    $matchedError = $remoteErrors[$errorIndex]
                    $usedErrorIndexes[$errorIndex] = $true
                    break
                }
            }
            if ($null -eq $matchedError -and $sameShortNameRequestCount -eq 1) {
                $fallbackErrorIndexes = New-Object System.Collections.Generic.List[int]
                for ($errorIndex = 0; $errorIndex -lt @($remoteErrors).Count; $errorIndex++) {
                    if ($usedErrorIndexes.ContainsKey($errorIndex)) {
                        continue
                    }
                    $errorHost = Get-HLFleetErrorHostName -ErrorRecord $remoteErrors[$errorIndex]
                    if (Test-HLFleetHostNameMatch -Requested $requestedComputer -Candidate $errorHost -AllowShortName) {
                        $fallbackErrorIndexes.Add($errorIndex)
                    }
                }
                if ($fallbackErrorIndexes.Count -eq 1) {
                    $matchedErrorIndex = $fallbackErrorIndexes[0]
                    $matchedError = $remoteErrors[$matchedErrorIndex]
                    $usedErrorIndexes[$matchedErrorIndex] = $true
                }
            }
        }

        if ($null -ne $matchedResult -and (Test-HLFleetScanResult -Result $matchedResult)) {
            $usedResultIndexes[$matchedResultIndex] = $true
            $assessment = ConvertTo-HLFleetCleanResult -Result $matchedResult
            $artifactPath = [string]$artifactPlan[$requestIndex].SuccessPath
            $stagingArtifactPath = [string]$artifactPlan[$requestIndex].StagingSuccessPath
            Write-HLFleetJsonFile -Path $stagingArtifactPath -InputObject $assessment
            $hostResult = [pscustomobject][ordered]@{
                ordinal               = $requestIndex + 1
                requestedComputerName = $requestedComputer
                computerName          = [string]$assessment.system.ComputerName
                status                = 'Succeeded'
                error                 = $null
                assessment            = $assessment
                artifactPath          = $artifactPath
            }
        }
        else {
            if ($matchedResultIndex -ge 0) {
                $usedResultIndexes[$matchedResultIndex] = $true
                $errorDetail = ConvertTo-HLFleetErrorDetail -FallbackMessage 'The remote host returned an invalid Hardening Lens result.'
            }
            elseif ($null -ne $matchedError) {
                $errorDetail = ConvertTo-HLFleetErrorDetail -ErrorRecord $matchedError
            }
            elseif ($null -ne $invocationError) {
                $errorDetail = ConvertTo-HLFleetErrorDetail -ErrorRecord $invocationError
            }
            else {
                $errorDetail = ConvertTo-HLFleetErrorDetail
            }

            $artifactPath = [string]$artifactPlan[$requestIndex].ErrorPath
            $stagingArtifactPath = [string]$artifactPlan[$requestIndex].StagingErrorPath
            $failureArtifact = [pscustomobject][ordered]@{
                fleetSchemaVersion     = '1.1'
                artifactType          = 'HardeningLens.FleetHostFailure'
                runId                 = $runId
                recordedAt            = (Get-HLFleetUtcNow).ToString('o')
                ordinal               = $requestIndex + 1
                requestedComputerName = $requestedComputer
                status                = 'Failed'
                error                 = $errorDetail
            }
            Write-HLFleetJsonFile -Path $stagingArtifactPath -InputObject $failureArtifact
            $hostResult = [pscustomobject][ordered]@{
                ordinal               = $requestIndex + 1
                requestedComputerName = $requestedComputer
                computerName          = $requestedComputer
                status                = 'Failed'
                error                 = $errorDetail
                assessment            = $null
                artifactPath          = $artifactPath
            }
        }

        $hostResults.Add($hostResult)
        $summaryRows.Add((ConvertTo-HLFleetSummaryRow -RunId $runId -HostResult $hostResult -BaselineSelection $baselineSelection))
    }

    $hostResultArray = $hostResults.ToArray()
    $summary = Get-HLFleetAggregateSummary -HostResults $hostResultArray
    $completedAt = Get-HLFleetUtcNow
    $fleetResult = [pscustomobject][ordered]@{
        '$schema'     = 'https://raw.githubusercontent.com/xGreeny/hardening-lens/v1.2.1/src/HardeningLens/Schema/fleet-result.schema.json'
        schemaVersion = '1.1'
        run           = [pscustomobject][ordered]@{
            id                = $runId
            startedAt         = $startedAt.ToString('o')
            completedAt       = $completedAt.ToString('o')
            moduleVersion     = Get-HLModuleVersion
            baselineSelection = $baselineSelection
            customBaseline    = [bool]($null -ne $customBaselineJson)
            redacted          = [bool]$Redact
            allowPartial      = [bool]$AllowPartial
            throttleLimit     = $ThrottleLimit
            requestedCount    = $summary.requestedCount
            succeededCount    = $summary.succeededCount
            failedCount       = $summary.failedCount
        }
        summary       = $summary
        artifacts     = [pscustomobject][ordered]@{
            outputDirectory = $outputRoot
            summaryPath     = $summaryPath
            resultPath      = $resultPath
            manifestPath    = $manifestPath
            commitMarkerPath = $commitMarkerPath
        }
        hosts         = $hostResultArray
    }

    Write-HLFleetCsvFile -InputObject $summaryRows.ToArray() -Path $stagingSummaryPath
    Write-HLFleetJsonFile -Path $stagingResultPath -InputObject $fleetResult
    $manifest = [pscustomobject][ordered]@{
        fleetSchemaVersion = '1.1'
        artifactType       = 'HardeningLens.FleetRun'
        run                = $fleetResult.run
        summary            = $fleetResult.summary
        artifacts          = $fleetResult.artifacts
        hosts              = @($hostResultArray | ForEach-Object {
            [pscustomobject][ordered]@{
                ordinal               = $_.ordinal
                requestedComputerName = $_.requestedComputerName
                computerName          = $_.computerName
                status                = $_.status
                error                 = $_.error
                artifactPath          = $_.artifactPath
            }
        })
        unassignedResults  = $remoteResults.Count - $usedResultIndexes.Count
        unassignedErrors   = @($remoteErrors).Count - $usedErrorIndexes.Count
    }
    Write-HLFleetJsonFile -Path $stagingManifestPath -InputObject $manifest
    $commitMarker = [pscustomobject][ordered]@{
        fleetSchemaVersion = '1.1'
        artifactType       = 'HardeningLens.FleetCommit'
        runId              = $runId
        completedAt        = $completedAt.ToString('o')
        manifest           = 'manifest.json'
    }
    Write-HLFleetJsonFile -Path $stagingCommitMarkerPath -InputObject $commitMarker
    Publish-HLFleetRunDirectory -StagingPath $stagingRoot -DestinationPath $runRoot -Force:$Force

    if ($summary.failedCount -gt 0) {
        Write-Warning ("Fleet assessment $runId completed with $($summary.failedCount) failed host(s). See $manifestPath.")
    }
    return $fleetResult
    }
    finally {
        if (Test-Path -LiteralPath $stagingRoot -PathType Container) {
            $stagingParent = [IO.Path]::GetFullPath((Split-Path -Path $stagingRoot -Parent))
            if ($stagingParent -ceq $outputRoot) {
                Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
            else {
                Write-Warning "Fleet staging cleanup was skipped because the path escaped the output directory: $stagingRoot"
            }
        }
    }
}
