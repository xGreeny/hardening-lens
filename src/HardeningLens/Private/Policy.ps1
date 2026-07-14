function ConvertTo-HLPolicyViolation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Code,

        [Parameter(Mandatory)]
        [string]$Message,

        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Threshold
    )

    return [pscustomobject][ordered]@{
        Code      = $Code
        Message   = $Message
        Actual    = $Actual
        Threshold = $Threshold
    }
}

function Get-HLPolicyExceptionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ScanResult,

        [Parameter(Mandatory)]
        [datetime]$AsOf
    )

    $seen = @{}
    $states = New-Object System.Collections.Generic.List[object]
    foreach ($result in @($ScanResult.results)) {
        if ($null -eq $result.exception) {
            continue
        }

        $exception = $result.exception
        $id = if ((Test-HLProperty -InputObject $exception -Name 'id') -and -not [string]::IsNullOrWhiteSpace([string]$exception.id)) {
            [string]$exception.id
        }
        else {
            'CONTROL-' + [string]$result.controlId
        }
        if ($seen.ContainsKey($id)) {
            continue
        }
        $seen[$id] = $true

        $expiry = [datetime]::MinValue
        $expiryValid = (Test-HLProperty -InputObject $exception -Name 'expires') -and
            (Test-HLDateString -Value $exception.expires -ParsedDate ([ref]$expiry))
        $effectiveStatus = if (-not $expiryValid) {
            'InvalidExpiry'
        }
        elseif ($expiry.Date -lt $AsOf.Date) {
            'Expired'
        }
        else {
            'Active'
        }

        $states.Add([pscustomobject][ordered]@{
            Id              = $id
            ControlId       = [string]$result.controlId
            Expires         = if ($expiryValid) { $expiry.ToString('yyyy-MM-dd') } else { [string]$exception.expires }
            EffectiveStatus = $effectiveStatus
        })
    }

    return @($states.ToArray() | Sort-Object Id, ControlId)
}

function Test-HLPolicyEvaluation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ScanResult,

        [AllowNull()]
        [Nullable[int]]$MaxFailed,

        [AllowNull()]
        [Nullable[int]]$MaxWarning,

        [AllowNull()]
        [Nullable[double]]$MinimumScore,

        [AllowNull()]
        [Nullable[double]]$MinimumCoverage,

        [switch]$DisallowPartialCollection,

        [switch]$DisallowExpiredExceptions,

        [Parameter(Mandatory)]
        [datetime]$AsOf
    )

    Assert-HLScanResult -ScanResult $ScanResult

    $summary = $ScanResult.summary
    $exceptionStates = @(Get-HLPolicyExceptionState -ScanResult $ScanResult -AsOf $AsOf)
    $expiredExceptions = @($exceptionStates | Where-Object EffectiveStatus -eq 'Expired')
    $invalidExpiryExceptions = @($exceptionStates | Where-Object EffectiveStatus -eq 'InvalidExpiry')
    $metrics = [pscustomobject][ordered]@{
        Total                       = [int]$summary.Total
        Failed                      = [int]$summary.Fail
        Warning                     = [int]$summary.Warning
        HardeningScore              = if ($null -eq $summary.HardeningScore) { $null } else { [double]$summary.HardeningScore }
        EvidenceCoverage            = if ($null -eq $summary.EvidenceCoverage) { $null } else { [double]$summary.EvidenceCoverage }
        PartialCollection           = [bool]$ScanResult.scan.partialCollection
        ExceptionCount              = $exceptionStates.Count
        ExpiredExceptionCount       = $expiredExceptions.Count
        InvalidExceptionExpiryCount = $invalidExpiryExceptions.Count
    }

    $violations = New-Object System.Collections.Generic.List[object]
    if ($null -ne $MaxFailed -and $metrics.Failed -gt [int]$MaxFailed) {
        $violations.Add((ConvertTo-HLPolicyViolation -Code 'MaxFailedExceeded' -Message "Failed controls ($($metrics.Failed)) exceed the allowed maximum ($MaxFailed)." -Actual $metrics.Failed -Threshold ([int]$MaxFailed)))
    }
    if ($null -ne $MaxWarning -and $metrics.Warning -gt [int]$MaxWarning) {
        $violations.Add((ConvertTo-HLPolicyViolation -Code 'MaxWarningExceeded' -Message "Warning controls ($($metrics.Warning)) exceed the allowed maximum ($MaxWarning)." -Actual $metrics.Warning -Threshold ([int]$MaxWarning)))
    }
    if ($null -ne $MinimumScore -and ($null -eq $metrics.HardeningScore -or $metrics.HardeningScore -lt [double]$MinimumScore)) {
        $violations.Add((ConvertTo-HLPolicyViolation -Code 'MinimumScoreNotMet' -Message "Hardening score does not meet the required minimum ($MinimumScore)." -Actual $metrics.HardeningScore -Threshold ([double]$MinimumScore)))
    }
    if ($null -ne $MinimumCoverage -and ($null -eq $metrics.EvidenceCoverage -or $metrics.EvidenceCoverage -lt [double]$MinimumCoverage)) {
        $violations.Add((ConvertTo-HLPolicyViolation -Code 'MinimumCoverageNotMet' -Message "Evidence coverage does not meet the required minimum ($MinimumCoverage)." -Actual $metrics.EvidenceCoverage -Threshold ([double]$MinimumCoverage)))
    }
    if ($DisallowPartialCollection -and $metrics.PartialCollection) {
        $violations.Add((ConvertTo-HLPolicyViolation -Code 'PartialCollectionDisallowed' -Message 'The scan used partial collection, which this policy disallows.' -Actual $true -Threshold $false))
    }
    if ($DisallowExpiredExceptions) {
        foreach ($state in $expiredExceptions) {
            $violations.Add((ConvertTo-HLPolicyViolation -Code 'ExpiredException' -Message "Exception '$($state.Id)' expired on $($state.Expires)." -Actual $state.Expires -Threshold $AsOf.Date.ToString('yyyy-MM-dd')))
        }
        foreach ($state in $invalidExpiryExceptions) {
            $violations.Add((ConvertTo-HLPolicyViolation -Code 'InvalidExceptionExpiry' -Message "Exception '$($state.Id)' has an invalid expiry value." -Actual $state.Expires -Threshold 'yyyy-MM-dd'))
        }
    }

    $passed = $violations.Count -eq 0
    return [pscustomobject][ordered]@{
        Passed       = $passed
        ExitCode     = if ($passed) { 0 } else { 1 }
        ComputerName = [string]$ScanResult.system.ComputerName
        ScanId       = [string]$ScanResult.scan.id
        EvaluatedAsOf = $AsOf.Date.ToString('yyyy-MM-dd')
        Violations   = $violations.ToArray()
        Metrics      = $metrics
    }
}
