function Test-HardeningLensPolicy {
    <#
    .SYNOPSIS
    Evaluates a Hardening Lens result against deterministic governance thresholds.

    .DESCRIPTION
    Accepts a scan object or exported JSON file and returns one policy result object.
    No threshold is enforced unless its parameter is supplied. FailOnViolation turns
    a failed evaluation into a terminating error with error id HardeningLens.PolicyViolation.

    .PARAMETER InputObject
    Scan result returned by Invoke-HardeningLens or imported from trusted JSON.

    .PARAMETER Path
    Path to an exported Hardening Lens result JSON file.

    .PARAMETER MaxFailed
    Maximum permitted number of failed controls.

    .PARAMETER MaxWarning
    Maximum permitted number of warning controls.

    .PARAMETER MinimumScore
    Minimum permitted hardening score from 0 through 100.

    .PARAMETER MinimumCoverage
    Minimum permitted evidence coverage from 0 through 100.

    .PARAMETER DisallowPartialCollection
    Fails policy evaluation when the result reports partial collection.

    .PARAMETER DisallowExpiredExceptions
    Fails policy evaluation for expired or malformed applied exception expiries.

    .PARAMETER AsOf
    Date used to evaluate exception expiry. Defaults to today.

    .PARAMETER FailOnViolation
    Throws a terminating error when one or more policy rules are violated.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Object')]
        [object]$InputObject,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$Path,

        [ValidateRange(0, [int]::MaxValue)]
        [int]$MaxFailed,

        [ValidateRange(0, [int]::MaxValue)]
        [int]$MaxWarning,

        [ValidateRange(0, 100)]
        [double]$MinimumScore,

        [ValidateRange(0, 100)]
        [double]$MinimumCoverage,

        [switch]$DisallowPartialCollection,

        [switch]$DisallowExpiredExceptions,

        [datetime]$AsOf = (Get-Date),

        [switch]$FailOnViolation
    )

    process {
        $scanResult = if ($PSCmdlet.ParameterSetName -eq 'Path') {
            Read-HLScanResult -InputObject $Path
        }
        else {
            $InputObject
        }

        $evaluationParameters = @{
            ScanResult                 = $scanResult
            AsOf                      = $AsOf
            DisallowPartialCollection = $DisallowPartialCollection
            DisallowExpiredExceptions = $DisallowExpiredExceptions
        }
        foreach ($parameterName in @('MaxFailed', 'MaxWarning', 'MinimumScore', 'MinimumCoverage')) {
            if ($PSBoundParameters.ContainsKey($parameterName)) {
                $evaluationParameters[$parameterName] = $PSBoundParameters[$parameterName]
            }
        }

        $evaluation = Test-HLPolicyEvaluation @evaluationParameters
        if ($FailOnViolation -and -not $evaluation.Passed) {
            $message = 'Hardening Lens policy failed: ' + (@($evaluation.Violations | ForEach-Object { $_.Message }) -join ' ')
            $exception = New-Object System.InvalidOperationException($message)
            $errorRecord = New-Object System.Management.Automation.ErrorRecord(
                $exception,
                'HardeningLens.PolicyViolation',
                [System.Management.Automation.ErrorCategory]::InvalidResult,
                $evaluation
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        $PSCmdlet.WriteObject($evaluation, $false)
    }
}
