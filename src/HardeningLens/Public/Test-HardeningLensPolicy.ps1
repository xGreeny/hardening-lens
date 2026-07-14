function Test-HardeningLensPolicy {
    [CmdletBinding(DefaultParameterSetName = 'PolicyPath')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject,

        [Parameter(Mandatory, ParameterSetName = 'PolicyPath')]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$PolicyPath,

        [Parameter(Mandatory, ParameterSetName = 'PolicyObject')]
        [object]$Policy
    )

    process {
        $policyDocument = if ($PSCmdlet.ParameterSetName -eq 'PolicyPath') {
            Get-Content -LiteralPath (Resolve-Path -LiteralPath $PolicyPath) -Raw -ErrorAction Stop | ConvertFrom-Json
        }
        else {
            $Policy
        }

        if ([string]$policyDocument.schemaVersion -ne '1.0') {
            throw "Unsupported policy schema version '$($policyDocument.schemaVersion)'."
        }

        $validation = $InputObject | Test-HardeningLensResult
        if (-not $validation.IsValid) {
            throw "The input result is invalid: $($validation.Errors -join ' | ')"
        }

        $checks = New-Object System.Collections.Generic.List[object]
        $addCheck = {
            param([string]$Name, [bool]$Passed, [object]$Actual, [object]$Expected, [string]$Message)
            $checks.Add([pscustomobject][ordered]@{
                Name     = $Name
                Passed   = $Passed
                Actual   = $Actual
                Expected = $Expected
                Message  = $Message
            })
        }

        $mode = Get-HLAssessmentMode -ScanResult $InputObject
        $requireFull = if ($null -ne $policyDocument.requireFullAssessment) { [bool]$policyDocument.requireFullAssessment } else { $true }
        & $addCheck 'Assessment completeness' (-not $requireFull -or $mode -eq 'Full') $mode (if ($requireFull) { 'Full' } else { 'Full or Focused' }) 'Focused results cannot prove the complete baseline unless the policy explicitly permits them.'

        $coverageProperty = @('EvidenceCoveragePercent', 'evidenceCoveragePercent', 'CoveragePercent', 'coveragePercent') | Where-Object { $null -ne $InputObject.summary.PSObject.Properties[$_] } | Select-Object -First 1
        $coverage = if ($null -ne $coverageProperty) { [double]$InputObject.summary.$coverageProperty } else { 0.0 }
        $minimumCoverage = if ($null -ne $policyDocument.minimumEvidenceCoverage) { [double]$policyDocument.minimumEvidenceCoverage } else { 0.0 }
        & $addCheck 'Evidence coverage' ($coverage -ge $minimumCoverage) $coverage $minimumCoverage 'Evidence coverage must meet the configured minimum.'

        $maximumErrors = if ($null -ne $policyDocument.maximumErrors) { [int]$policyDocument.maximumErrors } else { 0 }
        $errorCount = @($InputObject.results | Where-Object status -eq 'Error').Count
        & $addCheck 'Collection errors' ($errorCount -le $maximumErrors) $errorCount $maximumErrors 'Collection errors reduce the trustworthiness of the assessment.'

        $maximumUnknown = if ($null -ne $policyDocument.maximumUnknown) { [int]$policyDocument.maximumUnknown } else { [int]::MaxValue }
        $unknownCount = @($InputObject.results | Where-Object status -eq 'Unknown').Count
        & $addCheck 'Unknown controls' ($unknownCount -le $maximumUnknown) $unknownCount $maximumUnknown 'Unknown controls represent unresolved evidence.'

        $maximumFindings = $policyDocument.maximumFindings
        foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            $limitProperty = if ($null -ne $maximumFindings) { $maximumFindings.PSObject.Properties[$severity] } else { $null }
            if ($null -eq $limitProperty) { continue }
            $limit = [int]$limitProperty.Value
            $count = @($InputObject.results | Where-Object {
                [string]$_.severity -eq $severity -and [string]$_.status -in @('Fail', 'Warning')
            }).Count
            & $addCheck "$severity findings" ($count -le $limit) $count $limit "The number of $severity findings must remain within policy."
        }

        $maximumExceptedCritical = if ($null -ne $policyDocument.maximumExceptedCritical) { [int]$policyDocument.maximumExceptedCritical } else { [int]::MaxValue }
        $exceptedCritical = @($InputObject.results | Where-Object { [string]$_.severity -eq 'Critical' -and [string]$_.status -eq 'Excepted' }).Count
        & $addCheck 'Excepted critical findings' ($exceptedCritical -le $maximumExceptedCritical) $exceptedCritical $maximumExceptedCritical 'Critical exposure remains present even when formally excepted.'

        $warningDays = if ($null -ne $policyDocument.exceptionExpiryWarningDays) { [int]$policyDocument.exceptionExpiryWarningDays } else { 30 }
        $threshold = (Get-Date).ToUniversalTime().AddDays($warningDays)
        $expiring = @($InputObject.results | Where-Object {
            [string]$_.status -eq 'Excepted' -and $null -ne $_.exception -and $null -ne $_.exception.expires -and
            ([datetime]$_.exception.expires).ToUniversalTime() -le $threshold
        }).Count
        $maximumExpiring = if ($null -ne $policyDocument.maximumExpiringExceptions) { [int]$policyDocument.maximumExpiringExceptions } else { [int]::MaxValue }
        & $addCheck 'Expiring exceptions' ($expiring -le $maximumExpiring) $expiring $maximumExpiring "Exceptions expiring within $warningDays days require review."

        $failedChecks = @($checks | Where-Object Passed -eq $false)
        [pscustomobject][ordered]@{
            schemaVersion   = '1.0'
            passed          = $failedChecks.Count -eq 0
            assessmentMode  = $mode
            evaluatedAt     = (Get-Date).ToUniversalTime().ToString('o')
            failedCheckCount = $failedChecks.Count
            checks          = $checks.ToArray()
        }
    }
}
