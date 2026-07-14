function Test-HardeningLensResult {
    [CmdletBinding(DefaultParameterSetName = 'InputObject')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'InputObject')]
        [object]$InputObject,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$Path
    )

    process {
        $result = if ($PSCmdlet.ParameterSetName -eq 'Path') {
            Get-Content -LiteralPath (Resolve-Path -LiteralPath $Path) -Raw -ErrorAction Stop | ConvertFrom-Json
        }
        else {
            $InputObject
        }

        $errors = New-Object System.Collections.Generic.List[string]
        $warnings = New-Object System.Collections.Generic.List[string]
        foreach ($required in @('schemaVersion', 'scan', 'system', 'baseline', 'summary', 'results')) {
            if ($null -eq $result.PSObject.Properties[$required]) {
                $errors.Add("Missing required property '$required'.")
            }
        }

        if ($errors.Count -eq 0) {
            if ([string]$result.schemaVersion -ne '1.0') {
                $errors.Add("Unsupported result schema version '$($result.schemaVersion)'.")
            }

            $allowedStatus = @('Pass', 'Fail', 'Warning', 'Excepted', 'Unknown', 'Error', 'NotApplicable')
            $ids = @($result.results | ForEach-Object { [string]$_.id })
            foreach ($duplicate in @($ids | Group-Object | Where-Object Count -gt 1)) {
                $errors.Add("Duplicate control result '$($duplicate.Name)'.")
            }
            foreach ($item in @($result.results)) {
                if ([string]::IsNullOrWhiteSpace([string]$item.id)) {
                    $errors.Add('A control result has no id.')
                }
                if ([string]$item.status -notin $allowedStatus) {
                    $errors.Add("Control '$($item.id)' has unsupported status '$($item.status)'.")
                }
                if ([string]$item.status -eq 'Excepted' -and $null -eq $item.originalStatus) {
                    $warnings.Add("Excepted control '$($item.id)' does not expose originalStatus.")
                }
            }

            $selected = if ($null -ne $result.scan.selectedControlCount) { [int]$result.scan.selectedControlCount } else { @($result.results).Count }
            $baselineCount = if ($null -ne $result.scan.baselineControlCount) { [int]$result.scan.baselineControlCount } else { [int]$result.baseline.controlCount }
            if ($selected -ne @($result.results).Count) {
                $errors.Add("selectedControlCount is $selected but the result contains $(@($result.results).Count) controls.")
            }
            if ($baselineCount -lt $selected) {
                $errors.Add("baselineControlCount ($baselineCount) is lower than selectedControlCount ($selected).")
            }

            $mode = Get-HLAssessmentMode -ScanResult $result
            if ($mode -eq 'Focused' -and $selected -eq $baselineCount) {
                $warnings.Add('The result declares a focused assessment although every baseline control was selected.')
            }
            if ($mode -eq 'Full' -and $selected -lt $baselineCount) {
                $errors.Add('The result declares a full assessment but not every baseline control was selected.')
            }

            $recomputed = Get-HLSummary -Results @($result.results)
            foreach ($propertyName in @('Pass', 'Fail', 'Warning', 'Excepted', 'Unknown', 'Error', 'NotApplicable')) {
                $reportedProperty = $result.summary.PSObject.Properties[$propertyName]
                $computedProperty = $recomputed.PSObject.Properties[$propertyName]
                if ($null -ne $reportedProperty -and $null -ne $computedProperty -and [int]$reportedProperty.Value -ne [int]$computedProperty.Value) {
                    $errors.Add("Summary property '$propertyName' is $($reportedProperty.Value), expected $($computedProperty.Value).")
                }
            }
        }

        [pscustomobject][ordered]@{
            IsValid          = $errors.Count -eq 0
            SchemaVersion    = if ($null -ne $result.schemaVersion) { [string]$result.schemaVersion } else { $null }
            AssessmentMode   = if ($errors.Count -eq 0) { Get-HLAssessmentMode -ScanResult $result } else { $null }
            ResultCount      = if ($null -ne $result.results) { @($result.results).Count } else { 0 }
            Errors           = $errors.ToArray()
            Warnings         = $warnings.ToArray()
        }
    }
}
