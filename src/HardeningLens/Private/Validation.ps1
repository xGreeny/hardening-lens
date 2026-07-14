function Test-HLScanValidationProperty {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $false
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject.Contains($Name)
    }

    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Get-HLScanValidationProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($InputObject -is [System.Collections.IDictionary]) {
        $value = $InputObject[$Name]
    }
    else {
        $value = $InputObject.PSObject.Properties[$Name].Value
    }

    return ,$value
}

function Test-HLScanValidationObject {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    return $null -ne $Value -and (
        $Value -is [pscustomobject] -or
        $Value -is [System.Collections.IDictionary]
    )
}

function Test-HLScanValidationArray {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    return $null -ne $Value -and
        $Value -isnot [string] -and
        $Value -isnot [System.Collections.IDictionary] -and
        $Value -is [System.Collections.IEnumerable]
}

function Test-HLScanValidationInteger {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    return $Value -is [byte] -or
        $Value -is [sbyte] -or
        $Value -is [int16] -or
        $Value -is [uint16] -or
        $Value -is [int32] -or
        $Value -is [uint32] -or
        $Value -is [int64] -or
        $Value -is [uint64]
}

function Test-HLScanValidationNumber {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    return (Test-HLScanValidationInteger -Value $Value) -or
        $Value -is [single] -or
        $Value -is [double] -or
        $Value -is [decimal]
}

function Add-HLScanValidationError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Errors,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $Errors.Add(('{0}: {1}' -f $Path, $Message))
}

function Test-HLScanRequiredPropertySet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string[]]$Names,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Errors
    )

    foreach ($name in $Names) {
        if (-not (Test-HLScanValidationProperty -InputObject $InputObject -Name $name)) {
            Add-HLScanValidationError -Errors $Errors -Path (('{0}.{1}' -f $Path, $name).TrimStart('.')) -Message 'required property is missing.'
        }
    }
}

function Assert-HLScanObjectSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Root,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$RequiredProperties,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Errors
    )

    if (-not (Test-HLScanValidationProperty -InputObject $Root -Name $Name)) {
        return $null
    }

    $section = Get-HLScanValidationProperty -InputObject $Root -Name $Name
    if (-not (Test-HLScanValidationObject -Value $section)) {
        Add-HLScanValidationError -Errors $Errors -Path $Name -Message 'must be an object.'
        return $null
    }

    Test-HLScanRequiredPropertySet -InputObject $section -Names $RequiredProperties -Path $Name -Errors $Errors
    return $section
}

function Assert-HLScanResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$ScanResult
    )

    $errors = New-Object System.Collections.Generic.List[string]
    if (-not (Test-HLScanValidationObject -Value $ScanResult)) {
        throw 'Invalid Hardening Lens scan result: the input must be an object.'
    }

    Test-HLScanRequiredPropertySet -InputObject $ScanResult -Names @(
        'schemaVersion', 'scan', 'system', 'baseline', 'summary', 'results'
    ) -Path '' -Errors $errors

    if (Test-HLScanValidationProperty -InputObject $ScanResult -Name 'schemaVersion') {
        $schemaVersion = Get-HLScanValidationProperty -InputObject $ScanResult -Name 'schemaVersion'
        if ($schemaVersion -isnot [string] -or $schemaVersion -cne '1.0') {
            Add-HLScanValidationError -Errors $errors -Path 'schemaVersion' -Message "must be the string '1.0'."
        }
    }

    $scan = Assert-HLScanObjectSection -Root $ScanResult -Name 'scan' -RequiredProperties @(
        'id', 'collectedAt', 'moduleVersion', 'redacted', 'readOnly', 'elevated',
        'partialCollection', 'exceptionRegisterUsed', 'selectedControlCount'
    ) -Errors $errors
    $system = Assert-HLScanObjectSection -Root $ScanResult -Name 'system' -RequiredProperties @(
        'ComputerName', 'Domain', 'DomainJoined', 'DetectedRole', 'ProductType', 'OSCaption',
        'OSVersion', 'BuildNumber', 'OSArchitecture', 'Manufacturer', 'Model', 'PowerShellVersion',
        'PowerShellEdition', 'CurrentUser', 'IsElevated'
    ) -Errors $errors
    $baseline = Assert-HLScanObjectSection -Root $ScanResult -Name 'baseline' -RequiredProperties @(
        'name', 'displayName', 'version', 'description', 'source', 'sourceBasis',
        'supportedRoles', 'controlCount', 'notes'
    ) -Errors $errors
    $summary = Assert-HLScanObjectSection -Root $ScanResult -Name 'summary' -RequiredProperties @(
        'Total', 'Applicable', 'Pass', 'Fail', 'Warning', 'Excepted', 'Unknown', 'Error',
        'NotApplicable', 'HardeningScore', 'EvidenceCoverage', 'HighestOpenSeverity', 'ScoringModel'
    ) -Errors $errors

    if ($null -ne $scan) {
        $id = if (Test-HLScanValidationProperty -InputObject $scan -Name 'id') { Get-HLScanValidationProperty -InputObject $scan -Name 'id' } else { $null }
        $parsedGuid = [guid]::Empty
        if ($id -isnot [string] -or -not [guid]::TryParse([string]$id, [ref]$parsedGuid)) {
            Add-HLScanValidationError -Errors $errors -Path 'scan.id' -Message 'must be a UUID string.'
        }

        $collectedAt = if (Test-HLScanValidationProperty -InputObject $scan -Name 'collectedAt') { Get-HLScanValidationProperty -InputObject $scan -Name 'collectedAt' } else { $null }
        $parsedTimestamp = [datetimeoffset]::MinValue
        if ($collectedAt -isnot [datetime] -and $collectedAt -isnot [datetimeoffset] -and ($collectedAt -isnot [string] -or -not [datetimeoffset]::TryParse([string]$collectedAt, [ref]$parsedTimestamp))) {
            Add-HLScanValidationError -Errors $errors -Path 'scan.collectedAt' -Message 'must be a date-time string.'
        }

        $moduleVersion = if (Test-HLScanValidationProperty -InputObject $scan -Name 'moduleVersion') { Get-HLScanValidationProperty -InputObject $scan -Name 'moduleVersion' } else { $null }
        if ($moduleVersion -isnot [string] -or [string]$moduleVersion -notmatch '^\d+\.\d+\.\d+$') {
            Add-HLScanValidationError -Errors $errors -Path 'scan.moduleVersion' -Message 'must use semantic version form x.y.z.'
        }

        foreach ($booleanName in @('redacted', 'readOnly', 'elevated', 'partialCollection', 'exceptionRegisterUsed')) {
            if (Test-HLScanValidationProperty -InputObject $scan -Name $booleanName) {
                $booleanValue = Get-HLScanValidationProperty -InputObject $scan -Name $booleanName
                if ($booleanValue -isnot [bool]) {
                    Add-HLScanValidationError -Errors $errors -Path "scan.$booleanName" -Message 'must be a Boolean.'
                }
            }
        }

        if ((Test-HLScanValidationProperty -InputObject $scan -Name 'readOnly') -and (Get-HLScanValidationProperty -InputObject $scan -Name 'readOnly') -ne $true) {
            Add-HLScanValidationError -Errors $errors -Path 'scan.readOnly' -Message 'must be true.'
        }

        if (Test-HLScanValidationProperty -InputObject $scan -Name 'selectedControlCount') {
            $selectedControlCount = Get-HLScanValidationProperty -InputObject $scan -Name 'selectedControlCount'
            if (-not (Test-HLScanValidationInteger -Value $selectedControlCount) -or [decimal]$selectedControlCount -lt 0) {
                Add-HLScanValidationError -Errors $errors -Path 'scan.selectedControlCount' -Message 'must be a non-negative integer.'
            }
        }
    }

    if ($null -ne $system) {
        foreach ($stringName in @(
            'ComputerName', 'Domain', 'OSCaption', 'OSVersion', 'BuildNumber', 'OSArchitecture',
            'Manufacturer', 'Model', 'PowerShellVersion', 'PowerShellEdition', 'CurrentUser'
        )) {
            if ((Test-HLScanValidationProperty -InputObject $system -Name $stringName) -and (Get-HLScanValidationProperty -InputObject $system -Name $stringName) -isnot [string]) {
                Add-HLScanValidationError -Errors $errors -Path "system.$stringName" -Message 'must be a string.'
            }
        }

        if (Test-HLScanValidationProperty -InputObject $system -Name 'DetectedRole') {
            $role = Get-HLScanValidationProperty -InputObject $system -Name 'DetectedRole'
            if ($role -isnot [string] -or [string]$role -cnotin @('Workstation', 'MemberServer', 'DomainController', 'Unknown')) {
                Add-HLScanValidationError -Errors $errors -Path 'system.DetectedRole' -Message 'must be Workstation, MemberServer, DomainController, or Unknown.'
            }
        }

        if (Test-HLScanValidationProperty -InputObject $system -Name 'DomainJoined') {
            $domainJoined = Get-HLScanValidationProperty -InputObject $system -Name 'DomainJoined'
            if ($null -ne $domainJoined -and $domainJoined -isnot [bool]) {
                Add-HLScanValidationError -Errors $errors -Path 'system.DomainJoined' -Message 'must be null or a Boolean.'
            }
        }

        if ((Test-HLScanValidationProperty -InputObject $system -Name 'IsElevated') -and (Get-HLScanValidationProperty -InputObject $system -Name 'IsElevated') -isnot [bool]) {
            Add-HLScanValidationError -Errors $errors -Path 'system.IsElevated' -Message 'must be a Boolean.'
        }

        if (Test-HLScanValidationProperty -InputObject $system -Name 'ProductType') {
            $productType = Get-HLScanValidationProperty -InputObject $system -Name 'ProductType'
            if (-not (Test-HLScanValidationInteger -Value $productType) -or [decimal]$productType -lt 0 -or [decimal]$productType -gt 3) {
                Add-HLScanValidationError -Errors $errors -Path 'system.ProductType' -Message 'must be an integer from 0 through 3.'
            }
        }
    }

    if ($null -ne $baseline) {
        foreach ($stringName in @('name', 'displayName', 'description')) {
            if ((Test-HLScanValidationProperty -InputObject $baseline -Name $stringName) -and (Get-HLScanValidationProperty -InputObject $baseline -Name $stringName) -isnot [string]) {
                Add-HLScanValidationError -Errors $errors -Path "baseline.$stringName" -Message 'must be a string.'
            }
        }

        if (Test-HLScanValidationProperty -InputObject $baseline -Name 'version') {
            $baselineVersion = Get-HLScanValidationProperty -InputObject $baseline -Name 'version'
            if ($baselineVersion -isnot [string] -or [string]$baselineVersion -notmatch '^\d+\.\d+\.\d+$') {
                Add-HLScanValidationError -Errors $errors -Path 'baseline.version' -Message 'must use semantic version form x.y.z.'
            }
        }

        if (Test-HLScanValidationProperty -InputObject $baseline -Name 'source') {
            $source = Get-HLScanValidationProperty -InputObject $baseline -Name 'source'
            if ($source -isnot [string] -or [string]$source -cnotin @('BuiltIn', 'Custom')) {
                Add-HLScanValidationError -Errors $errors -Path 'baseline.source' -Message 'must be BuiltIn or Custom.'
            }
        }

        foreach ($arrayName in @('sourceBasis', 'supportedRoles', 'notes')) {
            if (Test-HLScanValidationProperty -InputObject $baseline -Name $arrayName) {
                $arrayValue = Get-HLScanValidationProperty -InputObject $baseline -Name $arrayName
                if (-not (Test-HLScanValidationArray -Value $arrayValue)) {
                    Add-HLScanValidationError -Errors $errors -Path "baseline.$arrayName" -Message 'must be an array.'
                }
                elseif (@($arrayValue | Where-Object { $_ -isnot [string] }).Count -gt 0) {
                    Add-HLScanValidationError -Errors $errors -Path "baseline.$arrayName" -Message 'must contain only strings.'
                }
            }
        }

        if (Test-HLScanValidationProperty -InputObject $baseline -Name 'controlCount') {
            $controlCount = Get-HLScanValidationProperty -InputObject $baseline -Name 'controlCount'
            if (-not (Test-HLScanValidationInteger -Value $controlCount) -or [decimal]$controlCount -lt 0) {
                Add-HLScanValidationError -Errors $errors -Path 'baseline.controlCount' -Message 'must be a non-negative integer.'
            }
        }
    }

    $results = $null
    if (Test-HLScanValidationProperty -InputObject $ScanResult -Name 'results') {
        $results = Get-HLScanValidationProperty -InputObject $ScanResult -Name 'results'
        if (-not (Test-HLScanValidationArray -Value $results)) {
            Add-HLScanValidationError -Errors $errors -Path 'results' -Message 'must be an array.'
            $results = $null
        }
    }

    $statusNames = @('Pass', 'Fail', 'Warning', 'Excepted', 'Unknown', 'Error', 'NotApplicable')
    $severityNames = @('Critical', 'High', 'Medium', 'Low', 'Informational')
    $statusCounts = @{}
    foreach ($statusName in $statusNames) { $statusCounts[$statusName] = 0 }
    $controlIds = @{}
    $resultCount = 0

    if ($null -ne $results) {
        foreach ($result in @($results)) {
            $index = $resultCount
            $resultCount++
            $resultPath = 'results[{0}]' -f $index
            if (-not (Test-HLScanValidationObject -Value $result)) {
                Add-HLScanValidationError -Errors $errors -Path $resultPath -Message 'must be an object.'
                continue
            }

            Test-HLScanRequiredPropertySet -InputObject $result -Names @(
                'controlId', 'title', 'category', 'severity', 'status', 'originalStatus', 'expected',
                'actual', 'message', 'evidence', 'rationale', 'remediation', 'references', 'tags',
                'probe', 'exception', 'collectedAt'
            ) -Path $resultPath -Errors $errors

            if (Test-HLScanValidationProperty -InputObject $result -Name 'controlId') {
                $controlId = Get-HLScanValidationProperty -InputObject $result -Name 'controlId'
                if ($controlId -isnot [string] -or [string]$controlId -cnotmatch '^HL-[A-Z]+-[0-9]{3}$') {
                    Add-HLScanValidationError -Errors $errors -Path "$resultPath.controlId" -Message 'must match HL-<CATEGORY>-<NNN>.'
                }
                elseif ($controlIds.ContainsKey([string]$controlId)) {
                    Add-HLScanValidationError -Errors $errors -Path "$resultPath.controlId" -Message "duplicate controlId '$controlId'."
                }
                else {
                    $controlIds[[string]$controlId] = $true
                }
            }

            foreach ($stringName in @('title', 'category', 'message', 'rationale', 'remediation', 'probe')) {
                if ((Test-HLScanValidationProperty -InputObject $result -Name $stringName) -and (Get-HLScanValidationProperty -InputObject $result -Name $stringName) -isnot [string]) {
                    Add-HLScanValidationError -Errors $errors -Path "$resultPath.$stringName" -Message 'must be a string.'
                }
            }

            if (Test-HLScanValidationProperty -InputObject $result -Name 'severity') {
                $severity = Get-HLScanValidationProperty -InputObject $result -Name 'severity'
                if ($severity -isnot [string] -or [string]$severity -cnotin $severityNames) {
                    Add-HLScanValidationError -Errors $errors -Path "$resultPath.severity" -Message ('must be one of: {0}.' -f ($severityNames -join ', '))
                }
            }

            if (Test-HLScanValidationProperty -InputObject $result -Name 'status') {
                $status = Get-HLScanValidationProperty -InputObject $result -Name 'status'
                if ($status -isnot [string] -or [string]$status -cnotin $statusNames) {
                    Add-HLScanValidationError -Errors $errors -Path "$resultPath.status" -Message ('must be one of: {0}.' -f ($statusNames -join ', '))
                }
                else {
                    $statusCounts[[string]$status]++
                }
            }

            foreach ($arrayName in @('references', 'tags')) {
                if (Test-HLScanValidationProperty -InputObject $result -Name $arrayName) {
                    $arrayValue = Get-HLScanValidationProperty -InputObject $result -Name $arrayName
                    if (-not (Test-HLScanValidationArray -Value $arrayValue)) {
                        Add-HLScanValidationError -Errors $errors -Path "$resultPath.$arrayName" -Message 'must be an array.'
                    }
                    elseif (@($arrayValue | Where-Object { $_ -isnot [string] }).Count -gt 0) {
                        Add-HLScanValidationError -Errors $errors -Path "$resultPath.$arrayName" -Message 'must contain only strings.'
                    }
                }
            }

            if (Test-HLScanValidationProperty -InputObject $result -Name 'originalStatus') {
                $originalStatus = Get-HLScanValidationProperty -InputObject $result -Name 'originalStatus'
                if ($null -ne $originalStatus -and $originalStatus -isnot [string]) {
                    Add-HLScanValidationError -Errors $errors -Path "$resultPath.originalStatus" -Message 'must be null or a string.'
                }
            }

            if (Test-HLScanValidationProperty -InputObject $result -Name 'exception') {
                $exception = Get-HLScanValidationProperty -InputObject $result -Name 'exception'
                if ($null -ne $exception -and -not (Test-HLScanValidationObject -Value $exception)) {
                    Add-HLScanValidationError -Errors $errors -Path "$resultPath.exception" -Message 'must be null or an object.'
                }
            }

            if (Test-HLScanValidationProperty -InputObject $result -Name 'collectedAt') {
                $resultTimestamp = Get-HLScanValidationProperty -InputObject $result -Name 'collectedAt'
                $parsedResultTimestamp = [datetimeoffset]::MinValue
                if ($resultTimestamp -isnot [datetime] -and $resultTimestamp -isnot [datetimeoffset] -and ($resultTimestamp -isnot [string] -or -not [datetimeoffset]::TryParse([string]$resultTimestamp, [ref]$parsedResultTimestamp))) {
                    Add-HLScanValidationError -Errors $errors -Path "$resultPath.collectedAt" -Message 'must be a date-time string.'
                }
            }
        }
    }

    if ($null -ne $summary) {
        foreach ($countName in @('Total', 'Applicable') + $statusNames) {
            if (Test-HLScanValidationProperty -InputObject $summary -Name $countName) {
                $countValue = Get-HLScanValidationProperty -InputObject $summary -Name $countName
                if (-not (Test-HLScanValidationInteger -Value $countValue) -or [decimal]$countValue -lt 0) {
                    Add-HLScanValidationError -Errors $errors -Path "summary.$countName" -Message 'must be a non-negative integer.'
                }
            }
        }

        foreach ($percentageName in @('HardeningScore', 'EvidenceCoverage')) {
            if (Test-HLScanValidationProperty -InputObject $summary -Name $percentageName) {
                $percentage = Get-HLScanValidationProperty -InputObject $summary -Name $percentageName
                if ($null -ne $percentage -and (-not (Test-HLScanValidationNumber -Value $percentage) -or [decimal]$percentage -lt 0 -or [decimal]$percentage -gt 100)) {
                    Add-HLScanValidationError -Errors $errors -Path "summary.$percentageName" -Message 'must be null or a number from 0 through 100.'
                }
            }
        }

        if (Test-HLScanValidationProperty -InputObject $summary -Name 'HighestOpenSeverity') {
            $highest = Get-HLScanValidationProperty -InputObject $summary -Name 'HighestOpenSeverity'
            if ($highest -isnot [string] -or [string]$highest -cnotin (@('None') + $severityNames)) {
                Add-HLScanValidationError -Errors $errors -Path 'summary.HighestOpenSeverity' -Message 'contains an unsupported severity.'
            }
        }

        if ((Test-HLScanValidationProperty -InputObject $summary -Name 'ScoringModel') -and (Get-HLScanValidationProperty -InputObject $summary -Name 'ScoringModel') -isnot [string]) {
            Add-HLScanValidationError -Errors $errors -Path 'summary.ScoringModel' -Message 'must be a string.'
        }

        if ((Test-HLScanValidationProperty -InputObject $summary -Name 'Total') -and (Test-HLScanValidationInteger -Value (Get-HLScanValidationProperty -InputObject $summary -Name 'Total'))) {
            if ([int64](Get-HLScanValidationProperty -InputObject $summary -Name 'Total') -ne $resultCount) {
                Add-HLScanValidationError -Errors $errors -Path 'summary.Total' -Message "must equal the results count ($resultCount)."
            }
        }

        foreach ($statusName in $statusNames) {
            if ((Test-HLScanValidationProperty -InputObject $summary -Name $statusName) -and (Test-HLScanValidationInteger -Value (Get-HLScanValidationProperty -InputObject $summary -Name $statusName))) {
                if ([int64](Get-HLScanValidationProperty -InputObject $summary -Name $statusName) -ne [int64]$statusCounts[$statusName]) {
                    Add-HLScanValidationError -Errors $errors -Path "summary.$statusName" -Message "must equal the matching results count ($($statusCounts[$statusName]))."
                }
            }
        }

        if ((Test-HLScanValidationProperty -InputObject $summary -Name 'Applicable') -and (Test-HLScanValidationInteger -Value (Get-HLScanValidationProperty -InputObject $summary -Name 'Applicable'))) {
            $expectedApplicable = $resultCount - [int]$statusCounts.NotApplicable
            if ([int64](Get-HLScanValidationProperty -InputObject $summary -Name 'Applicable') -ne $expectedApplicable) {
                Add-HLScanValidationError -Errors $errors -Path 'summary.Applicable' -Message "must equal the applicable results count ($expectedApplicable)."
            }
        }
    }

    if ($null -ne $scan -and (Test-HLScanValidationProperty -InputObject $scan -Name 'selectedControlCount')) {
        $selectedControlCount = Get-HLScanValidationProperty -InputObject $scan -Name 'selectedControlCount'
        if ((Test-HLScanValidationInteger -Value $selectedControlCount) -and [int64]$selectedControlCount -ne $resultCount) {
            Add-HLScanValidationError -Errors $errors -Path 'scan.selectedControlCount' -Message "must equal the results count ($resultCount)."
        }
    }

    if ($errors.Count -gt 0) {
        throw ("Invalid Hardening Lens scan result:{0} - {1}" -f [Environment]::NewLine, ($errors.ToArray() -join ([Environment]::NewLine + ' - ')))
    }
}
