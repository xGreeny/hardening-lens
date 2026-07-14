function Read-HLScanResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject
    )

    if ($InputObject -is [string]) {
        $resolved = (Resolve-Path -LiteralPath ([string]$InputObject) -ErrorAction Stop).Path
        return Get-Content -LiteralPath $resolved -Raw -ErrorAction Stop | ConvertFrom-Json
    }

    return $InputObject
}

function Test-HLOpenStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Status)

    return $Status -in @('Fail','Warning','Excepted','Error')
}

function ConvertTo-HLCanonicalJson {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return 'null'
    }

    if ($Value -is [System.Collections.IDictionary]) {
        [string[]]$names = @($Value.Keys | ForEach-Object { [string]$_ })
        [Array]::Sort($names, [StringComparer]::Ordinal)
        $members = foreach ($name in $names) {
            $encodedName = ConvertTo-Json -InputObject $name -Compress
            '{0}:{1}' -f $encodedName, (ConvertTo-HLCanonicalJson -Value $Value[$name])
        }
        return '{' + (@($members) -join ',') + '}'
    }

    if ($Value -is [pscustomobject]) {
        [string[]]$names = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
        [Array]::Sort($names, [StringComparer]::Ordinal)
        $members = foreach ($name in $names) {
            $encodedName = ConvertTo-Json -InputObject $name -Compress
            '{0}:{1}' -f $encodedName, (ConvertTo-HLCanonicalJson -Value $Value.PSObject.Properties[$name].Value)
        }
        return '{' + (@($members) -join ',') + '}'
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = foreach ($item in $Value) {
            ConvertTo-HLCanonicalJson -Value $item
        }
        return '[' + (@($items) -join ',') + ']'
    }

    # JSON-derived scalar values retain their JSON type and invariant representation.
    return (ConvertTo-Json -InputObject $Value -Depth 2 -Compress)
}

function Assert-HLComparableScanResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$ScanResult,

        [Parameter(Mandatory)]
        [ValidateSet('Reference', 'Difference')]
        [string]$InputName
    )

    if ($null -eq $ScanResult) {
        throw "$InputName scan result cannot be null."
    }

    foreach ($propertyName in @('schemaVersion', 'scan', 'system', 'baseline', 'summary', 'results')) {
        if (-not (Test-HLProperty -InputObject $ScanResult -Name $propertyName)) {
            throw "$InputName scan result is missing required property '$propertyName'."
        }
    }

    if ($ScanResult.schemaVersion -isnot [string] -or [string]$ScanResult.schemaVersion -cne '1.0') {
        throw "$InputName scan result uses unsupported schemaVersion '$($ScanResult.schemaVersion)'. Expected '1.0'."
    }

    foreach ($contract in @(
        @{ Object = $ScanResult.scan; Name = 'scan'; Properties = @('id', 'collectedAt') }
        @{ Object = $ScanResult.system; Name = 'system'; Properties = @('ComputerName') }
        @{ Object = $ScanResult.baseline; Name = 'baseline'; Properties = @('name') }
        @{ Object = $ScanResult.summary; Name = 'summary'; Properties = @('HardeningScore') }
    )) {
        if ($null -eq $contract.Object) {
            throw "$InputName scan result property '$($contract.Name)' cannot be null."
        }
        foreach ($propertyName in $contract.Properties) {
            if (-not (Test-HLProperty -InputObject $contract.Object -Name $propertyName)) {
                throw "$InputName scan result property '$($contract.Name)' is missing required property '$propertyName'."
            }
        }
    }

    if ($null -eq $ScanResult.results) {
        throw "$InputName scan result property 'results' cannot be null."
    }
    if ($ScanResult.results -is [string] -or $ScanResult.results -isnot [System.Collections.IEnumerable]) {
        throw "$InputName scan result property 'results' must be an array."
    }

    $seenControlIds = @{}
    foreach ($result in @($ScanResult.results)) {
        if ($null -eq $result) {
            throw "$InputName scan result contains a null result entry."
        }
        foreach ($propertyName in @('controlId', 'title', 'category', 'severity', 'status')) {
            if (-not (Test-HLProperty -InputObject $result -Name $propertyName)) {
                throw "$InputName scan result contains an entry missing required property '$propertyName'."
            }
        }

        $controlId = [string]$result.controlId
        if ([string]::IsNullOrWhiteSpace($controlId)) {
            throw "$InputName scan result contains an empty controlId."
        }
        if ($seenControlIds.ContainsKey($controlId)) {
            throw "$InputName scan result contains duplicate controlId '$controlId'."
        }
        $seenControlIds[$controlId] = $true
    }
}

function Get-HLResultStateFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result
    )

    # Keep collection timestamps and explanatory prose out of drift decisions.
    # The fingerprint represents effective assessment state, evidence, and governance.
    $state = [ordered]@{
        Status    = [string]$Result.status
        Severity  = [string]$Result.severity
        Expected  = $Result.expected
        Actual    = $Result.actual
        Evidence  = $Result.evidence
        Exception = $Result.exception
    }

    return (ConvertTo-HLCanonicalJson -Value $state)
}

function Compare-HLScanResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Reference,

        [Parameter(Mandatory)]
        [object]$Difference
    )

    $referenceById = @{}
    foreach ($result in @($Reference.results)) { $referenceById[[string]$result.controlId] = $result }
    $differenceById = @{}
    foreach ($result in @($Difference.results)) { $differenceById[[string]$result.controlId] = $result }

    $allIds = @($referenceById.Keys + $differenceById.Keys | Sort-Object -Unique)
    $changes = New-Object System.Collections.Generic.List[object]
    foreach ($id in $allIds) {
        $before = if ($referenceById.ContainsKey($id)) { $referenceById[$id] } else { $null }
        $after = if ($differenceById.ContainsKey($id)) { $differenceById[$id] } else { $null }
        $changeType = 'Unchanged'

        if ($null -eq $before) {
            $changeType = 'AddedControl'
        }
        elseif ($null -eq $after) {
            $changeType = 'RemovedControl'
        }
        else {
            $beforeOpen = Test-HLOpenStatus -Status ([string]$before.status)
            $afterOpen = Test-HLOpenStatus -Status ([string]$after.status)
            if (-not $beforeOpen -and $afterOpen) { $changeType = 'NewFinding' }
            elseif ($beforeOpen -and -not $afterOpen) { $changeType = 'Resolved' }
            elseif ((Get-HLResultStateFingerprint -Result $before) -cne (Get-HLResultStateFingerprint -Result $after)) { $changeType = 'Changed' }
        }

        $source = if ($null -ne $after) { $after } else { $before }
        $changes.Add([pscustomobject][ordered]@{
            ControlId     = $id
            Title         = [string]$source.title
            Severity      = [string]$source.severity
            Category      = [string]$source.category
            ChangeType    = $changeType
            BeforeStatus  = if ($null -ne $before) { [string]$before.status } else { $null }
            AfterStatus   = if ($null -ne $after) { [string]$after.status } else { $null }
            BeforeActual  = if ($null -ne $before) { $before.actual } else { $null }
            AfterActual   = if ($null -ne $after) { $after.actual } else { $null }
        })
    }

    $referenceScore = if ($null -ne $Reference.summary.HardeningScore) { [double]$Reference.summary.HardeningScore } else { $null }
    $differenceScore = if ($null -ne $Difference.summary.HardeningScore) { [double]$Difference.summary.HardeningScore } else { $null }
    $delta = if ($null -ne $referenceScore -and $null -ne $differenceScore) { [math]::Round($differenceScore - $referenceScore, 1) } else { $null }

    return [pscustomobject][ordered]@{
        '$schema'     = 'https://raw.githubusercontent.com/xGreeny/hardening-lens/v1.0.1/src/HardeningLens/Schema/comparison.schema.json'
        schemaVersion = '1.0'
        comparedAt    = (Get-Date).ToUniversalTime().ToString('o')
        computerName  = [string]$Difference.system.ComputerName
        baseline      = [string]$Difference.baseline.name
        referenceScan = [pscustomobject][ordered]@{ Id = [string]$Reference.scan.id; CollectedAt = [string]$Reference.scan.collectedAt; Score = $referenceScore }
        differenceScan = [pscustomobject][ordered]@{ Id = [string]$Difference.scan.id; CollectedAt = [string]$Difference.scan.collectedAt; Score = $differenceScore }
        summary       = [pscustomobject][ordered]@{
            ScoreDelta      = $delta
            NewFindings     = @($changes | Where-Object ChangeType -eq 'NewFinding').Count
            Resolved        = @($changes | Where-Object ChangeType -eq 'Resolved').Count
            Changed         = @($changes | Where-Object ChangeType -eq 'Changed').Count
            AddedControls   = @($changes | Where-Object ChangeType -eq 'AddedControl').Count
            RemovedControls = @($changes | Where-Object ChangeType -eq 'RemovedControl').Count
            Unchanged       = @($changes | Where-Object ChangeType -eq 'Unchanged').Count
        }
        changes       = $changes.ToArray()
    }
}

function ConvertTo-HLComparisonMarkdown {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Comparison)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Hardening Lens drift report')
    $lines.Add('')
    $lines.Add(('* **Host:** `{0}`' -f $Comparison.computerName))
    $lines.Add(('* **Baseline:** `{0}`' -f $Comparison.baseline))
    $lines.Add(('* **Reference:** `{0}` ({1})' -f $Comparison.referenceScan.Id, $Comparison.referenceScan.CollectedAt))
    $lines.Add(('* **Current:** `{0}` ({1})' -f $Comparison.differenceScan.Id, $Comparison.differenceScan.CollectedAt))
    $deltaText = if ($null -eq $Comparison.summary.ScoreDelta) { 'n/a' } else { '{0:+0.0;-0.0;0.0} points' -f [double]$Comparison.summary.ScoreDelta }
    $lines.Add(('* **Score delta:** {0}' -f $deltaText))
    $lines.Add('')
    $lines.Add('| New findings | Resolved | Changed | Added controls | Removed controls |')
    $lines.Add('|---:|---:|---:|---:|---:|')
    $lines.Add(('| {0} | {1} | {2} | {3} | {4} |' -f $Comparison.summary.NewFindings,$Comparison.summary.Resolved,$Comparison.summary.Changed,$Comparison.summary.AddedControls,$Comparison.summary.RemovedControls))
    $lines.Add('')

    $relevant = @($Comparison.changes | Where-Object { $_.ChangeType -ne 'Unchanged' } | Sort-Object @{Expression={Get-HLSeverityRank -Severity ([string]$_.Severity)};Descending=$true}, ControlId)
    if ($relevant.Count -eq 0) {
        $lines.Add('No control state or evidence changes were detected.')
    }
    else {
        $lines.Add('## Changes')
        $lines.Add('')
        $lines.Add('| Type | Control | Severity | Before | After |')
        $lines.Add('|---|---|---|---|---|')
        foreach ($change in $relevant) {
            $title = ([string]$change.Title).Replace('|','\|')
            $lines.Add(('| {0} | `{1}` - {2} | {3} | {4} | {5} |' -f $change.ChangeType,$change.ControlId,$title,$change.Severity,$change.BeforeStatus,$change.AfterStatus))
        }
    }
    $lines.Add('')
    $lines.Add('Generated by Hardening Lens. Review operational context before treating drift as a security incident or approved change.')
    return ($lines.ToArray() -join [Environment]::NewLine)
}
