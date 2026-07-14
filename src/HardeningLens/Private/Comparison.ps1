function Read-HLScanResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject
    )

    if ($InputObject -is [string]) {
        $resolved = (Resolve-Path -LiteralPath ([string]$InputObject) -ErrorAction Stop).Path
        $json = Get-Content -LiteralPath $resolved -Raw -ErrorAction Stop
        $converter = Get-Command -Name ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
        if ($converter.Parameters.ContainsKey('DateKind')) {
            return $json | ConvertFrom-Json -DateKind String
        }
        return $json | ConvertFrom-Json
    }

    return $InputObject
}

function Test-HLOpenStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Status)

    return $Status -in @('Fail','Warning','Excepted','Error')
}

function ConvertTo-HLCanonicalJsonString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $codePoint = [int][char]$character
        $escaped = switch ($codePoint) {
            8 { '\b' }
            9 { '\t' }
            10 { '\n' }
            12 { '\f' }
            13 { '\r' }
            34 { '\"' }
            92 { '\\' }
            default {
                if ($codePoint -lt 32) {
                    '\u{0:x4}' -f $codePoint
                }
                else {
                    [string]$character
                }
            }
        }
        [void]$builder.Append($escaped)
    }
    [void]$builder.Append('"')
    return $builder.ToString()
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

    # Test scalars before PSCustomObject because pipeline-decorated scalar values can
    # carry adapted PSObject properties while retaining their underlying CLR type.
    if ($Value -is [string] -or $Value -is [char]) {
        return (ConvertTo-HLCanonicalJsonString -Value ([string]$Value))
    }
    if ($Value -is [bool]) {
        return $(if ([bool]$Value) { 'true' } else { 'false' })
    }
    if ($Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [single] -or $Value -is [double]) {
        $number = [double]$Value
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) {
            throw 'Canonical JSON cannot represent NaN or infinity.'
        }
        return $number.ToString('R', [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [decimal]) {
        return ([decimal]$Value).ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [datetime]) {
        return (ConvertTo-HLCanonicalJsonString -Value ([datetime]$Value).ToString('o', [Globalization.CultureInfo]::InvariantCulture))
    }
    if ($Value -is [datetimeoffset]) {
        return (ConvertTo-HLCanonicalJsonString -Value ([datetimeoffset]$Value).ToString('o', [Globalization.CultureInfo]::InvariantCulture))
    }
    if ($Value -is [guid]) {
        return (ConvertTo-HLCanonicalJsonString -Value ([guid]$Value).ToString())
    }

    if ($Value -is [System.Collections.IDictionary]) {
        [string[]]$names = @($Value.Keys | ForEach-Object { [string]$_ })
        [Array]::Sort($names, [StringComparer]::Ordinal)
        $members = foreach ($name in $names) {
            $encodedName = ConvertTo-HLCanonicalJsonString -Value $name
            '{0}:{1}' -f $encodedName, (ConvertTo-HLCanonicalJson -Value $Value[$name])
        }
        return '{' + (@($members) -join ',') + '}'
    }

    if ($Value -is [pscustomobject]) {
        [string[]]$names = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
        [Array]::Sort($names, [StringComparer]::Ordinal)
        $members = foreach ($name in $names) {
            $encodedName = ConvertTo-HLCanonicalJsonString -Value $name
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

    # Fallback for uncommon scalar CLR types not produced by JSON inputs.
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

    $schemaVersion = if ($ScanResult.schemaVersion -is [string]) { [string]$ScanResult.schemaVersion } else { '' }
    if ($schemaVersion -cnotin @('1.0', '1.1')) {
        throw "$InputName scan result uses unsupported schemaVersion '$($ScanResult.schemaVersion)'. Expected '1.0' or '1.1'."
    }

    foreach ($contract in @(
        @{ Object = $ScanResult.scan; Name = 'scan'; Properties = @('id', 'collectedAt', 'moduleVersion') }
        @{ Object = $ScanResult.system; Name = 'system'; Properties = @('ComputerName') }
        @{ Object = $ScanResult.baseline; Name = 'baseline'; Properties = @('name', 'version') }
        @{ Object = $ScanResult.summary; Name = 'summary'; Properties = @('HardeningScore', 'EvidenceCoverage') }
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

        if ($schemaVersion -ceq '1.1') {
            if (-not (Test-HLProperty -InputObject $result -Name 'probeDurationMs')) {
                throw "$InputName schema 1.1 scan result '$controlId' is missing required property 'probeDurationMs'."
            }
            if ($result.probeDurationMs -isnot [int] -and $result.probeDurationMs -isnot [long]) {
                throw "$InputName schema 1.1 scan result '$controlId' property 'probeDurationMs' must be an integer."
            }
            if ([int64]$result.probeDurationMs -lt 0) {
                throw "$InputName schema 1.1 scan result '$controlId' property 'probeDurationMs' cannot be negative."
            }
        }
    }

    if ($schemaVersion -ceq '1.1') {
        if (-not (Test-HLProperty -InputObject $ScanResult.scan -Name 'collectionDurationMs')) {
            throw "$InputName schema 1.1 scan result is missing required property 'scan.collectionDurationMs'."
        }
        if (($ScanResult.scan.collectionDurationMs -isnot [int] -and $ScanResult.scan.collectionDurationMs -isnot [long]) -or
            [int64]$ScanResult.scan.collectionDurationMs -lt 0) {
            throw "$InputName schema 1.1 property 'scan.collectionDurationMs' must be a non-negative integer."
        }

        if (-not (Test-HLProperty -InputObject $ScanResult -Name 'provenance') -or $null -eq $ScanResult.provenance) {
            throw "$InputName schema 1.1 scan result is missing required property 'provenance'."
        }
        foreach ($propertyName in @('catalogVersion', 'catalogDigest', 'baselineDigest', 'capabilities')) {
            if (-not (Test-HLProperty -InputObject $ScanResult.provenance -Name $propertyName)) {
                throw "$InputName schema 1.1 provenance is missing required property '$propertyName'."
            }
        }
        if ($ScanResult.provenance.catalogVersion -isnot [string] -or [string]$ScanResult.provenance.catalogVersion -cnotmatch '^\d+\.\d+\.\d+$') {
            throw "$InputName schema 1.1 property 'provenance.catalogVersion' must use semantic version form x.y.z."
        }
        foreach ($digestName in @('catalogDigest', 'baselineDigest')) {
            if ($ScanResult.provenance.$digestName -isnot [string] -or [string]$ScanResult.provenance.$digestName -cnotmatch '^[a-f0-9]{64}$') {
                throw "$InputName schema 1.1 property 'provenance.$digestName' must be a lowercase SHA-256 digest."
            }
        }
        if ((Test-HLProperty -InputObject $ScanResult.provenance -Name 'exceptionDigest') -and
            ($ScanResult.provenance.exceptionDigest -isnot [string] -or [string]$ScanResult.provenance.exceptionDigest -cnotmatch '^[a-f0-9]{64}$')) {
            throw "$InputName schema 1.1 property 'provenance.exceptionDigest' must be a lowercase SHA-256 digest."
        }
        if ($ScanResult.provenance.capabilities -is [string] -or
            $ScanResult.provenance.capabilities -isnot [System.Collections.IEnumerable]) {
            throw "$InputName schema 1.1 property 'provenance.capabilities' must be an array."
        }
    }
}

function Get-HLComparisonPropertyValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if (-not $InputObject.Contains($Name)) {
            return $null
        }
        return $InputObject[$Name]
    }
    if ($null -eq $InputObject.PSObject.Properties[$Name]) {
        return $null
    }
    return $InputObject.PSObject.Properties[$Name].Value
}

function ConvertTo-HLNullableString {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }
    return [string]$Value
}

function ConvertTo-HLComparisonTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Value
    )

    if ($Value -is [datetimeoffset]) {
        return ([datetimeoffset]$Value).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [datetime]) {
        $timestamp = [datetime]$Value
        if ($timestamp.Kind -eq [DateTimeKind]::Unspecified) {
            $timestamp = [datetime]::SpecifyKind($timestamp, [DateTimeKind]::Utc)
        }
        else {
            $timestamp = $timestamp.ToUniversalTime()
        }
        return $timestamp.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    return [string]$Value
}

function Get-HLResultStateSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result
    )

    return [pscustomobject][ordered]@{
        Status    = [string]$Result.status
        Severity  = [string]$Result.severity
        Expected  = $Result.expected
        Actual    = $Result.actual
        Evidence  = $Result.evidence
        Exception = $Result.exception
    }
}

function Get-HLChangedField {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Before,

        [AllowNull()]
        [object]$After
    )

    if ($null -eq $Before -or $null -eq $After) {
        return @('Presence')
    }

    $changed = New-Object System.Collections.Generic.List[string]
    foreach ($fieldName in @('Status', 'Severity', 'Expected', 'Actual', 'Evidence', 'Exception')) {
        $beforeValue = $Before.PSObject.Properties[$fieldName].Value
        $afterValue = $After.PSObject.Properties[$fieldName].Value
        if ((ConvertTo-HLCanonicalJson -Value $beforeValue) -cne (ConvertTo-HLCanonicalJson -Value $afterValue)) {
            $changed.Add($fieldName)
        }
    }
    return $changed.ToArray()
}

function Get-HLResultStateFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result
    )

    # Keep collection timestamps and explanatory prose out of drift decisions.
    # The fingerprint represents effective assessment state, evidence, and governance.
    return (ConvertTo-HLCanonicalJson -Value (Get-HLResultStateSnapshot -Result $Result))
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
        $beforeState = if ($null -ne $before) { Get-HLResultStateSnapshot -Result $before } else { $null }
        $afterState = if ($null -ne $after) { Get-HLResultStateSnapshot -Result $after } else { $null }
        $changedFields = @(Get-HLChangedField -Before $beforeState -After $afterState)
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
            elseif ($changedFields.Count -gt 0) { $changeType = 'Changed' }
        }

        $source = if ($null -ne $after) { $after } else { $before }
        $changes.Add([pscustomobject][ordered]@{
            ControlId     = $id
            Title         = [string]$source.title
            Severity      = [string]$source.severity
            Category      = [string]$source.category
            ChangeType    = $changeType
            ChangedFields = @($changedFields)
            Before        = $beforeState
            After         = $afterState
            BeforeStatus  = if ($null -ne $beforeState) { [string]$beforeState.Status } else { $null }
            AfterStatus   = if ($null -ne $afterState) { [string]$afterState.Status } else { $null }
            BeforeActual  = if ($null -ne $beforeState) { $beforeState.Actual } else { $null }
            AfterActual   = if ($null -ne $afterState) { $afterState.Actual } else { $null }
        })
    }

    $referenceScore = if ($null -ne $Reference.summary.HardeningScore) { [double]$Reference.summary.HardeningScore } else { $null }
    $differenceScore = if ($null -ne $Difference.summary.HardeningScore) { [double]$Difference.summary.HardeningScore } else { $null }
    $scoreDelta = if ($null -ne $referenceScore -and $null -ne $differenceScore) { [math]::Round($differenceScore - $referenceScore, 1) } else { $null }
    $referenceCoverage = if ($null -ne $Reference.summary.EvidenceCoverage) { [double]$Reference.summary.EvidenceCoverage } else { $null }
    $differenceCoverage = if ($null -ne $Difference.summary.EvidenceCoverage) { [double]$Difference.summary.EvidenceCoverage } else { $null }
    $coverageDelta = if ($null -ne $referenceCoverage -and $null -ne $differenceCoverage) { [math]::Round($differenceCoverage - $referenceCoverage, 1) } else { $null }

    $referenceProvenance = Get-HLComparisonPropertyValue -InputObject $Reference -Name 'provenance'
    $differenceProvenance = Get-HLComparisonPropertyValue -InputObject $Difference -Name 'provenance'
    $referenceBaseline = [pscustomobject][ordered]@{
        Name    = [string]$Reference.baseline.name
        Version = [string]$Reference.baseline.version
        Digest  = ConvertTo-HLNullableString -Value (Get-HLComparisonPropertyValue -InputObject $referenceProvenance -Name 'baselineDigest')
    }
    $differenceBaseline = [pscustomobject][ordered]@{
        Name    = [string]$Difference.baseline.name
        Version = [string]$Difference.baseline.version
        Digest  = ConvertTo-HLNullableString -Value (Get-HLComparisonPropertyValue -InputObject $differenceProvenance -Name 'baselineDigest')
    }
    $referenceCatalog = [pscustomobject][ordered]@{
        Version = ConvertTo-HLNullableString -Value (Get-HLComparisonPropertyValue -InputObject $referenceProvenance -Name 'catalogVersion')
        Digest  = ConvertTo-HLNullableString -Value (Get-HLComparisonPropertyValue -InputObject $referenceProvenance -Name 'catalogDigest')
    }
    $differenceCatalog = [pscustomobject][ordered]@{
        Version = ConvertTo-HLNullableString -Value (Get-HLComparisonPropertyValue -InputObject $differenceProvenance -Name 'catalogVersion')
        Digest  = ConvertTo-HLNullableString -Value (Get-HLComparisonPropertyValue -InputObject $differenceProvenance -Name 'catalogDigest')
    }
    $referenceCollectionDuration = Get-HLComparisonPropertyValue -InputObject $Reference.scan -Name 'collectionDurationMs'
    $differenceCollectionDuration = Get-HLComparisonPropertyValue -InputObject $Difference.scan -Name 'collectionDurationMs'
    $referenceCapabilityValue = Get-HLComparisonPropertyValue -InputObject $referenceProvenance -Name 'capabilities'
    $differenceCapabilityValue = Get-HLComparisonPropertyValue -InputObject $differenceProvenance -Name 'capabilities'
    $referenceCapabilities = if ($null -ne $referenceCapabilityValue) { @($referenceCapabilityValue) } else { @() }
    $differenceCapabilities = if ($null -ne $differenceCapabilityValue) { @($differenceCapabilityValue) } else { @() }

    return [pscustomobject][ordered]@{
        '$schema'      = 'https://raw.githubusercontent.com/xGreeny/hardening-lens/v1.1.0/src/HardeningLens/Schema/comparison.schema.json'
        schemaVersion  = '1.1'
        comparedAt     = (Get-Date).ToUniversalTime().ToString('o')
        computerName   = [string]$Difference.system.ComputerName
        baseline       = [string]$Difference.baseline.name
        baselineContext = [pscustomobject][ordered]@{
            Reference  = $referenceBaseline
            Difference = $differenceBaseline
            Changed    = [bool]((ConvertTo-HLCanonicalJson -Value $referenceBaseline) -cne (ConvertTo-HLCanonicalJson -Value $differenceBaseline))
        }
        catalogContext = [pscustomobject][ordered]@{
            Reference  = $referenceCatalog
            Difference = $differenceCatalog
            Changed    = [bool]((ConvertTo-HLCanonicalJson -Value $referenceCatalog) -cne (ConvertTo-HLCanonicalJson -Value $differenceCatalog))
        }
        referenceScan  = [pscustomobject][ordered]@{
            Id                   = [string]$Reference.scan.id
            CollectedAt          = ConvertTo-HLComparisonTimestamp -Value $Reference.scan.collectedAt
            ResultSchemaVersion  = [string]$Reference.schemaVersion
            ModuleVersion        = [string]$Reference.scan.moduleVersion
            Score                = $referenceScore
            EvidenceCoverage     = $referenceCoverage
            CollectionDurationMs = if ($null -ne $referenceCollectionDuration) { [int64]$referenceCollectionDuration } else { $null }
            ExceptionDigest      = ConvertTo-HLNullableString -Value (Get-HLComparisonPropertyValue -InputObject $referenceProvenance -Name 'exceptionDigest')
            Capabilities         = @($referenceCapabilities)
        }
        differenceScan = [pscustomobject][ordered]@{
            Id                   = [string]$Difference.scan.id
            CollectedAt          = ConvertTo-HLComparisonTimestamp -Value $Difference.scan.collectedAt
            ResultSchemaVersion  = [string]$Difference.schemaVersion
            ModuleVersion        = [string]$Difference.scan.moduleVersion
            Score                = $differenceScore
            EvidenceCoverage     = $differenceCoverage
            CollectionDurationMs = if ($null -ne $differenceCollectionDuration) { [int64]$differenceCollectionDuration } else { $null }
            ExceptionDigest      = ConvertTo-HLNullableString -Value (Get-HLComparisonPropertyValue -InputObject $differenceProvenance -Name 'exceptionDigest')
            Capabilities         = @($differenceCapabilities)
        }
        summary        = [pscustomobject][ordered]@{
            ScoreDelta      = $scoreDelta
            CoverageDelta   = $coverageDelta
            NewFindings     = @($changes | Where-Object ChangeType -eq 'NewFinding').Count
            Resolved        = @($changes | Where-Object ChangeType -eq 'Resolved').Count
            Changed         = @($changes | Where-Object ChangeType -eq 'Changed').Count
            AddedControls   = @($changes | Where-Object ChangeType -eq 'AddedControl').Count
            RemovedControls = @($changes | Where-Object ChangeType -eq 'RemovedControl').Count
            Unchanged       = @($changes | Where-Object ChangeType -eq 'Unchanged').Count
        }
        changes        = $changes.ToArray()
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
    $referenceBaselineDigest = if ($null -ne $Comparison.baselineContext.Reference.Digest) { [string]$Comparison.baselineContext.Reference.Digest } else { 'legacy/unavailable' }
    $differenceBaselineDigest = if ($null -ne $Comparison.baselineContext.Difference.Digest) { [string]$Comparison.baselineContext.Difference.Digest } else { 'legacy/unavailable' }
    $referenceCatalogVersion = if ($null -ne $Comparison.catalogContext.Reference.Version) { [string]$Comparison.catalogContext.Reference.Version } else { 'legacy/unavailable' }
    $differenceCatalogVersion = if ($null -ne $Comparison.catalogContext.Difference.Version) { [string]$Comparison.catalogContext.Difference.Version } else { 'legacy/unavailable' }
    $referenceCatalogDigest = if ($null -ne $Comparison.catalogContext.Reference.Digest) { [string]$Comparison.catalogContext.Reference.Digest } else { 'legacy/unavailable' }
    $differenceCatalogDigest = if ($null -ne $Comparison.catalogContext.Difference.Digest) { [string]$Comparison.catalogContext.Difference.Digest } else { 'legacy/unavailable' }
    $lines.Add(('* **Baseline provenance:** `{0}` `{1}` (`{2}`) -> `{3}` `{4}` (`{5}`)' -f
        $Comparison.baselineContext.Reference.Name, $Comparison.baselineContext.Reference.Version, $referenceBaselineDigest,
        $Comparison.baselineContext.Difference.Name, $Comparison.baselineContext.Difference.Version, $differenceBaselineDigest))
    $lines.Add(('* **Catalog provenance:** `{0}` (`{1}`) -> `{2}` (`{3}`)' -f
        $referenceCatalogVersion, $referenceCatalogDigest, $differenceCatalogVersion, $differenceCatalogDigest))
    $deltaText = if ($null -eq $Comparison.summary.ScoreDelta) { 'n/a' } else { '{0:+0.0;-0.0;0.0} points' -f [double]$Comparison.summary.ScoreDelta }
    $coverageDeltaText = if ($null -eq $Comparison.summary.CoverageDelta) { 'n/a' } else { '{0:+0.0;-0.0;0.0} points' -f [double]$Comparison.summary.CoverageDelta }
    $lines.Add(('* **Score delta:** {0}' -f $deltaText))
    $lines.Add(('* **Evidence coverage delta:** {0}' -f $coverageDeltaText))
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
        $lines.Add('| Type | Control | Severity | Changed fields | Before | After |')
        $lines.Add('|---|---|---|---|---|---|')
        foreach ($change in $relevant) {
            $title = ([string]$change.Title).Replace('|','\|')
            $changedFieldText = @($change.ChangedFields) -join ', '
            $lines.Add(('| {0} | `{1}` - {2} | {3} | {4} | {5} | {6} |' -f $change.ChangeType,$change.ControlId,$title,$change.Severity,$changedFieldText,$change.BeforeStatus,$change.AfterStatus))
        }
    }
    $lines.Add('')
    $lines.Add('Generated by Hardening Lens. Review operational context before treating drift as a security incident or approved change.')
    return ($lines.ToArray() -join [Environment]::NewLine)
}
