function Test-HLProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $false
    }

    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Copy-HLObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject
    )

    return ($InputObject | ConvertTo-Json -Depth 40 | ConvertFrom-Json)
}

function Test-HLIsWindows {
    [CmdletBinding()]
    param()

    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Assert-HLWindows {
    [CmdletBinding()]
    param()

    if (-not (Test-HLIsWindows)) {
        throw 'Live Hardening Lens collection requires Windows. Catalog, baseline, report, and comparison commands remain cross-platform.'
    }
}

function Test-HLIsElevated {
    [CmdletBinding()]
    param()

    if (-not (Test-HLIsWindows)) {
        return $false
    }

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-HLModuleVersion {
    [CmdletBinding()]
    param()

    $manifestPath = Join-Path -Path $script:HLModuleRoot -ChildPath 'HardeningLens.psd1'
    try {
        $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        return $manifest.Version.ToString()
    }
    catch {
        return '0.0.0'
    }
}

function Get-HLSeverityWeight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity
    )

    switch ($Severity) {
        'Critical' { return 10 }
        'High' { return 7 }
        'Medium' { return 4 }
        'Low' { return 1 }
        default { return 0 }
    }
}

function Get-HLSeverityRank {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Severity
    )

    switch ($Severity) {
        'Critical' { return 4 }
        'High' { return 3 }
        'Medium' { return 2 }
        'Low' { return 1 }
        default { return 0 }
    }
}

function ConvertTo-HLDisplayString {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return '<not set>'
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [bool]) {
        return $Value.ToString()
    }

    if ($Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]) {
        return ($Value | ConvertTo-Json -Depth 15 -Compress)
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value | ForEach-Object { ConvertTo-HLDisplayString -Value $_ })
        return ($items -join ', ')
    }

    return [string]$Value
}

function New-HLProbeResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Unknown', 'Error', 'NotApplicable')]
        [string]$Status,

        [AllowNull()]
        [object]$Expected,

        [AllowNull()]
        [object]$Actual,

        [string]$Message = '',

        [AllowNull()]
        [object]$Evidence = $null
    )

    return [pscustomobject][ordered]@{
        Status   = $Status
        Expected = $Expected
        Actual   = $Actual
        Message  = $Message
        Evidence = $Evidence
    }
}

function Get-HLControlCatalog {
    [CmdletBinding()]
    param()

    if ($null -ne $script:HLControlCatalogCache) {
        return $script:HLControlCatalogCache
    }

    $path = Join-Path -Path $script:HLDataRoot -ChildPath 'control-catalog.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Control catalog not found: $path"
    }

    $catalog = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
    $script:HLControlCatalogCache = $catalog
    return $catalog
}

function Get-HLBuiltinBaselineNames {
    [CmdletBinding()]
    param()

    return @('Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')
}

function Get-HLBuiltinBaselinePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
        [string]$Name
    )

    $baselineRoot = Join-Path -Path $script:HLDataRoot -ChildPath 'Baselines'
    return Join-Path -Path $baselineRoot -ChildPath ($Name + '.json')
}

function Merge-HLParameterObject {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Base,

        [AllowNull()]
        [object]$Override
    )

    $merged = [ordered]@{}

    if ($null -ne $Base) {
        foreach ($property in $Base.PSObject.Properties) {
            $merged[$property.Name] = $property.Value
        }
    }

    if ($null -ne $Override) {
        foreach ($property in $Override.PSObject.Properties) {
            $merged[$property.Name] = $property.Value
        }
    }

    return [pscustomobject]$merged
}

function Resolve-HLControlDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$CatalogControl,

        [Parameter(Mandatory)]
        [object]$BaselineControl
    )

    $resolved = Copy-HLObject -InputObject $CatalogControl

    if ((Test-HLProperty -InputObject $BaselineControl -Name 'severity') -and -not [string]::IsNullOrWhiteSpace([string]$BaselineControl.severity)) {
        $resolved.severity = [string]$BaselineControl.severity
    }

    if (Test-HLProperty -InputObject $BaselineControl -Name 'parameters') {
        $resolved.parameters = Merge-HLParameterObject -Base $resolved.parameters -Override $BaselineControl.parameters
    }

    return $resolved
}

function Resolve-HLBaseline {
    [CmdletBinding()]
    param(
        [ValidateSet('Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
        [string]$Name,

        [string]$Path
    )

    $catalog = Get-HLControlCatalog
    $catalogById = @{}
    foreach ($control in @($catalog.controls)) {
        $catalogById[[string]$control.id] = $control
    }

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
        $custom = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop | ConvertFrom-Json

        if ((Test-HLProperty -InputObject $custom -Name 'extends') -and -not [string]::IsNullOrWhiteSpace([string]$custom.extends)) {
            if ([string]$custom.extends -notin (Get-HLBuiltinBaselineNames)) {
                throw "Custom baseline extends unsupported built-in baseline '$($custom.extends)'."
            }
            $basePath = Get-HLBuiltinBaselinePath -Name ([string]$custom.extends)
            $base = Get-Content -LiteralPath $basePath -Raw -ErrorAction Stop | ConvertFrom-Json
        }
        else {
            $base = [pscustomobject][ordered]@{
                schemaVersion = '1.0'
                name          = [string]$custom.name
                displayName   = [string]$custom.displayName
                version       = [string]$custom.version
                description   = if (Test-HLProperty -InputObject $custom -Name 'description') { [string]$custom.description } else { '' }
                sourceBasis   = @()
                supportedRoles = @()
                controls      = @()
                notes         = @()
            }
        }

        $baseline = Copy-HLObject -InputObject $base

        foreach ($metadataName in @('name', 'displayName', 'version', 'description', 'sourceBasis', 'supportedRoles', 'notes')) {
            if (Test-HLProperty -InputObject $custom -Name $metadataName) {
                if ($null -eq $baseline.PSObject.Properties[$metadataName]) {
                    $baseline | Add-Member -NotePropertyName $metadataName -NotePropertyValue $custom.$metadataName
                }
                else {
                    $baseline.$metadataName = $custom.$metadataName
                }
            }
        }

        $controlMap = [ordered]@{}
        foreach ($control in @($baseline.controls)) {
            $controlMap[[string]$control.id] = $control
        }

        if (Test-HLProperty -InputObject $custom -Name 'excludedControls') {
            foreach ($excludedId in @($custom.excludedControls)) {
                [void]$controlMap.Remove([string]$excludedId)
            }
        }

        foreach ($override in @($custom.controls)) {
            $id = [string]$override.id
            $enabled = $true
            if (Test-HLProperty -InputObject $override -Name 'enabled') {
                $enabled = [bool]$override.enabled
            }

            if (-not $enabled) {
                [void]$controlMap.Remove($id)
                continue
            }

            if ($controlMap.Contains($id)) {
                $existing = $controlMap[$id]
                if (Test-HLProperty -InputObject $override -Name 'severity') {
                    if ($null -eq $existing.PSObject.Properties['severity']) {
                        $existing | Add-Member -NotePropertyName severity -NotePropertyValue $override.severity
                    }
                    else {
                        $existing.severity = $override.severity
                    }
                }
                if (Test-HLProperty -InputObject $override -Name 'parameters') {
                    $currentParameters = if (Test-HLProperty -InputObject $existing -Name 'parameters') { $existing.parameters } else { $null }
                    $mergedParameters = Merge-HLParameterObject -Base $currentParameters -Override $override.parameters
                    if ($null -eq $existing.PSObject.Properties['parameters']) {
                        $existing | Add-Member -NotePropertyName parameters -NotePropertyValue $mergedParameters
                    }
                    else {
                        $existing.parameters = $mergedParameters
                    }
                }
                $controlMap[$id] = $existing
            }
            else {
                $controlMap[$id] = $override
            }
        }

        $baseline.controls = @($controlMap.Values)
        $baseline | Add-Member -NotePropertyName sourcePath -NotePropertyValue $resolvedPath -Force
    }
    else {
        if ([string]::IsNullOrWhiteSpace($Name)) {
            throw 'A baseline name or baseline path is required.'
        }
        $baselinePath = Get-HLBuiltinBaselinePath -Name $Name
        $baseline = Get-Content -LiteralPath $baselinePath -Raw -ErrorAction Stop | ConvertFrom-Json
        $baseline | Add-Member -NotePropertyName sourcePath -NotePropertyValue $baselinePath -Force
    }

    $seen = @{}
    $resolvedControls = New-Object System.Collections.Generic.List[object]
    foreach ($baselineControl in @($baseline.controls)) {
        $id = [string]$baselineControl.id
        if ($seen.ContainsKey($id)) {
            throw "Baseline '$($baseline.name)' contains duplicate control '$id'."
        }
        $seen[$id] = $true

        if (-not $catalogById.ContainsKey($id)) {
            throw "Baseline '$($baseline.name)' references unknown control '$id'."
        }

        $resolvedControls.Add((Resolve-HLControlDefinition -CatalogControl $catalogById[$id] -BaselineControl $baselineControl))
    }

    $baseline.controls = $resolvedControls.ToArray()
    $baseline | Add-Member -NotePropertyName controlCount -NotePropertyValue $resolvedControls.Count -Force
    return $baseline
}

function Get-HLSystemContext {
    [CmdletBinding()]
    param()

    Assert-HLWindows

    $os = $null
    $computerSystem = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        Write-Verbose "Unable to query Win32_OperatingSystem: $($_.Exception.Message)"
    }

    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    }
    catch {
        Write-Verbose "Unable to query Win32_ComputerSystem: $($_.Exception.Message)"
    }

    $productType = if ($null -ne $os -and $null -ne $os.ProductType) { [int]$os.ProductType } else { 0 }
    $role = switch ($productType) {
        1 { 'Workstation' }
        2 { 'DomainController' }
        3 { 'MemberServer' }
        default { 'Unknown' }
    }

    $computerName = if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { $env:COMPUTERNAME } else { [Environment]::MachineName }
    $domain = if ($null -ne $computerSystem) { [string]$computerSystem.Domain } else { [string]$env:USERDOMAIN }
    $currentUser = try { [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { [Environment]::UserName }

    return [pscustomobject][ordered]@{
        ComputerName      = $computerName
        Domain            = $domain
        DomainJoined      = if ($null -ne $computerSystem) { [bool]$computerSystem.PartOfDomain } else { $null }
        DetectedRole      = $role
        ProductType       = $productType
        OSCaption         = if ($null -ne $os) { [string]$os.Caption } else { [Environment]::OSVersion.VersionString }
        OSVersion         = if ($null -ne $os) { [string]$os.Version } else { [Environment]::OSVersion.Version.ToString() }
        BuildNumber       = if ($null -ne $os) { [string]$os.BuildNumber } else { [Environment]::OSVersion.Version.Build.ToString() }
        OSArchitecture    = if ($null -ne $os) { [string]$os.OSArchitecture } else { [string]$env:PROCESSOR_ARCHITECTURE }
        Manufacturer      = if ($null -ne $computerSystem) { [string]$computerSystem.Manufacturer } else { '' }
        Model             = if ($null -ne $computerSystem) { [string]$computerSystem.Model } else { '' }
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition = if ($null -ne $PSVersionTable.PSObject.Properties['PSEdition']) { [string]$PSVersionTable.PSEdition } else { 'Desktop' }
        CurrentUser       = $currentUser
        IsElevated        = Test-HLIsElevated
    }
}

function Get-HLAutoBaselineName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$SystemContext
    )

    switch ([int]$SystemContext.ProductType) {
        1 { return 'Workstation' }
        2 { return 'DomainController' }
        3 { return 'MemberServer' }
        default { throw 'Unable to determine a role-aware baseline automatically. Specify -Baseline explicitly.' }
    }
}

function Get-HLSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Results
    )

    $statusNames = @('Pass', 'Fail', 'Warning', 'Excepted', 'Unknown', 'Error', 'NotApplicable')
    $counts = [ordered]@{}
    foreach ($status in $statusNames) {
        $counts[$status] = @($Results | Where-Object { $_.status -eq $status }).Count
    }

    $weightedTotal = 0.0
    $weightedPass = 0.0
    $applicableCount = 0
    $coveredCount = 0

    foreach ($result in $Results) {
        if ($result.status -eq 'NotApplicable') {
            continue
        }

        $applicableCount++
        if ($result.status -notin @('Unknown', 'Error')) {
            $coveredCount++
        }

        $weight = Get-HLSeverityWeight -Severity ([string]$result.severity)
        if ($weight -le 0) {
            continue
        }

        $weightedTotal += $weight
        if ($result.status -eq 'Pass') {
            $weightedPass += $weight
        }
    }

    $score = if ($weightedTotal -gt 0) { [math]::Round(($weightedPass / $weightedTotal) * 100, 1) } else { $null }
    $coverage = if ($applicableCount -gt 0) { [math]::Round(($coveredCount / $applicableCount) * 100, 1) } else { $null }

    $highestOpenSeverity = 'None'
    $open = @($Results | Where-Object { $_.status -in @('Fail', 'Warning', 'Excepted', 'Error') })
    if ($open.Count -gt 0) {
        $highest = $open | Sort-Object @{ Expression = { Get-HLSeverityRank -Severity ([string]$_.severity) }; Descending = $true }, controlId | Select-Object -First 1
        $highestOpenSeverity = [string]$highest.severity
    }

    return [pscustomobject][ordered]@{
        Total               = $Results.Count
        Applicable          = $applicableCount
        Pass                = $counts.Pass
        Fail                = $counts.Fail
        Warning             = $counts.Warning
        Excepted            = $counts.Excepted
        Unknown             = $counts.Unknown
        Error               = $counts.Error
        NotApplicable       = $counts.NotApplicable
        HardeningScore      = $score
        EvidenceCoverage    = $coverage
        HighestOpenSeverity = $highestOpenSeverity
        ScoringModel        = 'Severity-weighted pass percentage. Exceptions, unknowns, warnings, and errors receive no pass credit; not-applicable and informational controls are excluded.'
    }
}

function ConvertTo-HLRedactedObject {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [hashtable]$ReplacementMap
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [string]) {
        $value = [string]$InputObject
        $keys = @($ReplacementMap.Keys | Sort-Object { ([string]$_).Length } -Descending)
        foreach ($key in $keys) {
            if (-not [string]::IsNullOrWhiteSpace([string]$key)) {
                $value = $value -replace [regex]::Escape([string]$key), [string]$ReplacementMap[$key]
            }
        }
        return $value
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $dictionary = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $dictionary[$key] = ConvertTo-HLRedactedObject -InputObject $InputObject[$key] -ReplacementMap $ReplacementMap
        }
        return [pscustomobject]$dictionary
    }

    if ($InputObject -is [pscustomobject]) {
        $properties = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $properties[$property.Name] = ConvertTo-HLRedactedObject -InputObject $property.Value -ReplacementMap $ReplacementMap
        }
        return [pscustomobject]$properties
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($item in $InputObject) {
            $items.Add((ConvertTo-HLRedactedObject -InputObject $item -ReplacementMap $ReplacementMap))
        }
        return $items.ToArray()
    }

    return $InputObject
}

function Protect-HLResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ScanResult
    )

    $copy = Copy-HLObject -InputObject $ScanResult
    $replacementMap = @{}

    if (Test-HLProperty -InputObject $copy -Name 'system') {
        if (-not [string]::IsNullOrWhiteSpace([string]$copy.system.ComputerName)) {
            $replacementMap[[string]$copy.system.ComputerName] = 'HOST-REDACTED'
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$copy.system.Domain)) {
            $replacementMap[[string]$copy.system.Domain] = 'DOMAIN.REDACTED'
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$copy.system.CurrentUser)) {
            $replacementMap[[string]$copy.system.CurrentUser] = 'USER-REDACTED'
        }
    }

    $redacted = ConvertTo-HLRedactedObject -InputObject $copy -ReplacementMap $replacementMap
    $redacted.scan.redacted = $true
    return $redacted
}

function Write-HLConsoleSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ScanResult
    )

    $summary = $ScanResult.summary
    $scoreText = if ($null -eq $summary.HardeningScore) { 'n/a' } else { '{0:N1}%' -f [double]$summary.HardeningScore }
    $coverageText = if ($null -eq $summary.EvidenceCoverage) { 'n/a' } else { '{0:N1}%' -f [double]$summary.EvidenceCoverage }

    Write-Host ''
    Write-Host ('HARDENING LENS // {0}' -f $ScanResult.system.ComputerName) -ForegroundColor Cyan
    Write-Host ('Baseline: {0} {1} | Score: {2} | Coverage: {3}' -f $ScanResult.baseline.displayName, $ScanResult.baseline.version, $scoreText, $coverageText)
    Write-Host ('PASS {0}  FAIL {1}  WARN {2}  EXCEPTED {3}  UNKNOWN {4}  ERROR {5}  N/A {6}' -f $summary.Pass, $summary.Fail, $summary.Warning, $summary.Excepted, $summary.Unknown, $summary.Error, $summary.NotApplicable)

    $findings = @($ScanResult.results | Where-Object { $_.status -in @('Fail', 'Error', 'Warning') } | Sort-Object @{ Expression = { Get-HLSeverityRank -Severity ([string]$_.severity) }; Descending = $true }, controlId | Select-Object -First 10)
    if ($findings.Count -gt 0) {
        Write-Host ''
        Write-Host 'Top findings:' -ForegroundColor Yellow
        foreach ($finding in $findings) {
            Write-Host ('[{0,-8}] [{1,-8}] {2}  {3}' -f $finding.severity.ToUpperInvariant(), $finding.status.ToUpperInvariant(), $finding.controlId, $finding.title)
        }
    }
    Write-Host ''
}
