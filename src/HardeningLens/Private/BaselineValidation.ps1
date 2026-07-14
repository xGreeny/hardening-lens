function Test-HLParameterType {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,

        [AllowNull()]
        [object]$Template
    )

    if ($null -eq $Template) {
        return $true
    }
    if ($null -eq $Value) {
        return $false
    }
    if ($Template -is [bool]) {
        return $Value -is [bool]
    }
    if ($Template -is [string]) {
        return $Value -is [string]
    }
    if ($Template -is [byte] -or $Template -is [int16] -or $Template -is [int32] -or $Template -is [int64]) {
        return $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]
    }
    if ($Template -is [single] -or $Template -is [double] -or $Template -is [decimal]) {
        return $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]
    }
    if ($Template -is [System.Collections.IDictionary] -or $Template -is [pscustomobject]) {
        return $Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]
    }
    if ($Template -is [System.Collections.IEnumerable] -and -not ($Template -is [string])) {
        return $Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])
    }

    return $Value.GetType() -eq $Template.GetType()
}

function Assert-HLBaselineDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Document,

        [Parameter(Mandatory)]
        [object]$Catalog,

        [string]$Source = 'baseline document'
    )

    $allowedRoot = @('$schema', 'schemaVersion', 'name', 'displayName', 'version', 'description', 'extends', 'sourceBasis', 'supportedRoles', 'excludedControls', 'controls', 'notes')
    foreach ($property in @($Document.PSObject.Properties)) {
        if ($property.Name -notin $allowedRoot) {
            throw "$Source contains unsupported property '$($property.Name)'."
        }
    }

    foreach ($required in @('schemaVersion', 'name', 'displayName', 'version', 'description', 'controls')) {
        if (-not (Test-HLProperty -InputObject $Document -Name $required) -or $null -eq $Document.$required) {
            throw "$Source is missing required property '$required'."
        }
    }
    if ([string]$Document.schemaVersion -ne '1.0') {
        throw "$Source schemaVersion must be '1.0'."
    }
    if ([string]$Document.name -notmatch '^[A-Za-z][A-Za-z0-9_-]{1,63}$') {
        throw "$Source name must start with a letter and contain 2 to 64 letters, digits, underscores, or hyphens."
    }
    if ([string]$Document.version -notmatch '^\d+\.\d+\.\d+$') {
        throw "$Source version must use semantic versioning (for example 1.0.0)."
    }
    if (([string]$Document.displayName).Trim().Length -lt 3) {
        throw "$Source displayName must contain at least 3 characters."
    }
    if (([string]$Document.description).Trim().Length -lt 20) {
        throw "$Source description must contain at least 20 characters."
    }

    $builtinNames = @(Get-HLBuiltinBaselineName)
    if ((Test-HLProperty -InputObject $Document -Name 'extends') -and [string]$Document.extends -notin $builtinNames) {
        throw "$Source extends unsupported built-in baseline '$($Document.extends)'."
    }
    if (Test-HLProperty -InputObject $Document -Name 'supportedRoles') {
        foreach ($role in @($Document.supportedRoles)) {
            if ([string]$role -notin $builtinNames) {
                throw "$Source contains unsupported role '$role'."
            }
        }
    }

    $catalogById = @{}
    foreach ($catalogControl in @($Catalog.controls)) {
        $catalogById[[string]$catalogControl.id] = $catalogControl
    }

    $excludedSeen = @{}
    if (Test-HLProperty -InputObject $Document -Name 'excludedControls') {
        foreach ($excludedIdValue in @($Document.excludedControls)) {
            $excludedId = [string]$excludedIdValue
            if (-not $catalogById.ContainsKey($excludedId)) {
                throw "$Source excludes unknown control '$excludedId'."
            }
            if ($excludedSeen.ContainsKey($excludedId)) {
                throw "$Source contains duplicate excluded control '$excludedId'."
            }
            $excludedSeen[$excludedId] = $true
        }
    }

    $controls = @($Document.controls)
    if ($controls.Count -eq 0) {
        throw "$Source must contain at least one control entry."
    }

    $controlSeen = @{}
    $allowedSeverity = @('Critical', 'High', 'Medium', 'Low', 'Informational')
    foreach ($entry in $controls) {
        foreach ($property in @($entry.PSObject.Properties)) {
            if ($property.Name -notin @('id', 'enabled', 'severity', 'parameters')) {
                throw "$Source control entry contains unsupported property '$($property.Name)'."
            }
        }
        if (-not (Test-HLProperty -InputObject $entry -Name 'id') -or [string]::IsNullOrWhiteSpace([string]$entry.id)) {
            throw "$Source contains a control entry without an id."
        }
        $id = [string]$entry.id
        if (-not $catalogById.ContainsKey($id)) {
            throw "$Source references unknown control '$id'."
        }
        if ($controlSeen.ContainsKey($id)) {
            throw "$Source contains duplicate control '$id'."
        }
        $controlSeen[$id] = $true

        if ((Test-HLProperty -InputObject $entry -Name 'enabled') -and $entry.enabled -isnot [bool]) {
            throw "$Source control '$id' enabled must be a boolean."
        }
        if ((Test-HLProperty -InputObject $entry -Name 'severity') -and [string]$entry.severity -notin $allowedSeverity) {
            throw "$Source control '$id' has unsupported severity '$($entry.severity)'."
        }
        if (Test-HLProperty -InputObject $entry -Name 'parameters') {
            if ($entry.parameters -isnot [pscustomobject] -and $entry.parameters -isnot [System.Collections.IDictionary]) {
                throw "$Source control '$id' parameters must be an object."
            }
            $template = $catalogById[$id].parameters
            foreach ($parameter in @($entry.parameters.PSObject.Properties)) {
                if (-not (Test-HLProperty -InputObject $template -Name $parameter.Name)) {
                    throw "$Source control '$id' contains unknown parameter '$($parameter.Name)'."
                }
                $expectedType = $template.PSObject.Properties[$parameter.Name].Value
                if (-not (Test-HLParameterType -Value $parameter.Value -Template $expectedType)) {
                    throw "$Source control '$id' parameter '$($parameter.Name)' has an incompatible type."
                }
            }
        }
    }
}
