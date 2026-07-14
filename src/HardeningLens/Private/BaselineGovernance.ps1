function Get-HLBaselineEffectiveControlCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Document
    )

    $controlIds = @{}
    if ((Test-HLProperty -InputObject $Document -Name 'extends') -and -not [string]::IsNullOrWhiteSpace([string]$Document.extends)) {
        $basePath = Get-HLBuiltinBaselinePath -Name ([string]$Document.extends)
        $base = Get-Content -LiteralPath $basePath -Raw -ErrorAction Stop | ConvertFrom-Json
        foreach ($control in @($base.controls)) {
            $controlIds[[string]$control.id] = $true
        }

        if (Test-HLProperty -InputObject $Document -Name 'excludedControls') {
            foreach ($excludedId in @($Document.excludedControls)) {
                if (-not $controlIds.ContainsKey([string]$excludedId)) {
                    throw "Baseline excludes control '$excludedId', which is not present in '$($Document.extends)'."
                }
                [void]$controlIds.Remove([string]$excludedId)
            }
        }
    }
    elseif ((Test-HLProperty -InputObject $Document -Name 'excludedControls') -and @($Document.excludedControls).Count -gt 0) {
        throw 'Baseline cannot use excludedControls without extending a built-in baseline.'
    }

    foreach ($control in @($Document.controls)) {
        $enabled = -not (Test-HLProperty -InputObject $control -Name 'enabled') -or [bool]$control.enabled
        if ($enabled) {
            $controlIds[[string]$control.id] = $true
        }
        else {
            [void]$controlIds.Remove([string]$control.id)
        }
    }

    return $controlIds.Count
}

function Test-HLBaselineRuntimeDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Document,

        [Parameter(Mandatory)]
        [string]$Source,

        [AllowNull()]
        [string]$Path
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $copy = $null
    $effectiveControlCount = 0
    try {
        $copy = Copy-HLObject -InputObject $Document
        $catalog = Get-HLControlCatalog
        Assert-HLBaselineDocument -Document $copy -Catalog $catalog -Source $Source
        $effectiveControlCount = Get-HLBaselineEffectiveControlCount -Document $copy
        if ($effectiveControlCount -eq 0) {
            $warnings.Add('The baseline resolves to zero enabled controls.')
        }
    }
    catch {
        $errors.Add($_.Exception.Message)
    }

    return [pscustomobject][ordered]@{
        IsValid      = $errors.Count -eq 0
        Errors       = $errors.ToArray()
        Warnings     = $warnings.ToArray()
        Name         = if ($null -ne $copy -and (Test-HLProperty -InputObject $copy -Name 'name')) { [string]$copy.name } else { $null }
        Version      = if ($null -ne $copy -and (Test-HLProperty -InputObject $copy -Name 'version')) { [string]$copy.version } else { $null }
        ControlCount = $effectiveControlCount
        Path         = $Path
    }
}
