function Get-HLAssessmentMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ScanResult
    )

    if ($null -ne $ScanResult.scan -and $null -ne $ScanResult.scan.assessmentMode) {
        return [string]$ScanResult.scan.assessmentMode
    }

    $selected = if ($null -ne $ScanResult.scan.selectedControlCount) { [int]$ScanResult.scan.selectedControlCount } else { @($ScanResult.results).Count }
    $baseline = if ($null -ne $ScanResult.scan.baselineControlCount) {
        [int]$ScanResult.scan.baselineControlCount
    }
    elseif ($null -ne $ScanResult.baseline.controlCount) {
        [int]$ScanResult.baseline.controlCount
    }
    else {
        $selected
    }

    if ($selected -lt $baseline) { return 'Focused' }
    return 'Full'
}

function ConvertTo-HLCanonicalObject {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [string] -or $InputObject -is [ValueType]) {
        return $InputObject
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in @($InputObject.Keys | Sort-Object { [string]$_ })) {
            $ordered[[string]$key] = ConvertTo-HLCanonicalObject -InputObject $InputObject[$key]
        }
        return [pscustomobject]$ordered
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($item in $InputObject) {
            $items.Add((ConvertTo-HLCanonicalObject -InputObject $item))
        }
        return $items.ToArray()
    }

    $properties = @($InputObject.PSObject.Properties | Where-Object {
        $_.MemberType -in @('NoteProperty', 'Property', 'AliasProperty', 'ScriptProperty') -and
        $_.Name -notin @('PSComputerName', 'RunspaceId', 'PSShowComputerName')
    } | Sort-Object Name)

    $result = [ordered]@{}
    foreach ($property in $properties) {
        $result[$property.Name] = ConvertTo-HLCanonicalObject -InputObject $property.Value
    }
    return [pscustomobject]$result
}

function Test-HLWildcardScopeOverlap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Left,

        [Parameter(Mandatory)]
        [string[]]$Right
    )

    foreach ($leftPattern in $Left) {
        foreach ($rightPattern in $Right) {
            if ($leftPattern -eq '*' -or $rightPattern -eq '*') { return $true }
            if ($leftPattern -ieq $rightPattern) { return $true }

            $leftLiteral = $leftPattern.TrimEnd('*')
            $rightLiteral = $rightPattern.TrimEnd('*')
            if ($leftPattern.EndsWith('*') -and $rightLiteral.StartsWith($leftLiteral, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
            if ($rightPattern.EndsWith('*') -and $leftLiteral.StartsWith($rightLiteral, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
    }
    return $false
}

function Add-HLAssessmentScopeBanner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html,

        [Parameter(Mandatory)]
        [object]$ScanResult
    )

    $mode = Get-HLAssessmentMode -ScanResult $ScanResult
    $selected = if ($null -ne $ScanResult.scan.selectedControlCount) { [int]$ScanResult.scan.selectedControlCount } else { @($ScanResult.results).Count }
    $baseline = if ($null -ne $ScanResult.scan.baselineControlCount) { [int]$ScanResult.scan.baselineControlCount } else { [int]$ScanResult.baseline.controlCount }
    $label = if ($mode -eq 'Focused') { 'FOCUSED ASSESSMENT' } else { 'FULL ASSESSMENT' }
    $detail = if ($mode -eq 'Focused') {
        "Scope score applies to $selected of $baseline baseline controls. It is not a complete baseline score."
    }
    else {
        "All $baseline baseline controls were selected for evaluation."
    }

    $banner = @"
<section style="margin:18px auto;max-width:1180px;padding:14px 18px;border:1px solid #3b82f6;border-radius:10px;background:#0b1b33;color:#dbeafe;font-family:system-ui,-apple-system,Segoe UI,sans-serif">
  <strong style="letter-spacing:.08em">$label</strong><br>
  <span style="color:#bfdbfe">$detail</span>
</section>
"@

    if ($Html -match '(?i)<body[^>]*>') {
        return [regex]::Replace($Html, '(?i)(<body[^>]*>)', ('$1' + [Environment]::NewLine + $banner), 1)
    }
    return $banner + $Html
}
