function ConvertTo-HLBoolean {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return [bool]$Value }
    $text = ([string]$Value).Trim()
    if ($text -match '^(?i:true|1|enabled)$') { return $true }
    if ($text -match '^(?i:false|0|disabled)$') { return $false }
    return $null
}

function ConvertTo-HLInteger {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $null }
    $parsed = 0
    if ([int]::TryParse([string]$Value, [ref]$parsed)) {
        return $parsed
    }
    try {
        return [int]$Value
    }
    catch {
        return $null
    }
}
