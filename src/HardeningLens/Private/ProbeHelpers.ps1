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

function Get-HLErrorCodeChain {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Exception
    )

    $codes = New-Object System.Collections.Generic.List[int64]
    $current = $Exception
    $depth = 0
    while ($null -ne $current -and $depth -lt 8) {
        $codes.Add(([int64]$current.HResult) -band 4294967295)
        if ($current -is [System.ComponentModel.Win32Exception]) {
            $codes.Add([int64]$current.NativeErrorCode)
        }
        $current = $current.InnerException
        $depth++
    }
    return $codes.ToArray()
}

function Test-HLErrorMatchesCode {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Exception,

        [Parameter(Mandatory)]
        [int64[]]$Code
    )

    if ($null -eq $Exception) {
        return $false
    }

    $normalized = @($Code | ForEach-Object { ([int64]$_) -band 4294967295 })
    foreach ($observed in @(Get-HLErrorCodeChain -Exception $Exception)) {
        if ($observed -in $normalized) {
            return $true
        }
    }

    # Provider messages are localized, but embedded hexadecimal error codes
    # are not; use them as a locale-independent fallback signal.
    $message = [string]$Exception.Message
    foreach ($value in $normalized) {
        if ($value -gt 65535 -and $message -match ('(?i)0x{0:x8}' -f $value)) {
            return $true
        }
    }
    return $false
}
