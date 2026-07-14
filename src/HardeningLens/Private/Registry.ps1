function ConvertFrom-HLRegistryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($Path -match '^(?i)HKLM:\\(.+)$') {
        return [pscustomobject]@{ Hive = 'LocalMachine'; SubKey = $Matches[1] }
    }
    if ($Path -match '^(?i)HKEY_LOCAL_MACHINE\\(.+)$') {
        return [pscustomobject]@{ Hive = 'LocalMachine'; SubKey = $Matches[1] }
    }
    if ($Path -match '^(?i)HKCU:\\(.+)$') {
        return [pscustomobject]@{ Hive = 'CurrentUser'; SubKey = $Matches[1] }
    }
    if ($Path -match '^(?i)HKEY_CURRENT_USER\\(.+)$') {
        return [pscustomobject]@{ Hive = 'CurrentUser'; SubKey = $Matches[1] }
    }

    throw "Unsupported registry path '$Path'. Use HKLM:\\ or HKCU:\\."
}

function Get-HLRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    Assert-HLWindows
    $parsed = ConvertFrom-HLRegistryPath -Path $Path
    $hive = if ($parsed.Hive -eq 'LocalMachine') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
    $view = if ([Environment]::Is64BitOperatingSystem) { [Microsoft.Win32.RegistryView]::Registry64 } else { [Microsoft.Win32.RegistryView]::Default }
    $baseKey = $null
    $key = $null

    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
        $key = $baseKey.OpenSubKey([string]$parsed.SubKey, $false)
        if ($null -eq $key) {
            return [pscustomobject][ordered]@{ KeyExists = $false; ValueExists = $false; Value = $null; Kind = $null; Path = $Path; Name = $Name }
        }

        $valueNames = @($key.GetValueNames())
        $valueExists = $Name -in $valueNames
        if (-not $valueExists) {
            return [pscustomobject][ordered]@{ KeyExists = $true; ValueExists = $false; Value = $null; Kind = $null; Path = $Path; Name = $Name }
        }

        return [pscustomobject][ordered]@{
            KeyExists   = $true
            ValueExists = $true
            Value       = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            Kind        = $key.GetValueKind($Name).ToString()
            Path        = $Path
            Name        = $Name
        }
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
}

function Get-HLRegistryKeyValueMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Assert-HLWindows
    $parsed = ConvertFrom-HLRegistryPath -Path $Path
    $hive = if ($parsed.Hive -eq 'LocalMachine') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
    $view = if ([Environment]::Is64BitOperatingSystem) { [Microsoft.Win32.RegistryView]::Registry64 } else { [Microsoft.Win32.RegistryView]::Default }
    $baseKey = $null
    $key = $null

    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
        $key = $baseKey.OpenSubKey([string]$parsed.SubKey, $false)
        if ($null -eq $key) {
            return $null
        }

        $values = [ordered]@{}
        foreach ($name in @($key.GetValueNames())) {
            $values[$name] = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
        return [pscustomobject]$values
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
}

function Invoke-HLRegistryValueProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [Parameter(Mandatory)]
        [object]$SystemContext,

        [AllowNull()]
        [object]$CollectionContext
    )

    $parameters = $Control.parameters
    $registryPath = [string]$parameters.path
    $registryName = [string]$parameters.name
    $providerName = 'RegistryValue:{0}:{1}' -f $registryPath, $registryName
    $registry = Get-HLProviderSnapshot -CollectionContext $CollectionContext -Name $providerName -Factory {
        Get-HLRegistryValue -Path $registryPath -Name $registryName
    }
    $expected = $parameters.expected
    $operator = if (Test-HLProperty -InputObject $parameters -Name 'operator') { [string]$parameters.operator } else { 'Equals' }

    if (-not $registry.ValueExists) {
        $missingIsPass = (Test-HLProperty -InputObject $parameters -Name 'missingIsPass') -and [bool]$parameters.missingIsPass
        if (-not $missingIsPass -and (Test-HLProperty -InputObject $parameters -Name 'missingIsPassOnBuildAtLeast')) {
            $build = 0
            [void][int]::TryParse([string]$SystemContext.BuildNumber, [ref]$build)
            if ($build -ge [int]$parameters.missingIsPassOnBuildAtLeast) {
                $missingIsPass = $true
            }
        }

        if ($missingIsPass) {
            return Get-HLProbeResult -Status Pass -Expected $expected -Actual '<not configured; secure operating-system default>' -Message 'The value is not explicitly configured and the secure operating-system default applies.' -Evidence $registry
        }
        return Get-HLProbeResult -Status Fail -Expected $expected -Actual '<not configured>' -Message "Registry value '$($parameters.name)' is not explicitly configured." -Evidence $registry
    }

    $warningValues = if (Test-HLProperty -InputObject $parameters -Name 'warningValues') { @($parameters.warningValues) } else { $null }
    return Get-HLValueProbeResult -Actual $registry.Value -Expected $expected -Operator $operator -WarningValues $warningValues -Evidence $registry
}
