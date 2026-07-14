function Get-HLRegistrySecurityValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            return [pscustomobject][ordered]@{ Resolved = $false; Present = $false; Value = $null; Path = $Path; Name = $Name; Error = $null }
        }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return [pscustomobject][ordered]@{ Resolved = $true; Present = $true; Value = $item.$Name; Path = $Path; Name = $Name; Error = $null }
    }
    catch [System.Management.Automation.PSArgumentException] {
        return [pscustomobject][ordered]@{ Resolved = $false; Present = $false; Value = $null; Path = $Path; Name = $Name; Error = $null }
    }
    catch {
        return [pscustomobject][ordered]@{ Resolved = $false; Present = $null; Value = $null; Path = $Path; Name = $Name; Error = $_.Exception.Message }
    }
}

function Invoke-HLRegistrySecurityValueProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Control)

    $parameters = $Control.parameters
    $evidence = Get-HLRegistrySecurityValue -Path ([string]$parameters.path) -Name ([string]$parameters.name)
    $missingStatus = if ($null -ne $parameters.missingStatus) { [string]$parameters.missingStatus } else { 'Unknown' }

    if ($null -ne $evidence.Error) {
        return Get-HLProbeResult -Status Error -Expected $parameters.expected -Actual $null -Message "Unable to read the security policy value: $($evidence.Error)" -Evidence $evidence
    }
    if (-not $evidence.Present) {
        return Get-HLProbeResult -Status $missingStatus -Expected $parameters.expected -Actual 'Not configured' -Message 'The policy value is not explicitly configured.' -Evidence $evidence
    }

    return Get-HLValueProbeResult -Actual $evidence.Value -Expected $parameters.expected -Operator ([string]$parameters.operator) -Evidence $evidence
}

function Invoke-HLTlsProtocolProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Control)

    $protocol = [string]$Control.parameters.protocol
    $side = if ($null -ne $Control.parameters.side) { [string]$Control.parameters.side } else { 'Server' }
    $expected = [string]$Control.parameters.expected
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\$side"
    $enabled = Get-HLRegistrySecurityValue -Path $path -Name 'Enabled'
    $disabledByDefault = Get-HLRegistrySecurityValue -Path $path -Name 'DisabledByDefault'
    $evidence = [pscustomobject][ordered]@{
        Protocol          = $protocol
        Side              = $side
        Path              = $path
        Enabled           = $enabled.Value
        DisabledByDefault = $disabledByDefault.Value
        Explicit          = [bool]($enabled.Present -and $disabledByDefault.Present)
    }

    if ($null -ne $enabled.Error -or $null -ne $disabledByDefault.Error) {
        return Get-HLProbeResult -Status Error -Expected $expected -Actual $null -Message 'The Schannel protocol state could not be collected.' -Evidence $evidence
    }
    if (-not $evidence.Explicit) {
        return Get-HLProbeResult -Status Unknown -Expected $expected -Actual 'Operating-system default' -Message 'The protocol is not explicitly configured; the effective default depends on the Windows release and patch level.' -Evidence $evidence
    }

    $isEnabled = ([int]$enabled.Value -ne 0) -and ([int]$disabledByDefault.Value -eq 0)
    if ($expected -eq 'Disabled') {
        if (-not $isEnabled -and [int]$enabled.Value -eq 0 -and [int]$disabledByDefault.Value -eq 1) {
            return Get-HLProbeResult -Status Pass -Expected 'Disabled' -Actual 'Disabled explicitly' -Message "$protocol $side is explicitly disabled." -Evidence $evidence
        }
        return Get-HLProbeResult -Status Fail -Expected 'Disabled' -Actual 'Enabled or incompletely disabled' -Message "$protocol $side is not disabled with an explicit secure configuration." -Evidence $evidence
    }

    if ($isEnabled) {
        return Get-HLProbeResult -Status Pass -Expected 'Enabled' -Actual 'Enabled explicitly' -Message "$protocol $side is explicitly enabled." -Evidence $evidence
    }
    return Get-HLProbeResult -Status Fail -Expected 'Enabled' -Actual 'Disabled or incompletely enabled' -Message "$protocol $side is not explicitly enabled." -Evidence $evidence
}

function Invoke-HLNetBiosProbe {
    [CmdletBinding()]
    param()

    try {
        $adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)
        if ($adapters.Count -eq 0) {
            return Get-HLProbeResult -Status Unknown -Expected 'Disabled on every active IP adapter' -Actual 'No active IP adapters returned' -Message 'NetBIOS posture could not be evaluated because no active IP adapters were returned.'
        }
        $evidence = @($adapters | ForEach-Object {
            [pscustomobject][ordered]@{
                Description          = [string]$_.Description
                SettingID            = [string]$_.SettingID
                TcpipNetbiosOptions  = [int]$_.TcpipNetbiosOptions
                State                = switch ([int]$_.TcpipNetbiosOptions) { 2 { 'Disabled' } 1 { 'Enabled' } default { 'DHCP or default' } }
            }
        })
        $enabled = @($evidence | Where-Object TcpipNetbiosOptions -eq 1)
        $defaulted = @($evidence | Where-Object TcpipNetbiosOptions -eq 0)
        if ($enabled.Count -gt 0) {
            return Get-HLProbeResult -Status Fail -Expected 'Disabled on every active IP adapter' -Actual ("Enabled on {0} adapter(s)" -f $enabled.Count) -Message 'NetBIOS over TCP/IP is explicitly enabled on one or more active adapters.' -Evidence $evidence
        }
        if ($defaulted.Count -gt 0) {
            return Get-HLProbeResult -Status Warning -Expected 'Disabled on every active IP adapter' -Actual ("DHCP/default on {0} adapter(s)" -f $defaulted.Count) -Message 'One or more active adapters inherit their NetBIOS state from DHCP or the operating-system default.' -Evidence $evidence
        }
        return Get-HLProbeResult -Status Pass -Expected 'Disabled on every active IP adapter' -Actual 'Disabled on all active adapters' -Message 'NetBIOS over TCP/IP is explicitly disabled on every active adapter.' -Evidence $evidence
    }
    catch {
        return Get-HLProbeResult -Status Error -Expected 'Disabled on every active IP adapter' -Actual $null -Message "Unable to query active network adapters: $($_.Exception.Message)"
    }
}

function Invoke-HLFirewallLoggingProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Control)

    if ($null -eq (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        return Get-HLProbeResult -Status Unknown -Expected 'Enabled for Domain, Private, and Public profiles' -Actual $null -Message 'Get-NetFirewallProfile is not available.'
    }
    $property = [string]$Control.parameters.property
    try {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Where-Object Name -in @('Domain', 'Private', 'Public'))
        $evidence = @($profiles | ForEach-Object {
            [pscustomobject][ordered]@{ Name = [string]$_.Name; Property = $property; Value = $_.$property; LogFileName = [string]$_.LogFileName; LogMaxSizeKilobytes = [int]$_.LogMaxSizeKilobytes }
        })
        $nonCompliant = @($evidence | Where-Object { (ConvertTo-HLBoolean -Value $_.Value) -ne $true })
        if ($profiles.Count -lt 3) {
            return Get-HLProbeResult -Status Unknown -Expected 'Enabled for Domain, Private, and Public profiles' -Actual 'Not every firewall profile was returned' -Message 'The active firewall policy store did not return all expected profiles.' -Evidence $evidence
        }
        if ($nonCompliant.Count -gt 0) {
            return Get-HLProbeResult -Status Fail -Expected 'Enabled for Domain, Private, and Public profiles' -Actual ("Disabled or unresolved: {0}" -f (@($nonCompliant.Name) -join ', ')) -Message "$property is not enabled for every firewall profile." -Evidence $evidence
        }
        return Get-HLProbeResult -Status Pass -Expected 'Enabled for Domain, Private, and Public profiles' -Actual 'Enabled on all profiles' -Message "$property is enabled for every firewall profile." -Evidence $evidence
    }
    catch {
        return Get-HLProbeResult -Status Error -Expected 'Enabled for Domain, Private, and Public profiles' -Actual $null -Message "Unable to query firewall logging: $($_.Exception.Message)"
    }
}

function Invoke-HLAlwaysInstallElevatedProbe {
    [CmdletBinding()]
    param()

    $locations = New-Object System.Collections.Generic.List[object]
    $machine = Get-HLRegistrySecurityValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    $locations.Add([pscustomobject][ordered]@{ Scope = 'LocalMachine'; Path = $machine.Path; Present = $machine.Present; Value = $machine.Value; Error = $machine.Error })

    try {
        $userHives = @(Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction Stop | Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' })
        foreach ($hive in $userHives) {
            $path = "Registry::HKEY_USERS\$($hive.PSChildName)\SOFTWARE\Policies\Microsoft\Windows\Installer"
            $value = Get-HLRegistrySecurityValue -Path $path -Name 'AlwaysInstallElevated'
            $locations.Add([pscustomobject][ordered]@{ Scope = $hive.PSChildName; Path = $path; Present = $value.Present; Value = $value.Value; Error = $value.Error })
        }
    }
    catch {
        $locations.Add([pscustomobject][ordered]@{ Scope = 'LoadedUserHives'; Path = 'Registry::HKEY_USERS'; Present = $null; Value = $null; Error = $_.Exception.Message })
    }

    $errors = @($locations | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Error) })
    $enabled = @($locations | Where-Object { $_.Present -eq $true -and [int]$_.Value -eq 1 })
    if ($enabled.Count -gt 0) {
        return Get-HLProbeResult -Status Fail -Expected 'Disabled in machine policy and every loaded user policy' -Actual ("Enabled in {0} scope(s)" -f $enabled.Count) -Message 'AlwaysInstallElevated is enabled and can allow elevated MSI installation.' -Evidence $locations.ToArray()
    }
    if ($errors.Count -gt 0) {
        return Get-HLProbeResult -Status Warning -Expected 'Disabled in machine policy and every loaded user policy' -Actual 'No enabled value found; one or more scopes were not readable' -Message 'AlwaysInstallElevated was not detected, but every loaded user scope could not be verified.' -Evidence $locations.ToArray()
    }
    return Get-HLProbeResult -Status Pass -Expected 'Disabled in machine policy and every loaded user policy' -Actual 'Disabled or not configured' -Message 'AlwaysInstallElevated is not enabled in machine policy or any loaded user policy.' -Evidence $locations.ToArray()
}

function Invoke-HLServiceStateProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Control,
        [Parameter(Mandatory)][object]$SystemContext
    )

    if ($null -ne $Control.parameters.onlyRole -and [string]$SystemContext.DetectedRole -ne [string]$Control.parameters.onlyRole) {
        return Get-HLProbeResult -Status NotApplicable -Expected $Control.parameters.expected -Actual ([string]$SystemContext.DetectedRole) -Message "The control applies only to $($Control.parameters.onlyRole)."
    }
    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f [string]$Control.parameters.name) -ErrorAction Stop
        if ($null -eq $service) {
            return Get-HLProbeResult -Status NotApplicable -Expected $Control.parameters.expected -Actual 'Service not installed' -Message 'The service is not installed on this system.'
        }
        $evidence = [pscustomobject][ordered]@{ Name = [string]$service.Name; State = [string]$service.State; StartMode = [string]$service.StartMode }
        $expected = [string]$Control.parameters.expected
        if ($expected -eq 'Disabled' -and [string]$service.StartMode -eq 'Disabled' -and [string]$service.State -ne 'Running') {
            return Get-HLProbeResult -Status Pass -Expected 'Disabled and not running' -Actual "$($service.StartMode) / $($service.State)" -Message 'The service is disabled and not running.' -Evidence $evidence
        }
        return Get-HLProbeResult -Status Fail -Expected 'Disabled and not running' -Actual "$($service.StartMode) / $($service.State)" -Message 'The service is available to start or is currently running.' -Evidence $evidence
    }
    catch {
        return Get-HLProbeResult -Status Error -Expected $Control.parameters.expected -Actual $null -Message "Unable to query the service: $($_.Exception.Message)"
    }
}

function Invoke-HLHVCIProbe {
    [CmdletBinding()]
    param()

    try {
        $deviceGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $configured = @($deviceGuard.SecurityServicesConfigured | ForEach-Object { [int]$_ })
        $running = @($deviceGuard.SecurityServicesRunning | ForEach-Object { [int]$_ })
        $evidence = [pscustomobject][ordered]@{
            VirtualizationBasedSecurityStatus = [int]$deviceGuard.VirtualizationBasedSecurityStatus
            SecurityServicesConfigured        = $configured
            SecurityServicesRunning           = $running
        }
        if (2 -in $running) {
            return Get-HLProbeResult -Status Pass -Expected 'Memory Integrity running' -Actual 'Running' -Message 'Hypervisor-protected code integrity is reported as running.' -Evidence $evidence
        }
        if (2 -in $configured) {
            return Get-HLProbeResult -Status Fail -Expected 'Memory Integrity running' -Actual 'Configured but not running' -Message 'Memory Integrity is configured but the security service is not running.' -Evidence $evidence
        }
        return Get-HLProbeResult -Status Fail -Expected 'Memory Integrity running' -Actual 'Not configured' -Message 'Memory Integrity is not configured or running.' -Evidence $evidence
    }
    catch {
        return Get-HLProbeResult -Status Unknown -Expected 'Memory Integrity running' -Actual $null -Message "Unable to query the Device Guard provider: $($_.Exception.Message)"
    }
}

function Invoke-HLDefenderExclusionProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Control)

    if ($null -eq (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        return Get-HLProbeResult -Status Unknown -Expected 'No unapproved Microsoft Defender exclusions' -Actual $null -Message 'Get-MpPreference is not available.'
    }
    try {
        $preference = Get-MpPreference -ErrorAction Stop
        $entries = New-Object System.Collections.Generic.List[object]
        foreach ($definition in @(
            @{ Type = 'Path'; Property = 'ExclusionPath' },
            @{ Type = 'Process'; Property = 'ExclusionProcess' },
            @{ Type = 'Extension'; Property = 'ExclusionExtension' },
            @{ Type = 'IPAddress'; Property = 'ExclusionIpAddress' }
        )) {
            foreach ($value in @($preference.($definition.Property) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
                $entries.Add([pscustomobject][ordered]@{ Type = $definition.Type; Value = [string]$value })
            }
        }
        $allowedPatterns = @($Control.parameters.allowedPatterns)
        $unapproved = @($entries | Where-Object {
            $entry = $_
            -not ($allowedPatterns | Where-Object { $entry.Value -like [string]$_ } | Select-Object -First 1)
        })
        if ($unapproved.Count -gt 0) {
            return Get-HLProbeResult -Status Fail -Expected 'No unapproved Microsoft Defender exclusions' -Actual ("{0} unapproved exclusion(s)" -f $unapproved.Count) -Message 'One or more Defender exclusions are outside the approved allowlist.' -Evidence $entries.ToArray()
        }
        if ($entries.Count -gt 0) {
            return Get-HLProbeResult -Status Pass -Expected 'Only approved Microsoft Defender exclusions' -Actual ("{0} approved exclusion(s)" -f $entries.Count) -Message 'Every Defender exclusion matches the configured allowlist.' -Evidence $entries.ToArray()
        }
        return Get-HLProbeResult -Status Pass -Expected 'No unapproved Microsoft Defender exclusions' -Actual 'No exclusions configured' -Message 'No Microsoft Defender exclusions are configured.' -Evidence @()
    }
    catch {
        return Get-HLProbeResult -Status Error -Expected 'No unapproved Microsoft Defender exclusions' -Actual $null -Message "Unable to query Defender exclusions: $($_.Exception.Message)"
    }
}

function Invoke-HLRdsPolicyProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Control)

    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $name = [string]$Control.parameters.name
    $value = Get-HLRegistrySecurityValue -Path $path -Name $name
    $missingStatus = if ($null -ne $Control.parameters.missingStatus) { [string]$Control.parameters.missingStatus } else { 'Unknown' }
    if ($null -ne $value.Error) {
        return Get-HLProbeResult -Status Error -Expected $Control.parameters.expected -Actual $null -Message "Unable to query the Remote Desktop Services policy: $($value.Error)" -Evidence $value
    }
    if (-not $value.Present) {
        return Get-HLProbeResult -Status $missingStatus -Expected $Control.parameters.expected -Actual 'Not configured' -Message 'The Remote Desktop Services policy is not explicitly configured.' -Evidence $value
    }
    return Get-HLValueProbeResult -Actual $value.Value -Expected $Control.parameters.expected -Operator ([string]$Control.parameters.operator) -Evidence $value
}
