function Invoke-HLLocalGuestAccountProbe {
    [CmdletBinding()]
    param()

    try {
        $accounts = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
        $guest = $accounts | Where-Object { [string]$_.SID -match '-501$' } | Select-Object -First 1
        if ($null -eq $guest) {
            return Get-HLProbeResult -Status Unknown -Expected 'Disabled' -Actual 'Built-in Guest account not located' -Message 'The RID 501 local account could not be located.'
        }

        $evidence = [pscustomobject][ordered]@{
            Name     = [string]$guest.Name
            SID      = [string]$guest.SID
            Disabled = [bool]$guest.Disabled
            Status   = [string]$guest.Status
        }
        if ([bool]$guest.Disabled) {
            return Get-HLProbeResult -Status Pass -Expected 'Disabled' -Actual 'Disabled' -Message 'The built-in Guest account is disabled.' -Evidence $evidence
        }
        return Get-HLProbeResult -Status Fail -Expected 'Disabled' -Actual 'Enabled' -Message 'The built-in Guest account is enabled.' -Evidence $evidence
    }
    catch {
        return Get-HLProbeResult -Status Error -Expected 'Disabled' -Actual $null -Message "Unable to query local accounts: $($_.Exception.Message)"
    }
}

function Invoke-HLCredentialGuardProbe {
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

        if (1 -in $running) {
            return Get-HLProbeResult -Status Pass -Expected 'Credential Guard running' -Actual 'Running' -Message 'Credential Guard is reported as running.' -Evidence $evidence
        }
        if (1 -in $configured) {
            return Get-HLProbeResult -Status Fail -Expected 'Credential Guard running' -Actual 'Configured but not running' -Message 'Credential Guard is configured but the security service is not running.' -Evidence $evidence
        }
        return Get-HLProbeResult -Status Fail -Expected 'Credential Guard running' -Actual 'Not configured' -Message 'Credential Guard is not configured or running.' -Evidence $evidence
    }
    catch {
        return Get-HLProbeResult -Status Unknown -Expected 'Credential Guard running' -Actual $null -Message "Unable to query the Device Guard provider: $($_.Exception.Message)"
    }
}

function Invoke-HLDeviceGuardServiceProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [AllowNull()]
        [object]$CollectionContext
    )

    $serviceId = [int]$Control.parameters.serviceId
    $serviceName = [string]$Control.parameters.serviceName
    $expected = "$serviceName running"
    try {
        $deviceGuard = Get-HLProviderSnapshot -CollectionContext $CollectionContext -Name 'DeviceGuard' -Factory {
            Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        }
        $configured = @($deviceGuard.SecurityServicesConfigured | ForEach-Object { [int]$_ })
        $running = @($deviceGuard.SecurityServicesRunning | ForEach-Object { [int]$_ })
        $evidence = [pscustomobject][ordered]@{
            ServiceId                         = $serviceId
            VirtualizationBasedSecurityStatus = [int]$deviceGuard.VirtualizationBasedSecurityStatus
            SecurityServicesConfigured        = $configured
            SecurityServicesRunning           = $running
        }

        if ($serviceId -in $running) {
            return Get-HLProbeResult -Status Pass -Expected $expected -Actual 'Running' -Message "$serviceName is reported as running." -Evidence $evidence
        }
        if ($serviceId -in $configured) {
            return Get-HLProbeResult -Status Fail -Expected $expected -Actual 'Configured but not running' -Message "$serviceName is configured but the security service is not running." -Evidence $evidence
        }
        return Get-HLProbeResult -Status Fail -Expected $expected -Actual 'Not configured' -Message "$serviceName is not configured or running." -Evidence $evidence
    }
    catch {
        return Get-HLProbeResult -Status Unknown -Expected $expected -Actual $null -Message "Unable to query the Device Guard provider: $($_.Exception.Message)"
    }
}

function Invoke-HLFirewallProfilesProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [AllowNull()]
        [object]$CollectionContext
    )

    if ($null -eq (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        return Get-HLProbeResult -Status Unknown -Expected 'Windows Firewall profile configuration' -Actual $null -Message 'Get-NetFirewallProfile is not available.'
    }

    try {
        $profiles = @(Get-HLProviderSnapshot -CollectionContext $CollectionContext -Name 'FirewallProfiles' -Factory {
            @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { [string]$_.Name -in @('Domain', 'Private', 'Public') })
        })
        if ($profiles.Count -lt 3) {
            return Get-HLProbeResult -Status Unknown -Expected 'Domain, Private, and Public profiles' -Actual (@($profiles.Name) -join ', ') -Message 'Not every expected firewall profile was returned.' -Evidence $profiles
        }

        $evidence = @($profiles | ForEach-Object {
            [pscustomobject][ordered]@{
                Name                  = [string]$_.Name
                Enabled               = [string]$_.Enabled
                DefaultInboundAction  = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
            }
        })
        $disabled = @($evidence | Where-Object { (ConvertTo-HLBoolean -Value $_.Enabled) -ne $true })
        $notBlocking = @($evidence | Where-Object { [string]$_.DefaultInboundAction -notmatch '^(?i:Block)$' })
        $requireInboundBlock = (Test-HLProperty -InputObject $Control.parameters -Name 'requireDefaultInboundBlock') -and [bool]$Control.parameters.requireDefaultInboundBlock

        if ($disabled.Count -gt 0) {
            return Get-HLProbeResult -Status Fail -Expected 'All firewall profiles enabled' -Actual ('Disabled or unresolved: {0}' -f (@($disabled.Name) -join ', ')) -Message 'One or more Windows Firewall profiles are disabled.' -Evidence $evidence
        }
        if ($requireInboundBlock -and $notBlocking.Count -gt 0) {
            return Get-HLProbeResult -Status Fail -Expected 'Default inbound action Block for all profiles' -Actual ('Not blocking: {0}' -f (@($notBlocking.Name) -join ', ')) -Message 'One or more firewall profiles do not use a default inbound Block action.' -Evidence $evidence
        }

        $expected = if ($requireInboundBlock) { 'Enabled with default inbound Block' } else { 'Enabled' }
        return Get-HLProbeResult -Status Pass -Expected $expected -Actual 'All profiles compliant' -Message 'Every firewall profile matches the baseline.' -Evidence $evidence
    }
    catch {
        return Get-HLProbeResult -Status Error -Expected 'Windows Firewall profile configuration' -Actual $null -Message "Unable to query Windows Firewall profiles: $($_.Exception.Message)"
    }
}

function Invoke-HLWindowsOptionalFeatureProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    if ($null -eq (Get-Command -Name Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
        return Get-HLProbeResult -Status Unknown -Expected 'Optional feature state' -Actual $null -Message 'Get-WindowsOptionalFeature is not available.'
    }

    $evaluationMode = if (Test-HLProperty -InputObject $Control.parameters -Name 'evaluationMode') { [string]$Control.parameters.evaluationMode } else { 'AllDisabled' }
    $evidence = New-Object System.Collections.Generic.List[object]
    $queryErrors = New-Object System.Collections.Generic.List[string]

    foreach ($featureName in @($Control.parameters.features)) {
        try {
            $feature = @(Get-WindowsOptionalFeature -Online -FeatureName ([string]$featureName) -ErrorAction Stop | Where-Object { $null -ne $_ })
            if ($feature.Count -eq 0) {
                # Windows 11 24H2 removes retired features such as PowerShell 2.0
                # entirely; the query then returns nothing instead of failing.
                $evidence.Add([pscustomobject][ordered]@{
                    FeatureName = [string]$featureName
                    Present     = $false
                    State       = 'NotPresent'
                    Error       = $null
                    Evaluated   = $false
                })
                continue
            }
            $evidence.Add([pscustomobject][ordered]@{
                FeatureName = [string]$featureName
                Present     = $true
                State       = [string]$feature[0].State
                Error       = $null
                Evaluated   = $false
            })
        }
        catch {
            $message = [string]$_.Exception.Message
            # 0x800F080C (unknown feature name) is matched through the error
            # code chain because DISM messages are localized.
            $notPresent = (Test-HLErrorMatchesCode -Exception $_.Exception -Code 0x800f080c) -or
                $message -match '(?i:feature name.+unknown|not recognized|does not exist|cannot find|could not be found)'
            if ($notPresent) {
                $evidence.Add([pscustomobject][ordered]@{
                    FeatureName = [string]$featureName
                    Present     = $false
                    State       = 'NotPresent'
                    Error       = $null
                    Evaluated   = $false
                })
            }
            else {
                $queryErrors.Add(('{0}: {1}' -f [string]$featureName, $message))
                $evidence.Add([pscustomobject][ordered]@{
                    FeatureName = [string]$featureName
                    Present     = $null
                    State       = 'QueryError'
                    Error       = $message
                    Evaluated   = $false
                })
            }
        }
    }

    if ($queryErrors.Count -gt 0) {
        return Get-HLProbeResult -Status Error -Expected 'Disabled or absent' -Actual 'Optional feature state could not be resolved' -Message ('Unable to query one or more optional features: {0}' -f ($queryErrors.ToArray() -join ' | ')) -Evidence $evidence.ToArray()
    }

    $present = @($evidence | Where-Object { $_.Present -eq $true })
    if ($present.Count -eq 0) {
        return Get-HLProbeResult -Status Pass -Expected 'Disabled or absent' -Actual 'Feature not present' -Message 'None of the configured feature names are present on this operating system.' -Evidence $evidence.ToArray()
    }

    $evaluated = if ($evaluationMode -eq 'FirstPresent') { @($present | Select-Object -First 1) } else { $present }
    foreach ($item in $evaluated) { $item.Evaluated = $true }
    $unsafe = @($evaluated | Where-Object { [string]$_.State -in @('Enabled', 'EnablePending') })
    $pending = @($evaluated | Where-Object { [string]$_.State -eq 'DisablePending' })
    $unexpected = @($evaluated | Where-Object { [string]$_.State -notin @('Disabled', 'DisabledWithPayloadRemoved', 'DisablePending', 'Enabled', 'EnablePending') })

    if ($unsafe.Count -gt 0) {
        return Get-HLProbeResult -Status Fail -Expected 'Disabled or absent' -Actual ((@($unsafe | ForEach-Object { "$($_.FeatureName)=$($_.State)" })) -join '; ') -Message 'At least one evaluated optional feature is enabled or pending enablement.' -Evidence $evidence.ToArray()
    }
    if ($pending.Count -gt 0) {
        return Get-HLProbeResult -Status Warning -Expected 'Disabled' -Actual 'Disable pending' -Message 'The evaluated feature is pending disablement; complete the required restart.' -Evidence $evidence.ToArray()
    }
    if ($unexpected.Count -gt 0) {
        return Get-HLProbeResult -Status Unknown -Expected 'Disabled or absent' -Actual ((@($unexpected | ForEach-Object { "$($_.FeatureName)=$($_.State)" })) -join '; ') -Message 'An optional feature returned an unrecognized state.' -Evidence $evidence.ToArray()
    }

    return Get-HLProbeResult -Status Pass -Expected 'Disabled or absent' -Actual 'Disabled' -Message 'Every evaluated optional feature is disabled.' -Evidence $evidence.ToArray()
}
