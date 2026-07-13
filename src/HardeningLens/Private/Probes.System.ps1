function Invoke-HLLocalGuestAccountProbe {
    [CmdletBinding()]
    param()

    try {
        $accounts = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
        $guest = $accounts | Where-Object { [string]$_.SID -match '-501$' } | Select-Object -First 1
        if ($null -eq $guest) {
            return New-HLProbeResult -Status Unknown -Expected 'Disabled' -Actual 'Built-in Guest account not located' -Message 'The RID 501 local account could not be located.'
        }

        $evidence = [pscustomobject][ordered]@{
            Name     = [string]$guest.Name
            SID      = [string]$guest.SID
            Disabled = [bool]$guest.Disabled
            Status   = [string]$guest.Status
        }
        if ([bool]$guest.Disabled) {
            return New-HLProbeResult -Status Pass -Expected 'Disabled' -Actual 'Disabled' -Message 'The built-in Guest account is disabled.' -Evidence $evidence
        }
        return New-HLProbeResult -Status Fail -Expected 'Disabled' -Actual 'Enabled' -Message 'The built-in Guest account is enabled.' -Evidence $evidence
    }
    catch {
        return New-HLProbeResult -Status Error -Expected 'Disabled' -Actual $null -Message "Unable to query local accounts: $($_.Exception.Message)"
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
            return New-HLProbeResult -Status Pass -Expected 'Credential Guard running' -Actual 'Running' -Message 'Credential Guard is reported as running.' -Evidence $evidence
        }
        if (1 -in $configured) {
            return New-HLProbeResult -Status Fail -Expected 'Credential Guard running' -Actual 'Configured but not running' -Message 'Credential Guard is configured but the security service is not running.' -Evidence $evidence
        }
        return New-HLProbeResult -Status Fail -Expected 'Credential Guard running' -Actual 'Not configured' -Message 'Credential Guard is not configured or running.' -Evidence $evidence
    }
    catch {
        return New-HLProbeResult -Status Unknown -Expected 'Credential Guard running' -Actual $null -Message "Unable to query the Device Guard provider: $($_.Exception.Message)"
    }
}

function Invoke-HLFirewallProfilesProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    if ($null -eq (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        return New-HLProbeResult -Status Unknown -Expected 'Windows Firewall profile configuration' -Actual $null -Message 'Get-NetFirewallProfile is not available.'
    }

    try {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { [string]$_.Name -in @('Domain', 'Private', 'Public') })
        if ($profiles.Count -lt 3) {
            return New-HLProbeResult -Status Unknown -Expected 'Domain, Private, and Public profiles' -Actual (@($profiles.Name) -join ', ') -Message 'Not every expected firewall profile was returned.' -Evidence $profiles
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
            return New-HLProbeResult -Status Fail -Expected 'All firewall profiles enabled' -Actual ('Disabled or unresolved: {0}' -f (@($disabled.Name) -join ', ')) -Message 'One or more Windows Firewall profiles are disabled.' -Evidence $evidence
        }
        if ($requireInboundBlock -and $notBlocking.Count -gt 0) {
            return New-HLProbeResult -Status Fail -Expected 'Default inbound action Block for all profiles' -Actual ('Not blocking: {0}' -f (@($notBlocking.Name) -join ', ')) -Message 'One or more firewall profiles do not use a default inbound Block action.' -Evidence $evidence
        }

        $expected = if ($requireInboundBlock) { 'Enabled with default inbound Block' } else { 'Enabled' }
        return New-HLProbeResult -Status Pass -Expected $expected -Actual 'All profiles compliant' -Message 'Every firewall profile matches the baseline.' -Evidence $evidence
    }
    catch {
        return New-HLProbeResult -Status Error -Expected 'Windows Firewall profile configuration' -Actual $null -Message "Unable to query Windows Firewall profiles: $($_.Exception.Message)"
    }
}

function Invoke-HLWindowsOptionalFeatureProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    if ($null -eq (Get-Command -Name Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
        return New-HLProbeResult -Status Unknown -Expected 'Optional feature state' -Actual $null -Message 'Get-WindowsOptionalFeature is not available.'
    }

    $evaluationMode = if (Test-HLProperty -InputObject $Control.parameters -Name 'evaluationMode') { [string]$Control.parameters.evaluationMode } else { 'AllDisabled' }
    $evidence = New-Object System.Collections.Generic.List[object]
    $queryErrors = New-Object System.Collections.Generic.List[string]

    foreach ($featureName in @($Control.parameters.features)) {
        try {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName ([string]$featureName) -ErrorAction Stop
            $evidence.Add([pscustomobject][ordered]@{
                FeatureName = [string]$featureName
                Present     = $true
                State       = [string]$feature.State
                Error       = $null
                Evaluated   = $false
            })
        }
        catch {
            $message = [string]$_.Exception.Message
            $notPresent = $message -match '(?i:0x800f080c|feature name.+unknown|not recognized|does not exist|cannot find|could not be found)'
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
        return New-HLProbeResult -Status Error -Expected 'Disabled or absent' -Actual 'Optional feature state could not be resolved' -Message ('Unable to query one or more optional features: {0}' -f (@($queryErrors) -join ' | ')) -Evidence @($evidence)
    }

    $present = @($evidence | Where-Object { $_.Present -eq $true })
    if ($present.Count -eq 0) {
        return New-HLProbeResult -Status Pass -Expected 'Disabled or absent' -Actual 'Feature not present' -Message 'None of the configured feature names are present on this operating system.' -Evidence @($evidence)
    }

    $evaluated = if ($evaluationMode -eq 'FirstPresent') { @($present | Select-Object -First 1) } else { $present }
    foreach ($item in $evaluated) { $item.Evaluated = $true }
    $unsafe = @($evaluated | Where-Object { [string]$_.State -in @('Enabled', 'EnablePending') })
    $pending = @($evaluated | Where-Object { [string]$_.State -eq 'DisablePending' })
    $unexpected = @($evaluated | Where-Object { [string]$_.State -notin @('Disabled', 'DisabledWithPayloadRemoved', 'DisablePending', 'Enabled', 'EnablePending') })

    if ($unsafe.Count -gt 0) {
        return New-HLProbeResult -Status Fail -Expected 'Disabled or absent' -Actual ((@($unsafe | ForEach-Object { "$($_.FeatureName)=$($_.State)" })) -join '; ') -Message 'At least one evaluated optional feature is enabled or pending enablement.' -Evidence @($evidence)
    }
    if ($pending.Count -gt 0) {
        return New-HLProbeResult -Status Warning -Expected 'Disabled' -Actual 'Disable pending' -Message 'The evaluated feature is pending disablement; complete the required restart.' -Evidence @($evidence)
    }
    if ($unexpected.Count -gt 0) {
        return New-HLProbeResult -Status Unknown -Expected 'Disabled or absent' -Actual ((@($unexpected | ForEach-Object { "$($_.FeatureName)=$($_.State)" })) -join '; ') -Message 'An optional feature returned an unrecognized state.' -Evidence @($evidence)
    }

    return New-HLProbeResult -Status Pass -Expected 'Disabled or absent' -Actual 'Disabled' -Message 'Every evaluated optional feature is disabled.' -Evidence @($evidence)
}
