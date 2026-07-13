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
                Name                 = [string]$_.Name
                Enabled              = [string]$_.Enabled
                DefaultInboundAction = [string]$_.DefaultInboundAction
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

function Invoke-HLSmbConfigurationProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [Parameter(Mandatory)]
        [ValidateSet('Server', 'Client')]
        [string]$Side
    )

    $commandName = if ($Side -eq 'Server') { 'Get-SmbServerConfiguration' } else { 'Get-SmbClientConfiguration' }
    if ($null -eq (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
        return New-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message "$commandName is not available."
    }

    try {
        $configuration = & $commandName -ErrorAction Stop
        $property = [string]$Control.parameters.property
        if (-not (Test-HLProperty -InputObject $configuration -Name $property)) {
            return New-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message "SMB $Side configuration does not expose '$property'."
        }
        $actual = $configuration.$property
        $evidence = [pscustomobject][ordered]@{ Side = $Side; Property = $property; Value = $actual }
        return New-HLValueProbeResult -Actual $actual -Expected $Control.parameters.expected -Operator Equals -Evidence $evidence
    }
    catch {
        return New-HLProbeResult -Status Error -Expected $Control.parameters.expected -Actual $null -Message "Unable to query SMB $Side configuration: $($_.Exception.Message)"
    }
}

function Get-HLWinRMValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Client', 'Service')]
        [string]$Target,

        [Parameter(Mandatory)]
        [ValidateSet('Basic', 'AllowUnencrypted')]
        [string]$Property
    )

    $wsmanPath = if ($Property -eq 'Basic') { "WSMan:\localhost\$Target\Auth\Basic" } else { "WSMan:\localhost\$Target\AllowUnencrypted" }
    try {
        $item = Get-Item -LiteralPath $wsmanPath -ErrorAction Stop
        $value = ConvertTo-HLBoolean -Value $item.Value
        if ($null -ne $value) {
            return [pscustomobject][ordered]@{ Resolved = $true; Value = $value; Source = $wsmanPath }
        }
    }
    catch {
        Write-Verbose "Unable to query $wsmanPath: $($_.Exception.Message)"
    }

    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\$Target"
    $registryName = if ($Property -eq 'Basic') { 'AllowBasic' } else { 'AllowUnencryptedTraffic' }
    try {
        $registry = Get-HLRegistryValue -Path $registryPath -Name $registryName
        if ($registry.ValueExists) {
            return [pscustomobject][ordered]@{ Resolved = $true; Value = [bool]([int]$registry.Value); Source = "$registryPath\$registryName" }
        }
    }
    catch {
        Write-Verbose "Unable to query WinRM policy registry: $($_.Exception.Message)"
    }

    return [pscustomobject][ordered]@{ Resolved = $false; Value = $null; Source = $null }
}

function Invoke-HLWinRMProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    $evidence = New-Object System.Collections.Generic.List[object]
    $unresolved = New-Object System.Collections.Generic.List[string]
    $nonCompliant = New-Object System.Collections.Generic.List[string]
    foreach ($target in @($Control.parameters.targets)) {
        $result = Get-HLWinRMValue -Target ([string]$target) -Property ([string]$Control.parameters.property)
        $evidence.Add([pscustomobject][ordered]@{ Target = [string]$target; Property = [string]$Control.parameters.property; Resolved = $result.Resolved; Value = $result.Value; Source = $result.Source })
        if (-not $result.Resolved) {
            $unresolved.Add([string]$target)
        }
        elseif ([bool]$result.Value -ne [bool]$Control.parameters.expected) {
            $nonCompliant.Add([string]$target)
        }
    }

    if ($nonCompliant.Count -gt 0) {
        return New-HLProbeResult -Status Fail -Expected $Control.parameters.expected -Actual ('Non-compliant: {0}' -f (@($nonCompliant) -join ', ')) -Message 'One or more WinRM client/service settings do not match the baseline.' -Evidence @($evidence)
    }
    if ($unresolved.Count -gt 0) {
        return New-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual ('Unresolved: {0}' -f (@($unresolved) -join ', ')) -Message 'The effective WinRM configuration could not be resolved for every target.' -Evidence @($evidence)
    }

    return New-HLProbeResult -Status Pass -Expected $Control.parameters.expected -Actual 'Compliant on Client and Service' -Message 'WinRM client and service settings match the baseline.' -Evidence @($evidence)
}

function Invoke-HLServiceProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    $name = [string]$Control.parameters.name
    try {
        $escaped = $name.Replace("'", "''")
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escaped'" -ErrorAction Stop
        if ($null -eq $service) {
            return New-HLProbeResult -Status Pass -Expected 'Disabled or absent' -Actual 'Service not installed' -Message "Service '$name' is not installed."
        }

        $evidence = [pscustomobject][ordered]@{ Name = [string]$service.Name; DisplayName = [string]$service.DisplayName; StartMode = [string]$service.StartMode; State = [string]$service.State }
        $startupOkay = [string]$service.StartMode -eq [string]$Control.parameters.startupType
        $stateOkay = -not [bool]$Control.parameters.requireStopped -or [string]$service.State -eq 'Stopped'
        if ($startupOkay -and $stateOkay) {
            return New-HLProbeResult -Status Pass -Expected 'Disabled and stopped' -Actual "$($service.StartMode), $($service.State)" -Message 'The service state matches the baseline.' -Evidence $evidence
        }
        return New-HLProbeResult -Status Fail -Expected 'Disabled and stopped' -Actual "$($service.StartMode), $($service.State)" -Message 'The service startup or runtime state does not match the baseline.' -Evidence $evidence
    }
    catch {
        return New-HLProbeResult -Status Error -Expected 'Disabled and stopped' -Actual $null -Message "Unable to query service '$name': $($_.Exception.Message)"
    }
}

function Invoke-HLDefenderStatusProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    if ($null -eq (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        return New-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message 'Get-MpComputerStatus is not available. Use an approved exception when another endpoint protection platform is authoritative.'
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $property = [string]$Control.parameters.property
        if (-not (Test-HLProperty -InputObject $status -Name $property)) {
            return New-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message "Defender status does not expose '$property'."
        }
        $actual = $status.$property
        $evidence = [pscustomobject][ordered]@{ Property = $property; Value = $actual; AntivirusEnabled = if (Test-HLProperty -InputObject $status -Name 'AntivirusEnabled') { $status.AntivirusEnabled } else { $null } }
        return New-HLValueProbeResult -Actual $actual -Expected $Control.parameters.expected -Operator ([string]$Control.parameters.operator) -Evidence $evidence
    }
    catch {
        return New-HLProbeResult -Status Error -Expected $Control.parameters.expected -Actual $null -Message "Unable to query Microsoft Defender status: $($_.Exception.Message)"
    }
}

function Invoke-HLDefenderPreferenceProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    if ($null -eq (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        return New-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message 'Get-MpPreference is not available. Use an approved exception when another endpoint protection platform is authoritative.'
    }

    try {
        $preference = Get-MpPreference -ErrorAction Stop
        $property = [string]$Control.parameters.property
        if (-not (Test-HLProperty -InputObject $preference -Name $property)) {
            return New-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message "Defender preference does not expose '$property'."
        }
        $actualRaw = $preference.$property
        $actualInt = ConvertTo-HLInteger -Value $actualRaw
        $actual = if ($null -ne $actualInt) { $actualInt } else { $actualRaw }
        $warningValues = if (Test-HLProperty -InputObject $Control.parameters -Name 'warningValues') { @($Control.parameters.warningValues) } else { $null }
        $evidence = [pscustomobject][ordered]@{ Property = $property; Value = $actual }
        return New-HLValueProbeResult -Actual $actual -Expected $Control.parameters.expected -Operator ([string]$Control.parameters.operator) -WarningValues $warningValues -Evidence $evidence
    }
    catch {
        return New-HLProbeResult -Status Error -Expected $Control.parameters.expected -Actual $null -Message "Unable to query Microsoft Defender preferences: $($_.Exception.Message)"
    }
}

function Invoke-HLDefenderSignatureAgeProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    if ($null -eq (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        return New-HLProbeResult -Status Unknown -Expected ('<= {0} days' -f [int]$Control.parameters.maximumAgeDays) -Actual $null -Message 'Get-MpComputerStatus is not available.'
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        if ($null -eq $status.AntivirusSignatureLastUpdated) {
            return New-HLProbeResult -Status Unknown -Expected ('<= {0} days' -f [int]$Control.parameters.maximumAgeDays) -Actual $null -Message 'Defender did not return a signature update timestamp.'
        }
        $updated = [datetime]$status.AntivirusSignatureLastUpdated
        $age = (Get-Date).ToUniversalTime() - $updated.ToUniversalTime()
        $ageDays = [math]::Round([double]$age.TotalDays, 2)
        $maximum = [int]$Control.parameters.maximumAgeDays
        $evidence = [pscustomobject][ordered]@{ LastUpdated = $updated.ToString('o'); AgeDays = $ageDays; Version = [string]$status.AntivirusSignatureVersion }
        if ($ageDays -le $maximum) {
            return New-HLProbeResult -Status Pass -Expected ("<= $maximum days") -Actual ("$ageDays days") -Message 'Defender signatures are within the baseline age.' -Evidence $evidence
        }
        return New-HLProbeResult -Status Fail -Expected ("<= $maximum days") -Actual ("$ageDays days") -Message 'Defender signatures are older than the baseline permits.' -Evidence $evidence
    }
    catch {
        return New-HLProbeResult -Status Error -Expected ('<= {0} days' -f [int]$Control.parameters.maximumAgeDays) -Actual $null -Message "Unable to determine Defender signature age: $($_.Exception.Message)"
    }
}

function Invoke-HLAsrRulesProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    if ($null -eq (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        return New-HLProbeResult -Status Unknown -Expected 'Required ASR rules enforced' -Actual $null -Message 'Get-MpPreference is not available.'
    }

    try {
        $preference = Get-MpPreference -ErrorAction Stop
        $ids = @($preference.AttackSurfaceReductionRules_Ids)
        $actions = @($preference.AttackSurfaceReductionRules_Actions)
        $configured = @{}
        for ($index = 0; $index -lt $ids.Count; $index++) {
            $id = ([string]$ids[$index]).ToLowerInvariant()
            $action = if ($index -lt $actions.Count) { ConvertTo-HLInteger -Value $actions[$index] } else { $null }
            $configured[$id] = $action
        }

        $labels = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit'; 5 = 'Not configured'; 6 = 'Warn' }
        $evidence = New-Object System.Collections.Generic.List[object]
        $failed = 0
        $warning = 0
        foreach ($rule in @($Control.parameters.requiredRules)) {
            $id = ([string]$rule.id).ToLowerInvariant()
            $action = if ($configured.ContainsKey($id)) { $configured[$id] } else { 5 }
            $label = if ($labels.ContainsKey([int]$action)) { $labels[[int]$action] } else { "Unknown ($action)" }
            $state = 'Fail'
            if ([int]$action -in @($rule.allowedActions | ForEach-Object { [int]$_ })) {
                $state = 'Pass'
            }
            elseif ([int]$action -eq 2) {
                $state = 'Warning'
                $warning++
            }
            else {
                $failed++
            }
            $evidence.Add([pscustomobject][ordered]@{ Id = $id; Name = [string]$rule.name; Action = [int]$action; ActionName = $label; AllowedActions = @($rule.allowedActions); Result = $state })
        }

        $expected = ('{0} required rules in approved enforcement modes' -f @($Control.parameters.requiredRules).Count)
        $actual = ('{0} pass, {1} audit-only, {2} fail' -f (@($evidence | Where-Object Result -eq 'Pass').Count), $warning, $failed)
        if ($failed -gt 0) {
            return New-HLProbeResult -Status Fail -Expected $expected -Actual $actual -Message 'One or more required ASR rules are missing, disabled, or configured in an unapproved mode.' -Evidence @($evidence)
        }
        if ($warning -gt 0) {
            return New-HLProbeResult -Status Warning -Expected $expected -Actual $actual -Message 'Every required ASR rule is present, but one or more rules remain in Audit mode.' -Evidence @($evidence)
        }
        return New-HLProbeResult -Status Pass -Expected $expected -Actual $actual -Message 'Every required ASR rule is configured in an approved enforcement mode.' -Evidence @($evidence)
    }
    catch {
        return New-HLProbeResult -Status Error -Expected 'Required ASR rules enforced' -Actual $null -Message "Unable to query ASR rules: $($_.Exception.Message)"
    }
}

function Invoke-HLPowerShellModuleLoggingProbe {
    [CmdletBinding()]
    param()

    $root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    $enabled = Get-HLRegistryValue -Path $root -Name 'EnableModuleLogging'
    $moduleNamesPath = "$root\ModuleNames"
    $moduleNames = Get-HLRegistryKeyValues -Path $moduleNamesPath
    $patterns = if ($null -ne $moduleNames) { @($moduleNames.PSObject.Properties | ForEach-Object { [string]$_.Value } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) } else { @() }
    $evidence = [pscustomobject][ordered]@{ Enabled = if ($enabled.ValueExists) { $enabled.Value } else { $null }; ModulePatterns = $patterns; PolicyPath = $root }

    if (-not $enabled.ValueExists -or [int]$enabled.Value -ne 1) {
        return New-HLProbeResult -Status Fail -Expected 'Enabled with at least one module pattern' -Actual 'Disabled or not configured' -Message 'PowerShell Module Logging is not enabled.' -Evidence $evidence
    }
    if ($patterns.Count -eq 0) {
        return New-HLProbeResult -Status Fail -Expected 'At least one module pattern' -Actual 'No patterns configured' -Message 'Module Logging is enabled but no module pattern is configured.' -Evidence $evidence
    }
    return New-HLProbeResult -Status Pass -Expected 'Enabled with at least one module pattern' -Actual ($patterns -join ', ') -Message 'PowerShell Module Logging is enabled with configured module patterns.' -Evidence $evidence
}

function Invoke-HLEventLogProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    try {
        $log = Get-WinEvent -ListLog ([string]$Control.parameters.logName) -ErrorAction Stop
        $minimum = [int64]$Control.parameters.minimumSizeBytes
        $requireEnabled = (Test-HLProperty -InputObject $Control.parameters -Name 'requireEnabled') -and [bool]$Control.parameters.requireEnabled
        $evidence = [pscustomobject][ordered]@{
            LogName        = [string]$log.LogName
            IsEnabled      = [bool]$log.IsEnabled
            MaximumSizeBytes = [int64]$log.MaximumSizeInBytes
            LogMode        = [string]$log.LogMode
            RecordCount    = $log.RecordCount
        }
        if ($requireEnabled -and -not [bool]$log.IsEnabled) {
            return New-HLProbeResult -Status Fail -Expected 'Enabled with sufficient capacity' -Actual 'Disabled' -Message 'The event log is disabled.' -Evidence $evidence
        }
        if ([int64]$log.MaximumSizeInBytes -lt $minimum) {
            return New-HLProbeResult -Status Fail -Expected ("At least $minimum bytes") -Actual ([int64]$log.MaximumSizeInBytes) -Message 'The event log maximum size is below the baseline.' -Evidence $evidence
        }
        return New-HLProbeResult -Status Pass -Expected ("At least $minimum bytes") -Actual ([int64]$log.MaximumSizeInBytes) -Message 'The event log capacity matches the baseline.' -Evidence $evidence
    }
    catch {
        return New-HLProbeResult -Status Error -Expected 'Event log enabled and sized' -Actual $null -Message "Unable to query event log '$($Control.parameters.logName)': $($_.Exception.Message)"
    }
}

function Invoke-HLBitLockerProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    if ($null -eq (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        return New-HLProbeResult -Status Unknown -Expected 'BitLocker protection enabled' -Actual $null -Message 'Get-BitLockerVolume is not available.'
    }

    $mountPoint = if ([string]$Control.parameters.mountPoint -eq 'SystemDrive') { [string]$env:SystemDrive } else { [string]$Control.parameters.mountPoint }
    try {
        $volume = Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
        $evidence = [pscustomobject][ordered]@{
            MountPoint       = [string]$volume.MountPoint
            VolumeStatus     = [string]$volume.VolumeStatus
            ProtectionStatus = [string]$volume.ProtectionStatus
            EncryptionMethod = [string]$volume.EncryptionMethod
            KeyProtectorTypes = @($volume.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
        }
        if ([string]$volume.ProtectionStatus -eq 'On' -and [string]$volume.VolumeStatus -eq 'FullyEncrypted') {
            return New-HLProbeResult -Status Pass -Expected 'Protection On and FullyEncrypted' -Actual 'Protection On and FullyEncrypted' -Message 'The operating system volume is fully encrypted and protected.' -Evidence $evidence
        }
        if ([string]$volume.ProtectionStatus -eq 'On' -and [string]$volume.VolumeStatus -match 'EncryptionInProgress') {
            return New-HLProbeResult -Status Warning -Expected 'FullyEncrypted' -Actual ([string]$volume.VolumeStatus) -Message 'BitLocker is enabled but encryption is still in progress.' -Evidence $evidence
        }
        return New-HLProbeResult -Status Fail -Expected 'Protection On and FullyEncrypted' -Actual ("$($volume.ProtectionStatus), $($volume.VolumeStatus)") -Message 'The operating system volume is not fully protected by BitLocker.' -Evidence $evidence
    }
    catch {
        return New-HLProbeResult -Status Error -Expected 'BitLocker protection enabled' -Actual $null -Message "Unable to query BitLocker on '$mountPoint': $($_.Exception.Message)"
    }
}

function Invoke-HLSecureBootProbe {
    [CmdletBinding()]
    param()

    if ($null -eq (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        return New-HLProbeResult -Status Unknown -Expected 'Enabled' -Actual $null -Message 'Confirm-SecureBootUEFI is not available.'
    }

    try {
        $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($enabled) {
            return New-HLProbeResult -Status Pass -Expected 'Enabled' -Actual 'Enabled' -Message 'Secure Boot is enabled.'
        }
        return New-HLProbeResult -Status Fail -Expected 'Enabled' -Actual 'Disabled' -Message 'Secure Boot is supported but disabled.'
    }
    catch {
        $message = [string]$_.Exception.Message
        if ($message -match '(?i:not supported|unsupported|not UEFI)') {
            return New-HLProbeResult -Status Fail -Expected 'Enabled' -Actual 'Unsupported by current firmware or virtual hardware' -Message $message
        }
        return New-HLProbeResult -Status Error -Expected 'Enabled' -Actual $null -Message "Unable to query Secure Boot: $message"
    }
}

function Invoke-HLAutoRunProbe {
    [CmdletBinding()]
    param()

    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $driveType = Get-HLRegistryValue -Path $path -Name 'NoDriveTypeAutoRun'
    $noAutorun = Get-HLRegistryValue -Path $path -Name 'NoAutorun'
    $evidence = [pscustomobject][ordered]@{
        Path               = $path
        NoDriveTypeAutoRun = if ($driveType.ValueExists) { $driveType.Value } else { $null }
        NoAutorun          = if ($noAutorun.ValueExists) { $noAutorun.Value } else { $null }
    }

    if ($driveType.ValueExists -and [int]$driveType.Value -eq 255 -and $noAutorun.ValueExists -and [int]$noAutorun.Value -eq 1) {
        return New-HLProbeResult -Status Pass -Expected 'NoDriveTypeAutoRun=255 and NoAutorun=1' -Actual 'Configured' -Message 'AutoRun and AutoPlay are disabled through machine policy.' -Evidence $evidence
    }
    return New-HLProbeResult -Status Fail -Expected 'NoDriveTypeAutoRun=255 and NoAutorun=1' -Actual (ConvertTo-HLDisplayString -Value $evidence) -Message 'AutoRun and AutoPlay are not fully disabled through machine policy.' -Evidence $evidence
}

function Invoke-HLProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [Parameter(Mandatory)]
        [object]$SystemContext
    )

    try {
        switch ([string]$Control.probe) {
            'RegistryValue'          { return Invoke-HLRegistryValueProbe -Control $Control -SystemContext $SystemContext }
            'LocalGuestAccount'      { return Invoke-HLLocalGuestAccountProbe }
            'CredentialGuard'        { return Invoke-HLCredentialGuardProbe }
            'LapsBackup'             { return Invoke-HLLapsBackupProbe }
            'LapsPasswordAge'        { return Invoke-HLLapsPasswordAgeProbe -Control $Control }
            'LapsAdEncryption'       { return Invoke-HLLapsAdEncryptionProbe }
            'LapsDsrmBackup'         { return Invoke-HLLapsDsrmBackupProbe -SystemContext $SystemContext }
            'FirewallProfiles'       { return Invoke-HLFirewallProfilesProbe -Control $Control }
            'WindowsOptionalFeature' { return Invoke-HLWindowsOptionalFeatureProbe -Control $Control }
            'SmbServer'              { return Invoke-HLSmbConfigurationProbe -Control $Control -Side Server }
            'SmbClient'              { return Invoke-HLSmbConfigurationProbe -Control $Control -Side Client }
            'WinRM'                  { return Invoke-HLWinRMProbe -Control $Control }
            'Service'                { return Invoke-HLServiceProbe -Control $Control }
            'DefenderStatus'         { return Invoke-HLDefenderStatusProbe -Control $Control }
            'DefenderPreference'     { return Invoke-HLDefenderPreferenceProbe -Control $Control }
            'DefenderSignatureAge'   { return Invoke-HLDefenderSignatureAgeProbe -Control $Control }
            'AsrRules'               { return Invoke-HLAsrRulesProbe -Control $Control }
            'PowerShellModuleLogging' { return Invoke-HLPowerShellModuleLoggingProbe }
            'AuditPolicy'            { return Invoke-HLAuditPolicyProbe -Control $Control }
            'EventLog'               { return Invoke-HLEventLogProbe -Control $Control }
            'BitLocker'              { return Invoke-HLBitLockerProbe -Control $Control }
            'SecureBoot'             { return Invoke-HLSecureBootProbe }
            'AutoRun'                { return Invoke-HLAutoRunProbe }
            default                  { return New-HLProbeResult -Status Error -Expected $null -Actual $null -Message "Unknown probe '$($Control.probe)' for control '$($Control.id)'." }
        }
    }
    catch {
        return New-HLProbeResult -Status Error -Expected $null -Actual $null -Message "Probe '$($Control.probe)' failed: $($_.Exception.Message)"
    }
}
