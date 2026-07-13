function Get-HLLapsEffectivePolicy {
    [CmdletBinding()]
    param()

    $roots = @(
        [pscustomobject]@{ Name = 'CSP'; Path = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' },
        [pscustomobject]@{ Name = 'GroupPolicy'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' },
        [pscustomobject]@{ Name = 'LocalConfiguration'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' },
        [pscustomobject]@{ Name = 'LegacyMicrosoftLAPS'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' }
    )

    foreach ($root in $roots) {
        $values = Get-HLRegistryKeyValueMap -Path $root.Path
        if ($null -eq $values) {
            continue
        }

        $properties = @($values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })
        if ($properties.Count -eq 0) {
            continue
        }

        if ($root.Name -eq 'LegacyMicrosoftLAPS') {
            return [pscustomobject][ordered]@{
                PolicySource               = $root.Name
                PolicyPath                 = $root.Path
                IsLegacy                   = $true
                BackupDirectory            = 0
                PasswordAgeDays            = 30
                ADPasswordEncryptionEnabled = 0
                ADBackupDSRMPassword       = 0
                ExplicitValues             = $values
            }
        }

        return [pscustomobject][ordered]@{
            PolicySource               = $root.Name
            PolicyPath                 = $root.Path
            IsLegacy                   = $false
            BackupDirectory            = if (Test-HLProperty -InputObject $values -Name 'BackupDirectory') { [int]$values.BackupDirectory } else { 0 }
            PasswordAgeDays            = if (Test-HLProperty -InputObject $values -Name 'PasswordAgeDays') { [int]$values.PasswordAgeDays } else { 30 }
            ADPasswordEncryptionEnabled = if (Test-HLProperty -InputObject $values -Name 'ADPasswordEncryptionEnabled') { [int]$values.ADPasswordEncryptionEnabled } else { 1 }
            ADBackupDSRMPassword       = if (Test-HLProperty -InputObject $values -Name 'ADBackupDSRMPassword') { [int]$values.ADBackupDSRMPassword } else { 0 }
            ExplicitValues             = $values
        }
    }

    return [pscustomobject][ordered]@{
        PolicySource               = 'None'
        PolicyPath                 = $null
        IsLegacy                   = $false
        BackupDirectory            = 0
        PasswordAgeDays            = 30
        ADPasswordEncryptionEnabled = 1
        ADBackupDSRMPassword       = 0
        ExplicitValues             = $null
    }
}

function Invoke-HLLapsBackupProbe {
    [CmdletBinding()]
    param()

    $policy = Get-HLLapsEffectivePolicy
    if ($policy.IsLegacy) {
        return Get-HLProbeResult -Status Fail -Expected 'Windows LAPS backup to Microsoft Entra ID or Active Directory' -Actual 'Legacy Microsoft LAPS policy detected' -Message 'Legacy Microsoft LAPS does not satisfy the Windows LAPS control.' -Evidence $policy
    }

    $actual = switch ([int]$policy.BackupDirectory) {
        1 { 'Microsoft Entra ID' }
        2 { 'Active Directory' }
        default { 'Disabled' }
    }

    if ([int]$policy.BackupDirectory -in @(1, 2)) {
        return Get-HLProbeResult -Status Pass -Expected 'Microsoft Entra ID or Active Directory' -Actual $actual -Message "Windows LAPS is active through $($policy.PolicySource)." -Evidence $policy
    }

    return Get-HLProbeResult -Status Fail -Expected 'Microsoft Entra ID or Active Directory' -Actual $actual -Message 'No active Windows LAPS password backup target is configured.' -Evidence $policy
}

function Invoke-HLLapsPasswordAgeProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    $policy = Get-HLLapsEffectivePolicy
    if ($policy.IsLegacy) {
        return Get-HLProbeResult -Status Fail -Expected ('<= {0} days using Windows LAPS' -f [int]$Control.parameters.maximumDays) -Actual 'Legacy Microsoft LAPS policy detected' -Message 'Legacy Microsoft LAPS does not satisfy the Windows LAPS control.' -Evidence $policy
    }

    if ([int]$policy.BackupDirectory -eq 0) {
        return Get-HLProbeResult -Status Fail -Expected ('<= {0} days' -f [int]$Control.parameters.maximumDays) -Actual 'LAPS backup disabled' -Message 'Password age cannot provide managed rotation while Windows LAPS backup is disabled.' -Evidence $policy
    }

    $maximumDays = [int]$Control.parameters.maximumDays
    if ([int]$policy.PasswordAgeDays -le $maximumDays) {
        return Get-HLProbeResult -Status Pass -Expected ('<= {0} days' -f $maximumDays) -Actual ('{0} days' -f [int]$policy.PasswordAgeDays) -Message 'The effective Windows LAPS password age is within the baseline.' -Evidence $policy
    }

    return Get-HLProbeResult -Status Fail -Expected ('<= {0} days' -f $maximumDays) -Actual ('{0} days' -f [int]$policy.PasswordAgeDays) -Message 'The effective Windows LAPS password age exceeds the baseline.' -Evidence $policy
}

function Invoke-HLLapsAdEncryptionProbe {
    [CmdletBinding()]
    param()

    $policy = Get-HLLapsEffectivePolicy
    if ($policy.IsLegacy) {
        return Get-HLProbeResult -Status Fail -Expected 'Windows LAPS AD password encryption enabled' -Actual 'Legacy Microsoft LAPS policy detected' -Message 'Legacy Microsoft LAPS does not provide the Windows LAPS AD encryption control.' -Evidence $policy
    }

    if ([int]$policy.BackupDirectory -eq 0) {
        return Get-HLProbeResult -Status Fail -Expected 'Windows LAPS backup enabled' -Actual 'Backup disabled' -Message 'No active Windows LAPS password backup target is configured.' -Evidence $policy
    }

    if ([int]$policy.BackupDirectory -eq 1) {
        return Get-HLProbeResult -Status NotApplicable -Expected 'AD password encryption when backing up to Active Directory' -Actual 'Microsoft Entra ID backup' -Message 'AD password encryption is not applicable to Entra-backed Windows LAPS.' -Evidence $policy
    }

    if ([int]$policy.ADPasswordEncryptionEnabled -eq 1) {
        return Get-HLProbeResult -Status Pass -Expected 'Enabled' -Actual 'Enabled' -Message 'Windows LAPS AD password encryption is enabled.' -Evidence $policy
    }

    return Get-HLProbeResult -Status Fail -Expected 'Enabled' -Actual 'Disabled' -Message 'Windows LAPS is AD-backed but password encryption is disabled.' -Evidence $policy
}

function Invoke-HLLapsDsrmBackupProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$SystemContext
    )

    if ([string]$SystemContext.DetectedRole -ne 'DomainController') {
        return Get-HLProbeResult -Status NotApplicable -Expected 'Enabled on domain controllers' -Actual $SystemContext.DetectedRole -Message 'DSRM password backup applies only to domain controllers.'
    }

    $policy = Get-HLLapsEffectivePolicy
    if ($policy.IsLegacy) {
        return Get-HLProbeResult -Status Fail -Expected 'Windows LAPS DSRM password backup enabled' -Actual 'Legacy Microsoft LAPS policy detected' -Message 'Legacy Microsoft LAPS does not provide Windows LAPS DSRM password management.' -Evidence $policy
    }

    if ([int]$policy.BackupDirectory -ne 2) {
        return Get-HLProbeResult -Status Fail -Expected 'Active Directory backup with DSRM management' -Actual ('BackupDirectory={0}' -f [int]$policy.BackupDirectory) -Message 'Domain controller DSRM management requires Active Directory-backed Windows LAPS.' -Evidence $policy
    }

    if ([int]$policy.ADPasswordEncryptionEnabled -ne 1) {
        return Get-HLProbeResult -Status Fail -Expected 'AD encryption enabled and DSRM backup enabled' -Actual 'AD password encryption disabled' -Message 'DSRM password backup depends on Windows LAPS AD password encryption.' -Evidence $policy
    }

    if ([int]$policy.ADBackupDSRMPassword -eq 1) {
        return Get-HLProbeResult -Status Pass -Expected 'Enabled' -Actual 'Enabled' -Message 'Windows LAPS DSRM password backup is enabled.' -Evidence $policy
    }

    return Get-HLProbeResult -Status Fail -Expected 'Enabled' -Actual 'Disabled' -Message 'Windows LAPS DSRM password backup is disabled.' -Evidence $policy
}
