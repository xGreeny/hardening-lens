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
            LogName          = [string]$log.LogName
            IsEnabled        = [bool]$log.IsEnabled
            MaximumSizeBytes = [int64]$log.MaximumSizeInBytes
            LogMode          = [string]$log.LogMode
            RecordCount      = $log.RecordCount
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
            MountPoint        = [string]$volume.MountPoint
            VolumeStatus      = [string]$volume.VolumeStatus
            ProtectionStatus  = [string]$volume.ProtectionStatus
            EncryptionMethod  = [string]$volume.EncryptionMethod
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
