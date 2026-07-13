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
            'RegistryValue'           { return Invoke-HLRegistryValueProbe -Control $Control -SystemContext $SystemContext }
            'LocalGuestAccount'       { return Invoke-HLLocalGuestAccountProbe }
            'CredentialGuard'         { return Invoke-HLCredentialGuardProbe }
            'LapsBackup'              { return Invoke-HLLapsBackupProbe }
            'LapsPasswordAge'         { return Invoke-HLLapsPasswordAgeProbe -Control $Control }
            'LapsAdEncryption'        { return Invoke-HLLapsAdEncryptionProbe }
            'LapsDsrmBackup'          { return Invoke-HLLapsDsrmBackupProbe -SystemContext $SystemContext }
            'FirewallProfiles'        { return Invoke-HLFirewallProfilesProbe -Control $Control }
            'WindowsOptionalFeature'  { return Invoke-HLWindowsOptionalFeatureProbe -Control $Control }
            'SmbServer'               { return Invoke-HLSmbConfigurationProbe -Control $Control -Side Server }
            'SmbClient'               { return Invoke-HLSmbConfigurationProbe -Control $Control -Side Client }
            'WinRM'                   { return Invoke-HLWinRMProbe -Control $Control }
            'Service'                 { return Invoke-HLServiceProbe -Control $Control }
            'DefenderStatus'          { return Invoke-HLDefenderStatusProbe -Control $Control }
            'DefenderPreference'      { return Invoke-HLDefenderPreferenceProbe -Control $Control }
            'DefenderSignatureAge'    { return Invoke-HLDefenderSignatureAgeProbe -Control $Control }
            'AsrRules'                { return Invoke-HLAsrRulesProbe -Control $Control }
            'PowerShellModuleLogging' { return Invoke-HLPowerShellModuleLoggingProbe }
            'AuditPolicy'             { return Invoke-HLAuditPolicyProbe -Control $Control }
            'EventLog'                { return Invoke-HLEventLogProbe -Control $Control }
            'BitLocker'               { return Invoke-HLBitLockerProbe -Control $Control }
            'SecureBoot'              { return Invoke-HLSecureBootProbe }
            'AutoRun'                 { return Invoke-HLAutoRunProbe }
            default                   { return New-HLProbeResult -Status Error -Expected $null -Actual $null -Message "Unknown probe '$($Control.probe)' for control '$($Control.id)'." }
        }
    }
    catch {
        return New-HLProbeResult -Status Error -Expected $null -Actual $null -Message "Probe '$($Control.probe)' failed: $($_.Exception.Message)"
    }
}
