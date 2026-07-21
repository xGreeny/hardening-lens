function New-HLCollectionContext {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates only an in-memory per-scan context and does not alter external state.')]
    [CmdletBinding()]
    param()

    return [pscustomobject][ordered]@{
        StartedAt       = (Get-Date).ToUniversalTime().ToString('o')
        Stopwatch       = [Diagnostics.Stopwatch]::StartNew()
        ProviderCache   = @{}
        ProviderMetrics = New-Object System.Collections.Generic.List[object]
    }
}

function Get-HLProviderSnapshot {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$CollectionContext,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Factory
    )

    if ($null -eq $CollectionContext) {
        return & $Factory
    }

    if ($CollectionContext.ProviderCache.ContainsKey($Name)) {
        $metric = @($CollectionContext.ProviderMetrics | Where-Object { $_.Name -ceq $Name } | Select-Object -First 1)
        if ($metric.Count -gt 0) {
            $metric[0].CacheHits = [int]$metric[0].CacheHits + 1
        }
        return $CollectionContext.ProviderCache[$Name]
    }

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $value = & $Factory
        $CollectionContext.ProviderCache[$Name] = $value
        $CollectionContext.ProviderMetrics.Add([pscustomobject][ordered]@{
            Name       = $Name
            DurationMs = [int][math]::Round($stopwatch.Elapsed.TotalMilliseconds)
            CacheHits  = 0
            Succeeded  = $true
        })
        return $value
    }
    catch {
        $CollectionContext.ProviderMetrics.Add([pscustomobject][ordered]@{
            Name       = $Name
            DurationMs = [int][math]::Round($stopwatch.Elapsed.TotalMilliseconds)
            CacheHits  = 0
            Succeeded  = $false
        })
        throw
    }
    finally {
        $stopwatch.Stop()
    }
}

function Get-HLContentDigest {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject
    )

    $canonical = ConvertTo-HLCanonicalJson -Value $InputObject
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
        return (($algorithm.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function Get-HLLogicalBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Baseline
    )

    $properties = [ordered]@{}
    foreach ($name in @('schemaVersion', 'name', 'displayName', 'version', 'description', 'sourceBasis', 'supportedRoles', 'controls', 'notes')) {
        if (Test-HLProperty -InputObject $Baseline -Name $name) {
            $properties[$name] = $Baseline.$name
        }
    }
    return [pscustomobject]$properties
}

function Get-HLProbeRegistry {
    [CmdletBinding()]
    param()

    if ($null -ne $script:HLProbeRegistryCache) {
        return $script:HLProbeRegistryCache
    }

    $registry = @{
        RegistryValue = [pscustomobject]@{
            RequiredCommands = @()
            ParameterNames = @('expected', 'missingIsPass', 'missingIsPassOnBuildAtLeast', 'name', 'operator', 'path')
            Handler = { param($control, $systemContext, $context) Invoke-HLRegistryValueProbe -Control $control -SystemContext $systemContext -CollectionContext $context }
        }
        LocalGuestAccount = [pscustomobject]@{
            RequiredCommands = @('Get-CimInstance')
            ParameterNames = @()
            Handler = { param($control, $systemContext, $context) Invoke-HLLocalGuestAccountProbe }
        }
        CredentialGuard = [pscustomobject]@{
            RequiredCommands = @('Get-CimInstance')
            ParameterNames = @()
            Handler = { param($control, $systemContext, $context) Invoke-HLCredentialGuardProbe }
        }
        DeviceGuardService = [pscustomobject]@{
            RequiredCommands = @('Get-CimInstance')
            ParameterNames = @('serviceId', 'serviceName')
            Handler = { param($control, $systemContext, $context) Invoke-HLDeviceGuardServiceProbe -Control $control -CollectionContext $context }
        }
        LapsBackup = [pscustomobject]@{
            RequiredCommands = @()
            ParameterNames = @()
            Handler = { param($control, $systemContext, $context) Invoke-HLLapsBackupProbe -CollectionContext $context }
        }
        LapsPasswordAge = [pscustomobject]@{
            RequiredCommands = @()
            ParameterNames = @('maximumDays')
            Handler = { param($control, $systemContext, $context) Invoke-HLLapsPasswordAgeProbe -Control $control -CollectionContext $context }
        }
        LapsAdEncryption = [pscustomobject]@{
            RequiredCommands = @()
            ParameterNames = @()
            Handler = { param($control, $systemContext, $context) Invoke-HLLapsAdEncryptionProbe -CollectionContext $context }
        }
        LapsDsrmBackup = [pscustomobject]@{
            RequiredCommands = @()
            ParameterNames = @()
            Handler = { param($control, $systemContext, $context) Invoke-HLLapsDsrmBackupProbe -SystemContext $systemContext -CollectionContext $context }
        }
        FirewallProfiles = [pscustomobject]@{
            RequiredCommands = @('Get-NetFirewallProfile')
            ParameterNames = @('requireDefaultInboundBlock', 'requireEnabled')
            Handler = { param($control, $systemContext, $context) Invoke-HLFirewallProfilesProbe -Control $control -CollectionContext $context }
        }
        WindowsOptionalFeature = [pscustomobject]@{
            RequiredCommands = @('Get-WindowsOptionalFeature')
            ParameterNames = @('evaluationMode', 'expectedState', 'features')
            Handler = { param($control, $systemContext, $context) Invoke-HLWindowsOptionalFeatureProbe -Control $control }
        }
        SmbServer = [pscustomobject]@{
            RequiredCommands = @('Get-SmbServerConfiguration')
            ParameterNames = @('expected', 'property')
            Handler = { param($control, $systemContext, $context) Invoke-HLSmbConfigurationProbe -Control $control -Side Server -CollectionContext $context }
        }
        SmbClient = [pscustomobject]@{
            RequiredCommands = @('Get-SmbClientConfiguration')
            ParameterNames = @('expected', 'property')
            Handler = { param($control, $systemContext, $context) Invoke-HLSmbConfigurationProbe -Control $control -Side Client -CollectionContext $context }
        }
        WinRM = [pscustomobject]@{
            RequiredCommands = @()
            ParameterNames = @('expected', 'property', 'targets')
            Handler = { param($control, $systemContext, $context) Invoke-HLWinRMProbe -Control $control }
        }
        Service = [pscustomobject]@{
            RequiredCommands = @('Get-CimInstance')
            ParameterNames = @('name', 'requireStopped', 'startupType')
            Handler = { param($control, $systemContext, $context) Invoke-HLServiceProbe -Control $control }
        }
        DefenderStatus = [pscustomobject]@{
            RequiredCommands = @('Get-MpComputerStatus')
            ParameterNames = @('expected', 'operator', 'property')
            Handler = { param($control, $systemContext, $context) Invoke-HLDefenderStatusProbe -Control $control -CollectionContext $context }
        }
        DefenderPreference = [pscustomobject]@{
            RequiredCommands = @('Get-MpPreference')
            ParameterNames = @('expected', 'operator', 'property', 'warningValues')
            Handler = { param($control, $systemContext, $context) Invoke-HLDefenderPreferenceProbe -Control $control -CollectionContext $context }
        }
        DefenderSignatureAge = [pscustomobject]@{
            RequiredCommands = @('Get-MpComputerStatus')
            ParameterNames = @('maximumAgeDays')
            Handler = { param($control, $systemContext, $context) Invoke-HLDefenderSignatureAgeProbe -Control $control -CollectionContext $context }
        }
        AsrRules = [pscustomobject]@{
            RequiredCommands = @('Get-MpPreference')
            ParameterNames = @('requiredRules')
            Handler = { param($control, $systemContext, $context) Invoke-HLAsrRulesProbe -Control $control -CollectionContext $context }
        }
        PowerShellModuleLogging = [pscustomobject]@{
            RequiredCommands = @()
            ParameterNames = @()
            Handler = { param($control, $systemContext, $context) Invoke-HLPowerShellModuleLoggingProbe }
        }
        AuditPolicy = [pscustomobject]@{
            RequiredCommands = @()
            ParameterNames = @('requiredFlags', 'subcategoryGuid', 'subcategoryName')
            Handler = { param($control, $systemContext, $context) Invoke-HLAuditPolicyProbe -Control $control }
        }
        EventLog = [pscustomobject]@{
            RequiredCommands = @('Get-WinEvent')
            ParameterNames = @('logName', 'minimumSizeBytes', 'requireEnabled')
            Handler = { param($control, $systemContext, $context) Invoke-HLEventLogProbe -Control $control }
        }
        BitLocker = [pscustomobject]@{
            RequiredCommands = @('Get-BitLockerVolume')
            ParameterNames = @('mountPoint')
            Handler = { param($control, $systemContext, $context) Invoke-HLBitLockerProbe -Control $control }
        }
        SecureBoot = [pscustomobject]@{
            RequiredCommands = @('Confirm-SecureBootUEFI')
            ParameterNames = @()
            Handler = { param($control, $systemContext, $context) Invoke-HLSecureBootProbe }
        }
        AutoRun = [pscustomobject]@{
            RequiredCommands = @()
            ParameterNames = @()
            Handler = { param($control, $systemContext, $context) Invoke-HLAutoRunProbe }
        }
    }

    $script:HLProbeRegistryCache = $registry
    return $registry
}

function Get-HLProbeCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Controls
    )

    $registry = Get-HLProbeRegistry
    $capabilities = New-Object System.Collections.Generic.List[object]
    $probeNames = @($Controls | ForEach-Object { [string]$_.probe } | Sort-Object -Unique)
    foreach ($probeName in $probeNames) {
        if (-not $registry.ContainsKey($probeName)) {
            $capabilities.Add([pscustomobject][ordered]@{
                name      = $probeName
                available = $false
                detail    = 'Probe is not registered.'
            })
            continue
        }

        $missing = @($registry[$probeName].RequiredCommands | Where-Object {
            $null -eq (Get-Command -Name $_ -ErrorAction SilentlyContinue)
        })
        $capabilities.Add([pscustomobject][ordered]@{
            name      = $probeName
            available = [bool]($missing.Count -eq 0)
            detail    = if ($missing.Count -eq 0) { $null } else { 'Missing command(s): {0}' -f ($missing -join ', ') }
        })
    }
    return $capabilities.ToArray()
}
