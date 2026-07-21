function Get-HLThirdPartyAntivirusSnapshot {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$CollectionContext
    )

    if ($null -eq (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        return $null
    }

    return Get-HLProviderSnapshot -CollectionContext $CollectionContext -Name 'SecurityCenterAntivirus' -Factory {
        try {
            @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    DisplayName  = [string]$_.displayName
                    ProductState = ConvertTo-HLInteger -Value $_.productState
                }
            })
        }
        catch {
            # Server SKUs do not expose the Security Center namespace; treat
            # the registration source as unavailable rather than failing.
            $null
        }
    }
}

function Get-HLDefenderServiceUnavailableResult {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$CollectionContext,

        [Parameter(Mandatory)]
        [object]$ErrorRecord,

        [AllowNull()]
        [object]$Expected
    )

    if (-not (Test-HLErrorMatchesCode -Exception $ErrorRecord.Exception -Code 0x800106ba)) {
        return $null
    }

    $thirdParty = Get-HLThirdPartyAntivirusSnapshot -CollectionContext $CollectionContext
    $evidence = [pscustomobject][ordered]@{
        DefenderServiceAvailable = $false
        ErrorCode                = '0x800106BA'
        ThirdPartyAntivirus      = if ($null -ne $thirdParty) { @($thirdParty) } else { $null }
    }
    return Get-HLProbeResult -Status Unknown -Expected $Expected -Actual 'Defender service not running' -Message 'The Microsoft Defender service is not running (0x800106BA). Verify that an authorized endpoint protection platform is active, and record an approved exception when a third-party product is authoritative.' -Evidence $evidence
}

function Invoke-HLDefenderStatusProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [AllowNull()]
        [object]$CollectionContext
    )

    if ($null -eq (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        return Get-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message 'Get-MpComputerStatus is not available. Use an approved exception when another endpoint protection platform is authoritative.'
    }

    try {
        $status = Get-HLProviderSnapshot -CollectionContext $CollectionContext -Name 'DefenderStatus' -Factory {
            Get-MpComputerStatus -ErrorAction Stop
        }
        $property = [string]$Control.parameters.property
        if (-not (Test-HLProperty -InputObject $status -Name $property)) {
            return Get-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message "Defender status does not expose '$property'."
        }
        $actual = $status.$property
        $antivirusEnabled = if (Test-HLProperty -InputObject $status -Name 'AntivirusEnabled') { $status.AntivirusEnabled } else { $null }
        $evidence = [pscustomobject][ordered]@{
            Property         = $property
            Value            = $actual
            AntivirusEnabled = $antivirusEnabled
            AMRunningMode    = if (Test-HLProperty -InputObject $status -Name 'AMRunningMode') { [string]$status.AMRunningMode } else { $null }
        }
        if ($antivirusEnabled -eq $false) {
            $thirdParty = Get-HLThirdPartyAntivirusSnapshot -CollectionContext $CollectionContext
            $evidence | Add-Member -NotePropertyName ThirdPartyAntivirus -NotePropertyValue $(if ($null -ne $thirdParty) { @($thirdParty) } else { $null })
        }
        return Get-HLValueProbeResult -Actual $actual -Expected $Control.parameters.expected -Operator ([string]$Control.parameters.operator) -Evidence $evidence
    }
    catch {
        $unavailable = Get-HLDefenderServiceUnavailableResult -CollectionContext $CollectionContext -ErrorRecord $_ -Expected $Control.parameters.expected
        if ($null -ne $unavailable) { return $unavailable }
        return Get-HLProbeResult -Status Error -Expected $Control.parameters.expected -Actual $null -Message "Unable to query Microsoft Defender status: $($_.Exception.Message)"
    }
}

function Invoke-HLDefenderPreferenceProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [AllowNull()]
        [object]$CollectionContext
    )

    if ($null -eq (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        return Get-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message 'Get-MpPreference is not available. Use an approved exception when another endpoint protection platform is authoritative.'
    }

    try {
        $preference = Get-HLProviderSnapshot -CollectionContext $CollectionContext -Name 'DefenderPreference' -Factory {
            Get-MpPreference -ErrorAction Stop
        }
        $property = [string]$Control.parameters.property
        if (-not (Test-HLProperty -InputObject $preference -Name $property)) {
            return Get-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message "Defender preference does not expose '$property'."
        }
        $actualRaw = $preference.$property
        $actualInt = ConvertTo-HLInteger -Value $actualRaw
        $actual = if ($null -ne $actualInt) { $actualInt } else { $actualRaw }
        $warningValues = if (Test-HLProperty -InputObject $Control.parameters -Name 'warningValues') { @($Control.parameters.warningValues) } else { $null }
        $evidence = [pscustomobject][ordered]@{ Property = $property; Value = $actual }
        return Get-HLValueProbeResult -Actual $actual -Expected $Control.parameters.expected -Operator ([string]$Control.parameters.operator) -WarningValues $warningValues -Evidence $evidence
    }
    catch {
        $unavailable = Get-HLDefenderServiceUnavailableResult -CollectionContext $CollectionContext -ErrorRecord $_ -Expected $Control.parameters.expected
        if ($null -ne $unavailable) { return $unavailable }
        return Get-HLProbeResult -Status Error -Expected $Control.parameters.expected -Actual $null -Message "Unable to query Microsoft Defender preferences: $($_.Exception.Message)"
    }
}

function Invoke-HLDefenderSignatureAgeProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [AllowNull()]
        [object]$CollectionContext
    )

    if ($null -eq (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        return Get-HLProbeResult -Status Unknown -Expected ('<= {0} days' -f [int]$Control.parameters.maximumAgeDays) -Actual $null -Message 'Get-MpComputerStatus is not available.'
    }

    try {
        $status = Get-HLProviderSnapshot -CollectionContext $CollectionContext -Name 'DefenderStatus' -Factory {
            Get-MpComputerStatus -ErrorAction Stop
        }
        if ($null -eq $status.AntivirusSignatureLastUpdated) {
            return Get-HLProbeResult -Status Unknown -Expected ('<= {0} days' -f [int]$Control.parameters.maximumAgeDays) -Actual $null -Message 'Defender did not return a signature update timestamp.'
        }
        $updated = [datetime]$status.AntivirusSignatureLastUpdated
        $age = (Get-Date).ToUniversalTime() - $updated.ToUniversalTime()
        $ageDays = [math]::Round([double]$age.TotalDays, 2)
        $maximum = [int]$Control.parameters.maximumAgeDays
        $evidence = [pscustomobject][ordered]@{ LastUpdated = $updated.ToString('o'); AgeDays = $ageDays; Version = [string]$status.AntivirusSignatureVersion }
        if ($ageDays -le $maximum) {
            return Get-HLProbeResult -Status Pass -Expected ("<= $maximum days") -Actual ("$ageDays days") -Message 'Defender signatures are within the baseline age.' -Evidence $evidence
        }
        return Get-HLProbeResult -Status Fail -Expected ("<= $maximum days") -Actual ("$ageDays days") -Message 'Defender signatures are older than the baseline permits.' -Evidence $evidence
    }
    catch {
        $unavailable = Get-HLDefenderServiceUnavailableResult -CollectionContext $CollectionContext -ErrorRecord $_ -Expected ('<= {0} days' -f [int]$Control.parameters.maximumAgeDays)
        if ($null -ne $unavailable) { return $unavailable }
        return Get-HLProbeResult -Status Error -Expected ('<= {0} days' -f [int]$Control.parameters.maximumAgeDays) -Actual $null -Message "Unable to determine Defender signature age: $($_.Exception.Message)"
    }
}

function Invoke-HLAsrRulesProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [AllowNull()]
        [object]$CollectionContext
    )

    if ($null -eq (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        return Get-HLProbeResult -Status Unknown -Expected 'Required ASR rules enforced' -Actual $null -Message 'Get-MpPreference is not available.'
    }

    try {
        $preference = Get-HLProviderSnapshot -CollectionContext $CollectionContext -Name 'DefenderPreference' -Factory {
            Get-MpPreference -ErrorAction Stop
        }
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
            return Get-HLProbeResult -Status Fail -Expected $expected -Actual $actual -Message 'One or more required ASR rules are missing, disabled, or configured in an unapproved mode.' -Evidence $evidence.ToArray()
        }
        if ($warning -gt 0) {
            return Get-HLProbeResult -Status Warning -Expected $expected -Actual $actual -Message 'Every required ASR rule is present, but one or more rules remain in Audit mode.' -Evidence $evidence.ToArray()
        }
        return Get-HLProbeResult -Status Pass -Expected $expected -Actual $actual -Message 'Every required ASR rule is configured in an approved enforcement mode.' -Evidence $evidence.ToArray()
    }
    catch {
        $unavailable = Get-HLDefenderServiceUnavailableResult -CollectionContext $CollectionContext -ErrorRecord $_ -Expected 'Required ASR rules enforced'
        if ($null -ne $unavailable) { return $unavailable }
        return Get-HLProbeResult -Status Error -Expected 'Required ASR rules enforced' -Actual $null -Message "Unable to query ASR rules: $($_.Exception.Message)"
    }
}
