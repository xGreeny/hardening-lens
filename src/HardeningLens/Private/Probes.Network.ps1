function Invoke-HLSmbConfigurationProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [Parameter(Mandatory)]
        [ValidateSet('Server', 'Client')]
        [string]$Side,

        [AllowNull()]
        [object]$CollectionContext
    )

    $commandName = if ($Side -eq 'Server') { 'Get-SmbServerConfiguration' } else { 'Get-SmbClientConfiguration' }
    if ($null -eq (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
        return Get-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message "$commandName is not available."
    }

    try {
        $configuration = Get-HLProviderSnapshot -CollectionContext $CollectionContext -Name ("SmbConfiguration:$Side") -Factory {
            & $commandName -ErrorAction Stop
        }
        $property = [string]$Control.parameters.property
        if (-not (Test-HLProperty -InputObject $configuration -Name $property)) {
            return Get-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual $null -Message "SMB $Side configuration does not expose '$property'."
        }
        $actual = $configuration.$property
        $evidence = [pscustomobject][ordered]@{ Side = $Side; Property = $property; Value = $actual }
        return Get-HLValueProbeResult -Actual $actual -Expected $Control.parameters.expected -Operator Equals -Evidence $evidence
    }
    catch {
        return Get-HLProbeResult -Status Error -Expected $Control.parameters.expected -Actual $null -Message "Unable to query SMB $Side configuration: $($_.Exception.Message)"
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
        Write-Verbose "Unable to query ${wsmanPath}: $($_.Exception.Message)"
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
        return Get-HLProbeResult -Status Fail -Expected $Control.parameters.expected -Actual ('Non-compliant: {0}' -f ($nonCompliant.ToArray() -join ', ')) -Message 'One or more WinRM client/service settings do not match the baseline.' -Evidence $evidence.ToArray()
    }
    if ($unresolved.Count -gt 0) {
        return Get-HLProbeResult -Status Unknown -Expected $Control.parameters.expected -Actual ('Unresolved: {0}' -f ($unresolved.ToArray() -join ', ')) -Message 'The effective WinRM configuration could not be resolved for every target.' -Evidence $evidence.ToArray()
    }

    return Get-HLProbeResult -Status Pass -Expected $Control.parameters.expected -Actual 'Compliant on Client and Service' -Message 'WinRM client and service settings match the baseline.' -Evidence $evidence.ToArray()
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
            return Get-HLProbeResult -Status Pass -Expected 'Disabled or absent' -Actual 'Service not installed' -Message "Service '$name' is not installed."
        }

        $evidence = [pscustomobject][ordered]@{ Name = [string]$service.Name; DisplayName = [string]$service.DisplayName; StartMode = [string]$service.StartMode; State = [string]$service.State }
        $startupOkay = [string]$service.StartMode -eq [string]$Control.parameters.startupType
        $stateOkay = -not [bool]$Control.parameters.requireStopped -or [string]$service.State -eq 'Stopped'
        if ($startupOkay -and $stateOkay) {
            return Get-HLProbeResult -Status Pass -Expected 'Disabled and stopped' -Actual "$($service.StartMode), $($service.State)" -Message 'The service state matches the baseline.' -Evidence $evidence
        }
        return Get-HLProbeResult -Status Fail -Expected 'Disabled and stopped' -Actual "$($service.StartMode), $($service.State)" -Message 'The service startup or runtime state does not match the baseline.' -Evidence $evidence
    }
    catch {
        return Get-HLProbeResult -Status Error -Expected 'Disabled and stopped' -Actual $null -Message "Unable to query service '$name': $($_.Exception.Message)"
    }
}
