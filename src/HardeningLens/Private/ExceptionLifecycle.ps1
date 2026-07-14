function Merge-HLNoteProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $InputObject.PSObject.Properties[$Name]) {
        $InputObject | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
    else {
        $InputObject.$Name = $Value
    }
}

function Get-HLExceptionEffectiveStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Exception,

        [datetime]$AsOf = (Get-Date)
    )

    $status = [string]$Exception.status
    if ($status -ne 'Approved') {
        return $status
    }

    $expiry = [datetime]::MinValue
    if ((Test-HLProperty -InputObject $Exception -Name 'expires') -and
        (Test-HLDateString -Value $Exception.expires -ParsedDate ([ref]$expiry)) -and
        $expiry.Date -lt $AsOf.Date) {
        return 'Expired'
    }

    return $status
}

function Get-HLExceptionApprovalFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Exception
    )

    $baselines = $null
    if (Test-HLProperty -InputObject $Exception -Name 'baselines') {
        $baselines = @(@($Exception.baselines | ForEach-Object { [string]$_ }) | Sort-Object -CaseSensitive)
    }
    $material = [pscustomobject][ordered]@{
        controlId            = [string]$Exception.controlId
        owner                = [string]$Exception.owner
        reason               = [string]$Exception.reason
        ticket               = [string]$Exception.ticket
        expires              = [string]$Exception.expires
        targets              = @(@($Exception.targets | ForEach-Object { [string]$_ }) | Sort-Object -CaseSensitive)
        baselines            = $baselines
        compensatingControls = @(@($Exception.compensatingControls | ForEach-Object { [string]$_ }) | Sort-Object -CaseSensitive)
        approvedBy           = if (Test-HLProperty -InputObject $Exception -Name 'approvedBy') { [string]$Exception.approvedBy } else { $null }
        approvedOn           = if (Test-HLProperty -InputObject $Exception -Name 'approvedOn') { [string]$Exception.approvedOn } else { $null }
    }
    return $material | ConvertTo-Json -Depth 10 -Compress
}

function ConvertTo-HLDraftException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [string]$ControlId,

        [Parameter(Mandatory)]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Reason,

        [Parameter(Mandatory)]
        [string]$Ticket,

        [Parameter(Mandatory)]
        [datetime]$Expires,

        [Parameter(Mandatory)]
        [string[]]$Target,

        [AllowNull()]
        [string[]]$Baseline,

        [AllowNull()]
        [string[]]$CompensatingControl
    )

    $entry = [pscustomobject][ordered]@{
        id                   = $Id
        controlId            = $ControlId
        status               = 'Draft'
        owner                = $Owner.Trim()
        reason               = $Reason.Trim()
        ticket               = $Ticket.Trim()
        expires              = $Expires.ToString('yyyy-MM-dd')
        targets              = @($Target)
        compensatingControls = @($CompensatingControl | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    }
    if ($null -ne $Baseline -and @($Baseline).Count -gt 0) {
        $entry | Add-Member -NotePropertyName baselines -NotePropertyValue @($Baseline)
    }

    return $entry
}

function Assert-HLExceptionTransition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CurrentStatus,

        [Parameter(Mandatory)]
        [string]$DesiredStatus
    )

    $allowed = @{
        Draft    = @('Draft', 'Approved', 'Revoked')
        Approved = @('Approved', 'Revoked')
        Revoked  = @('Revoked')
    }
    if (-not $allowed.ContainsKey($CurrentStatus) -or $DesiredStatus -notin $allowed[$CurrentStatus]) {
        throw "Unsupported exception transition from '$CurrentStatus' to '$DesiredStatus'."
    }
}
