function Set-HardeningLensException {
    <#
    .SYNOPSIS
    Adds or transitions an exception in an existing governed exception register.

    .DESCRIPTION
    Adds Draft entries and performs forward-only Draft, Approved, Revoked lifecycle
    transitions. Approved entries require approval, ticket, expiry, and compensating
    control metadata. Changing an Approved entry resets it to Draft and removes its
    approval metadata so that the changed terms require an explicit new approval. The
    complete read-modify-write cycle is serialized and the file is replaced atomically.

    .PARAMETER Path
    Path to an existing valid Hardening Lens exception register.

    .PARAMETER Add
    Adds a new Draft entry. When Id is omitted, a unique ID is generated.

    .PARAMETER Id
    Exception ID to add or update.

    .PARAMETER Status
    Desired persisted status. Expired is an effective state of an Approved entry whose
    expiry date has passed and is not written as a separate schema status.

    .PARAMETER Revoke
    Transitions the selected Draft or Approved exception to Revoked. Revoke and Status
    cannot be supplied together.

    .PARAMETER Force
    Allows Add to replace an existing Draft with the same ID. Approved and Revoked
    entries are never replaced by Add.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Update', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Add')]
        [switch]$Add,

        [Parameter(ParameterSetName = 'Add')]
        [Parameter(Mandatory, ParameterSetName = 'Update')]
        [ValidatePattern('^EXC-[A-Za-z0-9._-]+$')]
        [string]$Id,

        [Parameter(Mandatory, ParameterSetName = 'Add')]
        [Parameter(ParameterSetName = 'Update')]
        [string]$ControlId,

        [Parameter(Mandatory, ParameterSetName = 'Add')]
        [Parameter(ParameterSetName = 'Update')]
        [string]$Owner,

        [Parameter(Mandatory, ParameterSetName = 'Add')]
        [Parameter(ParameterSetName = 'Update')]
        [string]$Reason,

        [Parameter(Mandatory, ParameterSetName = 'Add')]
        [Parameter(ParameterSetName = 'Update')]
        [string]$Ticket,

        [Parameter(Mandatory, ParameterSetName = 'Add')]
        [Parameter(ParameterSetName = 'Update')]
        [datetime]$Expires,

        [Parameter(Mandatory, ParameterSetName = 'Add')]
        [Parameter(ParameterSetName = 'Update')]
        [string[]]$Target,

        [Parameter(ParameterSetName = 'Add')]
        [Parameter(ParameterSetName = 'Update')]
        [string[]]$Baseline,

        [Parameter(ParameterSetName = 'Add')]
        [Parameter(ParameterSetName = 'Update')]
        [string[]]$CompensatingControl,

        [Parameter(ParameterSetName = 'Update')]
        [ValidateSet('Draft', 'Approved', 'Revoked')]
        [string]$Status,

        [Parameter(ParameterSetName = 'Update')]
        [switch]$Revoke,

        [Parameter(ParameterSetName = 'Update')]
        [string]$ApprovedBy,

        [Parameter(ParameterSetName = 'Update')]
        [datetime]$ApprovedOn,

        [switch]$Force
    )

    $fullPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $fileLock = Enter-HLFileLock -Path $fullPath
    try {
    $file = Read-HLExceptionFile -Path $fullPath
    $existingValidation = Test-HLExceptionDocument -Document $file.Document
    if (-not $existingValidation.IsValid) {
        throw ('Existing exception register is invalid: {0}' -f (@($existingValidation.Errors) -join ' '))
    }

    $document = Copy-HLObject -InputObject $file.Document
    $exceptions = @($document.exceptions)
    $approvalReset = $false
    if ($PSCmdlet.ParameterSetName -eq 'Add' -and [string]::IsNullOrWhiteSpace($Id)) {
        do {
            $Id = 'EXC-' + ([guid]::NewGuid().ToString('N').Substring(0, 12).ToUpperInvariant())
        } while (@($exceptions | Where-Object { [string]$_.id -ieq $Id }).Count -gt 0)
    }

    $matches = @($exceptions | Where-Object { [string]$_.id -ieq $Id })
    $previousStatus = $null
    if ($PSCmdlet.ParameterSetName -eq 'Add') {
        $newEntry = ConvertTo-HLDraftException -Id $Id -ControlId $ControlId -Owner $Owner -Reason $Reason -Ticket $Ticket -Expires $Expires -Target $Target -Baseline $Baseline -CompensatingControl $CompensatingControl
        if ($matches.Count -gt 0) {
            if (-not $Force) {
                throw "Exception '$Id' already exists. Use -Force only to replace an existing Draft."
            }
            if ($matches.Count -ne 1 -or [string]$matches[0].status -ne 'Draft') {
                throw "Exception '$Id' cannot be replaced because it is not a unique Draft entry."
            }
            $previousStatus = 'Draft'
            $exceptions = @($exceptions | Where-Object { [string]$_.id -ine $Id }) + @($newEntry)
        }
        else {
            $exceptions = @($exceptions) + @($newEntry)
        }
        $entry = $newEntry
    }
    else {
        if ($matches.Count -eq 0) {
            throw "Exception '$Id' was not found. Use -Add to create a Draft entry."
        }
        if ($matches.Count -gt 1) {
            throw "Exception '$Id' is not unique in the register."
        }

        if ($Revoke -and $PSBoundParameters.ContainsKey('Status')) {
            throw '-Revoke and -Status cannot be used together.'
        }

        $entry = $matches[0]
        $previousStatus = [string]$entry.status
        $approvalFingerprintBefore = if ($previousStatus -eq 'Approved') {
            Get-HLExceptionApprovalFingerprint -Exception $entry
        }
        else {
            $null
        }
        $desiredStatus = if ($Revoke) { 'Revoked' } elseif ($PSBoundParameters.ContainsKey('Status')) { $Status } else { $previousStatus }
        Assert-HLExceptionTransition -CurrentStatus $previousStatus -DesiredStatus $desiredStatus

        foreach ($propertyMap in @(
            @('ControlId', 'controlId'),
            @('Owner', 'owner'),
            @('Reason', 'reason'),
            @('Ticket', 'ticket'),
            @('Target', 'targets'),
            @('CompensatingControl', 'compensatingControls'),
            @('ApprovedBy', 'approvedBy')
        )) {
            if ($PSBoundParameters.ContainsKey($propertyMap[0])) {
                $value = $PSBoundParameters[$propertyMap[0]]
                if ($value -is [string]) {
                    $value = $value.Trim()
                }
                elseif ($value -is [System.Collections.IEnumerable]) {
                    $value = @($value)
                }
                Merge-HLNoteProperty -InputObject $entry -Name $propertyMap[1] -Value $value
            }
        }

        if ($PSBoundParameters.ContainsKey('Expires')) {
            Merge-HLNoteProperty -InputObject $entry -Name 'expires' -Value $Expires.ToString('yyyy-MM-dd')
        }
        if ($PSBoundParameters.ContainsKey('Baseline')) {
            if ($null -eq $Baseline -or @($Baseline).Count -eq 0) {
                [void]$entry.PSObject.Properties.Remove('baselines')
            }
            else {
                Merge-HLNoteProperty -InputObject $entry -Name 'baselines' -Value @($Baseline)
            }
        }
        if ($PSBoundParameters.ContainsKey('ApprovedOn')) {
            Merge-HLNoteProperty -InputObject $entry -Name 'approvedOn' -Value $ApprovedOn.ToString('yyyy-MM-dd')
        }
        elseif ($desiredStatus -eq 'Approved' -and $previousStatus -ne 'Approved') {
            Merge-HLNoteProperty -InputObject $entry -Name 'approvedOn' -Value (Get-Date).ToString('yyyy-MM-dd')
        }

        if ($previousStatus -eq 'Approved' -and $desiredStatus -eq 'Approved') {
            $approvalFingerprintAfter = Get-HLExceptionApprovalFingerprint -Exception $entry
            if ($approvalFingerprintBefore -cne $approvalFingerprintAfter) {
                $desiredStatus = 'Draft'
                [void]$entry.PSObject.Properties.Remove('approvedBy')
                [void]$entry.PSObject.Properties.Remove('approvedOn')
                $approvalReset = $true
            }
        }
        Merge-HLNoteProperty -InputObject $entry -Name 'status' -Value $desiredStatus

        if ($desiredStatus -eq 'Approved' -and (-not (Test-HLProperty -InputObject $entry -Name 'approvedBy') -or [string]::IsNullOrWhiteSpace([string]$entry.approvedBy))) {
            throw '-ApprovedBy is required when approving an exception.'
        }
    }

    Merge-HLNoteProperty -InputObject $document -Name 'exceptions' -Value @($exceptions)
    $updatedValidation = Test-HLExceptionDocument -Document $document
    if (-not $updatedValidation.IsValid) {
        throw ('Updated exception register is invalid: {0}' -f (@($updatedValidation.Errors) -join ' '))
    }

    $beforeJson = $file.Document | ConvertTo-Json -Depth 30 -Compress
    $afterJson = $document | ConvertTo-Json -Depth 30 -Compress
    $wouldChange = $beforeJson -cne $afterJson
    $changed = $false
    if ($wouldChange -and $PSCmdlet.ShouldProcess($fullPath, "Update exception '$Id'")) {
        Write-HLAtomicUtf8File -Path $fullPath -Content (($document | ConvertTo-Json -Depth 30) + [Environment]::NewLine)
        $changed = $true
    }

    return [pscustomobject][ordered]@{
        Path           = $fullPath
        Id             = $Id
        PreviousStatus = $previousStatus
        Status         = [string]$entry.status
        EffectiveStatus = Get-HLExceptionEffectiveStatus -Exception $entry
        ApprovalReset  = $approvalReset
        WouldChange    = $wouldChange
        Changed        = $changed
        Exception      = Copy-HLObject -InputObject $entry
    }
    }
    finally {
        Exit-HLFileLock -Lock $fileLock
    }
}
