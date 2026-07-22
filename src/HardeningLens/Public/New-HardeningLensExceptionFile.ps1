function New-HardeningLensExceptionFile {
    <#
    .SYNOPSIS
    Creates an empty exception register or a register with one governed exception entry.

    .DESCRIPTION
    Builds a schema-compatible exception register. Approved entries require an approver,
    approval date, expiry date, and at least one compensating control. Creation is
    serialized with lifecycle updates and committed through an atomic file replacement.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$ControlId,

        [string[]]$Target = @('*'),

        [string[]]$Baseline,

        [ValidateSet('Draft', 'Approved')]
        [string]$Status = 'Draft',

        [string]$Owner,

        [string]$Reason,

        [string]$Ticket,

        [datetime]$Expires,

        [string]$ApprovedBy,

        [datetime]$ApprovedOn = (Get-Date),

        [string[]]$CompensatingControl,

        [switch]$Force
    )

    $fullPath = ConvertTo-HLFullPath -Path $Path
    if ((Test-Path -LiteralPath $fullPath) -and -not $Force) {
        throw "File already exists: $fullPath. Use -Force to overwrite."
    }

    $exceptions = @()
    if (-not [string]::IsNullOrWhiteSpace($ControlId)) {
        $catalogIds = @((Get-HLControlCatalog).controls | ForEach-Object { [string]$_.id })
        if ($ControlId -notin $catalogIds) {
            throw "Control '$ControlId' is not present in the Hardening Lens catalog."
        }

        foreach ($requiredValue in @{
            Owner = $Owner
            Reason = $Reason
            Ticket = $Ticket
        }.GetEnumerator()) {
            if ([string]::IsNullOrWhiteSpace([string]$requiredValue.Value)) {
                throw "-$($requiredValue.Key) is required when -ControlId is specified."
            }
        }
        if ($Reason.Trim().Length -lt 10) {
            throw '-Reason must contain at least 10 characters.'
        }
        if ($Expires -eq [datetime]::MinValue) {
            throw '-Expires is required when -ControlId is specified.'
        }
        if ($null -eq $Target -or @($Target).Count -eq 0 -or @($Target | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
            throw '-Target must contain at least one non-empty host pattern.'
        }

        $entry = [ordered]@{
            id                   = 'EXC-' + ([guid]::NewGuid().ToString('N').Substring(0, 12).ToUpperInvariant())
            controlId            = $ControlId
            status               = $Status
            owner                = $Owner.Trim()
            reason               = $Reason.Trim()
            ticket               = $Ticket.Trim()
            expires              = $Expires.ToString('yyyy-MM-dd')
            targets              = @($Target)
            compensatingControls = @($CompensatingControl | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        }
        if ($null -ne $Baseline -and @($Baseline).Count -gt 0) {
            if (@($Baseline | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
                throw '-Baseline contains an empty baseline name.'
            }
            $entry.baselines = @($Baseline)
        }
        if ($Status -eq 'Approved') {
            if ([string]::IsNullOrWhiteSpace($ApprovedBy)) {
                throw '-ApprovedBy is required for an Approved exception.'
            }
            if ($null -eq $CompensatingControl -or @($entry.compensatingControls).Count -eq 0) {
                throw '-CompensatingControl requires at least one entry for an Approved exception.'
            }
            if ($ApprovedOn.Date -gt (Get-Date).Date) {
                throw '-ApprovedOn cannot be in the future.'
            }
            if ($ApprovedOn.Date -gt $Expires.Date) {
                throw '-ApprovedOn cannot occur after -Expires.'
            }
            $entry.approvedBy = $ApprovedBy.Trim()
            $entry.approvedOn = $ApprovedOn.ToString('yyyy-MM-dd')
        }
        $exceptions = @([pscustomobject]$entry)
    }

    $document = [pscustomobject][ordered]@{
        '$schema'     = 'https://raw.githubusercontent.com/xGreeny/hardening-lens/v1.0.1/src/HardeningLens/Schema/exception.schema.json'
        schemaVersion = '1.0'
        exceptions    = $exceptions
    }

    if ($PSCmdlet.ShouldProcess($fullPath, 'Create Hardening Lens exception register')) {
        $parent = Split-Path -Path $fullPath -Parent
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            [void](New-Item -Path $parent -ItemType Directory -Force)
        }

        $fileLock = Enter-HLFileLock -Path $fullPath
        try {
            # Repeat the no-clobber check while holding the same lock used by lifecycle
            # updates. This closes the check/write race between cooperating processes.
            if ((Test-Path -LiteralPath $fullPath) -and -not $Force) {
                throw "File already exists: $fullPath. Use -Force to overwrite."
            }
            try {
                Write-HLAtomicUtf8File -Path $fullPath -Content (($document | ConvertTo-Json -Depth 20) + [Environment]::NewLine) -NoClobber:(-not $Force)
            }
            catch [System.IO.IOException] {
                if (-not $Force -and (Test-Path -LiteralPath $fullPath)) {
                    throw "File already exists: $fullPath. Use -Force to overwrite."
                }
                throw
            }
            return Get-Item -LiteralPath $fullPath
        }
        finally {
            Exit-HLFileLock -Lock $fileLock
        }
    }
}
