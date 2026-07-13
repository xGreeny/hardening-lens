function Read-HLExceptionFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $document = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop | ConvertFrom-Json
    return [pscustomobject][ordered]@{
        Path       = $resolvedPath
        Document   = $document
        Exceptions = @($document.exceptions)
    }
}

function Test-HLDateString {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory)]
        [ref]$ParsedDate
    )

    $candidate = [datetime]::MinValue
    $valid = [datetime]::TryParseExact(
        [string]$Value,
        'yyyy-MM-dd',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None,
        [ref]$candidate
    )
    if ($valid) {
        $ParsedDate.Value = $candidate
    }
    return $valid
}

function Test-HLExceptionDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Document
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $catalogIds = @((Get-HLControlCatalog).controls | ForEach-Object { [string]$_.id })

    if (-not (Test-HLProperty -InputObject $Document -Name 'schemaVersion') -or [string]$Document.schemaVersion -ne '1.0') {
        $errors.Add("schemaVersion must be '1.0'.")
    }
    if (-not (Test-HLProperty -InputObject $Document -Name 'exceptions')) {
        $errors.Add('The document must contain an exceptions array.')
        return [pscustomobject][ordered]@{ IsValid = $false; Errors = $errors.ToArray(); Warnings = $warnings.ToArray(); ExceptionCount = 0 }
    }

    $seen = @{}
    $index = 0
    foreach ($exception in @($Document.exceptions)) {
        $index++
        $prefix = "Exception #$index"
        foreach ($required in @('id', 'controlId', 'status', 'owner', 'reason', 'ticket', 'expires', 'targets')) {
            if (-not (Test-HLProperty -InputObject $exception -Name $required) -or $null -eq $exception.$required) {
                $errors.Add("$prefix is missing required property '$required'.")
            }
        }

        if (Test-HLProperty -InputObject $exception -Name 'id') {
            $id = [string]$exception.id
            if ([string]::IsNullOrWhiteSpace($id)) {
                $errors.Add("$prefix has an empty id.")
            }
            elseif ($id -notmatch '^EXC-[A-Za-z0-9._-]+$') {
                $errors.Add("Exception id '$id' does not match EXC-<identifier>.")
            }
            elseif ($seen.ContainsKey($id)) {
                $errors.Add("Duplicate exception id '$id'.")
            }
            else {
                $seen[$id] = $true
            }
        }

        if (Test-HLProperty -InputObject $exception -Name 'controlId') {
            $controlId = [string]$exception.controlId
            if ($controlId -notin $catalogIds) {
                $errors.Add("$prefix references unknown control '$controlId'.")
            }
        }

        $status = if (Test-HLProperty -InputObject $exception -Name 'status') { [string]$exception.status } else { '' }
        if ($status -notin @('Draft', 'Approved', 'Revoked')) {
            $errors.Add("$prefix has unsupported status '$status'.")
        }

        foreach ($propertyName in @('owner', 'ticket')) {
            if ((Test-HLProperty -InputObject $exception -Name $propertyName) -and [string]::IsNullOrWhiteSpace([string]$exception.$propertyName)) {
                $errors.Add("$prefix property '$propertyName' must not be empty.")
            }
        }
        if ((Test-HLProperty -InputObject $exception -Name 'reason') -and ([string]$exception.reason).Trim().Length -lt 10) {
            $errors.Add("$prefix reason must contain at least 10 characters.")
        }

        if (Test-HLProperty -InputObject $exception -Name 'targets') {
            $targets = @($exception.targets)
            if ($targets.Count -eq 0) {
                $errors.Add("$prefix must contain at least one target pattern.")
            }
            elseif (@($targets | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
                $errors.Add("$prefix contains an empty target pattern.")
            }
            if ('*' -in @($targets | ForEach-Object { [string]$_ })) {
                $warnings.Add("$prefix applies to every host. Prefer a narrower target pattern when operationally possible.")
            }
        }

        if ((Test-HLProperty -InputObject $exception -Name 'baselines') -and @($exception.baselines | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
            $errors.Add("$prefix contains an empty baseline name.")
        }

        $expiry = [datetime]::MinValue
        $expiryValid = $false
        if (Test-HLProperty -InputObject $exception -Name 'expires') {
            $expiryValid = Test-HLDateString -Value $exception.expires -ParsedDate ([ref]$expiry)
            if (-not $expiryValid) {
                $errors.Add("$prefix expires must use yyyy-MM-dd.")
            }
            elseif ($status -eq 'Approved' -and $expiry.Date -lt (Get-Date).Date) {
                $warnings.Add("$prefix is approved but expired on $($expiry.ToString('yyyy-MM-dd')). It will not be applied.")
            }
        }

        if ($status -eq 'Approved') {
            if (-not (Test-HLProperty -InputObject $exception -Name 'approvedBy') -or [string]::IsNullOrWhiteSpace([string]$exception.approvedBy)) {
                $errors.Add("$prefix is Approved but approvedBy is missing.")
            }

            $approvedOn = [datetime]::MinValue
            $approvedOnValid = $false
            if (-not (Test-HLProperty -InputObject $exception -Name 'approvedOn') -or [string]::IsNullOrWhiteSpace([string]$exception.approvedOn)) {
                $errors.Add("$prefix is Approved but approvedOn is missing.")
            }
            else {
                $approvedOnValid = Test-HLDateString -Value $exception.approvedOn -ParsedDate ([ref]$approvedOn)
                if (-not $approvedOnValid) {
                    $errors.Add("$prefix approvedOn must use yyyy-MM-dd.")
                }
                elseif ($approvedOn.Date -gt (Get-Date).Date) {
                    $errors.Add("$prefix approvedOn cannot be in the future.")
                }
            }

            if (-not (Test-HLProperty -InputObject $exception -Name 'compensatingControls') -or @($exception.compensatingControls).Count -eq 0) {
                $errors.Add("$prefix is Approved but compensatingControls is empty.")
            }
            elseif (@($exception.compensatingControls | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
                $errors.Add("$prefix contains an empty compensating control.")
            }

            if ($expiryValid -and $approvedOnValid -and $approvedOn.Date -gt $expiry.Date) {
                $errors.Add("$prefix approvedOn occurs after expires.")
            }
        }
    }

    return [pscustomobject][ordered]@{
        IsValid        = $errors.Count -eq 0
        Errors         = $errors.ToArray()
        Warnings       = $warnings.ToArray()
        ExceptionCount = @($Document.exceptions).Count
    }
}

function Get-HLApplicableException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Exceptions,

        [Parameter(Mandatory)]
        [string]$ControlId,

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [string]$BaselineName
    )

    foreach ($exception in @($Exceptions)) {
        if ([string]$exception.status -ne 'Approved') { continue }
        if ([string]$exception.controlId -ne $ControlId) { continue }

        $expiry = [datetime]::MinValue
        if (-not (Test-HLDateString -Value $exception.expires -ParsedDate ([ref]$expiry))) { continue }
        if ($expiry.Date -lt (Get-Date).Date) { continue }

        $targetMatch = $false
        foreach ($target in @($exception.targets)) {
            if ($ComputerName -like [string]$target) {
                $targetMatch = $true
                break
            }
        }
        if (-not $targetMatch) { continue }

        if ((Test-HLProperty -InputObject $exception -Name 'baselines') -and @($exception.baselines).Count -gt 0) {
            if ($BaselineName -notin @($exception.baselines | ForEach-Object { [string]$_ })) { continue }
        }

        return $exception
    }

    return $null
}
