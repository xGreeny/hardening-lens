function Invoke-HardeningLens {
    <#
    .SYNOPSIS
    Runs a read-only Windows security posture assessment.

    .DESCRIPTION
    Resolves a built-in or custom baseline, collects local evidence through read-only Windows APIs and cmdlets, applies active governed exceptions, and returns a structured scan result. The command makes no configuration changes.

    .PARAMETER Baseline
    Built-in baseline name. Auto selects Workstation, MemberServer, or DomainController from Win32_OperatingSystem. AVDSessionHost must be selected explicitly.

    .PARAMETER BaselinePath
    Path to a custom baseline JSON document. Custom baselines can extend one built-in profile.

    .PARAMETER ControlId
    Runs only selected controls from the resolved baseline.

    .PARAMETER ExceptionsPath
    Path to a governed exception register. Only Approved, unexpired, matching exceptions are applied.

    .PARAMETER AllowPartial
    Permits collection without elevation. Controls that cannot be resolved remain Unknown or Error rather than being skipped silently.

    .PARAMETER Redact
    Replaces computer, domain, and current-user identifiers in the returned result.

    .PARAMETER NoConsole
    Suppresses the interactive summary.

    .EXAMPLE
    Invoke-HardeningLens -Baseline MemberServer -ExceptionsPath .\exceptions.json

    .EXAMPLE
    Invoke-HardeningLens -BaselinePath .\custom-baseline.json -ControlId HL-SMB-003,HL-SMB-004 -Redact
    #>
    [CmdletBinding(DefaultParameterSetName = 'Named')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Hardening Lens is the singular product name.')]
    param(
        [Parameter(ParameterSetName = 'Named')]
        [ValidateSet('Auto', 'Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
        [string]$Baseline = 'Auto',

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [ValidateNotNullOrEmpty()]
        [string]$BaselinePath,

        [ValidateNotNullOrEmpty()]
        [string[]]$ControlId,

        [string]$ExceptionsPath,

        [switch]$AllowPartial,

        [switch]$Redact,

        [switch]$NoConsole
    )

    Assert-HLWindows
    $collectionContext = New-HLCollectionContext
    $systemContext = Get-HLSystemContext
    if (-not $systemContext.IsElevated -and -not $AllowPartial) {
        throw 'Run Hardening Lens from an elevated PowerShell session, or use -AllowPartial to preserve unresolved controls as evidence gaps.'
    }

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        $resolvedBaseline = Resolve-HLBaseline -Path $BaselinePath
        $baselineSource = 'Custom'
    }
    else {
        $baselineName = if ($Baseline -eq 'Auto') { Get-HLAutoBaselineName -SystemContext $systemContext } else { $Baseline }
        $resolvedBaseline = Resolve-HLBaseline -Name $baselineName
        $baselineSource = 'BuiltIn'
    }

    if ([string]$resolvedBaseline.name -ne 'AVDSessionHost' -and @($resolvedBaseline.supportedRoles).Count -gt 0 -and [string]$systemContext.DetectedRole -notin @($resolvedBaseline.supportedRoles)) {
        Write-Warning "Detected role '$($systemContext.DetectedRole)' is not listed by baseline '$($resolvedBaseline.name)'. The explicit baseline selection is retained."
    }

    $exceptions = @()
    $exceptionValidation = $null
    $exceptionDocument = $null
    if (-not [string]::IsNullOrWhiteSpace($ExceptionsPath)) {
        $exceptionFile = Read-HLExceptionFile -Path $ExceptionsPath
        $exceptionDocument = $exceptionFile.Document
        $exceptionValidation = Test-HLExceptionDocument -Document $exceptionFile.Document
        if (-not $exceptionValidation.IsValid) {
            throw ('Exception register validation failed: {0}' -f (@($exceptionValidation.Errors) -join ' '))
        }
        foreach ($warning in @($exceptionValidation.Warnings)) {
            Write-Verbose $warning
        }
        $exceptions = @($exceptionFile.Exceptions)
    }

    $controls = @($resolvedBaseline.controls)
    if ($null -ne $ControlId -and @($ControlId).Count -gt 0) {
        $baselineIds = @($controls | ForEach-Object { [string]$_.id })
        foreach ($requestedId in @($ControlId)) {
            if ([string]$requestedId -notin $baselineIds) {
                throw "Control '$requestedId' is not present in baseline '$($resolvedBaseline.name)'."
            }
        }
        $controls = @($controls | Where-Object { [string]$_.id -in @($ControlId) })
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($control in $controls) {
        Write-Verbose "Evaluating $($control.id): $($control.title)"
        $collectedAt = (Get-Date).ToUniversalTime().ToString('o')
        $probeResult = Invoke-HLProbe -Control $control -SystemContext $systemContext -CollectionContext $collectionContext
        $status = [string]$probeResult.Status
        $originalStatus = $null
        $appliedException = $null

        if ($status -in @('Fail', 'Warning') -and $exceptions.Count -gt 0) {
            $match = Get-HLApplicableException -Exceptions $exceptions -ControlId ([string]$control.id) -ComputerName ([string]$systemContext.ComputerName) -BaselineName ([string]$resolvedBaseline.name)
            if ($null -ne $match) {
                $originalStatus = $status
                $status = 'Excepted'
                $appliedException = [pscustomobject][ordered]@{
                    id                   = [string]$match.id
                    owner                = [string]$match.owner
                    reason               = [string]$match.reason
                    ticket               = [string]$match.ticket
                    expires              = [string]$match.expires
                    approvedBy           = if (Test-HLProperty -InputObject $match -Name 'approvedBy') { [string]$match.approvedBy } else { '' }
                    compensatingControls = if (Test-HLProperty -InputObject $match -Name 'compensatingControls') { @($match.compensatingControls) } else { @() }
                }
            }
        }

        $results.Add([pscustomobject][ordered]@{
            controlId      = [string]$control.id
            title          = [string]$control.title
            category       = [string]$control.category
            severity       = [string]$control.severity
            status         = $status
            originalStatus = $originalStatus
            expected       = $probeResult.Expected
            actual         = $probeResult.Actual
            message        = [string]$probeResult.Message
            evidence       = $probeResult.Evidence
            rationale      = [string]$control.rationale
            remediation    = [string]$control.remediation
            references     = @($control.references)
            tags           = @($control.tags)
            probe          = [string]$control.probe
            exception      = $appliedException
            collectedAt    = $collectedAt
            probeDurationMs = [int]$probeResult.DurationMs
        })
    }

    $collectionContext.Stopwatch.Stop()
    $catalog = Get-HLControlCatalog
    $provenance = [pscustomobject][ordered]@{
        catalogVersion = [string]$catalog.catalogVersion
        catalogDigest  = Get-HLContentDigest -InputObject $catalog
        baselineDigest = Get-HLContentDigest -InputObject (Get-HLLogicalBaseline -Baseline $resolvedBaseline)
        capabilities   = @(Get-HLProbeCapability -Controls $controls)
    }
    if ($null -ne $exceptionDocument) {
        $provenance | Add-Member -NotePropertyName exceptionDigest -NotePropertyValue (Get-HLContentDigest -InputObject $exceptionDocument)
    }

    $scanResult = [pscustomobject][ordered]@{
        '$schema'     = 'https://raw.githubusercontent.com/xGreeny/hardening-lens/v1.2.1/src/HardeningLens/Schema/result.schema.json'
        schemaVersion = '1.1'
        scan = [pscustomobject][ordered]@{
            id                    = [guid]::NewGuid().ToString()
            collectedAt           = (Get-Date).ToUniversalTime().ToString('o')
            moduleVersion         = Get-HLModuleVersion
            redacted              = $false
            readOnly              = $true
            elevated             = [bool]$systemContext.IsElevated
            partialCollection     = [bool](-not $systemContext.IsElevated)
            exceptionRegisterUsed = [bool](-not [string]::IsNullOrWhiteSpace($ExceptionsPath))
            selectedControlCount  = @($controls).Count
            collectionDurationMs  = [int][math]::Round($collectionContext.Stopwatch.Elapsed.TotalMilliseconds)
        }
        system = $systemContext
        baseline = [pscustomobject][ordered]@{
            name          = [string]$resolvedBaseline.name
            displayName   = [string]$resolvedBaseline.displayName
            version       = [string]$resolvedBaseline.version
            description   = [string]$resolvedBaseline.description
            source        = $baselineSource
            sourceBasis   = @($resolvedBaseline.sourceBasis)
            supportedRoles = @($resolvedBaseline.supportedRoles)
            controlCount  = @($controls).Count
            notes         = @($resolvedBaseline.notes)
        }
        provenance = $provenance
        summary = Get-HLSummary -Results $results.ToArray()
        results = $results.ToArray()
    }

    if ($Redact) {
        $scanResult = Protect-HLResult -ScanResult $scanResult
    }

    if (-not $NoConsole) {
        Write-HLConsoleSummary -ScanResult $scanResult
    }

    $PSCmdlet.WriteObject($scanResult, $false)
}
