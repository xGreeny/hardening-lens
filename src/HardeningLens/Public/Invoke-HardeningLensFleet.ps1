function Invoke-HardeningLensFleet {
    <#
    .SYNOPSIS
    Runs Hardening Lens assessments across remote Windows computers.

    .DESCRIPTION
    Collects computer names from the pipeline, transfers the current Hardening Lens module to each target, and invokes the read-only Invoke-HardeningLens assessment through PowerShell remoting. The command returns one consolidated schema-versioned fleet result whose hosts array contains exactly one ordered outcome for every requested computer.

    .PARAMETER ComputerName
    Remote computer names. Values can be supplied directly, through the pipeline, or through properties named ComputerName, CN, Name, or DNSHostName.

    .PARAMETER Baseline
    Built-in baseline name. Auto lets each remote computer select its role-specific baseline.

    .PARAMETER CustomBaselinePath
    Local path to a custom baseline JSON document. The document is transferred to each remote computer for the assessment.

    .PARAMETER ControlId
    Runs only selected controls from the resolved baseline on every computer.

    .PARAMETER ExceptionPath
    Local path to a governed exception register. The document is transferred to each remote computer.

    .PARAMETER Redact
    Redacts computer, domain, and current-user identifiers in every successful assessment.

    .PARAMETER Credential
    Credential used by PowerShell remoting.

    .PARAMETER ThrottleLimit
    Maximum number of concurrent remoting operations.

    .PARAMETER OutputDirectory
    Parent directory for committed run directories containing host results, failures, summary CSV, manifest, commit marker, and consolidated fleet result.

    .PARAMETER Force
    Transactionally replaces a committed run only when the same run identity already exists. The previous run remains intact until the replacement is fully staged.

    .PARAMETER AllowPartial
    Permits non-elevated assessments on remote computers. Unresolved controls remain explicit evidence gaps.

    .PARAMETER FailOnHostError
    Throws a terminating error after all machine-readable artifacts are written when any requested host failed.

    .EXAMPLE
    'server-01','server-02' | Invoke-HardeningLensFleet -Baseline Auto -OutputDirectory .\fleet-results

    .EXAMPLE
    Invoke-HardeningLensFleet -ComputerName (Get-Content .\servers.txt) -CustomBaselinePath .\custom-baseline.json -ExceptionPath .\exceptions.json -AllowPartial
    #>
    [CmdletBinding(DefaultParameterSetName = 'BuiltIn')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Hardening Lens is the singular product name and Fleet identifies the assessment scope.')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
        [Alias('CN', 'Name', 'DNSHostName')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [Parameter(ParameterSetName = 'BuiltIn')]
        [ValidateSet('Auto', 'Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
        [string]$Baseline = 'Auto',

        [Parameter(Mandatory, ParameterSetName = 'Custom')]
        [Alias('BaselinePath')]
        [ValidateNotNullOrEmpty()]
        [string]$CustomBaselinePath,

        [ValidateNotNullOrEmpty()]
        [string[]]$ControlId,

        [Alias('ExceptionsPath')]
        [string]$ExceptionPath,

        [switch]$Redact,

        [pscredential]$Credential,

        [ValidateRange(1, 1024)]
        [int]$ThrottleLimit = 12,

        [ValidateNotNullOrEmpty()]
        [string]$OutputDirectory = (Join-Path -Path (Get-Location).Path -ChildPath 'fleet-results'),

        [switch]$Force,

        [switch]$AllowPartial,

        [switch]$FailOnHostError
    )

    begin {
        $requestedComputers = New-Object System.Collections.Generic.List[string]
    }

    process {
        foreach ($name in @($ComputerName)) {
            if ([string]::IsNullOrWhiteSpace([string]$name)) {
                throw 'ComputerName must not contain empty entries.'
            }
            $requestedComputers.Add(([string]$name).Trim())
        }
    }

    end {
        $parameters = @{
            ComputerName    = $requestedComputers.ToArray()
            Baseline        = $Baseline
            ControlId       = $ControlId
            ExceptionPath   = $ExceptionPath
            Redact          = $Redact
            ThrottleLimit   = $ThrottleLimit
            OutputDirectory = $OutputDirectory
            Force           = $Force
            AllowPartial    = $AllowPartial
        }
        if ($PSCmdlet.ParameterSetName -eq 'Custom') {
            $parameters.CustomBaselinePath = $CustomBaselinePath
        }
        if ($null -ne $Credential) {
            $parameters.Credential = $Credential
        }

        $fleetResult = Invoke-HLFleetAssessment @parameters
        $PSCmdlet.WriteObject($fleetResult, $false)
        if ($FailOnHostError -and $fleetResult.summary.failedCount -gt 0) {
            throw "Fleet assessment $($fleetResult.run.id) failed on $($fleetResult.summary.failedCount) of $($fleetResult.summary.requestedCount) requested host(s)."
        }
    }
}
