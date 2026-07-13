function Get-HardeningLensBaseline {
    <#
    .SYNOPSIS
    Lists built-in baselines or resolves a built-in/custom baseline.
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(ParameterSetName = 'Named')]
        [ValidateSet('Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$Path,

        [switch]$IncludeControls
    )

    if ($PSCmdlet.ParameterSetName -eq 'List' -or ($PSCmdlet.ParameterSetName -eq 'Named' -and [string]::IsNullOrWhiteSpace($Name))) {
        $items = foreach ($baselineName in Get-HLBuiltinBaselineNames) {
            $baseline = Resolve-HLBaseline -Name $baselineName
            [pscustomobject][ordered]@{
                Name           = [string]$baseline.name
                DisplayName    = [string]$baseline.displayName
                Version        = [string]$baseline.version
                Description    = [string]$baseline.description
                SupportedRoles = @($baseline.supportedRoles)
                ControlCount   = [int]$baseline.controlCount
            }
        }
        return @($items)
    }

    $resolved = if ($PSCmdlet.ParameterSetName -eq 'Path') { Resolve-HLBaseline -Path $Path } else { Resolve-HLBaseline -Name $Name }
    if ($IncludeControls) {
        return $resolved
    }

    return [pscustomobject][ordered]@{
        Name           = [string]$resolved.name
        DisplayName    = [string]$resolved.displayName
        Version        = [string]$resolved.version
        Description    = [string]$resolved.description
        SupportedRoles = @($resolved.supportedRoles)
        ControlCount   = [int]$resolved.controlCount
        ControlIds     = @($resolved.controls | ForEach-Object { [string]$_.id })
        Notes          = @($resolved.notes)
    }
}
