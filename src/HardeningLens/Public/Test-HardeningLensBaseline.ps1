function Test-HardeningLensBaseline {
    <#
    .SYNOPSIS
    Validates a custom Hardening Lens baseline and returns a structured result.

    .DESCRIPTION
    Performs the same catalog, override, exclusion, and parameter-type validation used
    at assessment runtime. Input objects are deep-copied and are never modified.

    .PARAMETER InputObject
    Baseline document object to validate.

    .PARAMETER Path
    Path to a custom baseline JSON document.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Object')]
        [object]$InputObject,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$Path
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            try {
                $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
                $document = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop | ConvertFrom-Json
                return Test-HLBaselineRuntimeDocument -Document $document -Source "Custom baseline '$resolvedPath'" -Path $resolvedPath
            }
            catch {
                return [pscustomobject][ordered]@{
                    IsValid      = $false
                    Errors       = @($_.Exception.Message)
                    Warnings     = @()
                    Name         = $null
                    Version      = $null
                    ControlCount = 0
                    Path         = $Path
                }
            }
        }

        return Test-HLBaselineRuntimeDocument -Document $InputObject -Source 'Baseline input object' -Path $null
    }
}
