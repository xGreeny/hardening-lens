function Get-HardeningLensControl {
    <#
    .SYNOPSIS
    Returns controls from the curated Hardening Lens catalog.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Id,

        [string]$Category,

        [string]$Tag,

        [switch]$RawCatalog
    )

    # The catalog is cached for performance. Never expose that mutable cache through
    # the public API: callers commonly enrich returned objects for their own reports.
    $catalog = Copy-HLObject -InputObject (Get-HLControlCatalog)
    if ($RawCatalog) {
        return $catalog
    }

    $controls = @($catalog.controls)
    if ($null -ne $Id -and @($Id).Count -gt 0) {
        $controls = @($controls | Where-Object {
            $controlId = [string]$_.id
            @($Id | Where-Object { $controlId -like [string]$_ }).Count -gt 0
        })
    }
    if (-not [string]::IsNullOrWhiteSpace($Category)) {
        $controls = @($controls | Where-Object { [string]$_.category -like $Category })
    }
    if (-not [string]::IsNullOrWhiteSpace($Tag)) {
        $controls = @($controls | Where-Object { $Tag -in @($_.tags) })
    }

    return @($controls | Sort-Object category, id)
}
