function Export-HardeningLensFleetReport {
    <#
    .SYNOPSIS
    Exports an aggregated, self-contained HTML report for a fleet assessment.

    .DESCRIPTION
    Renders the consolidated result of Invoke-HardeningLensFleet as one portable HTML page: run metadata, per-host scores and status counts, failed collections, and the controls affecting the most hosts. The report embeds no external scripts, styles, fonts, or images and uses a restrictive Content Security Policy.

    .PARAMETER InputObject
    Fleet result returned by Invoke-HardeningLensFleet.

    .PARAMETER Path
    Path to a previously written fleet-result JSON file.

    .PARAMETER OutputDirectory
    Destination directory. It is created when missing.

    .PARAMETER FileNamePrefix
    Optional file name prefix without an extension.

    .PARAMETER Force
    Overwrites an existing report file. Without Force, an existing file causes an error.

    .EXAMPLE
    Invoke-HardeningLensFleet -ComputerName SRV-01, SRV-02 -Baseline MemberServer -OutputDirectory .\fleet | Export-HardeningLensFleetReport -OutputDirectory .\fleet

    .EXAMPLE
    Export-HardeningLensFleetReport -Path .\fleet\run\fleet-result.json -OutputDirectory .\reports
    #>
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Object')]
        [object]$InputObject,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [string]$OutputDirectory = (Get-Location).Path,

        [string]$FileNamePrefix,

        [switch]$Force
    )

    begin {
        $usedPrefixes = @{}
    }

    process {
        $fleetResult = if ($PSCmdlet.ParameterSetName -eq 'Path') {
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
                throw "Fleet result file not found: '$Path'."
            }
            Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
        }
        else {
            $InputObject
        }
        Assert-HLFleetResult -FleetResult $fleetResult

        if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
            [void](New-Item -Path $OutputDirectory -ItemType Directory -Force)
        }
        $resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory -ErrorAction Stop).Path

        if ([string]::IsNullOrWhiteSpace($FileNamePrefix)) {
            $runPart = ConvertTo-HLFileNamePart -Value (@(([string]$fleetResult.run.id) -split '-')[0])
            $timestamp = try { ([datetime]$fleetResult.run.completedAt).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') } catch { (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') }
            $basePrefix = "hardening-lens-fleet-$runPart-$timestamp"
        }
        else {
            $basePrefix = ConvertTo-HLFileNamePart -Value $FileNamePrefix
        }

        if ([string]::IsNullOrWhiteSpace($basePrefix)) {
            throw 'FileNamePrefix does not contain any valid file-name characters.'
        }

        $currentPrefix = $basePrefix
        $suffix = 1
        while ($usedPrefixes.ContainsKey($currentPrefix)) {
            $suffix++
            $currentPrefix = '{0}-{1}' -f $basePrefix, $suffix
        }
        $usedPrefixes[$currentPrefix] = $true

        $outputPath = Join-Path -Path $resolvedOutput -ChildPath ($currentPrefix + '.html')
        if (-not $Force -and (Test-Path -LiteralPath $outputPath)) {
            throw ("Output file already exists: '{0}'. Use -Force to overwrite the existing report file." -f $outputPath)
        }

        $content = ConvertTo-HLFleetHtmlReport -FleetResult $fleetResult
        Write-HLReportFile -Path $outputPath -Content $content -Force:$Force
        $file = Get-Item -LiteralPath $outputPath
        return [pscustomobject][ordered]@{
            Format = 'Html'
            Path   = $file.FullName
            Bytes  = $file.Length
        }
    }
}
