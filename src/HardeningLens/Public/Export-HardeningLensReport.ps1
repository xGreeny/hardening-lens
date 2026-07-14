function Export-HardeningLensReport {
    <#
    .SYNOPSIS
    Exports a Hardening Lens scan as self-contained HTML, JSON, and/or CSV.

    .PARAMETER InputObject
    Scan result returned by Invoke-HardeningLens.

    .PARAMETER Path
    Path to a previously exported scan JSON file.

    .PARAMETER Format
    One or more output formats. The default is Html, Json, and Csv.

    .PARAMETER OutputDirectory
    Destination directory. It is created when missing.

    .PARAMETER FileNamePrefix
    Optional file name prefix without an extension.

    .PARAMETER Force
    Overwrites existing report files. Without Force, existing files cause an error.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Object')]
        [object]$InputObject,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$Path,

        [ValidateSet('Html', 'Json', 'Csv')]
        [string[]]$Format = @('Html', 'Json', 'Csv'),

        [string]$OutputDirectory = (Get-Location).Path,

        [string]$FileNamePrefix,

        [switch]$Force
    )

    begin {
        $usedPrefixes = @{}
    }

    process {
        $scanResult = if ($PSCmdlet.ParameterSetName -eq 'Path') { Read-HLScanResult -InputObject $Path } else { $InputObject }
        Assert-HLScanResult -ScanResult $scanResult

        if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
            [void](New-Item -Path $OutputDirectory -ItemType Directory -Force)
        }
        $resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory -ErrorAction Stop).Path

        if ([string]::IsNullOrWhiteSpace($FileNamePrefix)) {
            $hostPart = ConvertTo-HLFileNamePart -Value ([string]$scanResult.system.ComputerName)
            $timestamp = try { ([datetime]$scanResult.scan.collectedAt).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') } catch { (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') }
            $basePrefix = "hardening-lens-$hostPart-$timestamp"
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

        $plannedOutputs = New-Object System.Collections.Generic.List[object]
        foreach ($outputFormat in @($Format | Sort-Object -Unique)) {
            $extension = switch ($outputFormat) {
                'Html' { '.html' }
                'Json' { '.json' }
                'Csv' { '.csv' }
            }
            $plannedOutputs.Add([pscustomobject][ordered]@{
                Format = $outputFormat
                Path = Join-Path -Path $resolvedOutput -ChildPath ($currentPrefix + $extension)
            })
        }

        if (-not $Force) {
            $existing = @($plannedOutputs | Where-Object { Test-Path -LiteralPath $_.Path })
            if ($existing.Count -gt 0) {
                throw ("Output file already exists: '{0}'. Use -Force to overwrite existing report files." -f $existing[0].Path)
            }
        }

        $written = New-Object System.Collections.Generic.List[object]
        foreach ($plannedOutput in $plannedOutputs) {
            $content = switch ($plannedOutput.Format) {
                'Html' {
                    ConvertTo-HLHtmlReport -ScanResult $scanResult
                }
                'Json' {
                    ($scanResult | ConvertTo-Json -Depth 40) + [Environment]::NewLine
                }
                'Csv' {
                    $csv = @($scanResult.results | ForEach-Object { ConvertTo-HLFlatResult -Result $_ } | ConvertTo-Csv -NoTypeInformation)
                    ($csv -join [Environment]::NewLine) + [Environment]::NewLine
                }
            }

            Write-HLReportFile -Path $plannedOutput.Path -Content $content -Force:$Force
            $file = Get-Item -LiteralPath $plannedOutput.Path
            $written.Add([pscustomobject][ordered]@{ Format = $plannedOutput.Format; Path = $file.FullName; Bytes = $file.Length })
        }

        return $written.ToArray()
    }
}
