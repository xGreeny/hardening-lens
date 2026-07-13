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

        [string]$FileNamePrefix
    )

    process {
        $scanResult = if ($PSCmdlet.ParameterSetName -eq 'Path') { Read-HLScanResult -InputObject $Path } else { $InputObject }
        if (-not (Test-HLProperty -InputObject $scanResult -Name 'schemaVersion') -or [string]$scanResult.schemaVersion -ne '1.0') {
            throw 'Input is not a supported Hardening Lens scan result.'
        }

        if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
            [void](New-Item -Path $OutputDirectory -ItemType Directory -Force)
        }
        $resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory -ErrorAction Stop).Path

        if ([string]::IsNullOrWhiteSpace($FileNamePrefix)) {
            $hostPart = ConvertTo-HLFileNamePart -Value ([string]$scanResult.system.ComputerName)
            $timestamp = try { ([datetime]$scanResult.scan.collectedAt).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') } catch { (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') }
            $FileNamePrefix = "hardening-lens-$hostPart-$timestamp"
        }
        else {
            $FileNamePrefix = ConvertTo-HLFileNamePart -Value $FileNamePrefix
        }

        $written = New-Object System.Collections.Generic.List[object]
        foreach ($outputFormat in @($Format | Sort-Object -Unique)) {
            switch ($outputFormat) {
                'Html' {
                    $outputPath = Join-Path -Path $resolvedOutput -ChildPath ($FileNamePrefix + '.html')
                    Write-HLUtf8File -Path $outputPath -Content (ConvertTo-HLHtmlReport -ScanResult $scanResult)
                }
                'Json' {
                    $outputPath = Join-Path -Path $resolvedOutput -ChildPath ($FileNamePrefix + '.json')
                    Write-HLUtf8File -Path $outputPath -Content (($scanResult | ConvertTo-Json -Depth 40) + [Environment]::NewLine)
                }
                'Csv' {
                    $outputPath = Join-Path -Path $resolvedOutput -ChildPath ($FileNamePrefix + '.csv')
                    $csv = @($scanResult.results | ForEach-Object { ConvertTo-HLFlatResult -Result $_ } | ConvertTo-Csv -NoTypeInformation)
                    Write-HLUtf8File -Path $outputPath -Content (($csv -join [Environment]::NewLine) + [Environment]::NewLine)
                }
            }

            $file = Get-Item -LiteralPath $outputPath
            $written.Add([pscustomobject][ordered]@{ Format = $outputFormat; Path = $file.FullName; Bytes = $file.Length })
        }

        return $written.ToArray()
    }
}
