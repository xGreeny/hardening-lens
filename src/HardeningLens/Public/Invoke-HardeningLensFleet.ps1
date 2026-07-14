function Invoke-HardeningLensFleet {
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ComputerName')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [Parameter(Mandatory, ParameterSetName = 'Inventory')]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$InventoryPath,

        [ValidateSet('Auto', 'Workstation', 'MemberServer', 'DomainController', 'AVDSessionHost')]
        [string]$Baseline = 'Auto',

        [string]$CustomBaselinePath,

        [string]$ExceptionsPath,

        [Parameter(Mandatory)]
        [string]$OutputDirectory,

        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = 8,

        [ValidateRange(30, 3600)]
        [int]$TimeoutSeconds = 300,

        [ValidateRange(0, 5)]
        [int]$RetryCount = 1,

        [pscredential]$Credential,

        [switch]$Resume,

        [switch]$Redact
    )

    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    $resolvedOutput = [System.IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory))
    $resultDirectory = Join-Path -Path $resolvedOutput -ChildPath 'results'
    $failureDirectory = Join-Path -Path $resolvedOutput -ChildPath 'failures'
    [void](New-Item -Path $resultDirectory -ItemType Directory -Force)
    [void](New-Item -Path $failureDirectory -ItemType Directory -Force)

    $targets = New-Object System.Collections.Generic.List[object]
    if ($PSCmdlet.ParameterSetName -eq 'Inventory') {
        $inventory = Get-Content -LiteralPath (Resolve-Path -LiteralPath $InventoryPath) -Raw -ErrorAction Stop | ConvertFrom-Json
        foreach ($target in @($inventory.targets)) {
            if ([string]::IsNullOrWhiteSpace([string]$target.computerName)) {
                throw 'Every fleet inventory target requires computerName.'
            }
            $targetBaseline = if ([string]::IsNullOrWhiteSpace([string]$target.baseline)) { $Baseline } else { [string]$target.baseline }
            $targets.Add([pscustomobject][ordered]@{
                ComputerName = [string]$target.computerName
                Baseline     = $targetBaseline
                Tags         = @($target.tags)
            })
        }
    }
    else {
        foreach ($name in $ComputerName) {
            $targets.Add([pscustomobject][ordered]@{ ComputerName = [string]$name; Baseline = $Baseline; Tags = @() })
        }
    }

    if ($targets.Count -eq 0) { throw 'No fleet targets were supplied.' }
    $duplicateNames = @($targets | Group-Object ComputerName | Where-Object Count -gt 1)
    if ($duplicateNames.Count -gt 0) {
        throw "Fleet inventory contains duplicate targets: $(@($duplicateNames.Name) -join ', ')."
    }

    $runId = [guid]::NewGuid().ToString()
    $startedAt = (Get-Date).ToUniversalTime()
    $records = New-Object System.Collections.Generic.List[object]
    $pending = New-Object System.Collections.Generic.List[object]

    foreach ($target in $targets) {
        $safeName = ([string]$target.ComputerName -replace '[^A-Za-z0-9._-]', '_')
        $existingPath = Join-Path -Path $resultDirectory -ChildPath "$safeName.json"
        if ($Resume -and (Test-Path -LiteralPath $existingPath)) {
            $records.Add([pscustomobject][ordered]@{
                ComputerName = $target.ComputerName
                Baseline     = $target.Baseline
                Tags         = $target.Tags
                Outcome      = 'SkippedFromResume'
                Attempts     = 0
                DurationMs   = 0
                ResultPath   = $existingPath
                FailurePath  = $null
                Message      = 'An existing successful result was retained.'
            })
        }
        else {
            $pending.Add($target)
        }
    }

    $archivePath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("HardeningLens-{0}.zip" -f [guid]::NewGuid())
    try {
        Compress-Archive -Path (Join-Path -Path $moduleRoot -ChildPath '*') -DestinationPath $archivePath -CompressionLevel Optimal -Force
        $moduleArchive = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($archivePath))
        $exceptionContent = if (-not [string]::IsNullOrWhiteSpace($ExceptionsPath)) { Get-Content -LiteralPath (Resolve-Path -LiteralPath $ExceptionsPath) -Raw } else { $null }
        $customBaselineContent = if (-not [string]::IsNullOrWhiteSpace($CustomBaselinePath)) { Get-Content -LiteralPath (Resolve-Path -LiteralPath $CustomBaselinePath) -Raw } else { $null }

        $attempt = 0
        while ($pending.Count -gt 0 -and $attempt -le $RetryCount) {
            $attempt++
            $configuration = [ordered]@{}
            foreach ($target in $pending) {
                $configuration[[string]$target.ComputerName] = [ordered]@{ Baseline = [string]$target.Baseline; Tags = @($target.Tags) }
            }
            $configurationJson = $configuration | ConvertTo-Json -Depth 12 -Compress
            $names = @($pending | ForEach-Object ComputerName)
            $invokeParameters = @{
                ComputerName  = $names
                AsJob         = $true
                ThrottleLimit = $ThrottleLimit
                ScriptBlock   = {
                    param($Archive, $ConfigurationJson, $ExceptionJson, $CustomBaselineJson, $UseRedaction)
                    $started = [datetime]::UtcNow
                    $temporaryRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("HardeningLens-{0}" -f [guid]::NewGuid())
                    try {
                        [void](New-Item -Path $temporaryRoot -ItemType Directory -Force)
                        $zipPath = Join-Path -Path $temporaryRoot -ChildPath 'module.zip'
                        [System.IO.File]::WriteAllBytes($zipPath, [Convert]::FromBase64String($Archive))
                        Expand-Archive -LiteralPath $zipPath -DestinationPath (Join-Path $temporaryRoot 'module') -Force
                        $manifestPath = Join-Path -Path $temporaryRoot -ChildPath 'module/HardeningLens.psd1'
                        Import-Module -Name $manifestPath -Force -ErrorAction Stop
                        $configuration = $ConfigurationJson | ConvertFrom-Json
                        $computerConfig = $configuration.PSObject.Properties | Where-Object { $_.Name -ieq $env:COMPUTERNAME } | Select-Object -First 1
                        if ($null -eq $computerConfig) { throw "No fleet configuration exists for $env:COMPUTERNAME." }

                        $parameters = @{ Baseline = [string]$computerConfig.Value.Baseline; NoConsole = $true }
                        if ($UseRedaction) { $parameters.Redact = $true }
                        if (-not [string]::IsNullOrWhiteSpace($ExceptionJson)) {
                            $remoteExceptionPath = Join-Path $temporaryRoot 'exceptions.json'
                            Set-Content -LiteralPath $remoteExceptionPath -Value $ExceptionJson -Encoding UTF8
                            $parameters.ExceptionsPath = $remoteExceptionPath
                        }
                        if (-not [string]::IsNullOrWhiteSpace($CustomBaselineJson)) {
                            $remoteBaselinePath = Join-Path $temporaryRoot 'custom-baseline.json'
                            Set-Content -LiteralPath $remoteBaselinePath -Value $CustomBaselineJson -Encoding UTF8
                            $parameters.CustomBaselinePath = $remoteBaselinePath
                        }

                        $scanResult = Invoke-HardeningLens @parameters
                        [pscustomobject][ordered]@{
                            ComputerName = $env:COMPUTERNAME
                            Outcome      = 'Completed'
                            DurationMs   = [int]([datetime]::UtcNow - $started).TotalMilliseconds
                            Result       = $scanResult
                            Message      = 'Assessment completed.'
                        }
                    }
                    catch {
                        [pscustomobject][ordered]@{
                            ComputerName = $env:COMPUTERNAME
                            Outcome      = 'AssessmentFailed'
                            DurationMs   = [int]([datetime]::UtcNow - $started).TotalMilliseconds
                            Result       = $null
                            Message      = $_.Exception.Message
                        }
                    }
                    finally {
                        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
                ArgumentList  = @($moduleArchive, $configurationJson, $exceptionContent, $customBaselineContent, [bool]$Redact)
                ErrorAction   = 'SilentlyContinue'
            }
            if ($null -ne $Credential) { $invokeParameters.Credential = $Credential }

            $job = Invoke-Command @invokeParameters
            $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
            if ($null -eq $completed) {
                Stop-Job -Job $job -Force -ErrorAction SilentlyContinue
            }

            $nextPending = New-Object System.Collections.Generic.List[object]
            foreach ($target in $pending) {
                $child = @($job.ChildJobs | Where-Object { [string]$_.Location -ieq [string]$target.ComputerName } | Select-Object -First 1)
                $response = if ($child.Count -gt 0) { Receive-Job -Job $child[0] -ErrorAction SilentlyContinue | Select-Object -Last 1 } else { $null }
                $safeName = ([string]$target.ComputerName -replace '[^A-Za-z0-9._-]', '_')
                if ($null -ne $response -and [string]$response.Outcome -eq 'Completed' -and $null -ne $response.Result) {
                    $resultPath = Join-Path -Path $resultDirectory -ChildPath "$safeName.json"
                    $response.Result | ConvertTo-Json -Depth 60 | Set-Content -LiteralPath $resultPath -Encoding UTF8
                    $records.Add([pscustomobject][ordered]@{
                        ComputerName = $target.ComputerName
                        Baseline     = $target.Baseline
                        Tags         = $target.Tags
                        Outcome      = 'Completed'
                        Attempts     = $attempt
                        DurationMs   = [int]$response.DurationMs
                        ResultPath   = $resultPath
                        FailurePath  = $null
                        Message      = [string]$response.Message
                    })
                }
                elseif ($attempt -le $RetryCount) {
                    $nextPending.Add($target)
                }
                else {
                    $message = if ($null -ne $response) { [string]$response.Message } elseif ($child.Count -gt 0 -and $child[0].Error.Count -gt 0) { [string]$child[0].Error[0].Exception.Message } else { 'No response was received before the timeout or the WinRM connection failed.' }
                    $outcome = if ($null -ne $response) { [string]$response.Outcome } elseif ($null -eq $completed) { 'TimedOut' } else { 'ConnectionFailed' }
                    $failure = [pscustomobject][ordered]@{
                        schemaVersion = '1.0'
                        runId         = $runId
                        computerName  = $target.ComputerName
                        baseline      = $target.Baseline
                        tags          = $target.Tags
                        outcome       = $outcome
                        attempts      = $attempt
                        message       = $message
                        recordedAt    = (Get-Date).ToUniversalTime().ToString('o')
                    }
                    $failurePath = Join-Path -Path $failureDirectory -ChildPath "$safeName.json"
                    $failure | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $failurePath -Encoding UTF8
                    $records.Add([pscustomobject][ordered]@{
                        ComputerName = $target.ComputerName
                        Baseline     = $target.Baseline
                        Tags         = $target.Tags
                        Outcome      = $outcome
                        Attempts     = $attempt
                        DurationMs   = if ($null -ne $response) { [int]$response.DurationMs } else { $TimeoutSeconds * 1000 }
                        ResultPath   = $null
                        FailurePath  = $failurePath
                        Message      = $message
                    })
                }
            }
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            $pending = $nextPending
        }
    }
    finally {
        Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
    }

    $finishedAt = (Get-Date).ToUniversalTime()
    $completedRecords = @($records | Where-Object Outcome -eq 'Completed')
    $failedRecords = @($records | Where-Object Outcome -in @('ConnectionFailed', 'AssessmentFailed', 'TimedOut'))
    $skippedRecords = @($records | Where-Object Outcome -eq 'SkippedFromResume')
    $scores = New-Object System.Collections.Generic.List[double]
    $coverages = New-Object System.Collections.Generic.List[double]
    foreach ($record in $completedRecords) {
        $scan = Get-Content -LiteralPath $record.ResultPath -Raw | ConvertFrom-Json
        foreach ($candidate in @('ScorePercent', 'scorePercent')) {
            if ($null -ne $scan.summary.PSObject.Properties[$candidate]) { $scores.Add([double]$scan.summary.$candidate); break }
        }
        foreach ($candidate in @('EvidenceCoveragePercent', 'evidenceCoveragePercent', 'CoveragePercent', 'coveragePercent')) {
            if ($null -ne $scan.summary.PSObject.Properties[$candidate]) { $coverages.Add([double]$scan.summary.$candidate); break }
        }
    }

    $manifest = [pscustomobject][ordered]@{
        schemaVersion          = '1.0'
        runId                  = $runId
        startedAt              = $startedAt.ToString('o')
        finishedAt             = $finishedAt.ToString('o')
        durationMs             = [int]($finishedAt - $startedAt).TotalMilliseconds
        requested              = $targets.Count
        completed              = $completedRecords.Count
        failed                 = $failedRecords.Count
        skippedFromResume      = $skippedRecords.Count
        averageScorePercent    = if ($scores.Count -gt 0) { [math]::Round(($scores | Measure-Object -Average).Average, 1) } else { $null }
        averageCoveragePercent = if ($coverages.Count -gt 0) { [math]::Round(($coverages | Measure-Object -Average).Average, 1) } else { $null }
        records                = $records.ToArray()
    }
    $manifestPath = Join-Path -Path $resolvedOutput -ChildPath 'run-manifest.json'
    $manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $records | Export-Csv -LiteralPath (Join-Path $resolvedOutput 'fleet-summary.csv') -NoTypeInformation -Encoding UTF8

    $rows = @($records | ForEach-Object {
        "<tr><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.ComputerName))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.Baseline))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.Outcome))</td><td>$([int]$_.Attempts)</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.Message))</td></tr>"
    }) -join [Environment]::NewLine
    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Hardening Lens Fleet Report</title><style>body{font-family:system-ui;background:#07111f;color:#dbeafe;margin:0;padding:32px}main{max-width:1200px;margin:auto}.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card,table{background:#0d1b2e;border:1px solid #263b55;border-radius:10px}.card{padding:16px}.value{font-size:2rem;font-weight:700}table{width:100%;border-collapse:collapse;margin-top:22px;overflow:hidden}th,td{padding:10px;border-bottom:1px solid #263b55;text-align:left}th{color:#93c5fd}</style></head><body><main><h1>Hardening Lens Fleet Report</h1><p>Run <code>$runId</code></p><div class="cards"><div class="card"><div>Requested</div><div class="value">$($manifest.requested)</div></div><div class="card"><div>Completed</div><div class="value">$($manifest.completed)</div></div><div class="card"><div>Failed</div><div class="value">$($manifest.failed)</div></div><div class="card"><div>Skipped</div><div class="value">$($manifest.skippedFromResume)</div></div></div><table><thead><tr><th>Computer</th><th>Baseline</th><th>Outcome</th><th>Attempts</th><th>Message</th></tr></thead><tbody>$rows</tbody></table></main></body></html>
"@
    Set-Content -LiteralPath (Join-Path $resolvedOutput 'fleet-report.html') -Value $html -Encoding UTF8
    return $manifest
}
