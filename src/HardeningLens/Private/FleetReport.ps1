function Assert-HLFleetResult {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$FleetResult
    )

    if ($null -eq $FleetResult) {
        throw 'The fleet result is null. Provide the object returned by Invoke-HardeningLensFleet or a fleet-result JSON file.'
    }
    foreach ($required in @('schemaVersion', 'run', 'summary', 'hosts')) {
        if (-not (Test-HLProperty -InputObject $FleetResult -Name $required)) {
            throw "The fleet result does not contain the required property '$required'."
        }
    }
    if ([string]$FleetResult.schemaVersion -ne '1.1') {
        throw "Unsupported fleet result schema version '$($FleetResult.schemaVersion)'. Supported: 1.1."
    }
    foreach ($required in @('id', 'startedAt', 'completedAt', 'baselineSelection')) {
        if (-not (Test-HLProperty -InputObject $FleetResult.run -Name $required)) {
            throw "The fleet result run block does not contain the required property '$required'."
        }
    }
    $hostEntries = @($FleetResult.hosts)
    if ($hostEntries.Count -eq 0) {
        throw 'The fleet result does not contain any host outcome.'
    }
    foreach ($hostEntry in $hostEntries) {
        foreach ($required in @('requestedComputerName', 'status')) {
            if (-not (Test-HLProperty -InputObject $hostEntry -Name $required)) {
                throw "A fleet host outcome does not contain the required property '$required'."
            }
        }
        if ([string]$hostEntry.status -notin @('Succeeded', 'Failed')) {
            throw "Unsupported fleet host status '$($hostEntry.status)'."
        }
    }
}

function Get-HLFleetReportScript {
    [CmdletBinding()]
    param()

    return @'
(function(){const search=document.getElementById('hostSearch'),status=document.getElementById('hostStatusFilter'),rows=[...document.querySelectorAll('#hostRows tr')],count=document.getElementById('hostVisibleCount');function filter(){const q=search.value.trim().toLowerCase();let visible=0;rows.forEach(r=>{const ok=(!q||r.dataset.search.includes(q))&&(!status.value||r.dataset.status===status.value);r.classList.toggle('hidden',!ok);if(ok)visible++;});count.textContent=visible+' of '+rows.length+' hosts';}search.addEventListener('input',filter);status.addEventListener('change',filter);filter();})();
'@
}

function Get-HLFleetTopFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$HostEntries,

        [int]$Top = 15
    )

    $succeeded = @($HostEntries | Where-Object { [string]$_.status -eq 'Succeeded' -and $null -ne $_.assessment })
    $byControl = @{}
    foreach ($hostEntry in $succeeded) {
        foreach ($result in @($hostEntry.assessment.results)) {
            if ([string]$result.status -notin @('Fail', 'Warning', 'Error', 'Excepted')) {
                continue
            }
            $controlId = [string]$result.controlId
            if (-not $byControl.ContainsKey($controlId)) {
                $byControl[$controlId] = [pscustomobject][ordered]@{
                    ControlId = $controlId
                    Title     = [string]$result.title
                    Category  = [string]$result.category
                    Severity  = [string]$result.severity
                    Fail      = 0
                    Warning   = 0
                    Error     = 0
                    Excepted  = 0
                    Affected  = 0
                }
            }
            $entry = $byControl[$controlId]
            $status = [string]$result.status
            $entry.$status = [int]$entry.$status + 1
            $entry.Affected = [int]$entry.Affected + 1
        }
    }

    return @($byControl.Values |
        Sort-Object @{ Expression = { Get-HLSeverityRank -Severity ([string]$_.Severity) }; Descending = $true },
            @{ Expression = { [int]$_.Affected }; Descending = $true },
            ControlId |
        Select-Object -First $Top)
}

function ConvertTo-HLFleetHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$FleetResult
    )

    $builder = New-Object Text.StringBuilder
    $reportScript = Get-HLFleetReportScript
    $reportScriptHash = Get-HLInlineScriptHash -Script $reportScript
    $run = $FleetResult.run
    $summary = $FleetResult.summary
    $hostEntries = @($FleetResult.hosts)
    $succeededHosts = @($hostEntries | Where-Object { [string]$_.status -eq 'Succeeded' })
    $averageScore = if ((Test-HLProperty -InputObject $summary -Name 'averageHardeningScore') -and $null -ne $summary.averageHardeningScore) { '{0:N1}%' -f [double]$summary.averageHardeningScore } else { 'n/a' }
    $averageCoverage = if ((Test-HLProperty -InputObject $summary -Name 'averageEvidenceCoverage') -and $null -ne $summary.averageEvidenceCoverage) { '{0:N1}%' -f [double]$summary.averageEvidenceCoverage } else { 'n/a' }
    $totalFail = 0
    $totalError = 0
    foreach ($hostEntry in $succeededHosts) {
        if ($null -ne $hostEntry.assessment) {
            $totalFail += [int]$hostEntry.assessment.summary.Fail
            $totalError += [int]$hostEntry.assessment.summary.Error
        }
    }
    $started = try { ([datetime]$run.startedAt).ToString('yyyy-MM-dd HH:mm:ss K') } catch { [string]$run.startedAt }
    $completed = try { ([datetime]$run.completedAt).ToString('yyyy-MM-dd HH:mm:ss K') } catch { [string]$run.completedAt }

    [void]$builder.AppendLine('<!doctype html>')
    [void]$builder.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$builder.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$builder.AppendLine(('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; script-src ''sha256-{0}''; img-src data:; base-uri ''none''; form-action ''none''">' -f (ConvertTo-HLHtmlEncoded $reportScriptHash)))
    [void]$builder.AppendLine('<title>Hardening Lens Fleet Report</title>')
    [void]$builder.AppendLine(@'
<style>
:root{--bg:#07110d;--panel:#0c1b14;--line:#244434;--text:#e7f3ec;--muted:#9eb7aa;--accent:#55e69d;--pass:#3ed598;--fail:#ff6b6b;--warn:#ffc857;--except:#b892ff;--unknown:#7ea7c9;--error:#ff8f5a;--na:#798b82}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% -10%,#123c28 0,transparent 32%),var(--bg);color:var(--text);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent)}code,pre,.mono{font-family:"Cascadia Code","SFMono-Regular",Consolas,monospace}.wrap{max-width:1500px;margin:0 auto;padding:32px}.hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(85,230,157,.09),rgba(12,27,20,.96));border-radius:18px;padding:28px;box-shadow:0 24px 80px rgba(0,0,0,.3)}.eyebrow{color:var(--accent);letter-spacing:.16em;text-transform:uppercase;font:700 12px/1.4 monospace}.hero h1{font-size:clamp(30px,5vw,52px);margin:7px 0 8px}.subtitle{color:var(--muted);margin:0}.meta-grid,.metric-grid{display:grid;gap:14px}.meta-grid{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin-top:22px}.metric-grid{grid-template-columns:repeat(auto-fit,minmax(135px,1fr));margin:22px 0}.card{border:1px solid var(--line);background:var(--panel);border-radius:14px;padding:16px}.metric .value{font:800 27px/1.1 monospace}.metric .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin-top:6px}.score{color:var(--accent)}.section{margin-top:28px}.section h2{font-size:22px;margin:0 0 12px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;padding:14px;border:1px solid var(--line);background:var(--panel);border-radius:14px;margin-bottom:12px}.toolbar input,.toolbar select{background:#07110d;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 11px;min-width:180px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px;background:var(--panel)}table{width:100%;border-collapse:collapse;min-width:980px}th,td{padding:12px 13px;text-align:left;vertical-align:top;border-bottom:1px solid rgba(36,68,52,.72)}th{position:sticky;top:0;background:#0e2017;color:#bcd1c5;font-size:12px;text-transform:uppercase;letter-spacing:.06em;z-index:1}tr:hover td{background:rgba(85,230,157,.03)}.badge{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:2px 8px;font:700 11px/1.5 monospace;text-transform:uppercase}.badge.pass,.badge.succeeded{color:var(--pass)}.badge.fail,.badge.failed{color:var(--fail)}.badge.warning{color:var(--warn)}.badge.excepted{color:var(--except)}.badge.unknown{color:var(--unknown)}.badge.error{color:var(--error)}.badge.na{color:var(--na)}.severity{font-weight:700}.sev-critical{color:#ff5b77}.sev-high{color:#ff8f5a}.sev-medium{color:#ffc857}.sev-low{color:#8cb9dc}.sev-informational{color:var(--muted)}.small{font-size:12px;color:var(--muted)}.kv{display:grid;grid-template-columns:minmax(150px,220px) 1fr;gap:7px 15px}.kv div:nth-child(odd){color:var(--muted)}.method{color:var(--muted)}.hidden{display:none!important}.footer{color:var(--muted);text-align:center;margin:28px 0 8px;font-size:12px}@media(max-width:700px){.wrap{padding:16px}.hero{padding:20px}.kv{grid-template-columns:1fr}}
@media print{body{background:#fff;color:#111}.wrap{max-width:none;padding:0}.hero,.card,.toolbar,.table-wrap{background:#fff;border-color:#bbb;box-shadow:none}.toolbar{display:none}a{color:#111}.small,.method,.subtitle,.metric .label{color:#444}th{position:static;background:#eee;color:#111}.badge{border-color:#555;color:#111!important}}
</style>
'@)
    [void]$builder.AppendLine('</head><body><main class="wrap">')
    [void]$builder.AppendLine('<section class="hero">')
    [void]$builder.AppendLine('<div class="eyebrow">xGreeny / Windows Security Engineering</div>')
    [void]$builder.AppendLine('<h1>Hardening Lens Fleet</h1>')
    [void]$builder.AppendLine(('<p class="subtitle">Aggregated read-only posture assessment for <strong>{0}</strong> host(s) against <strong>{1}</strong>.</p>' -f (ConvertTo-HLHtmlEncoded $summary.requestedCount),(ConvertTo-HLHtmlEncoded $run.baselineSelection)))
    [void]$builder.AppendLine('<div class="meta-grid">')
    foreach ($meta in @(
        @('Run ID', $run.id),
        @('Started', $started),
        @('Completed', $completed),
        @('Baseline selection', $run.baselineSelection),
        @('Module version', $run.moduleVersion),
        @('Result schema', $FleetResult.schemaVersion),
        @('Redacted', $run.redacted)
    )) {
        [void]$builder.AppendLine(('<div class="card"><div class="small">{0}</div><div class="mono">{1}</div></div>' -f (ConvertTo-HLHtmlEncoded $meta[0]),(ConvertTo-HLHtmlEncoded $meta[1])))
    }
    [void]$builder.AppendLine('</div></section>')

    [void]$builder.AppendLine('<section class="metric-grid">')
    foreach ($metric in @(
        @('Hosts requested', $summary.requestedCount, ''),
        @('Succeeded', $summary.succeededCount, 'pass'),
        @('Failed collections', $summary.failedCount, 'fail'),
        @('Average score', $averageScore, 'score'),
        @('Average coverage', $averageCoverage, ''),
        @('Failing controls', $totalFail, 'fail'),
        @('Collection errors', $totalError, 'error')
    )) {
        [void]$builder.AppendLine(('<div class="card metric"><div class="value {2}">{1}</div><div class="label">{0}</div></div>' -f (ConvertTo-HLHtmlEncoded $metric[0]),(ConvertTo-HLHtmlEncoded $metric[1]),(ConvertTo-HLHtmlEncoded $metric[2])))
    }
    [void]$builder.AppendLine('</section>')

    [void]$builder.AppendLine('<section class="section"><h2>Hosts</h2>')
    [void]$builder.AppendLine('<div class="toolbar"><input id="hostSearch" type="search" placeholder="Search host..." aria-label="Search hosts"><select id="hostStatusFilter"><option value="">All outcomes</option><option>Succeeded</option><option>Failed</option></select><span id="hostVisibleCount" class="small"></span></div>')
    [void]$builder.AppendLine('<div class="table-wrap"><table><thead><tr><th>Host</th><th>Outcome</th><th>Score</th><th>Coverage</th><th>Pass</th><th>Fail</th><th>Warning</th><th>Excepted</th><th>Unknown</th><th>Error</th><th>Highest open severity</th><th>Detail</th></tr></thead><tbody id="hostRows">')
    foreach ($hostEntry in $hostEntries) {
        $hostName = [string]$hostEntry.requestedComputerName
        $status = [string]$hostEntry.status
        $statusClass = if ($status -eq 'Succeeded') { 'succeeded' } else { 'failed' }
        $searchText = ("$hostName $status").ToLowerInvariant()
        if ($status -eq 'Succeeded' -and $null -ne $hostEntry.assessment) {
            $hostSummary = $hostEntry.assessment.summary
            $hostScore = if ($null -ne $hostSummary.HardeningScore) { '{0:N1}%' -f [double]$hostSummary.HardeningScore } else { 'n/a' }
            $hostCoverage = if ($null -ne $hostSummary.EvidenceCoverage) { '{0:N1}%' -f [double]$hostSummary.EvidenceCoverage } else { 'n/a' }
            $detail = 'Baseline {0} {1}' -f [string]$hostEntry.assessment.baseline.name, [string]$hostEntry.assessment.baseline.version
            [void]$builder.AppendLine(('<tr data-status="{0}" data-search="{1}"><td><strong class="mono">{2}</strong></td><td><span class="badge {3}">{0}</span></td><td class="mono">{4}</td><td class="mono">{5}</td><td>{6}</td><td>{7}</td><td>{8}</td><td>{9}</td><td>{10}</td><td>{11}</td><td class="severity {12}">{13}</td><td class="small">{14}</td></tr>' -f (ConvertTo-HLHtmlEncoded $status),(ConvertTo-HLHtmlEncoded $searchText),(ConvertTo-HLHtmlEncoded $hostName),$statusClass,(ConvertTo-HLHtmlEncoded $hostScore),(ConvertTo-HLHtmlEncoded $hostCoverage),(ConvertTo-HLHtmlEncoded $hostSummary.Pass),(ConvertTo-HLHtmlEncoded $hostSummary.Fail),(ConvertTo-HLHtmlEncoded $hostSummary.Warning),(ConvertTo-HLHtmlEncoded $hostSummary.Excepted),(ConvertTo-HLHtmlEncoded $hostSummary.Unknown),(ConvertTo-HLHtmlEncoded $hostSummary.Error),(Get-HLSeverityClass -Severity ([string]$hostSummary.HighestOpenSeverity)),(ConvertTo-HLHtmlEncoded $hostSummary.HighestOpenSeverity),(ConvertTo-HLHtmlEncoded $detail)))
        }
        else {
            $errorText = if ((Test-HLProperty -InputObject $hostEntry -Name 'error') -and $null -ne $hostEntry.error) { ConvertTo-HLDisplayString -Value $hostEntry.error } else { 'No detail recorded.' }
            [void]$builder.AppendLine(('<tr data-status="{0}" data-search="{1}"><td><strong class="mono">{2}</strong></td><td><span class="badge {3}">{0}</span></td><td class="mono">n/a</td><td class="mono">n/a</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td class="small">{4}</td></tr>' -f (ConvertTo-HLHtmlEncoded $status),(ConvertTo-HLHtmlEncoded $searchText),(ConvertTo-HLHtmlEncoded $hostName),$statusClass,(ConvertTo-HLHtmlEncoded $errorText)))
        }
    }
    [void]$builder.AppendLine('</tbody></table></div></section>')

    $topFindings = @(Get-HLFleetTopFinding -HostEntries $hostEntries)
    [void]$builder.AppendLine('<section class="section"><h2>Most affected controls</h2>')
    if ($topFindings.Count -eq 0) {
        [void]$builder.AppendLine('<div class="card">No failing, warning, error, or excepted controls were recorded on any successfully assessed host.</div>')
    }
    else {
        [void]$builder.AppendLine('<div class="table-wrap"><table><thead><tr><th>Control</th><th>Severity</th><th>Category</th><th>Affected hosts</th><th>Fail</th><th>Warning</th><th>Error</th><th>Excepted</th></tr></thead><tbody>')
        foreach ($finding in $topFindings) {
            [void]$builder.AppendLine(('<tr><td><strong class="mono">{0}</strong><br>{1}</td><td class="severity {2}">{3}</td><td>{4}</td><td class="mono">{5} / {6}</td><td>{7}</td><td>{8}</td><td>{9}</td><td>{10}</td></tr>' -f (ConvertTo-HLHtmlEncoded $finding.ControlId),(ConvertTo-HLHtmlEncoded $finding.Title),(Get-HLSeverityClass -Severity ([string]$finding.Severity)),(ConvertTo-HLHtmlEncoded $finding.Severity),(ConvertTo-HLHtmlEncoded $finding.Category),(ConvertTo-HLHtmlEncoded $finding.Affected),(ConvertTo-HLHtmlEncoded $succeededHosts.Count),(ConvertTo-HLHtmlEncoded $finding.Fail),(ConvertTo-HLHtmlEncoded $finding.Warning),(ConvertTo-HLHtmlEncoded $finding.Error),(ConvertTo-HLHtmlEncoded $finding.Excepted)))
        }
        [void]$builder.AppendLine('</tbody></table></div>')
    }
    [void]$builder.AppendLine('</section>')

    [void]$builder.AppendLine('<section class="section card"><h2>Assessment model</h2>')
    [void]$builder.AppendLine('<p class="method">Per-host scores are severity-weighted pass percentages; the fleet averages are unweighted means across successfully assessed hosts. Failed collections carry no posture data and are reported separately.</p>')
    [void]$builder.AppendLine('<p class="method">Hardening Lens is a read-only technical posture assessment. It does not change devices, prove policy intent, replace risk assessment, or certify compliance with Microsoft, CIS, NIST, or another framework.</p>')
    [void]$builder.AppendLine('</section>')
    [void]$builder.AppendLine(('<div class="footer mono">hardening-lens / xGreeny | fleet result schema {0}</div>' -f (ConvertTo-HLHtmlEncoded $FleetResult.schemaVersion)))
    [void]$builder.Append('<script>')
    [void]$builder.Append($reportScript)
    [void]$builder.AppendLine('</script>')
    [void]$builder.AppendLine('</main></body></html>')
    return $builder.ToString()
}
