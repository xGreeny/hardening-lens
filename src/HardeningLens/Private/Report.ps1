function ConvertTo-HLHtmlEncoded {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-HLFileNamePart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $invalid = [IO.Path]::GetInvalidFileNameChars()
    $escaped = [regex]::Escape((-join $invalid))
    $safe = $Value -replace "[$escaped]", '-'
    $safe = $safe -replace '[^A-Za-z0-9._-]', '-'
    $safe = $safe -replace '-{2,}', '-'
    return $safe.Trim('-')
}

function Get-HLStatusClass {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Status)

    switch ($Status) {
        'Pass' { return 'pass' }
        'Fail' { return 'fail' }
        'Warning' { return 'warning' }
        'Excepted' { return 'excepted' }
        'Unknown' { return 'unknown' }
        'Error' { return 'error' }
        default { return 'na' }
    }
}

function Get-HLSeverityClass {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Severity)

    switch ($Severity) {
        'Critical' { return 'sev-critical' }
        'High' { return 'sev-high' }
        'Medium' { return 'sev-medium' }
        'Low' { return 'sev-low' }
        'Informational' { return 'sev-informational' }
        default { return 'sev-informational' }
    }
}

function ConvertTo-HLAllowedReferenceUri {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    $uri = $null
    if (-not [uri]::TryCreate([string]$Value, [UriKind]::Absolute, [ref]$uri)) {
        return $null
    }

    if ($uri.Scheme -ine 'https' -or
        $uri.DnsSafeHost -ine 'learn.microsoft.com' -or
        -not $uri.IsDefaultPort -or
        -not [string]::IsNullOrEmpty($uri.UserInfo)) {
        return $null
    }

    return $uri.AbsoluteUri
}

function Get-HLReportScript {
    [CmdletBinding()]
    param()

    return @'
(function(){const search=document.getElementById('search'),status=document.getElementById('statusFilter'),severity=document.getElementById('severityFilter'),rows=[...document.querySelectorAll('#controlRows tr')],count=document.getElementById('visibleCount');function filter(){const q=search.value.trim().toLowerCase();let visible=0;rows.forEach(r=>{const ok=(!q||r.dataset.search.includes(q))&&(!status.value||r.dataset.status===status.value)&&(!severity.value||r.dataset.severity===severity.value);r.classList.toggle('hidden',!ok);if(ok)visible++;});count.textContent=visible+' of '+rows.length+' controls';}search.addEventListener('input',filter);status.addEventListener('change',filter);severity.addEventListener('change',filter);filter();})();
'@
}

function Get-HLInlineScriptHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Script
    )

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Script)
        return [Convert]::ToBase64String($sha256.ComputeHash($bytes))
    }
    finally {
        $sha256.Dispose()
    }
}

function Protect-HLCsvCell {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    $text = [string]$Value
    if ($text -match '^[=+\-@\t\r\n]') {
        return "'$text"
    }

    return $text
}

function Write-HLReportFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content,

        [switch]$Force
    )

    if ($Force) {
        Write-HLUtf8File -Path $Path -Content $Content
        return
    }

    $encoding = New-Object Text.UTF8Encoding($false)
    $bytes = $encoding.GetBytes($Content)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally {
        $stream.Dispose()
    }
}

function ConvertTo-HLHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ScanResult
    )

    $builder = New-Object Text.StringBuilder
    $reportScript = Get-HLReportScript
    $reportScriptHash = Get-HLInlineScriptHash -Script $reportScript
    $summary = $ScanResult.summary
    $score = if ($null -eq $summary.HardeningScore) { 'n/a' } else { '{0:N1}%' -f [double]$summary.HardeningScore }
    $coverage = if ($null -eq $summary.EvidenceCoverage) { 'n/a' } else { '{0:N1}%' -f [double]$summary.EvidenceCoverage }
    $collected = try { ([datetime]$ScanResult.scan.collectedAt).ToString('yyyy-MM-dd HH:mm:ss K') } catch { [string]$ScanResult.scan.collectedAt }
    $catalogVersion = if (Test-HLProperty -InputObject $ScanResult -Name 'provenance') { [string]$ScanResult.provenance.catalogVersion } else { 'legacy/unavailable' }

    [void]$builder.AppendLine('<!doctype html>')
    [void]$builder.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$builder.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$builder.AppendLine(('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; script-src ''sha256-{0}''; img-src data:; base-uri ''none''; form-action ''none''">' -f (ConvertTo-HLHtmlEncoded $reportScriptHash)))
    [void]$builder.AppendLine('<title>Hardening Lens Report</title>')
    [void]$builder.AppendLine(@'
<style>
:root{--bg:#07110d;--panel:#0c1b14;--panel2:#10241a;--line:#244434;--text:#e7f3ec;--muted:#9eb7aa;--accent:#55e69d;--pass:#3ed598;--fail:#ff6b6b;--warn:#ffc857;--except:#b892ff;--unknown:#7ea7c9;--error:#ff8f5a;--na:#798b82}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% -10%,#123c28 0,transparent 32%),var(--bg);color:var(--text);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent)}code,pre,.mono{font-family:"Cascadia Code","SFMono-Regular",Consolas,monospace}.wrap{max-width:1500px;margin:0 auto;padding:32px}.hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(85,230,157,.09),rgba(12,27,20,.96));border-radius:18px;padding:28px;box-shadow:0 24px 80px rgba(0,0,0,.3)}.eyebrow{color:var(--accent);letter-spacing:.16em;text-transform:uppercase;font:700 12px/1.4 monospace}.hero h1{font-size:clamp(30px,5vw,52px);margin:7px 0 8px}.subtitle{color:var(--muted);margin:0}.meta-grid,.metric-grid{display:grid;gap:14px}.meta-grid{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin-top:22px}.metric-grid{grid-template-columns:repeat(auto-fit,minmax(135px,1fr));margin:22px 0}.card{border:1px solid var(--line);background:var(--panel);border-radius:14px;padding:16px}.metric .value{font:800 27px/1.1 monospace}.metric .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin-top:6px}.score{color:var(--accent)}.section{margin-top:28px}.section h2{font-size:22px;margin:0 0 12px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;padding:14px;border:1px solid var(--line);background:var(--panel);border-radius:14px;margin-bottom:12px}.toolbar input,.toolbar select{background:#07110d;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 11px;min-width:180px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px;background:var(--panel)}table{width:100%;border-collapse:collapse;min-width:980px}th,td{padding:12px 13px;text-align:left;vertical-align:top;border-bottom:1px solid rgba(36,68,52,.72)}th{position:sticky;top:0;background:#0e2017;color:#bcd1c5;font-size:12px;text-transform:uppercase;letter-spacing:.06em;z-index:1}tr:hover td{background:rgba(85,230,157,.03)}.badge{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:2px 8px;font:700 11px/1.5 monospace;text-transform:uppercase}.badge.pass{color:var(--pass)}.badge.fail{color:var(--fail)}.badge.warning{color:var(--warn)}.badge.excepted{color:var(--except)}.badge.unknown{color:var(--unknown)}.badge.error{color:var(--error)}.badge.na{color:var(--na)}.severity{font-weight:700}.sev-critical{color:#ff5b77}.sev-high{color:#ff8f5a}.sev-medium{color:#ffc857}.sev-low{color:#8cb9dc}.sev-informational{color:var(--muted)}.finding{border:1px solid var(--line);border-left-width:5px;background:var(--panel);border-radius:12px;padding:16px;margin:10px 0}.finding.fail{border-left-color:var(--fail)}.finding.warning{border-left-color:var(--warn)}.finding.error{border-left-color:var(--error)}.finding.excepted{border-left-color:var(--except)}.finding-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.finding h3{margin:0 0 5px;font-size:17px}.small{font-size:12px;color:var(--muted)}details{margin-top:10px}summary{cursor:pointer;color:var(--accent)}pre{white-space:pre-wrap;word-break:break-word;background:#06100b;border:1px solid var(--line);border-radius:9px;padding:12px;color:#cce1d5;max-height:430px;overflow:auto}.kv{display:grid;grid-template-columns:minmax(150px,220px) 1fr;gap:7px 15px}.kv div:nth-child(odd){color:var(--muted)}.method{color:var(--muted)}.hidden{display:none!important}.footer{color:var(--muted);text-align:center;margin:28px 0 8px;font-size:12px}@media(max-width:700px){.wrap{padding:16px}.hero{padding:20px}.kv{grid-template-columns:1fr}.finding-head{display:block}}
@media print{body{background:#fff;color:#111}.wrap{max-width:none;padding:0}.hero,.card,.toolbar,.table-wrap,.finding{background:#fff;border-color:#bbb;box-shadow:none}.toolbar{display:none}a{color:#111}.small,.method,.subtitle,.metric .label{color:#444}th{position:static;background:#eee;color:#111}pre{background:#f5f5f5;color:#111;border-color:#ccc}.badge{border-color:#555;color:#111!important}}
</style>
'@)
    [void]$builder.AppendLine('</head><body><main class="wrap">')
    [void]$builder.AppendLine('<section class="hero">')
    [void]$builder.AppendLine('<div class="eyebrow">xGreeny / Windows Security Engineering</div>')
    [void]$builder.AppendLine('<h1>Hardening Lens</h1>')
    [void]$builder.AppendLine(('<p class="subtitle">Read-only posture assessment for <strong>{0}</strong> against <strong>{1}</strong>.</p>' -f (ConvertTo-HLHtmlEncoded $ScanResult.system.ComputerName),(ConvertTo-HLHtmlEncoded $ScanResult.baseline.displayName)))
    [void]$builder.AppendLine('<div class="meta-grid">')
    foreach ($meta in @(
        @('Collected', $collected),
        @('Operating system', "$($ScanResult.system.OSCaption) ($($ScanResult.system.BuildNumber))"),
        @('Detected role', $ScanResult.system.DetectedRole),
        @('Baseline', "$($ScanResult.baseline.name) $($ScanResult.baseline.version)"),
        @('Module / catalog', "$($ScanResult.scan.moduleVersion) / $catalogVersion"),
        @('Result schema', $ScanResult.schemaVersion),
        @('Scan ID', $ScanResult.scan.id),
        @('Redacted', $ScanResult.scan.redacted)
    )) {
        [void]$builder.AppendLine(('<div class="card"><div class="small">{0}</div><div class="mono">{1}</div></div>' -f (ConvertTo-HLHtmlEncoded $meta[0]),(ConvertTo-HLHtmlEncoded $meta[1])))
    }
    [void]$builder.AppendLine('</div></section>')

    [void]$builder.AppendLine('<section class="metric-grid">')
    foreach ($metric in @(
        @('Hardening score', $score, 'score'),
        @('Evidence coverage', $coverage, ''),
        @('Pass', $summary.Pass, 'pass'),
        @('Fail', $summary.Fail, 'fail'),
        @('Warning', $summary.Warning, 'warning'),
        @('Excepted', $summary.Excepted, 'excepted'),
        @('Unknown', $summary.Unknown, 'unknown'),
        @('Error', $summary.Error, 'error')
    )) {
        [void]$builder.AppendLine(('<div class="card metric"><div class="value {2}">{1}</div><div class="label">{0}</div></div>' -f (ConvertTo-HLHtmlEncoded $metric[0]),(ConvertTo-HLHtmlEncoded $metric[1]),(ConvertTo-HLHtmlEncoded $metric[2])))
    }
    [void]$builder.AppendLine('</section>')

    $findings = @($ScanResult.results | Where-Object { $_.status -in @('Fail','Warning','Error','Excepted') } | Sort-Object @{Expression={Get-HLSeverityRank -Severity ([string]$_.severity)};Descending=$true}, controlId)
    [void]$builder.AppendLine('<section class="section"><h2>Prioritized findings</h2>')
    if ($findings.Count -eq 0) {
        [void]$builder.AppendLine('<div class="card">No failing, warning, error, or excepted controls were recorded.</div>')
    }
    foreach ($finding in $findings) {
        $statusClass = Get-HLStatusClass -Status ([string]$finding.status)
        $severityClass = Get-HLSeverityClass -Severity ([string]$finding.severity)
        [void]$builder.AppendLine(('<article class="finding {0}"><div class="finding-head"><div><h3><span class="mono">{1}</span> - {2}</h3><div class="small">{3}</div></div><div><span class="badge {0}">{4}</span> <span class="severity {5}">{6}</span></div></div>' -f $statusClass,(ConvertTo-HLHtmlEncoded $finding.controlId),(ConvertTo-HLHtmlEncoded $finding.title),(ConvertTo-HLHtmlEncoded $finding.category),(ConvertTo-HLHtmlEncoded $finding.status),$severityClass,(ConvertTo-HLHtmlEncoded $finding.severity)))
        [void]$builder.AppendLine(('<p>{0}</p>' -f (ConvertTo-HLHtmlEncoded $finding.message)))
        [void]$builder.AppendLine('<div class="kv">')
        [void]$builder.AppendLine(('<div>Expected</div><div class="mono">{0}</div>' -f (ConvertTo-HLHtmlEncoded (ConvertTo-HLDisplayString -Value $finding.expected))))
        [void]$builder.AppendLine(('<div>Actual</div><div class="mono">{0}</div>' -f (ConvertTo-HLHtmlEncoded (ConvertTo-HLDisplayString -Value $finding.actual))))
        [void]$builder.AppendLine(('<div>Why it matters</div><div>{0}</div>' -f (ConvertTo-HLHtmlEncoded $finding.rationale)))
        [void]$builder.AppendLine(('<div>Remediation</div><div>{0}</div>' -f (ConvertTo-HLHtmlEncoded $finding.remediation)))
        if ($null -ne $finding.exception) {
            [void]$builder.AppendLine(('<div>Exception</div><div><span class="mono">{0}</span> | owner {1} | expires {2}<br>{3}</div>' -f (ConvertTo-HLHtmlEncoded $finding.exception.id),(ConvertTo-HLHtmlEncoded $finding.exception.owner),(ConvertTo-HLHtmlEncoded $finding.exception.expires),(ConvertTo-HLHtmlEncoded $finding.exception.reason)))
        }
        [void]$builder.AppendLine('</div>')
        $allowedReferences = @($finding.references | ForEach-Object { ConvertTo-HLAllowedReferenceUri -Value $_ } | Where-Object { $null -ne $_ })
        if ($allowedReferences.Count -gt 0) {
            [void]$builder.Append('<p class="small">References: ')
            $links = @()
            foreach ($reference in $allowedReferences) {
                $encoded = ConvertTo-HLHtmlEncoded ([string]$reference)
                $links += ('<a href="{0}" target="_blank" rel="noopener noreferrer">Microsoft guidance</a>' -f $encoded)
            }
            [void]$builder.Append(($links -join ' | '))
            [void]$builder.AppendLine('</p>')
        }
        $evidenceJson = if ($null -eq $finding.evidence) { 'No additional evidence.' } else { $finding.evidence | ConvertTo-Json -Depth 20 }
        [void]$builder.AppendLine(('<details><summary>Evidence</summary><pre>{0}</pre></details></article>' -f (ConvertTo-HLHtmlEncoded $evidenceJson)))
    }
    [void]$builder.AppendLine('</section>')

    [void]$builder.AppendLine('<section class="section"><h2>All controls</h2>')
    [void]$builder.AppendLine('<div class="toolbar"><input id="search" type="search" placeholder="Search control, title, category..." aria-label="Search"><select id="statusFilter"><option value="">All statuses</option><option>Pass</option><option>Fail</option><option>Warning</option><option>Excepted</option><option>Unknown</option><option>Error</option><option>NotApplicable</option></select><select id="severityFilter"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option></select><span id="visibleCount" class="small"></span></div>')
    [void]$builder.AppendLine('<div class="table-wrap"><table><thead><tr><th>Control</th><th>Status</th><th>Severity</th><th>Category</th><th>Expected</th><th>Actual</th><th>Message</th></tr></thead><tbody id="controlRows">')
    foreach ($result in @($ScanResult.results)) {
        $statusClass = Get-HLStatusClass -Status ([string]$result.status)
        $severityClass = Get-HLSeverityClass -Severity ([string]$result.severity)
        $searchText = "$($result.controlId) $($result.title) $($result.category) $($result.status) $($result.severity)".ToLowerInvariant()
        [void]$builder.AppendLine(('<tr data-status="{0}" data-severity="{1}" data-search="{2}"><td><strong class="mono">{3}</strong><br>{4}</td><td><span class="badge {5}">{0}</span></td><td class="severity {6}">{1}</td><td>{7}</td><td class="mono">{8}</td><td class="mono">{9}</td><td>{10}</td></tr>' -f (ConvertTo-HLHtmlEncoded $result.status),(ConvertTo-HLHtmlEncoded $result.severity),(ConvertTo-HLHtmlEncoded $searchText),(ConvertTo-HLHtmlEncoded $result.controlId),(ConvertTo-HLHtmlEncoded $result.title),$statusClass,$severityClass,(ConvertTo-HLHtmlEncoded $result.category),(ConvertTo-HLHtmlEncoded (ConvertTo-HLDisplayString -Value $result.expected)),(ConvertTo-HLHtmlEncoded (ConvertTo-HLDisplayString -Value $result.actual)),(ConvertTo-HLHtmlEncoded $result.message)))
    }
    [void]$builder.AppendLine('</tbody></table></div></section>')

    if (Test-HLProperty -InputObject $ScanResult -Name 'provenance') {
        $exceptionDigest = if (Test-HLProperty -InputObject $ScanResult.provenance -Name 'exceptionDigest') { [string]$ScanResult.provenance.exceptionDigest } else { 'not used' }
        $capabilityText = @($ScanResult.provenance.capabilities | ForEach-Object {
            if ($_.available) { "$(($_.name)): available" } else { "$(($_.name)): unavailable ($($_.detail))" }
        }) -join '; '
        [void]$builder.AppendLine('<section class="section card"><h2>Assessment provenance</h2><div class="kv">')
        foreach ($provenanceItem in @(
            @('Catalog digest', $ScanResult.provenance.catalogDigest),
            @('Effective baseline digest', $ScanResult.provenance.baselineDigest),
            @('Exception register digest', $exceptionDigest),
            @('Collection duration', "$($ScanResult.scan.collectionDurationMs) ms"),
            @('Probe capabilities', $capabilityText)
        )) {
            [void]$builder.AppendLine(('<div>{0}</div><div class="mono">{1}</div>' -f (ConvertTo-HLHtmlEncoded $provenanceItem[0]), (ConvertTo-HLHtmlEncoded $provenanceItem[1])))
        }
        [void]$builder.AppendLine('</div></section>')
    }

    [void]$builder.AppendLine('<section class="section card"><h2>Assessment model</h2>')
    [void]$builder.AppendLine(('<p class="method">{0}</p>' -f (ConvertTo-HLHtmlEncoded $summary.ScoringModel)))
    [void]$builder.AppendLine('<p class="method">Hardening Lens is a read-only technical posture assessment. It does not change the device, prove policy intent, replace risk assessment, or certify compliance with Microsoft, CIS, NIST, or another framework. Validate findings against application requirements and change-control procedures before remediation.</p>')
    [void]$builder.AppendLine('</section>')
    [void]$builder.AppendLine(('<div class="footer mono">hardening-lens / xGreeny | report schema {0}</div>' -f (ConvertTo-HLHtmlEncoded $ScanResult.schemaVersion)))
    [void]$builder.Append('<script>')
    [void]$builder.Append($reportScript)
    [void]$builder.AppendLine('</script>')
    [void]$builder.AppendLine('</main></body></html>')
    return $builder.ToString()
}

function ConvertTo-HLFlatResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Result)

    $flatResult = [pscustomobject][ordered]@{
        ControlId      = [string]$Result.controlId
        Title          = [string]$Result.title
        Category       = [string]$Result.category
        Severity       = [string]$Result.severity
        Status         = [string]$Result.status
        OriginalStatus = if ($null -ne $Result.originalStatus) { [string]$Result.originalStatus } else { '' }
        Expected       = ConvertTo-HLDisplayString -Value $Result.expected
        Actual         = ConvertTo-HLDisplayString -Value $Result.actual
        Message        = [string]$Result.message
        ExceptionId    = if ($null -ne $Result.exception) { [string]$Result.exception.id } else { '' }
        ExceptionOwner = if ($null -ne $Result.exception) { [string]$Result.exception.owner } else { '' }
        ExceptionExpiry = if ($null -ne $Result.exception) { [string]$Result.exception.expires } else { '' }
        Remediation    = [string]$Result.remediation
        References     = @($Result.references) -join '; '
    }

    $safeResult = [ordered]@{}
    foreach ($property in $flatResult.PSObject.Properties) {
        $safeResult[$property.Name] = Protect-HLCsvCell -Value $property.Value
    }

    return [pscustomobject]$safeResult
}
