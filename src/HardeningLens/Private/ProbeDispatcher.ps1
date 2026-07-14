function Invoke-HLProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control,

        [Parameter(Mandatory)]
        [object]$SystemContext,

        [AllowNull()]
        [object]$CollectionContext
    )

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $probeName = [string]$Control.probe
        $registry = Get-HLProbeRegistry
        if (-not $registry.ContainsKey($probeName)) {
            $result = Get-HLProbeResult -Status Error -Expected $null -Actual $null -Message "Unknown probe '$probeName' for control '$($Control.id)'."
        }
        else {
            $entry = $registry[$probeName]
            $parameterNames = if (Test-HLProperty -InputObject $Control -Name 'parameters') {
                @($Control.parameters.PSObject.Properties | ForEach-Object { [string]$_.Name })
            }
            else {
                @()
            }
            $unsupported = @($parameterNames | Where-Object { $_ -notin @($entry.ParameterNames) } | Sort-Object -Unique)
            if ($unsupported.Count -gt 0) {
                $result = Get-HLProbeResult -Status Error -Expected $null -Actual $null -Message (
                    "Probe '$probeName' received unsupported parameter(s): {0}." -f ($unsupported -join ', ')
                )
            }
            else {
                $result = & $entry.Handler $Control $SystemContext $CollectionContext
            }
        }
    }
    catch {
        $result = Get-HLProbeResult -Status Error -Expected $null -Actual $null -Message "Probe '$($Control.probe)' failed: $($_.Exception.Message)"
    }
    finally {
        $stopwatch.Stop()
    }

    $result | Add-Member -NotePropertyName DurationMs -NotePropertyValue ([int][math]::Round($stopwatch.Elapsed.TotalMilliseconds)) -Force
    return $result
}
