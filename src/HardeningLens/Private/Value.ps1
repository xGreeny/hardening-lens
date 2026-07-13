function Test-HLValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Expected,

        [Parameter(Mandatory)]
        [ValidateSet('Equals', 'NotEquals', 'In', 'NotIn', 'GreaterOrEqual', 'LessOrEqual', 'ContainsAll')]
        [string]$Operator
    )

    switch ($Operator) {
        'Equals' {
            return $Actual -eq $Expected
        }
        'NotEquals' {
            return $Actual -ne $Expected
        }
        'In' {
            return $Actual -in @($Expected)
        }
        'NotIn' {
            return $Actual -notin @($Expected)
        }
        'GreaterOrEqual' {
            if ($null -eq $Actual) { return $false }
            return [double]$Actual -ge [double]$Expected
        }
        'LessOrEqual' {
            if ($null -eq $Actual) { return $false }
            return [double]$Actual -le [double]$Expected
        }
        'ContainsAll' {
            $actualItems = @($Actual | ForEach-Object { [string]$_ })
            foreach ($item in @($Expected)) {
                if ([string]$item -notin $actualItems) {
                    return $false
                }
            }
            return $true
        }
    }
}

function New-HLValueProbeResult {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Expected,

        [Parameter(Mandatory)]
        [string]$Operator,

        [AllowNull()]
        [object[]]$WarningValues,

        [string]$SuccessMessage = 'The effective value matches the baseline.',

        [string]$FailureMessage = 'The effective value does not match the baseline.',

        [AllowNull()]
        [object]$Evidence = $null
    )

    if (Test-HLValue -Actual $Actual -Expected $Expected -Operator $Operator) {
        return New-HLProbeResult -Status Pass -Expected $Expected -Actual $Actual -Message $SuccessMessage -Evidence $Evidence
    }

    if ($null -ne $WarningValues -and $Actual -in @($WarningValues)) {
        return New-HLProbeResult -Status Warning -Expected $Expected -Actual $Actual -Message 'The control is in audit or warning mode and is not fully enforced.' -Evidence $Evidence
    }

    return New-HLProbeResult -Status Fail -Expected $Expected -Actual $Actual -Message $FailureMessage -Evidence $Evidence
}
