function Initialize-HLAuditNativeType {
    [CmdletBinding()]
    param()

    if ($script:HLAuditNativeLoaded -or ('HardeningLens.NativeAuditPolicy' -as [type])) {
        $script:HLAuditNativeLoaded = $true
        return
    }

    $source = @'
using System;
using System.Runtime.InteropServices;

namespace HardeningLens
{
    public static class NativeAuditPolicy
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct AUDIT_POLICY_INFORMATION
        {
            public Guid AuditSubCategoryGuid;
            public UInt32 AuditingInformation;
            public Guid AuditCategoryGuid;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool AuditQuerySystemPolicy(
            [In] Guid[] pSubCategoryGuids,
            UInt32 PolicyCount,
            out IntPtr ppAuditPolicy
        );

        [DllImport("advapi32.dll")]
        public static extern void AuditFree(IntPtr buffer);
    }
}
'@

    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
    $script:HLAuditNativeLoaded = $true
}

function Get-HLAuditPolicySetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid]$SubcategoryGuid
    )

    Assert-HLWindows
    Initialize-HLAuditNativeType

    $buffer = [IntPtr]::Zero
    $guids = [guid[]]@($SubcategoryGuid)
    $success = [HardeningLens.NativeAuditPolicy]::AuditQuerySystemPolicy($guids, 1, [ref]$buffer)
    if (-not $success) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "AuditQuerySystemPolicy failed with Win32 error $errorCode."
    }

    try {
        $type = [type][HardeningLens.NativeAuditPolicy+AUDIT_POLICY_INFORMATION]
        $information = [Runtime.InteropServices.Marshal]::PtrToStructure($buffer, $type)
        $raw = [uint32]$information.AuditingInformation
        return [pscustomobject][ordered]@{
            SubcategoryGuid = $SubcategoryGuid.ToString()
            RawValue        = $raw
            Success         = [bool](($raw -band 1) -eq 1)
            Failure         = [bool](($raw -band 2) -eq 2)
            None            = [bool](($raw -band 4) -eq 4)
        }
    }
    finally {
        if ($buffer -ne [IntPtr]::Zero) {
            [HardeningLens.NativeAuditPolicy]::AuditFree($buffer)
        }
    }
}

function Invoke-HLAuditPolicyProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    $parameters = $Control.parameters
    $setting = Get-HLAuditPolicySetting -SubcategoryGuid ([guid][string]$parameters.subcategoryGuid)
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($requiredFlag in @($parameters.requiredFlags)) {
        if (-not [bool]$setting.$requiredFlag) {
            $missing.Add([string]$requiredFlag)
        }
    }

    $actualFlags = New-Object System.Collections.Generic.List[string]
    if ($setting.Success) { $actualFlags.Add('Success') }
    if ($setting.Failure) { $actualFlags.Add('Failure') }
    if ($actualFlags.Count -eq 0) { $actualFlags.Add('No Auditing') }

    $expected = @($parameters.requiredFlags) -join ' and '
    $actual = @($actualFlags) -join ' and '
    $evidence = [pscustomobject][ordered]@{
        SubcategoryName = [string]$parameters.subcategoryName
        SubcategoryGuid = [string]$parameters.subcategoryGuid
        RawValue        = $setting.RawValue
        Success         = $setting.Success
        Failure         = $setting.Failure
    }

    if ($missing.Count -eq 0) {
        return New-HLProbeResult -Status Pass -Expected $expected -Actual $actual -Message 'The effective advanced audit policy contains every required flag.' -Evidence $evidence
    }

    return New-HLProbeResult -Status Fail -Expected $expected -Actual $actual -Message ('Missing required audit flags: {0}.' -f (@($missing) -join ', ')) -Evidence $evidence
}
