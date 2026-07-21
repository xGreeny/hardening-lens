function Initialize-HLAuditNativeType {
    [CmdletBinding()]
    param()

    if ($script:HLAuditNativeLoaded -or ('HardeningLens.NativeAuditPolicy2' -as [type])) {
        $script:HLAuditNativeLoaded = $true
        return
    }

    $source = @'
using System;
using System.Runtime.InteropServices;

namespace HardeningLens
{
    public static class NativeAuditPolicy2
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
        private static extern bool AuditQuerySystemPolicy(
            [In] Guid[] pSubCategoryGuids,
            UInt32 PolicyCount,
            out IntPtr ppAuditPolicy
        );

        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr buffer);

        // Marshalling stays in C# because the PowerShell 5.1 binder can select
        // the PtrToStructure(IntPtr, object) overload and fail at runtime.
        public static AUDIT_POLICY_INFORMATION QuerySinglePolicy(Guid subCategoryGuid)
        {
            IntPtr buffer = IntPtr.Zero;
            bool success = AuditQuerySystemPolicy(new Guid[] { subCategoryGuid }, 1, out buffer);
            if (!success)
            {
                int errorCode = Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(
                    errorCode,
                    "AuditQuerySystemPolicy failed with Win32 error " + errorCode + "."
                );
            }

            try
            {
                return (AUDIT_POLICY_INFORMATION)Marshal.PtrToStructure(buffer, typeof(AUDIT_POLICY_INFORMATION));
            }
            finally
            {
                AuditFree(buffer);
            }
        }
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

    $information = [HardeningLens.NativeAuditPolicy2]::QuerySinglePolicy($SubcategoryGuid)
    $raw = [uint32]$information.AuditingInformation
    return [pscustomobject][ordered]@{
        SubcategoryGuid = $SubcategoryGuid.ToString()
        RawValue        = $raw
        Success         = [bool](($raw -band 1) -eq 1)
        Failure         = [bool](($raw -band 2) -eq 2)
        None            = [bool](($raw -band 4) -eq 4)
    }
}

function Invoke-HLAuditPolicyProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Control
    )

    $parameters = $Control.parameters
    try {
        $setting = Get-HLAuditPolicySetting -SubcategoryGuid ([guid][string]$parameters.subcategoryGuid)
    }
    catch {
        if (Test-HLErrorMatchesCode -Exception $_.Exception -Code 1314, 0x80070522) {
            return Get-HLProbeResult -Status Unknown -Expected (@($parameters.requiredFlags) -join ' and ') -Actual $null -Message 'Querying the advanced audit policy requires an elevated session holding SeSecurityPrivilege. Collect with elevation to resolve this control.'
        }
        throw
    }
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
    $actual = $actualFlags.ToArray() -join ' and '
    $evidence = [pscustomobject][ordered]@{
        SubcategoryName = [string]$parameters.subcategoryName
        SubcategoryGuid = [string]$parameters.subcategoryGuid
        RawValue        = $setting.RawValue
        Success         = $setting.Success
        Failure         = $setting.Failure
    }

    if ($missing.Count -eq 0) {
        return Get-HLProbeResult -Status Pass -Expected $expected -Actual $actual -Message 'The effective advanced audit policy contains every required flag.' -Evidence $evidence
    }

    return Get-HLProbeResult -Status Fail -Expected $expected -Actual $actual -Message ('Missing required audit flags: {0}.' -f ($missing.ToArray() -join ', ')) -Evidence $evidence
}
