function Test-HardeningLensExceptionFile {
    <#
    .SYNOPSIS
    Validates exception structure, control references, approval metadata, and expiry dates.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $file = Read-HLExceptionFile -Path $Path
        $result = Test-HLExceptionDocument -Document $file.Document
        $result | Add-Member -NotePropertyName Path -NotePropertyValue $file.Path -Force
        return $result
    }
    catch {
        return [pscustomobject][ordered]@{
            IsValid        = $false
            Errors         = @($_.Exception.Message)
            Warnings       = @()
            ExceptionCount = 0
            Path           = $Path
        }
    }
}
