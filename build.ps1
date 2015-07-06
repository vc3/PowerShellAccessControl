[CmdletBinding()]
param(
    [switch] $IgnoreWarnings
)

$OutputFile = "$PSScriptRoot\bin\ROE.PowerShellAccessControl.dll"
if (-not (Test-Path (Split-Path $OutputFile))) { New-Item -ItemType directory -Path (Split-Path $OutputFile) -Force | Out-Null }

#region Compile dll

# This makes sure the Microsoft.Management.Infrastructure assembly is loaded
gcim win32_computersystem | Out-Null 
$ReferencedAssemblies = echo System.DirectoryServices, System.Management, Microsoft.Management.Infrastructure, System.ServiceProcess, Microsoft.WSMan.Management, Microsoft.PowerShell.Commands.Management, Microsoft.CSharp, Microsoft.Management.Infrastructure.CimCmdlets #, Microsoft.ActiveDirectory.Management

$UsingStatements = @()
$SourceCode = @()
dir $PSScriptRoot\src -Filter *.cs -Recurse | Get-Content -Raw | % {
    foreach ($line in ($_ -split "`n")) {
        if ($line -match "^using .*;") {
            $UsingStatements += $line
        }
        else {
            $SourceCode += $line
        }
    }
}

$UsingStatements = $UsingStatements | Select-Object -Unique
$SourceCode = ($UsingStatements + $SourceCode) -join "`n"
Write-Debug ($UsingStatements -join "`n")
Add-Type -TypeDefinition $SourceCode -ReferencedAssemblies $ReferencedAssemblies -OutputAssembly $OutputFile -IgnoreWarnings:$IgnoreWarnings
#endregion
