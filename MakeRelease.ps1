# This is mostly from PSReadLine's MakeRelease.ps1
param([switch] $Install)

add-type -AssemblyName System.IO.Compression.FileSystem

$targetDir = "${env:Temp}\PowerShellAccessControl"

if (Test-Path -Path $targetDir)
{
    rmdir -Recurse $targetDir
}

$null = mkdir $targetDir

if (-not(Get-Command -Name msbuild -ErrorAction Ignore))
{
    $env:path += ";${env:SystemRoot}\Microsoft.Net\Framework\v4.0.30319"
}

msbuild $PSScriptRoot\src\PowerShellAccessControl.sln /t:Rebuild /p:Configuration=Release

copy $PSScriptRoot\module_files\* $targetDir -recurse
copy $PSScriptRoot\src\bin\Release\PowerShellAccessControl.dll $targetDir

del $PSScriptRoot\PowerShellAccessControl.zip -ErrorAction Ignore
[System.IO.Compression.ZipFile]::CreateFromDirectory($targetDir, "$PSScriptRoot\PowerShellAccessControl.zip")

if ($Install)
{
    $InstallDir = "$HOME\Documents\WindowsPowerShell\Modules"

    if (-not(Test-Path -Path $InstallDir))
    {
        mkdir -force $InstallDir
    }

    try
    {
        if (Test-Path -Path $InstallDir\PowerShellAccessControl)
        {
            rmdir -Recurse -force $InstallDir\PowerShellAccessControl -ErrorAction Stop
        }
        copy -Recurse $targetDir $InstallDir
    }
    catch
    {
        Write-Error -Message "Can't install, module is probably in use."
    }
}
