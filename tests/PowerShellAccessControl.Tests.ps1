$UserIsAdmin = $true
Import-Module PowerShellAccessControl

$Sddl = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)S:AI(AU;OICIFA;FA;;;WD)(AU;OICIIDSA;SD;;;WD)"
$SDfromSddl = New-PacSecurityDescriptor -Sddl $Sddl -ObjectType FileObject -IsContainer
Describe "New-PacSecurityDescriptor" {
    
    It "Creates a folder's security descriptor" {
        $SDfromSddl.Access.Count | Should Be 8
        $SDfromSddl.Audit.Count | Should Be 2
    }

    It "Can output valid SDDL" {
        $NewSD = New-PacSecurityDescriptor -Sddl $SDfromSddl.Sddl -ObjectType $SDfromSddl.ObjectType -IsContainer:$SDfromSddl.IsContainer
        $NewSD.Sddl -eq $SDfromSddl.Sddl | Should Be $true
    }

    It "Can output valid binary form" {
        $NewSD = New-PacSecurityDescriptor -BinarySD ($SDfromSddl.GetSecurityDescriptorBinaryForm()) -ObjectType $SDfromSddl.ObjectType -IsContainer:$SDfromSddl.IsContainer
        $NewSD.Sddl -eq $SDfromSddl.Sddl | Should Be $true
    }
}

if (-not $UserIsAdmin) {
    Write-Warning "Unable to test -Audit switch on Get-PacSecurityDescriptor because user is not administrator"
}
Describe "Get-PacSecurityDescriptor" {
    Context "Works with folders" {
        $Path = "C:\Windows"
        $Acl = Get-Acl $Path

        It "Matches Get-Acl output without -Audit" {
            (Get-PacSecurityDescriptor $Path).Sddl | Should Be $Acl.Sddl
        }

        if ($UserIsAdmin) {
            $AclWithAudit = Get-Acl $Path -Audit
            It "Matches Get-Acl output with -Audit" {
                (Get-PacSecurityDescriptor $Path -Audit).Sddl | Should Be $AclWithAudit.Sddl
            }

            It "Matches Get-Acl output with -PacSDOption (New-PacSDOption -Audit)" {
                (Get-PacSecurityDescriptor $Path -PacSDOption (New-PacSDOption -Audit)).Sddl | Should Be $AclWithAudit.Sddl
            }

            It "Works with limited sections (Audit)" {
                (Get-PacSecurityDescriptor $Path -PacSDOption (New-PacSDOption -SecurityDescriptorSections Audit)).Sddl | Should Be $AclWithAudit.GetSecurityDescriptorSddlForm("Audit")
            }

        }

        It "Works with limited sections (Owner, Access)" {
            (Get-PacSecurityDescriptor $Path -PacSDOption (New-PacSDOption -SecurityDescriptorSections Owner, Access)).Sddl | Should Be $Acl.GetSecurityDescriptorSddlForm("Owner, Access")
        }

        if ($UserIsAdmin) {

            $File = New-Item $TestDrive\bypass_acl_check -ItemType File
            $File | Add-PacAccessControlEntry -AceType Deny -Principal "Everyone" -FolderRights FullControl -PassThru | Set-PacOwner -Principal ([System.Security.Principal.SecurityIdentifier] "S-1-5-6-7-8-9") -Apply -Force

            It "Should throw an error for SD it can't read (File)" {
                Write-Warning "Need to get this to test for specific exception; first, is that possible, and, if so, fix module to start throwing them"
                { $File | Get-PacSecurityDescriptor -ErrorAction Stop } | Should Throw
            }

            It "Can bypass Acl check (File)" {
                $File | Get-PacSecurityDescriptor -PacSDOption (New-PacSDOption -BypassAclCheck) | % Sddl | Should Not BeNullOrEmpty
            }

            # Cleanup
            $File | Set-PacOwner -Force -WarningAction SilentlyContinue
            $File | Get-PacAccessControlEntry -ExcludeInherited | Remove-PacAccessControlEntry -Force
        }
        else {
            Write-Warning "Unable to test -BypassAcl functionality b/c user is not administrator"
        }

        if ($UserIsAdmin) {
            It "Gets NTFS rights for UNC share" {
                Get-PacSecurityDescriptor \\$env:computername\c$ -ea Stop | Select -exp ObjectType | Should Be "FileObject"
            }
        }
        else {
            Write-Warning "Unable to test UNC functionality b/c user is not administrator (admin C$ share is tested)"
        }

        It "Works with FileSystem PSDrives whose root is different than name (TestDrive:\)" {
            $ErrorActionPreference = "Stop"
            $PsDriveSddl = (Get-PacSecurityDescriptor TestDrive:\).Sddl
            $FolderSddl = (Get-PacSecurityDescriptor $TestDrive).Sddl
            $PsDriveSddl | Should Not BeNullOrEmpty
            $PsDriveSddl -eq $FolderSddl | Should Be $true
        }

        It "Works with custom Registry PSDrives" {

            $RegPsDriveRoot = "HKLM:\SOFTWARE\Microsoft"
            $RegPsDriveName = "pac_registry_pester_test"
            New-PSDrive -PSProvider Registry -Root $RegPsDriveRoot -Name $RegPsDriveName

            $ErrorActionPreference = "Stop"
            $PsDriveSddl = (Get-PacSecurityDescriptor "${RegPsDriveName}:").Sddl
            $RegSddl = (Get-PacSecurityDescriptor $RegPsDriveRoot).Sddl
            $PsDriveSddl | Should Not BeNullOrEmpty
            $PsDriveSddl -eq $RegSddl | Should Be $true
        }
    }

}