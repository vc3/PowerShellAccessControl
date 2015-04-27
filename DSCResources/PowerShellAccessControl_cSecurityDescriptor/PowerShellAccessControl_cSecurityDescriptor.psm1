# We're gonna have to use some internal functions for Principal -> SID translation
$Module = Import-Module $PSScriptRoot\..\..\PowerShellAccessControl.psd1 -PassThru

# The Set-TargetResource currently overwrites anything sent to it, even if just one component is what's causing
# the test to fail. Should function be re-written to internally call Test-TargetResource for each single component?
$CsvProperties = @(
    "AceType"
    "Principal" 
    "AccessMask"
    "AppliesTo"
    "OnlyApplyToThisContainer"
    @{Name="AuditSuccess"; E={ $_.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success }}
    @{Name="AuditFailure"; E={ $_.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Failure }}
)
$AcePropertyList = echo AccessMaskDisplay, AceType, AppliesTo, DisplayName, InheritanceString, InheritedFrom, OnlyApplyToThisContainer, Path, Principal, AccessMask, AceFlags, AceQualifier, AuditFlags, BinaryLength, InheritanceFlags, IsCallback, IsInherited, OpaqueLength, PropagationFlags, SecurityIdentifier

$ExcludeIncludeInheritedAcesInCheck = $true
function Get-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param (
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType
	)

    $Params = PrepareParams $PSBoundParameters 
    $GetSdParams = $Params.GetSdParams
    $GetSdParams.Audit = $true

    $SD = Get-SecurityDescriptor @GetSdParams -ErrorAction Stop

    if ($SD.AreAccessRulesProtected) {
        $AccessInheritance = "Disabled"
    }
    else {
        $AccessInheritance = "Enabled"
    }

    if ($SD.AreAuditRulesProtected) {
        $AuditInheritance = "Disabled"
    }
    else {
        $AuditInheritance = "Enabled"
    }

	$returnValue = @{
		Path = $Path
		ObjectType = $ObjectType
		Owner = & $Module { $args[0] | ConvertToIdentityReference -ErrorAction Stop -ReturnSid } $SD.Owner
		Group = & $Module { $args[0] | ConvertToIdentityReference -ErrorAction Stop -ReturnSid } $SD.Group
		Access = $SD | Get-AccessControlEntry -AceType AccessAllowed, AccessDenied -NotInherited:$ExcludeIncludeInheritedAcesInCheck | select $CsvProperties | select * -ExcludeProperty Audit* | ConvertTo-Csv -NoTypeInformation | Out-String
		AccessInheritance = $AccessInheritance
		Audit = $SD | Get-AccessControlEntry -AceType SystemAudit -NotInherited:$ExcludeIncludeInheritedAcesInCheck | select $CsvProperties | ConvertTo-Csv -NoTypeInformation | Out-String
		AuditInheritance = $AuditInheritance
	}

	$returnValue
}

function Set-TargetResource {
	[CmdletBinding()]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[System.String]
		$Owner,

		[System.String]
		$Group,

		[System.String]
		$Access,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$AccessInheritance,

		[System.String]
		$Audit,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$AuditInheritance
	)

    $Params = PrepareParams $PSBoundParameters 
    $GetSdParams = $Params.GetSdParams
    $GetSdParams.Audit = $true

    $SD = Get-SecurityDescriptor @GetSdParams -ErrorAction Stop
    $Sections = [System.Security.AccessControl.AccessControlSections]::None

    # Not all parameters are required, so only check sections that were provided
    foreach ($CurrentSection in "Owner","Group") {
        if ($PSBoundParameters.ContainsKey($CurrentSection)) {
            Write-Verbose ("Setting section $CurrentSection to {0}" -f $PSBoundParameters.$CurrentSection)
            $IdentityReference = & $Module { $args[0] | ConvertToIdentityReference -ErrorAction Stop -ReturnSid } $PSBoundParameters.$CurrentSection
            $SD.SecurityDescriptor.$CurrentSection = $IdentityReference

            $Sections = $Sections -bor [System.Security.AccessControl.AccessControlSections]::$CurrentSection
        }
    }
    foreach ($AclType in "Access", "Audit") {
        if ($PSBoundParameters.ContainsKey($AclType)) {
            Write-Verbose "Setting section $AclType"
            $Aces = $PSBoundParameters.$AclType | ConvertCsvToAce

            Write-Verbose "    Removing all $AclType ACEs"
            $RemoveParams = @{ 
                "RemoveAll${AclType}Entries" = $true 
            }
            $SD | Remove-AccessControlEntry @RemoveParams -ErrorAction Stop

            Write-Verbose "    Adding new ACEs"
            foreach ($CurrentAce in $Aces) {
                $SD | Add-AccessControlEntry -AceObject $CurrentAce -ErrorAction Stop
            }

            $Sections = $Sections -bor [System.Security.AccessControl.AccessControlSections]::$AclType
        }

        if ($PSBoundParameters.ContainsKey("${AclType}Inheritance")) {
            $Action = $PSBoundParameters["${AclType}Inheritance"] -replace "d$"
            Write-Verbose "Setting section ${AclType}Inheritance to ${Action}d"

            $Parameters = @{
                InputObject = $SD
                Force = $true     # Make it silent
                $AclType = $true
            }

            & "${Action}-AclInheritance" @Parameters
        }
    }

    Write-Verbose ("Applying security descriptor with the following sections: {0}" -f ([PowerShellAccessControl.PInvoke.SecurityInformation] $Sections))
    $SD | Set-SecurityDescriptor -Force -Sections $Sections
}

function Test-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[System.String]
		$Owner,

		[System.String]
		$Group,

		[System.String]
		$Access,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$AccessInheritance,

		[System.String]
		$Audit,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$AuditInheritance
	)

    $CurrentSdHashTable = Get-TargetResource -Path $Path -ObjectType $ObjectType

    # This will be set to false at the first failed test
    $TestsPassed = $true

    # Not all parameters are required, so only check sections that were provided
    foreach ($CurrentSection in "Owner","Group") {
        if ($PSBoundParameters.ContainsKey($CurrentSection)) {
            Write-Verbose "Checking section $CurrentSection"
            $Sid = & $Module { $args[0] | ConvertToIdentityReference -ErrorAction Stop -ReturnSid } $PSBoundParameters.$CurrentSection

            if ($Sid.ToString() -ne $CurrentSdHashTable[$CurrentSection].ToString()) {
                Write-Verbose "    Test failed"
                $TestsPassed = $false
                break
            }
            Write-Verbose "    Test passed"
        }
    }
    foreach ($AclType in "Access", "Audit") {
        if ($PSBoundParameters.ContainsKey($AclType)) {
            Write-Verbose "Checking section $AclType"

            $CurrentAces = $CurrentSdHashTable.$AclType | ConvertCsvToAce
            $NewAces = $PSBoundParameters.$AclType | ConvertCsvToAce

            if ($CurrentAces -eq $null) { $CurrentAces = @() }
            if ($NewAces -eq $null) { $NewAces = @() }
Write-Debug comparing
            if (Compare-Object -ReferenceObject $CurrentAces -DifferenceObject $NewAces -Property $AcePropertyList -Debug:$false) {
                # Lists are different. It's possible to look to see where they are different, and only fix what's
                # wrong, but no point b/c DSC is supposed to fix this "All or Nothing".
                Write-Verbose "    Test failed"
                $TestsPassed = $false
                break  # break out of foreach block
            }
            Write-Verbose "    Test passed"
        }

        if ($PSBoundParameters.ContainsKey("${AclType}Inheritance")) {
            Write-Verbose "Checking section ${AclType}Inheritance"
            if ($PSBoundParameters["${AclType}Inheritance"] -ne $CurrentSdHashTable["${AclType}Inheritance"]) {
                Write-Verbose "    Test failed"
                $TestsPassed = $false
                break
            }
            Write-Verbose "    Test passed"
        }
    }

    $TestsPassed
}

function PrepareParams {
    param(
        [hashtable] $Parameters
    )

    $GetSdParams = @{}
    $NewSdParams = @{}

    $NewSdParams.Verbose = $GetSdParams.Verbose = $false
    $GetSdParams.Path = $Parameters.Path

    $NewSdParams.Sddl = $Parameters.Sddl

    # The $Type parameter is handled with a ValidateSet(), and the strings mentioned there don't necessarily correspond to the 
    # System.Security.AccessControl.ResourceType enumeration that Get-SecurityDescriptor uses. Here's where we translate that:
    if ($Parameters.ContainsKey("ObjectType")) {
        switch ($Parameters.ObjectType) {
            
            { "File", "Directory" -contains $_ } {
# This actually works better if we let the module figure out if it's a file or directory
#                $GetSdParams.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
            }

            Directory {
                $NewSdParams.IsContainer = $true
            }

            RegistryKey {
#                $GetSdParams.ObjectType = [System.Security.AccessControl.ResourceType]::RegistryKey
                $NewSdParams.IsContainer = $true
            }

            Service {
                $GetSdParams.ObjectType = [System.Security.AccessControl.ResourceType]::Service
            }

            WmiNamespace {
                $NewSdParams.IsContainer = $true
                $GetSdParams.Path = "CimInstance: \\.\{0}:__SystemSecurity=@" -f $GetSdParams.Path
            }

            default {
                throw ('Unknown $Type parameter: {0}' -f $Parameters.Type)
            }
        }
    }

    @{
        GetSdParams = $GetSdParams
        NewSdParams = $NewSdParams
    }
}

filter GetBoolValue {
<#
Any switch parameters to New-AccessControlEntry need to be boolean values. Since the inputs are supposed to come
from a CSV, value is probably going to be strings 'True' or 'False'. This function will properly convert those
to boolean values. Alternatively, it will check to see if the strings are valid ints, and if they are, cast those
to boolean values.
#>

    switch ($_) {
        ([bool]::TrueString) {
            $true
            break
        }
        
        ([bool]::FalseString) {
            $false
            break
        }

        default {
            if (($_ -as [int]) -ne $null) {
                [bool][int] $_
                break
            }

            throw "Unable to convert '$_' to boolean"
            
        }
    }
}

function ConvertObjectToHash {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        $InputObject
    )

    process {
        foreach ($CurrentObject in $InputObject) {
            $ReturnHash = @{}
            
            foreach ($Property in ($CurrentObject | Get-Member -MemberType Properties | select -ExpandProperty Name)) {
                if ($CurrentObject.$Property -ne $null) {
                    $ReturnHash.$Property = $CurrentObject.$Property
                }
            }

            $ReturnHash
        }
    }
}

function ConvertCsvToAce {

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string] $InputCsv
    )

    process {
        $ParamHashTable = $InputCsv | ConvertFrom-Csv -ErrorAction Stop | ConvertObjectToHash

        # This next foreach block fixes the switch parameters that can be supplied to New-Ace function
        $ParamHashTable | ForEach-Object {
            foreach ($SwitchProperty in "OnlyApplyToThisContainer", "AuditSuccess", "AuditFailure") {
                if ($_.ContainsKey($SwitchProperty)) {
                    $_.$SwitchProperty = $_.$SwitchProperty | GetBoolValue
                }
            }
        }

        $ParamHashTable | ForEach-Object { New-AccessControlEntry -ErrorAction Stop @_ -GenericAce }
    }
}
Export-ModuleMember -Function *-TargetResource

