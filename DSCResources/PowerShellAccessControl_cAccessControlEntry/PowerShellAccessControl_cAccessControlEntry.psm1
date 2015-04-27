Import-Module $PSScriptRoot\..\..\PowerShellAccessControl.psd1

function Get-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[parameter(Mandatory = $true)]
		[ValidateSet("AccessAllowed","AccessDenied","SystemAudit")]
		[System.String]
		$AceType = "AccessAllowed",

		[parameter(Mandatory = $true)]
		[System.String]
		$Principal
	)

    $Params = CleanParams $PSBoundParameters -GetMode
    $GetSdParams = $Params.GetSdParams
    $GetAceParams = $Params.AceFunctionParams

    $CurrentActionString = "Getting ACEs of type '$AceType' for '$Principal' on '$Path'"
    Write-Verbose $CurrentActionString
    Write-Debug $CurrentActionString
    Get-SecurityDescriptor @GetSdParams | Get-AccessControlEntry @GetAceParams | ForEach-Object {

	    $returnValue = @{
		    Path = $Path
		    ObjectType = $ObjectType
		    AceType = $_.AceType
		    Principal = $_.Principal
		    AccessMask = $_.AccessMask
		    AppliesTo = $_.AppliesTo.ToString()
		    OnlyApplyToThisContainer = $_.OnlyApplyToThisContainer
	    }
        
        if ($returnValue.AceType -eq "SystemAudit") {
		    $returnValue.AuditSuccess = ($_.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success)
		    $returnValue.AuditFailure = ($_.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Failure)
        }

        $returnValue
    }
}

function Set-TargetResource {
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = "Present",

		[parameter(Mandatory = $true)]
		[ValidateSet("AccessAllowed","AccessDenied","SystemAudit")]
		[System.String]
		$AceType,

		[System.Boolean]
		$AuditSuccess,

		[System.Boolean]
		$AuditFailure,

		[parameter(Mandatory = $true)]
		[System.String]
		$Principal,

		[System.UInt32]
		$AccessMask,

		[System.String]
		$AppliesTo,

		[System.Boolean]
		$OnlyApplyToThisContainer,

		[System.Boolean]
		$Specific
	)

    $CommandParams = @{
        Force = $true
        Apply = $true
    }

    switch ($Ensure) {

        "Present" {
            $Command = "Add-AccessControlEntry"
            $CommandParams.AddEvenIfAclDoesntExist = $true # Sometimes ACL might not exist. Since Get-SD is called with -Audit switch when AceType is SystemAudit, shouldn't have to worry about overwriting ACL
        }

        "Absent" {
            $Command = "Remove-AccessControlEntry"
        }

        default {
            throw 'Unknown value for $Ensure parameter'
        }
    }

    $Params = CleanParams $PSBoundParameters -SetMode
    $GetSdParams = $Params.GetSdParams
    $NewAceParams = $Params.AceFunctionParams

    $Ace = New-AccessControlEntry @NewAceParams
    $SDObject = Get-SecurityDescriptor @GetSdParams

    $CurrentActionString = "Calling $Command on $Path ($Principal $AceType ACE)"
    Write-Verbose $CurrentActionString
    Write-Debug $CurrentActionString
    & $Command -SDObject $SDObject -AceObject $Ace @CommandParams
}

function Test-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = "Present",

		[parameter(Mandatory = $true)]
		[ValidateSet("AccessAllowed","AccessDenied","SystemAudit")]
		[System.String]
		$AceType,

		[System.Boolean]
		$AuditSuccess,

		[System.Boolean]
		$AuditFailure,

		[parameter(Mandatory = $true)]
		[System.String]
		$Principal,

		[System.UInt32]
		$AccessMask,

		[System.String]
		$AppliesTo,

		[System.Boolean]
		$OnlyApplyToThisContainer,

		[System.Boolean]
		$Specific
	)

    $Params = CleanParams $PSBoundParameters 
    $GetSdParams = $Params.GetSdParams
    $GetAceParams = $Params.AceFunctionParams

    $CurrentActionString = "Testing to see if $AceType ACE for $Principal on $Path is $Ensure"
    Write-Verbose $CurrentActionString
    Write-Debug $CurrentActionString
    $Present = [bool] (Get-SecurityDescriptor @GetSdParams | Get-AccessControlEntry @GetAceParams)

    switch ($Ensure) {
        "Present" {
            return $Present
        }

        "Absent" {
            return -not $Present
        }
    }
}

function CleanParams {
    param(
        [hashtable] $Parameters,
        [switch] $SetMode,  # Used to check if an AccessMask should be added when not provided
        [switch] $GetMode   # Get-TargetResource gets exepmt from certain checks
    )

    $GetSdParams = @{}

    $Parameters.Verbose = $false

    # Takes PSBoundParameters from Test/Set functions, does param validation/cleaning so that the helper functions
    # can receive the hash tables as input
    
    # Ensure isn't used by any of the PAC module functions
    $Ensure = $Parameters.Ensure
    $null = $Parameters.Remove("Ensure")

    if (-not $SetMode) {
        # When Get-Ace is called, make sure only non-inherited, explicit ACEs are shown
        $Parameters.NotInherited = $true
    }

    # Path is used by Get-SecurityDescriptor, but not by Get/New/Add/Remove-AccessControlEntry (at least not how the
    # *-TargetResource functions are used:
    $GetSdParams.Path = $Parameters.Path
    $null = $Parameters.Remove("Path")

    # Go through each non-mandatory parameter and, if a value wasn't provided, provide the default values
    # here. Why do it here and not use default values in the param() block? These functions depend on
    # PSBoundParameters, which won't reflect default values.
    if ((-not $Parameters.AccessMask) -and (-not $GetMode)) {
        # This is OK if 'Ensure' is 'Absent' (Get-Ace in Test-TargetResource will return any ACE matching
        # the AceType if no AccessMask is provided, Remove-Ace in Set-TargetResource will remove all Access
        # since we're going to set all AccessMask bits

        if ($Ensure -ne "Absent") {
            throw "AccessMask required"
        }

        if ($SetMode) {
            $Parameters.AccessMask = [Int32]::MaxValue
        }
    }

    if (-not $Parameters.OnlyApplyToThisContainer -and $SetMode) {
        # By default, ACE propagation will occur, so set this value to $false
        $Parameters.OnlyApplyToThisContainer = $false
    }


    if (-not $Parameters.AppliesTo -and $SetMode) {
        # AppliesTo wasn't specified, but directories and registry keys don't usually have ACEs that only
        # apply to the object (which is what the PAC functions will assume if we used the AccessMask parameter
        # w/o specifying AppliesTo). For that reason, we check the objecttype here and make the necessary changes:
        switch ($Parameters.ObjectType) {
            Directory {
                $AppliesToString = "Object, ChildContainers, ChildObjects"
            }

            { "WmiNamespace", "RegistryKey" -contains $_ } {
                $AppliesToString = "Object, ChildContainers"
            }

            default {
                $AppliesToString = "Object"
            }
        }
        $Parameters.AppliesTo = $AppliesToString
    }

    # The $Type parameter is handled with a ValidateSet(), and the strings mentioned there don't necessarily correspond to the 
    # System.Security.AccessControl.ResourceType enumeration that Get-SecurityDescriptor uses. Here's where we translate that:
    if ($Parameters.ContainsKey("ObjectType")) {
        switch ($Parameters.ObjectType) {
            
            { "File", "Directory" -contains $_ } {
# This actually works better if we let the module figure out if it's a file or directory
#                $GetSdParams.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
            }

            RegistryKey {
#                $GetSdParams.ObjectType = [System.Security.AccessControl.ResourceType]::RegistryKey
            }

            Service {
                $GetSdParams.ObjectType = [System.Security.AccessControl.ResourceType]::Service
            }

            WmiNamespace {
                $GetSdParams.Path = "CimInstance: \\.\{0}:__SystemSecurity=@" -f $GetSdParams.Path
            }

            default {
                throw ('Unknown $Type parameter: {0}' -f $Parameters.Type)
            }

        }

        $null = $Parameters.Remove("ObjectType")
    }

    if (-not $Parameters.AceType) {
        $null = $Parameters.Add("AceType", "AccessAllowed")
    }
    elseif ($Parameters.AceType -eq "SystemAudit") {
        if ((-not $GetMode) -and (-not ($Parameters.AuditSuccess -or $Parameters.AuditFailure))) {
            throw "Change configuration to assign 'AuditSuccess' and/or 'AuditFailure' as `$true"
        }

        $GetSdParams.Audit = $true

        if (-not $SetMode) {
            $AuditFlags = 0
            foreach ($AuditType in "Success", "Failure") {
                if ($Parameters.ContainsKey("Audit$AuditType")) {
                    $Parameters.Remove("Audit$AuditType")
                    $AuditFlags = $AuditFlags -bor [System.Security.AccessControl.AuditFlags]::$AuditType
                }
            }
            $Parameters.AuditFlags = $AuditFlags
        }
    }

    @{
        GetSdParams = $GetSdParams
        AceFunctionParams = $Parameters
    }
}

Export-ModuleMember -Function *-TargetResource
