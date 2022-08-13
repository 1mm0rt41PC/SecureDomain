## With bloodhound you can spot week acl between users / computers
## Week ACL between users
# MATCH p=(u1:User)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink*1..]->(u2:User) WHERE NOT(u1.name CONTAINS "MSOL_") RETURN p LIMIT 200
## Week ACL between computers
# MATCH p=(u1:Computer)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink*1..]->(u2:Computer) WHERE NOT(u1.name CONTAINS "MSOL_") RETURN p LIMIT 200
## Week ACL users to computers
# MATCH p=(u1:User)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink*1..]->(u2:Computer) WHERE NOT(u1.name CONTAINS "MSOL_") RETURN p LIMIT 200
## Week ACL computers to users
# MATCH p=(u1:Computer)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink*1..]->(u2:User) WHERE NOT(u1.name CONTAINS "MSOL_") RETURN p LIMIT 200
## All strange direct ACLs
# MATCH p=(u1)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink*1..]->(u2) WHERE NOT(u1.name CONTAINS "MSOL_") AND NOT(u2.name CONTAINS "MSOL_") AND NOT(u1.name CONTAINS "ADMIN") AND NOT(u2.name CONTAINS "ADMIN") RETURN p LIMIT 200


########################################################
########################################################
# IF YOU ARE READ TO APPLY ALL CHANGE, SET IT TO $false
$testMode=$true
########################################################
########################################################

# List computers with an incorrect owner
Get-ADComputer -Filter * | Select-Object Name, @{Label="Owner";Expression={(get-acl -Path ("AD:"+$_.DistinguishedName)).Owner}}

# Get the name of the group administrators of the domain internationally
$domainAdmins = New-Object System.Security.Principal.SecurityIdentifier(((Get-ADDomain).DomainSID.Value)+"-512")
$stringNameDA = $domainAdmins.Translate( [System.Security.Principal.NTAccount]).Value


########################################################
<#
.SYNOPSIS
    Change the owner of the object to "Domain Admins" ($domainAdmins)

.DESCRIPTION
    Change the owner of the object to "Domain Admins" ($domainAdmins)

.PARAMETER obj
    The object to change, can be a computer, a user, a group or an OU
	
.PARAMETER modePreview
    Apply change or juste print what will be change ?
#>
function setOwnerToDA( $obj, $modePreview=$false )
{
	$comppath = $obj.DistinguishedName.ToString()
	$comppath = "AD:$comppath"
	$acl = Get-Acl -Path $comppath
	if( $acl.Owner -eq $stringNameDA -or $acl.Owner.StartsWith("BUILTIN\") -or $acl.Owner.StartsWith("AUTORITE NT\") -or $acl.Owner.StartsWith("NT AUTHORITY\") ){
		return ;
	}
	if( $modePreview ){
		Write-Host -BackgroundColor DarkRed "PreviewMode ! NO CHANGE on ACL"
	}else{
		Write-Host -BackgroundColor DarkGreen "PreviewMode disabled ! CHANGING ACLs !"
	}
	Write-Host "Changing owner of $($obj.Name) from $($acl.Owner) to $stringNameDA"
	if( $modePreview -eq $false ){
		$acl.SetOwner($domainAdmins)
		Set-Acl -Path $comppath -AclObject $acl
	}
}


########################################################
<#
.SYNOPSIS
    Test if $sUser is a valid user in the AD.

.DESCRIPTION
    Test if $sUser is a valid user in the AD.

.PARAMETER sUser
    The username to test
#>
function isAdUser( $sUser )
{
	#Write-Host "    $sUser"
	if( $sUser.StartsWith("MSOL_") ){
		return $false
	}
	try{
		Get-ADUser $sUser | out-null
		return $true
	}catch{
		return $false
	}
}


########################################################
<#
.SYNOPSIS
    Test if $sUser is a valid computer in the AD.

.DESCRIPTION
    Test if $sUser is a valid computer in the AD.

.PARAMETER sUser
    The username to test
#>
function isAdComputer( $sUser )
{
	#Write-Host "    $sUser"
	try{
		Get-ADComputer $sUser | out-null
		return $true
	}catch{
		return $false
	}
}


########################################################
<#
.SYNOPSIS
    Test if $sUser is a valid group in the AD.

.DESCRIPTION
    Test if $sUser is a valid group in the AD.

.PARAMETER sUser
    The username to test
#>
function isAdGroup( $sUser )
{
	#Write-Host "    $sUser"
	try{
		Get-ADGroup $sUser | out-null
		return $true
	}catch{
		return $false
	}
}


########################################################
<#
.SYNOPSIS
    Remove ACLs that are not inherited and that not pass $funcTester

.DESCRIPTION
    Remove ACLs that are not inherited and that not pass $funcTester

.PARAMETER obj
    The object to change, can be a computer, a user, a group or an OU
	
.PARAMETER modePreview
    Apply change or juste print what will be change ?
	
.PARAMETER funcTester
    Function to use to check ACLs
#>
function removeWeekAcl_fromUsers( $obj, $modePreview=$false, $funcTester='isAdUser' )
{
	$comppath = $obj.DistinguishedName.ToString()
	$comppath = "AD:$comppath"
	$acl = Get-Acl -Path $comppath

	$acls_to_remove=$acl.access | where-object { ($_.IsInherited -eq $false) -and ($_.IdentityReference.ToString().StartsWith($env:USERDOMAIN)) -and ( &$funcTester ($_.IdentityReference.Value.ToString().Split('\')[1])) }

	if( $acls_to_remove.Count -gt 0 ){
		if( $modePreview ){
			Write-Host -BackgroundColor DarkRed "PreviewMode ! NO CHANGE on ACL"
		}else{
			Write-Host -BackgroundColor DarkGreen "PreviewMode disabled ! CHANGING ACLs !"
		}

		foreach( $aclr in $acls_to_remove ){
			Write-Host "Removing ACL for $($aclr.IdentityReference.Value) on $comppath"
			if( $modePreview -eq $false ){
				$acl.RemoveAccessRule($aclr) | Out-Null
				Set-Acl -Path $comppath -AclObject $acl | Out-Null
			}
		}
	}
}


########################################################
########################################################
########################################################

# Let's clean up this AD
Get-ADComputer -Filter * | foreach {
	Write-Host "Analyzing $($_.Name)"
	removeWeekAcl_fromUsers $_ $testMode 'isAdUser'
	removeWeekAcl_fromUsers $_ $testMode 'isAdComputer'
	setOwnerToDA $_ $testMode
}
Get-ADOrganizationalUnit -Filter * | foreach {
	Write-Host "Analyzing $($_.Name)"
	removeWeekAcl_fromUsers $_ $testMode 'isAdUser'
	removeWeekAcl_fromUsers $_ $testMode 'isAdComputer'
	setOwnerToDA $_ $testMode
}

Get-ADUser -Filter * | foreach {
	Write-Host "Analyzing $($_.Name)"
	removeWeekAcl_fromUsers $_ $testMode 'isAdUser'
	removeWeekAcl_fromUsers $_ $testMode 'isAdComputer'
	setOwnerToDA $_ $testMode
}
Get-ADGroup -Filter * | foreach {
	Write-Host "Analyzing $($_.Name)"
	removeWeekAcl_fromUsers $_ $testMode 'isAdUser'
	removeWeekAcl_fromUsers $_ $testMode 'isAdComputer'
	setOwnerToDA $_ $testMode
}
