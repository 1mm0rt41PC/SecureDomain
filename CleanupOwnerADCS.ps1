########################################################
########################################################
# IF YOU ARE READ TO APPLY ALL CHANGE, SET IT TO $false
$testMode=$true
########################################################
########################################################

$global:count_ACL = 0;
$global:count_Owner = 0;
$global:domain_Base = (Get-ADDomain).DistinguishedName
$global:domain_SID = (Get-ADDomain).DomainSID.Value



function SidTo-String( $sid )
{
	if( $sid.StartsWith('-') ){
		$sid = $global:domain_SID+$sid
	}
	return (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate( [System.Security.Principal.NTAccount]).Value
}

# Get the name of the group administrators of the domain internationally
$Secure_SID = @(
	SidTo-String '-512';# Domain Admins
	SidTo-String '-519';# Enterprise Admins
	SidTo-String '-500';# DOM\Administrator
	SidTo-String '-516';# DOM\Domain Controllers
	SidTo-String '-521';# DOM\Read Only Domain Controllers 
	SidTo-String '-498';# DOM\Enterprise Read Only Domain Controllers 
	SidTo-String 'S-1-5-32-544';	# BUILTIN\Administrators
	SidTo-String 'S-1-5-9';	 	# BUILTIN\ENTERPRISE DOMAIN CONTROLLERS
	#SidTo-String 'S-1-5-10';   	# Self
	SidTo-String 'S-1-5-19';	# NT Authority
	SidTo-String 'S-1-5-18';	# Local System
)

<#
.SYNOPSIS
	Change the owner of the object to "Domain Admins"

.DESCRIPTION
	Change the owner of the object to "Domain Admins"

.PARAMETER obj
	The object to change, can be a computer, a user, a group or an OU
	
.PARAMETER modePreview
	Apply change or juste print what will be change ?
#>
function setOwnerToDA( $obj, $modePreview=$true, $setOwnerSID=($global:domain_SID+"-512"), $setOwnerName=(SidTo-String '-512'), $allowOwnerComputer=$false )
{
	try{
		$comppath = $obj.DistinguishedName.ToString()
		$comppath = "AD:$comppath"
		$acl = Get-Acl -Path $comppath
		if( $acl -eq $null ){
			Write-Host -NoNewLine -BackgroundColor DarkRed "[@] Unable to get ACL for ``"
			Write-Host -ForegroundColor DarkCyan $obj.Name -NoNewLine
			Write-Host -BackgroundColor DarkRed "``. Object `$acl is NULL"
			Write-Host -BackgroundColor DarkRed "Run this script with full admin priviliege !"
			return;
		}
		if( $acl.Owner -eq $setOwnerName -or $Secure_SID.Contains($acl.Owner) -or ($allowOwnerComputer -eq $true -and $acl.Owner.EndsWith("$"))){
			Write-Host -NoNewLine -ForegroundColor Green "[+]"
			Write-Host -NoNewLine " Valid owner for ``"
			Write-Host -NoNewLine -ForegroundColor DarkCyan $obj.Name
			Write-Host "``"
			return ;
		}
		$global:count_Owner += 1
		if( $modePreview ){
			Write-Host -NoNewLine "... Changing owner of ``"
			Write-Host -NoNewLine -ForegroundColor DarkCyan $obj.Name
			Write-Host -NoNewLine "`` from ``"
			Write-Host -NoNewLine -ForegroundColor DarkCyan $acl.Owner
			Write-Host -NoNewLine "`` to ``"
			Write-Host -NoNewLine -ForegroundColor DarkCyan $setOwnerName
			Write-Host -NoNewLine "`` "
			Write-Host -NoNewLine -BackgroundColor DarkGreen "(PreviewMode ! NO CHANGE on ACL)"
			Write-Host "."
		}else{
			Write-Host -NoNewLine -BackgroundColor DarkRed "/!\"
			Write-Host -NoNewLine " Changing owner of ``"
			Write-Host -NoNewLine -ForegroundColor DarkCyan $obj.Name
			Write-Host -NoNewLine "`` from ``"
			Write-Host -NoNewLine -ForegroundColor DarkCyan $acl.Owner
			Write-Host -NoNewLine "`` to ``"
			Write-Host -NoNewLine -ForegroundColor DarkCyan $setOwnerName
			Write-Host -NoNewLine "`` "
			Write-Host -NoNewLine -BackgroundColor DarkRed "(💥PROD mode ! CHANGING ACLs !)"
			Write-Host "."
			try{
				$acl.SetOwner($setOwnerSID)
				Set-Acl -Path $comppath -AclObject $acl
			}Catch{
				Write-Host -NoNewLine -BackgroundColor DarkRed "[@] Error when WRITTING owner for ``"
				Write-Host -ForegroundColor DarkCyan $obj.Name -NoNewLine
				Write-Host -BackgroundColor DarkRed "``"
			}
		}
	}Catch{
		Write-Host -NoNewLine -BackgroundColor DarkRed "[@] Error when reading owner for ``"
		Write-Host -ForegroundColor DarkCyan $obj.Name -NoNewLine
		Write-Host -BackgroundColor DarkRed "``"
	}
}



Get-ADObject -Filter * -SearchBase ("CN=Public Key Services,CN=Services,CN=Configuration,"+$global:domain_Base) -Properties * | foreach {
	$obj = [PSCustomObject]@{
		Name			   = "PKI: "+$_.DistinguishedName.ToString();
		DistinguishedName  = $_.DistinguishedName.ToString();
	}
	setOwnerToDA $obj $testMode
}
