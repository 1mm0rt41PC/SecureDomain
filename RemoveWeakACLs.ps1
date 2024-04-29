## With bloodhound you can spot weak acl between users / computers
## Weak ACL between users
# MATCH p=(u1:User)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink*1..]->(u2:User) WHERE NOT(u1.name CONTAINS "MSOL_") RETURN p LIMIT 200
## Weak ACL between computers
# MATCH p=(u1:Computer)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink*1..]->(u2:Computer) WHERE NOT(u1.name CONTAINS "MSOL_") RETURN p LIMIT 200
## Weak ACL users to computers
# MATCH p=(u1:User)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink*1..]->(u2:Computer) WHERE NOT(u1.name CONTAINS "MSOL_") RETURN p LIMIT 200
## Weak ACL computers to users
# MATCH p=(u1:Computer)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink*1..]->(u2:User) WHERE NOT(u1.name CONTAINS "MSOL_") RETURN p LIMIT 200
## All strange direct ACLs
# MATCH p=(u1)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink*1..]->(u2) WHERE NOT(u1.name CONTAINS "MSOL_") AND NOT(u2.name CONTAINS "MSOL_") AND NOT(u1.name CONTAINS "ADMIN") AND NOT(u2.name CONTAINS "ADMIN") RETURN p LIMIT 200
## Print as CSV all unusual ACLs
# MATCH p=(u1:User)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink]->(u2) WHERE NOT(u1.name CONTAINS "MSOL_") and NOT(u2.name CONTAINS "HEALTHMAILBOX") RETURN u1.name,type(r),u2.name
# MATCH p=(u1:Computer)-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AddSelf|WriteSPN|AddKeyCredentialLink]->(u2) WHERE NOT(u1.name CONTAINS "MSOL_") and NOT(u2.name CONTAINS "HEALTHMAILBOX") RETURN u1.name,type(r),u2.name


<#
# To view only Owner of each item:

$allowedSid = @(
	(New-Object System.Security.Principal.SecurityIdentifier("$((Get-ADDomain).DomainSID.Value)-512")).Translate( [System.Security.Principal.NTAccount]).Value;
	(New-Object System.Security.Principal.SecurityIdentifier("$((Get-ADDomain).DomainSID.Value)-500")).Translate( [System.Security.Principal.NTAccount]).Value;
	(New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")).Translate( [System.Security.Principal.NTAccount]).Value;
	(New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate( [System.Security.Principal.NTAccount]).Value;
)
$output = Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -Filter '*' -Properties DisplayName,Name,ObjectClass,nTSecurityDescriptor | Select ObjectClass,DistinguishedName,@{Label="Owner";Expression={$_.nTSecurityDescriptor.Owner}},@{Label="Name";Expression={
if($_.ObjectClass -eq 'groupPolicyContainer' ){
	if( $_.DisplayName -ne $null -and $_.DisplayName -ne ""){$_.DisplayName}else{$_.Name}
}else{
	if( $_.Name -ne $null -and $_.Name -ne ""){$_.Name}else{$_.DisplayName}
}
}} | where { -not( $_.Owner -in $allowedSid) }
try {
	$output += Get-ChildItem -ErrorAction Ignore -Recurse C:\Windows\SYSVOL\domain | Select-Object @{Label="ObjectClass";Expression={"Folder SYSVOL"}},@{Label="DistinguishedName";Expression={$_.FullName}}, @{Label="Owner";Expression={(Get-Acl -Path $_.FullName).Owner}},Name | where { -not( $_.Owner -in $allowedSid) }
}catch{
	Write-Host "Unable to test ACL for SYSVOL. Please run the script on Domain Controller"
}
$output | ConvertTo-Csv -NoTypeInformation | Out-File -Encoding UTF8 C:\All-ACL.csv
$output | Out-GridView
#>

########################################################
########################################################

$ErrorActionPreference = "Stop"
$log = "$($env:TMP)\$([guid]::NewGuid().ToString()).txt"
Start-Transcript -Path $log -Force 


Write-Host -NoNewLine -ForegroundColor DarkMagenta "[?] "
$global:viewIfValid=$(Read-Host "Verbose mode that show valid acl [Y/n] ?") -in @("y","Y","")

Write-Host -NoNewLine -ForegroundColor DarkMagenta "[?] "
$global:checkOwner=$(Read-Host "Control owner ship [Y/n] ?") -in @("y","Y","")

Write-Host -NoNewLine -ForegroundColor DarkMagenta "[?] "
$global:checkInheritanceACL=$(Read-Host "Control ACL without inheritance [Y/n] ?") -in @("y","Y","")

Write-Host -NoNewLine -ForegroundColor DarkMagenta "[?] "
$global:checkOnlyOutdatedSID=$(Read-Host "Control only ACL with unused/old SID user/group [Y/n] ?") -in @("y","Y","")

Write-Host -NoNewLine -ForegroundColor DarkMagenta "[?] "
$global:checkVulnADCSTemplate=$(Read-Host "Control ADCS ACL [y/N] ?") -in @("y","Y")

Write-Host -NoNewLine -ForegroundColor DarkMagenta "[?] "
$global:testMode = (-not ($(Read-Host 'Confirm prod mode by typing "PROD". Type anything else for test only') -in @("PROD")))
if( $global:testMode ){
	Write-Host -NoNewLine -ForegroundColor Green "[+] "
	Write-Host -NoNewLine "Deployement in "
 	Write-Host -NoNewLine -BackgroundColor Green "TEST"
  	Write-Host -NoNewLine " mode = "
 	Write-Host -BackgroundColor Green $global:testMode
}else{
	Write-Host -NoNewLine -BackgroundColor DarkRed "/!\ "
	Write-Host -NoNewLine "Deployement in "
 	Write-Host -NoNewLine -BackgroundColor DarkRed "PROD"
  	Write-Host -NoNewLine " mode = "
 	Write-Host -BackgroundColor DarkRed (-not $global:testMode)
}
if( $global:testMode -eq $false -and -not ($(Read-Host "Confirm prod mode [y/n] ?") -in @("y","Y")) ){
	Write-Host "Are you realy ready ? Exiting..."
	Exit
}

Write-Host -ForegroundColor DarkCyan "########################################################"
Write-Host -NoNewLine -ForegroundColor Green "[+] "; Write-Host -NoNewLine -ForegroundColor DarkCyan "testMode= "; Write-Host $testMode
Write-Host -NoNewLine -ForegroundColor Green "[+] "; Write-Host -NoNewLine -ForegroundColor DarkCyan "viewIfValid= "; Write-Host $global:viewIfValid
Write-Host -NoNewLine -ForegroundColor Green "[+] "; Write-Host -NoNewLine -ForegroundColor DarkCyan "checkOwner= "; Write-Host $global:checkOwner
Write-Host -NoNewLine -ForegroundColor Green "[+] "; Write-Host -NoNewLine -ForegroundColor DarkCyan "checkInheritanceACL= "; Write-Host $global:checkInheritanceACL
Write-Host -NoNewLine -ForegroundColor Green "[+] "; Write-Host -NoNewLine -ForegroundColor DarkCyan "checkOnlyOutdatedSID= "; Write-Host $global:checkOnlyOutdatedSID
Write-Host -NoNewLine -ForegroundColor Green "[+] "; Write-Host -NoNewLine -ForegroundColor DarkCyan "checkVulnADCSTemplate= "; Write-Host $global:checkVulnADCSTemplate
if( -not($(Read-Host "Continue [Y/n] ?") -in @("y","Y","")) ){
	Exit
}


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
# Extended privileges
$ExtendedPriv = @{
	'00299570-246d-11d0-a768-00aa006e0529'=@("User-Force-Change-Password","Permits reseting password on user account.");
	'05c74c5e-4deb-43b4-bd9f-86664c2a7fd5'=@("Enable-Per-User-Reversibly-Encrypted-Password","Extended control access right that allows users to enable or disable the ``reversible encrypted password`` setting for user and computer objects.");
	'06bd3200-df3e-11d1-9c86-006008764d0e'=@("msmq-Receive","Allows receiving messages from the queue.");
	'06bd3201-df3e-11d1-9c86-006008764d0e'=@("msmq-Peek","Aallows peeking at messages in the queue.");
	'06bd3202-df3e-11d1-9c86-006008764d0e'=@("msmq-Send","Allows sending messages to the queue.");
	'06bd3203-df3e-11d1-9c86-006008764d0e'=@("msmq-Receive-journal","Allows receiving messages from the queue's Journal.");
	'0bc1554e-0a99-11d1-adbb-00c04fd8d5cd'=@("Recalculate-Hierarchy","Extended right to force the DS to recalculate the hierarchy.");
	'0e10c968-78fb-11d2-90d4-00c04f79dc55'=@("Certificate-Enrollment","Extended right needed to cause certificate enrollment.");
	'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'=@("DS-Replication-Get-Changes","Extended right needed to replicate changes from a given NC.");
	'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'=@("DS-Replication-Synchronize","Extended right needed to synchronize replication from a given NC.");
	'1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'=@("DS-Replication-Manage-Topology","Extended right needed to update the replication topology for a given NC.");
	'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'=@("DS-Replication-Get-Changes-All","Control access right that allows the replication of secret domain data.");
	'1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd'=@("Allocate-Rids","Extended right needed to request rid pool.");
	'280f369c-67c7-438e-ae98-1d46f3c6f541'=@("Update-Password-Not-Required-Bit","Extended control access right that allows a user to enable or disable the ``password not required`` setting for user objects.");
	'440820ad-65b4-11d1-a3da-0000f875ae0d'=@("Add-GUID","Extended right needed at the NC root to add an object with a specific GUID.");
	'45ec5156-db7e-47bb-b53f-dbeb2d03c40f'=@("Reanimate-Tombstones","Control access right that allows deleted schema elements to be restored.");
	'4b6e08c0-df3c-11d1-9c86-006008764d0e'=@("msmq-Receive-Dead-Letter","Allows receiving messages from the Dead Letter queue.");
	'4b6e08c1-df3c-11d1-9c86-006008764d0e'=@("msmq-Peek-Dead-Letter","Allows peeking at messages in the Dead Letter queue.");
	'4b6e08c2-df3c-11d1-9c86-006008764d0e'=@("msmq-Receive-computer-Journal","Allows receiving messages from the Computer Journal queue.");
	'4b6e08c3-df3c-11d1-9c86-006008764d0e'=@("msmq-Peek-computer-Journal","Allows peeking at messages in the Computer Journal queue.");
	'4ecc03fe-ffc0-4947-b630-eb672a8a9dbc'=@("DS-Query-Self-Quota","Control access right which allows a user to query the user's own quotas.");
	'62dd28a8-7f46-11d2-b9ad-00c04f79f805'=@("Recalculate-Security-Inheritance","Extended right needed to force DS to recompute ACL inheritance on a Naming Context.");
	'68b1d179-0d15-4d4f-ab71-46152e79a7bc'=@("Allowed-To-Authenticate","The control access right controls who can authenticate to a particular machine or service. It basically lives on computer, user and InetOrgPerson objects. It is also applicable on the domain object if access is allowed for the entire domain we. It can be applied to OU’s to permit users to be able to set inheritable ACE’s on OU’s containing a set of user/computer objects.");
	'69ae6200-7f46-11d2-b9ad-00c04f79f805'=@("DS-Check-Stale-Phantoms","Extended right needed to force DS to check stale phantom objects.");
	'91d67418-0135-4acc-8d79-c08e857cfbec'=@("SAM-Enumerate-Entire-Domain","This is a special control access right that can be used to restrict who can be allowed to use downlevel API such as NetQueryDisplayInformation and NetUser/GroupEnum and enumerate the entire domain.");
	'9432c620-033c-4db7-8b58-14ef6d0bf477'=@("Refresh-Group-Cache","This is for no GC logon. No GC logon relies on caching group memberships and this control access right is used to permission administrators/operators with rights to cause an immediate refresh of the cache, contacting an available G.C.");
	'9923a32a-3607-11d2-b9be-0000f87a36b2'=@("DS-Install-Replica","Extended right needed to do a replica install.");
	'ab721a52-1e2f-11d0-9819-00aa0040529b'=@("Domain-Administer-Server","Legacy SAM right.");
	'ab721a53-1e2f-11d0-9819-00aa0040529b'=@("User-Change-Password","Permits changing password on user account.");
	'ab721a54-1e2f-11d0-9819-00aa0040529b'=@("Send-As","Exchange right: allows sending mail as the mailbox.");
	'ab721a56-1e2f-11d0-9819-00aa0040529b'=@("Receive-As","Exchange right: allows receiving mail as a given mailbox.");
	'b4e60130-df3f-11d1-9c86-006008764d0e'=@("msmq-Open-Connector","Allows to open connector queue.");
	'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'=@("Generate-RSoP-Planning","The user who has the rights on an OU/Domain will be able to generate planning mode RSoP data for the users/computers within the OU.");
	'b7b1b3de-ab09-4242-9e30-9980e5d322f7'=@("Generate-RSoP-Logging","The user who has the rights on an OU/Domain will be able to generate logging mode RSoP data for the users/computers within the OU.");
	'ba33815a-4f93-4c76-87f3-57574bff8109'=@("Migrate-SID-History","Extended right that enables a user to migrate the SID-History without administrator privileges.");
	'bae50096-4752-11d1-9052-00c04fc2d4cf'=@("Change-PDC","Extended right needed to change the primary domain controller (PDC) emulator FSMO role owner.");
	'be2bb760-7f46-11d2-b9ad-00c04f79f805'=@("Update-Schema-Cache","Extended right to force a schema cache update.");
	'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd'=@("Change-Infrastructure-Master","Extended right needed to change the infrastructure FSMO role owner.");
	'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501'=@("Unexpire-Password","Extended control access right that allows a user to restore an expired password for a user object.");
	'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd'=@("Change-Rid-Master","Extended right needed to change the relative identifier (RID) master FSMO role owner.");
	'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd'=@("Change-Schema-Master","Extended right needed to change the schema master FSMO role owner.");
	'e2a36dc9-ae17-47c3-b58b-be34c55ba633'=@("Create-Inbound-Forest-Trust","Extended control access right that enables users to create an inbound-only trust between forests by adding them to the appropriate group.");
	'edacfd8f-ffb3-11d1-b41d-00a0c968f939'=@("Apply-Group-Policy","Extended right used by Group Policy engine to determine if a GPO applies to a user/computer or not.");
	'ee914b82-0a98-11d1-adbb-00c04fd8d5cd'=@("Abandon-Replication:","Extended right needed to cancel a replication sync.");
	'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96'=@("DS-Replication-Monitor-Topology","Extended control access right that allows the reading of replication monitoring data, such as replication status and object metadata.");
	'fec364e0-0a98-11d1-adbb-00c04fd8d5cd'=@("Do-Garbage-Collection","Extended right to force the Directory Service to do garbage collection. Control right to force the Directory Service to do garbage collection.");
	'a05b8cc2-17bc-4802-a710-e7c15ab866a2'=@("Certificate-AutoEnrollment","");
}
$PKI_CertUsage=@{
	"2.5.29.37.0"= "Any Purpose";
	"1.3.6.1.4.1.311.20.2.2"= "Smart Card Logon";
	"1.3.6.1.5.5.7.3.2"= "Client Authentication";
	"1.3.6.1.5.2.3.4"= "PKINIT Client Authentication";
	"1.3.6.1.5.5.7.3.1"= "Server Authentication";
	"1.3.6.1.5.2.3.5"= "KDC Authentication";
}
[Flags()] enum MS_PKI_ENROLLMENT_FLAG
{
	INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
	PEND_ALL_REQUESTS = 0x00000002
	PUBLISH_TO_KRA_CONTAINER = 0x00000004
	PUBLISH_TO_DS = 0x00000008
	AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
	AUTO_ENROLLMENT = 0x00000020
	CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80
	PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
	USER_INTERACTION_REQUIRED = 0x00000100
	ADD_TEMPLATE_NAME = 0x200
	REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
	ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
	ADD_OCSP_NOCHECK = 0x00001000
	ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
	NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
	INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
	ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
	ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
	SKIP_AUTO_RENEWAL = 0x00040000
	NO_SECURITY_EXTENSION = 0x00080000
}
[Flags()] enum MS_PKI_CERTIFICATE_NAME_FLAG
{
	ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
	ADD_EMAIL = 0x00000002
	ADD_OBJ_GUID = 0x00000004
	OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
	ADD_DIRECTORY_PATH = 0x00000100
	ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
	SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
	SUBJECT_ALT_REQUIRE_SPN = 0x00800000
	SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
	SUBJECT_ALT_REQUIRE_UPN = 0x02000000
	SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
	SUBJECT_ALT_REQUIRE_DNS = 0x08000000
	SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
	SUBJECT_REQUIRE_EMAIL = 0x20000000
	SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
	SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000
}

########################################################
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
function setOwnerToDA( $obj, $modePreview=$true, $setOwnerSID=($global:domain_SID+"-512"), $setOwnerName=(SidTo-String '-512'), $allowOwnerComputer=$false, $isFile=$false )
{
	if( $global:checkOwner -ne $true ){
		return ;
 	}
	try{
		$comppath = $obj.DistinguishedName.ToString()
  		if( $isFile -eq $false ){
			$comppath = "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$comppath"
		}
		$acl = Get-Acl -Path $comppath
		if( $acl -eq $null ){
			Write-Host -NoNewLine -BackgroundColor DarkRed "[@] Unable to get ACL for ``"
			Write-Host -ForegroundColor DarkCyan $obj.Name -NoNewLine
			Write-Host -BackgroundColor DarkRed "``. Object `$acl is NULL"
			Write-Host -BackgroundColor DarkRed "Run this script with full admin priviliege !"
			return;
		}
		if( $global:checkOnlyOutdatedSID -eq $true ){
			if( -not $acl.Owner.StartsWith('O:') ){
				if( $global:viewIfValid -eq $true ){
					Write-Host -NoNewLine -ForegroundColor Green "[+]"
					Write-Host -NoNewLine " Valid owner for ``"
					Write-Host -NoNewLine -ForegroundColor DarkCyan $obj.Name
					Write-Host "``"
				}
				return ;
			}
		}else{
			if( $acl.Owner -eq $setOwnerName -or $Secure_SID.Contains($acl.Owner) -or ($allowOwnerComputer -eq $true -and $acl.Owner.EndsWith("$"))){
				if( $global:viewIfValid -eq $true ){
					Write-Host -NoNewLine -ForegroundColor Green "[+]"
					Write-Host -NoNewLine " Valid owner for ``"
					Write-Host -NoNewLine -ForegroundColor DarkCyan $obj.Name
					Write-Host "``"
				}
				return ;
			}
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
				$acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($setOwnerSID)))
				Set-Acl -Path $comppath -AclObject $acl
			}Catch{
				Write-Host -NoNewLine -BackgroundColor DarkRed "[@] Error when WRITTING owner for ``"
				Write-Host -ForegroundColor DarkCyan $obj.Name -NoNewLine
				Write-Host -BackgroundColor DarkRed "``"
				Write-Callstack $_
			}
		}
	}Catch{
		Write-Host -NoNewLine -BackgroundColor DarkRed "[@] Error when reading owner for ``"
		Write-Host -ForegroundColor DarkCyan $obj.Name -NoNewLine
		Write-Host -BackgroundColor DarkRed "``"
		Write-Callstack $_
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
	#Write-Host "	$sUser"
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
	#Write-Host "	$sUser"
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
	#Write-Host "	$sUser"
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
function removeWeakAcl_fromUsers( $obj, $modePreview=$true, $funcTester='isAdUser', $isFile=$false )
{
	if( $global:checkInheritanceACL -ne $true ){
		return;
 	}
	try{
		$comppath = $obj.DistinguishedName
  		if( $isFile -eq $false ){
			$comppath = "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$comppath"
   		}
		$acl = Get-Acl -Path $comppath
		
		
		$acls_to_remove = $acl.access | where-object { ($_.IsInherited -eq $false) -and ($_.IdentityReference.ToString().StartsWith($env:USERDOMAIN)) -and ( &$funcTester ($_.IdentityReference.Value.ToString().Split('\')[1])) }

		if( $global:checkOnlyOutdatedSID ){
			$acls_to_remove = $acls_to_remove | where { $_.IdentityReference.ToString().StartsWith('O:') }
		}

		$global:count_ACL += $acls_to_remove.Count

		if( $acls_to_remove.Count -gt 0 ){
			if( $modePreview ){
				Write-Host -BackgroundColor DarkRed "=== PreviewMode ! NO CHANGE on ACL ==="
			}else{
				Write-Host -BackgroundColor DarkGreen "PreviewMode disabled ! CHANGING ACLs !"
			}

			foreach( $aclr in $acls_to_remove ){
				if( $modePreview ){
					Write-Host -NoNewLine "..."
				}else{
					Write-Host -NoNewLine -BackgroundColor DarkRed "/!\"
				}
				Write-Host " Removing ACL for $($aclr.IdentityReference.Value) on $comppath"
				if( $modePreview -eq $false ){
					try{
						$acl.RemoveAccessRule($aclr) | Out-Null
						Set-Acl -Path $comppath -AclObject $acl | Out-Null
					}Catch{
						Write-Host -NoNewLine -BackgroundColor DarkRed "[@] Error when WRITTING ACL for ``"
						Write-Host -ForegroundColor DarkCyan $obj.Name -NoNewLine
						Write-Host -BackgroundColor DarkRed "``"
						Write-Host $_.ScriptStackTrace
					}
				}
			}
		}else{
  			if( $global:viewIfValid -eq $true ){
				Write-Host -NoNewLine -ForegroundColor Green "[+]"
				Write-Host -NoNewLine " Valid ACL ($funcTester) for ``"
				Write-Host -NoNewLine -ForegroundColor DarkCyan $obj.Name
				Write-Host "``"
   			}
		}
	}Catch{
		Write-Host -NoNewLine -BackgroundColor DarkRed "[@] Error when reading ACL for ``"
		Write-Host -ForegroundColor DarkCyan $obj.Name -NoNewLine
		Write-Host -BackgroundColor DarkRed "``"
		Write-Host $_.ScriptStackTrace
	}
}


########################################################
<#
.SYNOPSIS
	Write a stacktrace with all information

.DESCRIPTION
   Write a stacktrace with all information

.PARAMETER ErrorRecord
	The Exception
	
.PARAMETER Skip
	Number of function to ignore in the callstack
#>
function Write-Callstack([System.Management.Automation.ErrorRecord]$ErrorRecord=$null, [int]$Skip=1)
{
	Write-Host # blank line
	if( $ErrorRecord ){
		Write-Host -ForegroundColor Red "$ErrorRecord $($ErrorRecord.InvocationInfo.PositionMessage)"
		if ($ErrorRecord.Exception){
			Write-Host -ForegroundColor Red $ErrorRecord.Exception
		}
		if ((Get-Member -InputObject $ErrorRecord -Name ScriptStackTrace) -ne $null){
			#PS 3.0 has a stack trace on the ErrorRecord; if we have it, use it & skip the manual stack trace below
			Write-Host -ForegroundColor Red $ErrorRecord.ScriptStackTrace
			return
		}
	}
	Get-PSCallStack | Select -Skip $Skip | % {
		Write-Host -ForegroundColor Yellow -NoNewLine "! "
		Write-Host -ForegroundColor Red $_.Command $_.Location $(if ($_.Arguments.Length -le 80) { $_.Arguments })
	}
}


########################################################
########################################################
########################################################


# Let's clean up this AD
Write-Host "=== Computers ==="
Get-ADComputer -Filter * -Property nTSecurityDescriptor | foreach {
	$obj = [PSCustomObject]@{
		Name                   = "Computer: "+$_.SamAccountName;
		DistinguishedName      = $_.DistinguishedName.ToString();
  		nTSecurityDescriptor   = $_.nTSecurityDescriptor;
	}
	removeWeakAcl_fromUsers $obj $testMode 'isAdUser'
	removeWeakAcl_fromUsers $obj $testMode 'isAdComputer'
	setOwnerToDA $obj $testMode
}
Write-Host "=== Organizational Unit ==="
Get-ADObject -Filter '*' -Property nTSecurityDescriptor | where { $_.ObjectClass -eq 'organizationalUnit' -or $_.ObjectClass -eq 'container' } | foreach {
	$obj = [PSCustomObject]@{
		Name			   = "OU: "+$_.DistinguishedName.ToString();
		DistinguishedName          = $_.DistinguishedName.ToString();
    		nTSecurityDescriptor       = $_.nTSecurityDescriptor;
	}
	removeWeakAcl_fromUsers $obj $testMode 'isAdUser'
	removeWeakAcl_fromUsers $obj $testMode 'isAdComputer'
	setOwnerToDA $obj $testMode
}

Write-Host "=== Users ==="
Get-ADUser -Filter * -Property nTSecurityDescriptor | foreach {
	$obj = [PSCustomObject]@{
		Name			   = "User: "+$_.SamAccountName;
		DistinguishedName          = $_.DistinguishedName.ToString();
		nTSecurityDescriptor       = $_.nTSecurityDescriptor;
	}
	removeWeakAcl_fromUsers $obj $testMode 'isAdUser'
	removeWeakAcl_fromUsers $obj $testMode 'isAdComputer'
	setOwnerToDA $obj $testMode
}

Write-Host "=== Groups ==="
Get-ADGroup -Filter * -Property nTSecurityDescriptor | foreach {
	$obj = [PSCustomObject]@{
		Name			   = "Group: "+$_.SamAccountName;
		DistinguishedName          = $_.DistinguishedName.ToString();
    		nTSecurityDescriptor       = $_.nTSecurityDescriptor;
	}
	removeWeakAcl_fromUsers $obj $testMode 'isAdUser'
	removeWeakAcl_fromUsers $obj $testMode 'isAdComputer'
	setOwnerToDA $obj $testMode
}

Write-Host "=== GPO ==="
Get-GPO -all | foreach {
	$obj = [PSCustomObject]@{
		Name			   = "GPO: "+$_.DisplayName;
		DistinguishedName          = $_.Path.ToString();
    		nTSecurityDescriptor       = $null;
                Owner                      = $_.Owner;
	}
	setOwnerToDA $obj $testMode
}

Write-Host "=== DNS Entries ==="
Get-ADObject -Filter * -Property nTSecurityDescriptor -SearchBase ("CN=MicrosoftDNS,DC=DomainDnsZones,"+$global:domain_Base) | foreach {
	$obj = [PSCustomObject]@{
		Name			   = "DomainDnsZones: "+$_.DistinguishedName.ToString();
		DistinguishedName          = $_.DistinguishedName.ToString();
    		nTSecurityDescriptor       = $_.nTSecurityDescriptor;
	}
	setOwnerToDA $obj $testMode -allowOwnerComputer $true
}
Get-ADObject -Filter * -Property nTSecurityDescriptor -SearchBase ("CN=MicrosoftDNS,DC=ForestDnsZones,"+$global:domain_Base) | foreach {
	$obj = [PSCustomObject]@{
		Name			   = "ForestDnsZones: "+$_.DistinguishedName.ToString();
		DistinguishedName          = $_.DistinguishedName.ToString();
    		nTSecurityDescriptor       = $_.nTSecurityDescriptor;
	}
	setOwnerToDA $obj $testMode -allowOwnerComputer $true
}

Write-Host "=== SYSVOL Entries ==="
Get-ChildItem -ErrorAction Ignore -Recurse C:\Windows\SYSVOL\domain | Select-Object @{Label="ObjectClass";Expression={"Folder SYSVOL"}},@{Label="DistinguishedName";Expression={$_.FullName}}, @{Label="Owner";Expression={(Get-Acl -Path $_.FullName).Owner}},Name | where { -not( $_.Owner -in $Secure_SID) } | %{
	$obj = [PSCustomObject]@{
		Name			   = "SYSVOL: "+$_.DistinguishedName.ToString();
		DistinguishedName          = $_.DistinguishedName.ToString();
    		nTSecurityDescriptor       = $null;
	}
	setOwnerToDA $obj $testMode -allowOwnerComputer $true -isFile $true
	removeWeakAcl_fromUsers $obj $testMode 'isAdUser' -isFile $true
	removeWeakAcl_fromUsers $obj $testMode 'isAdComputer' -isFile $true
}


Write-Host "=== ADCS Entries ==="
Get-ADObject -Filter * -Property nTSecurityDescriptor -SearchBase ("CN=Public Key Services,CN=Services,CN=Configuration,"+$global:domain_Base) | foreach {
	$obj = [PSCustomObject]@{
		Name			   = "PKI: "+$_.DistinguishedName.ToString();
		DistinguishedName          = $_.DistinguishedName.ToString();
      		nTSecurityDescriptor       = $_.nTSecurityDescriptor;
	}
	setOwnerToDA $obj $testMode
	removeWeakAcl_fromUsers $obj $testMode 'isAdUser'
	removeWeakAcl_fromUsers $obj $testMode 'isAdComputer'
	
	$comppath = "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$($obj.DistinguishedName)"
	$acl = Get-Acl -Path $comppath
	$acl.Access | where { -not ($Secure_SID.Contains($_.IdentityReference.ToString())) } | foreach {
		$ace = $_.ActiveDirectoryRights.ToString()
		if( $ace.Contains('ExtendedRight') ){
			$IdentityReference = $_.IdentityReference
			$ObjectType = $_.ObjectType.ToString()
			$extd = $ObjectType
			try{
				$extd = $ExtendedPriv[$ObjectType][0]				
			}Catch{}
			$ace = $ace.Replace('ExtendedRight',"ExtendedRight ($extd)")
		}
		if( $ace.Contains('Write') -or $ace.Contains('Delete') ){
			Write-Host -NoNewLine -BackgroundColor DarkRed "/!\"
			Write-Host -NoNewLine " ``"
			Write-Host -NoNewLine -ForegroundColor DarkCyan $IdentityReference
			Write-Host -NoNewLine "`` has critical permission ("
			Write-Host -NoNewLine -ForegroundColor DarkRed $ace
			Write-Host -NoNewLine ") on ``"
			Write-Host -NoNewLine -ForegroundColor DarkCyan $comppath
			Write-Host -NoNewLine -BackgroundColor DarkGreen "(PreviewMode ! NO CHANGE on ACL)"
			Write-Host "."
			$global:count_ACL += 1
		}
	}
}
if( $global:checkVulnADCSTemplate -eq $true ){
	$CA = Get-Adobject -SearchBase ("CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,"+$global:domain_Base) -Filter {objectClass -eq "pKIEnrollmentService"} -Properties *
	$template = Get-ADObject -Property nTSecurityDescriptor -SearchBase ("CN=Public Key Services,CN=Services,CN=Configuration,"+$global:domain_Base) -Filter {objectClass -eq "pKICertificateTemplate"} -Properties * | foreach {
		$obj = [PSCustomObject]@{
			DisplayName		 = "PKI: "+$_.DistinguishedName.ToString();
			Name				= $_.Name.ToString();
			DistinguishedName   = $_.DistinguishedName.ToString();
			isEnabled		   = $false;
			pKIExtendedKeyUsage = $_.pKIExtendedKeyUsage;
			msPKIEnrollmentFlag = [MS_PKI_ENROLLMENT_FLAG]$_['msPKI-Enrollment-Flag'];
			msPKICertificateNameFlag = [MS_PKI_CERTIFICATE_NAME_FLAG]$_['msPKI-Certificate-Name-Flag'];
			AutoEnrollment	  = $false;
			Enrollee_Supplies_Subject = $false;
			ManagementApproval		= $false;
			CriticalCertUsage		 = $false;
		}
		$obj.isEnabled = ($CA | where { $_.certificateTemplates.Contains($obj.Name) }) -ne $null;
		$obj.CriticalCertUsage = ($PKI_CertUsage.Keys | where { $obj.pKIExtendedKeyUsage.Contains($_) } | foreach { $PKI_CertUsage[$_] }) -join ","
		$obj.AutoEnrollment = $obj.msPKIEnrollmentFlag.HasFlag([MS_PKI_ENROLLMENT_FLAG]::AUTO_ENROLLMENT)
		$obj.Enrollee_Supplies_Subject = $obj.msPKICertificateNameFlag.HasFlag([MS_PKI_CERTIFICATE_NAME_FLAG]::ENROLLEE_SUPPLIES_SUBJECT)
		$obj.ManagementApproval = $obj.msPKIEnrollmentFlag.HasFlag([MS_PKI_ENROLLMENT_FLAG]::PEND_ALL_REQUESTS)
		$obj
	}
	$template | where {$_.isEnabled} | Select Name,msPKIEnrollmentFlag,msPKICertificateNameFlag,AutoEnrollment,Enrollee_Supplies_Subject,ManagementApproval,CriticalCertUsage | ft *
	
	$template | where {$_.isEnabled -and -not [string]::IsNullOrEmpty($_.CriticalCertUsage) -and $_.Enrollee_Supplies_Subject -and -not $obj.ManagementApproval } | foreach {
		$comppath = "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$($_.DistinguishedName)"
		$acl = Get-Acl -Path $comppath
		$acl.Access | where { -not ($Secure_SID.Contains($_.IdentityReference.ToString())) } | foreach {
			$ace = $_.ActiveDirectoryRights.ToString()
			if( $ace.Contains('ExtendedRight') ){
				$IdentityReference = $_.IdentityReference
				$ObjectType = $_.ObjectType.ToString()
				$extd = $ObjectType
				try{
					$extd = $ExtendedPriv[$ObjectType][0]				
				}Catch{}
				$ace = $ace.Replace('ExtendedRight',"ExtendedRight ($extd)")
				if( $ace.Contains('Certificate-Enrollment') ){
					Write-Host -NoNewLine -BackgroundColor DarkRed "CRITICAL /!\"
					Write-Host -NoNewLine " ``"
					Write-Host -NoNewLine -ForegroundColor DarkCyan $IdentityReference
					Write-Host -NoNewLine "`` can forge a malicious certificate via ``"
					Write-Host -NoNewLine -ForegroundColor DarkCyan $comppath
					Write-Host -NoNewLine " "
					Write-Host -NoNewLine -BackgroundColor DarkGreen "(PreviewMode ! NO CHANGE on ACL)"
					Write-Host "."
					$global:count_ACL += 1
				}
			}
		}
	}
}


Write-Host "==============================================================================="
Write-Host -NoNewLine "Number of weak ACL: "
Write-Host -ForegroundColor DarkCyan $global:count_ACL

Stop-Transcript > $null
Write-Host "All actions have been logger into $log"
Write-Host -NoNewLine "Number of invalid owner: "
Write-Host -ForegroundColor DarkCyan $global:count_Owner
