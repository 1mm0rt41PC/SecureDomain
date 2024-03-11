$Tier0_SID = @(
	'498',# Enterprise Read-only Domain Controllers
	'512',# Domain Admins
	'516',# Domain Controllers
	'517',# Cert Publishers
	'518',# Schema Admins
	'519',# Enterprise Admins
	'520',# Group Policy Creator Owners
	'521',# Read-only Domain Controllers
	'522',# Clonable Domain Controllers
	'526',# Key Admins
	'527',# Enterprise Key Admins
	'S-1-5-9'# Enterprise Domain Controllers
	'S-1-5-32-544',# Administrators
	'S-1-5-32-547',# Power Users
	'S-1-5-32-548',# Account Operators
	'S-1-5-32-549',# Server Operators
	'S-1-5-32-550',# Print Operators
	'S-1-5-32-551',# Backup Operators
	'S-1-5-32-552',# Replicator
	'S-1-5-32-557' # BUILTIN\Incoming Forest Trust Builders
)
$Tier0_SAN = @(
 	'DNSADMINS',
 	'EXCHANGE WINDOWS PERMISSIONS'
)
$Tier0_SPN = @(
	'AgpmServer'
)

$Tier0_SPN | %{
	$spn = $_
 	Get-ADUser -Filter '*' | where { ($_.ServicePrincipalName -Join ',').Contains($spn)  } | %{
	 	[PSCustomObject]@{
			'SPN'= $spn;
   			'User'= $_.DistinguishedName
      		}
  	}
} | ConvertTo-Json

Get-ADGroup -Filter '*' | where { $Tier0_SID.Contains($_.SID.tostring().split('-')[-1]) -or $Tier0_SID.Contains($_.SID.tostring()) -Or $Tier0_SAN.Contains($_.SamAccountName.ToUpper()) } | %{
	[PSCustomObject]@{
		'Group'=$_.SamAccountName;
		'Members'=$_ | Get-ADGroupMember -Recursive | %{
			$grp=$_
			try{
				$grp | Get-ADUser -ErrorAction Stop -Properties Name,SamAccountName,UserPrincipalName,Enabled,SID,AccountNotDelegated,DistinguishedName,ObjectClass,AllowReversiblePasswordEncryption,Certificates,DoesNotRequirePreAuth,userCertificate
			}catch{
				$grp.DistinguishedName | Get-ADComputer -Properties Name,SamAccountName,UserPrincipalName,Enabled,SID,DistinguishedName,ObjectClass,DNSHostName,AllowReversiblePasswordEncryption,Certificates,DoesNotRequirePreAuth,IPv4Address,PrincipalsAllowedToDelegateToAccount,servicePrincipalName,userCertificate
			}
		};
	}
} | ConvertTo-Json
