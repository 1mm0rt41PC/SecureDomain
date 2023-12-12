$global:mode_preview=$true

# List all SID allowed to have adminCount=1
$domainSid = (Get-ADDomain).DomainSID.ToString()
$criticalGroupsSID=@(
	'S-1-5-32-550',# Opérateurs d’impression
	'S-1-5-32-551',# Opérateurs de sauvegarde
	'S-1-5-32-552',# Duplicateurs
	'S-1-5-32-549',# Opérateurs de serveur
	'S-1-5-32-548',# Opérateurs de compte
	($domainSid+'-518'),# Administrateurs du schéma
	($domainSid+'-519'),# Administrateurs de l’entreprise
	($domainSid+'-512'),# Admins du domaine
	($domainSid+'-526'),# Administrateurs clés
	($domainSid+'-527') # Administrateurs clés Enterprise
)
# Keep only groups in sAMAccountName format
$criticalGroupsName = $criticalGroupsSID | foreach {
	try{
		$x=(New-Object System.Security.Principal.SecurityIdentifier($_)).Translate([System.Security.Principal.NTAccount]).Value.ToString().Split('\')[1]
		Get-ADGroup $x | Out-Null
		$x
	}catch{}
}
# Get a list of all users and groups that are realy affected by adminCount
$usersMemberOfCriticalGroups = $criticalGroupsName | foreach {
	Get-ADGroupMember -Identity "$_" -Recursive | Get-ADUser -Properties *
} | sort -Unique

$usersMemberOfCriticalGroups | where { $_.AccountNotDelegated -ne $true } | foreach {
	$ret = $_ | Select sAMAccountName,DistinguishedName,@{ Name="AccountNotDelegated-Fixed"; Expression = { -not $global:mode_preview } }
	if( $global:mode_preview -eq $false ){
		$_ | Set-ADUser -AccountNotDelegated $true
	}
	$ret
}