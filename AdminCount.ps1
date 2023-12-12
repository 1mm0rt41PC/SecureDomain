$global:mode_preview=$true

# List all SID allowed to have adminCount=1
$domainSid = (Get-ADDomain).DomainSID.ToString()
$allowedAdminCount=@(
	'S-1-5-32-544',# Administrateurs
	'S-1-5-32-550',# Opérateurs d’impression
	'S-1-5-32-551',# Opérateurs de sauvegarde
	'S-1-5-32-552',# Duplicateurs
	'S-1-5-32-549',# Opérateurs de serveur
	'S-1-5-32-548',# Opérateurs de compte
	($domainSid+'-500'),# Administrateur
	($domainSid+'-502'),# krbtgt
	($domainSid+'-516'),# Contrôleurs de domaine
	($domainSid+'-518'),# Administrateurs du schéma
	($domainSid+'-519'),# Administrateurs de l’entreprise
	($domainSid+'-512'),# Admins du domaine
	($domainSid+'-521'),# Contrôleurs de domaine en lecture seule
	($domainSid+'-526'),# Administrateurs clés
	($domainSid+'-527') # Administrateurs clés Enterprise
)
# Keep only groups in sAMAccountName format
$allowedAdminCountNamed = $allowedAdminCount | foreach {
	try{
		$x=(New-Object System.Security.Principal.SecurityIdentifier($_)).Translate([System.Security.Principal.NTAccount]).Value.ToString().Split('\')[1]
		Get-ADGroup $x | Out-Null
		$x
	}catch{}
}
# Get a list of all users and groups that are realy affected by adminCount
$realAdminCount = $allowedAdminCountNamed | foreach {
	$x = Get-ADGroupMember -Identity "$_" -Recursive | foreach { $_.SamAccountName }
	$x += Get-ADGroupMember -Identity "$_" | foreach { $_.SamAccountName }
	$x
} | sort -Unique
# Remove adminCount on groups and Users that are not memberof sensitives groups
Get-ADObject -Filter {admincount -gt 0} -Properties * | where { -not $allowedAdminCount.Contains($_.objectSid.ToString()) -And -not $realAdminCount.Contains($_.sAMAccountName) } | foreach {
	$ret = $_ | Select sAMAccountName,ObjectClass,DistinguishedName,@{ Name="AdminCountFixed"; Expression = { -not $global:mode_preview } } 
	if( $global:mode_preview -eq $false ){
		$_ | Set-ADObject -Replace @{adminCount=0}
		DSACLS "$($_.DistinguishedName)" /resetDefaultDACL | Out-Null
	}
	$ret
}