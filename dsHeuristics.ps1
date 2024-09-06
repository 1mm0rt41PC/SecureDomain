$dsHeuristics = (Get-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName) -Properties dsHeuristics).dsHeuristics
if(($dsHeuristics -eq "") -or ($dsHeuristics.Length -lt 7)){
	$msg = "[+] Anonymous access is already disable ! (dsHeuristics=$dsHeuristics)"
}elseif(($ValuedsHeuristics.Length -ge 7) -and ($ValuedsHeuristics[6] -eq "2")){
	$msg = "[!] Anonymous access is enabled (dsHeuristics=$dsHeuristics)"
}
Write-Host "$msg"
$msg | Out-File -Encoding ASCII dsHeuristics.log
Write-Host "Do it on all domain"

<#
fLDAPBlockAnonOps permet d'autoriser des opérations LDAP sans authentification ;
fAllowAnonNSPI permet d'autoriser l'accès anonyme au Name Service Provider Interface (NSPI) ;
dwAdminSDExMask permet de définir les groupes protégés par le mécanisme SDProp ;
DoNotVerifyUPNAndOrSPNUniqueness permet de relaxer les vérifications sur l'unicité des UPN et SPN ;
LDAPAddAuthZVerifications permet de désactiver l'audit et la protection apportée par la KB5008383 ;
BlockOwnerImplicitRights permet de désactiver l'audit et la protection apportée par laKB5008383.

Les paramètres dangereux configurés dans la propriété dSHeuristics doivent être modifiés et réinitialisés à leur valeur par défaut :

fLDAPBlockAnonOps ne doit pas être configuré ou avoir une valeur différente de 2 ;
fAllowAnonNSPI doit valoir 0 ;
dwAdminSDExMask doit valoir 0 ;
DoNotVerifyUPNAndOrSPNUniqueness doit valoir 0 ;
LDAPAddAuthZVerifications ne doit pas être configuré ou avoir une valeur différente de 2 pour atteindre le niveau 3 ; cette valeur doit être explicitement positionnée à 1 pour atteindre le niveau 5 ;
BlockOwnerImplicitRights ne doit pas être configuré ou avoir une valeur différente de 2 pour atteindre le niveau 3 ; cette valeur doit être explicitement positionnée à 1 pour atteindre le niveau 5.
#>
