$groupName       = 'T-SQL' # 15 char max !!!!!!!
$targetServer    = 'sql-<instance>'
$portOrInstance  = '<instance>'
$gmsa_san        = "T-SQL-<id>"
$OU              = "OU=OU_du_Groupe,DC=domain,DC=lan"
$targetServiceClass = 'MSSQLSvc'
$targetService   = "$targetServiceClass/$targetServer:$portOrInstance","$targetServiceClass/${targetServer}.${domain}:$portOrInstance"
$domain          = $env:USERDNSDOMAIN
New-ADGroup -Name $groupName -GroupeScope Global -GroupCategory Security -Path $OU
New-ADServiceAccount -name $gmsa_san -enabled $true -DNSHostName "${targetServer}.${domain}" -PrincipalsAllowedToRetrieveManagedPassword $groupName -ServicePrincipalName $targetService -KerberosEncryptionType AES128,AES256


Install-ADServiceAccount $gmsa_san
Test-ADServiceAccount $gmsa_san
