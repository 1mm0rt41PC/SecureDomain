$FormatEnumerationLimit=-1

Get-ADUser -Filter { ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | select SamAccountName, ServicePrincipalName | Out-String -Width 4096

Get-ADComputer -Filter { ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | select SamAccountName, ServicePrincipalName | Out-String -Width 4096
