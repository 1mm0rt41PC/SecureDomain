$FormatEnumerationLimit=-1

$root = Get-AdDomain
$dom = @($root.DNSRoot)
$dom += Get-AdDomain | Select -ExpandProperty ChildDomains

$dom | %{
	$dom = Get-AdDomain $_
	Get-AdUser -Server $dom.PDCEmulator -Properties ServicePrincipalNames -Filter { ServicePrincipalNames -ne "$null"} | where {$_.ServicePrincipalNames -ne $null } | Select SamAccountName,DistinguishedName,ServicePrincipalNames
} | ConvertTo-Json

# Mono-domain
# Get-AdUser -Filter { ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | select SamAccountName, ServicePrincipalName | Out-String -Width 4096
