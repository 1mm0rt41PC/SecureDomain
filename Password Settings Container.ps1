# "The security database has not been started" 
$container='Password Settings Container'
$fullPath = "CN=$container,CN=System,$((Get-ADDomain).DistinguishedName)"
try {
	Get-ADObject $fullPath -ErrorAction Stop | Out-Null
	Write-Host "[*] No corruption on '$container'"
}catch{
	Write-Host "[!] System corrupted ! Recreation of '$container'"
	New-ADObject -Name "$container" -Type msDS-PasswordSettingsContainer -Path "CN=System,$((Get-ADDomain).DistinguishedName)" -ProtectedFromAccidentalDeletion $true
	
	Write-Host "[*] Fix owner to avoid critical issue"
	$acl = Get-Acl "AD:$fullPath"
	$acl.SetOwner([System.Security.Principal.SecurityIdentifier]((Get-ADDomain).DomainSID.Value+"-512"))
	Set-Acl -Path "AD:$fullPath" -AclObject $acl
	
	Get-ADObject $fullPath -Properties *
	
	# If needed to delete this item
	# Set-ADObject "CN=$container,CN=System,$((Get-ADDomain).DistinguishedName)" -ProtectedFromAccidentalDeletion $false
	# Remove-ADObject "CN=$container,CN=System,$((Get-ADDomain).DistinguishedName)"
}
