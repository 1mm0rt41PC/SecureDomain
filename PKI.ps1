Import-Module 'config.ps1'

###############################################################################
# Basic configuration
$ComputerName   = 'PKI-SRV01'

Rename-Computer -NewName $ComputerName
Add-Computer -computername $ComputerName -domainname $domain –credential $domain_netbios\administrator -restart -force

Add-WindowsFeature Adcs-Cert-Authority -includeManagementTools
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
Get-WindowsFeature AD-Certificate

$param = @{
	CAType='EnterpriseRootCA';
	CryptoProvderName='ECDSA_P521#Microsoft Software Key Storage Provider';
	KeyLength=521;
	HashAlogrythm='SHA512';
	CaCommonName="$domain_netbios-ca-1";
	CADistinguishedNameSuffix="CN=$domain_netbios-ca-1,$LDAP_DN";
	ValidityPeriod='year';
	ValidityPeriodUnits=10;
	DatabaseDirectory='C:\Windows\system32\CertLog';
	LogDirectory='C:\Windows\system32\CertLog';
}
Install-Adcs-CertificationAuthority @param

Add-CATemplate -Name CodeSigning
