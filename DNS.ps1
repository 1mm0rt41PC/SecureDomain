###############################################################################
# Basic configuration
$IP_SRV         = $IP_DNS
$ComputerName   = 'DNS-SRV01'

###############################################################################
c:\windows\system32\sysprep\sysprep.exe /oobe /generalize /reboot
Rename-Computer -NewName $ComputerName
New-NetIPAddress –IPAddress $IP_SRV -DefaultGateway $IP_GATEWAY -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex
Set-DNSClientServerAddress –InterfaceIndex (Get-NetAdapter).InterfaceIndex –ServerAddresses '8.8.8.8'

Add-Computer -computername $ComputerName -domainname $domain –credential $domain_netbios\administrator -restart -force

Install-WindowsFeature DNS -IncludeManagementTools

# Import / export
# => https://www.virtualizationhowto.com/2019/07/export-and-import-dns-zone-with-powershell-from-one-server-to-another/
# Import
#dnscmd /zoneadd "yourzone.com" /primary /file yourzone.com.dns /load