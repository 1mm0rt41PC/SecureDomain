Import-Module 'config.ps1'
Import-Module 'Function_New-GPOSchTask.ps1'
Import-Module 'Function_FWRule.ps1'

$IP_SRV         = $IP_DHCP
$ComputerName   = 'DHCP-SRV01'
$ETH_NAME       = (Get-NetAdapter).Name


Rename-Computer -NewName $ComputerName

ipconfig /release
netsh.exe int ip set dns $ETH_NAME static $IP_DNS
netsh.exe interface ip set address name="$ETH_NAME" static $IP_SRV 255.255.255.0 $IP_GATEWAY 1

#New-NetIPAddress –IPAddress $IP_SRV -DefaultGateway $IP_GATEWAY -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex
#Set-DNSClientServerAddress –InterfaceIndex (Get-NetAdapter).InterfaceIndex –ServerAddresses $IP_DNS

Add-Computer -computername $ComputerName -domainname $domain –credential $domain_netbios\administrateur -restart -force

Install-WindowsFeature -name DHCP -IncludeManagementTools
Add-DhcpServerV4Scope -Name "DHCP Scope" -StartRange 10.10.0.0 -EndRange 10.10.0.250 -SubnetMask 255.255.255.0
Set-DhcpServerV4OptionValue -DnsServer $IP_DNS -Router $IP_GATEWAY
Set-DhcpServerv4Scope -ScopeId 10.10.0.0 -LeaseDuration 1.00:00:00
Restart-service dhcpserver
