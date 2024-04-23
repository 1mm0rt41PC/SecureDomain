###########################################################################################
# [1mm0rt41][NiceToHave](GPO,Computer) DNS Suffix
###########################################################################################
New-GPO -Name "[1mm0rt41][NiceToHave](GPO,Computer) DNS Suffix" -Comment "##################################`r`n`r`nThe typical name resolution process for Microsoft Windows 2000 uses the primary DNS suffix and any connection-specific DNS suffixes. If these suffixes do not work, the devolution of the primary DNS suffix is attempted by the name resolution process.`r`n`r`nWhen a domain suffix search list is configured on a client, only that list is used. The primary DNS suffix and any connection-specific DNS suffixes are not used, nor is the devolution of the primary suffix attempted. The domain suffix search list is an administrative override of all standard Domain Name Resolver (DNR) look-up mechanisms.`r`n`r`nSide effect: None`r`nIf disabled: Can block access to some ressource that doesn't known AD Suffix" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "SearchList" -Value "suffix-dns.mycorp.local,suffix2.corp.lo" -Type String >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "SearchList" -Value "suffix-dns.mycorp.local,suffix2.corp.lo" -Type String >$null
	$_
}


###########################################################################################
# [1mm0rt41][Security](GPO,Computer) LLMNR
###########################################################################################
New-GPO -Name "[1mm0rt41][Security](GPO,Computer) LLMNR" -Comment "##################################`r`n`r`nProtection against Man-In-The-Middle.`r`nSide effect: Check first that dns suffix is deployed everywhere" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Value 0 -Type DWord >$null
	$GpoSessionName = Open-NetGPO -PolicyStore ("{0}\{1}" -f $env:USERDNSDOMAIN,$_.DisplayName)
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Drop LLMNR" -Group "[GPO][1mm0rt41][Security](GPO,Computer) LLMNR" -Action Block -Direction Outbound -Protocol UDP -RemotePort 5355 >$null
	Save-NetGPO -GPOSession $GpoSessionName >$null
	$_
}


###########################################################################################
# [1mm0rt41][Security](GPO,Computer) NetBios
###########################################################################################
New-GPO -Name "[1mm0rt41][Security](GPO,Computer) NetBios" -Comment "##################################`r`n`r`nProtection against Man-In-The-Middle.`r`nSide effect: Check first that dns suffix is deployed everywhere" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -ValueName "NodeType" -Value 2 -Type DWord >$null
	$GpoSessionName = Open-NetGPO -PolicyStore ("{0}\{1}" -f $env:USERDNSDOMAIN,$_.DisplayName)
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Drop NetBios" -Group "[GPO][1mm0rt41][Security](GPO,Computer) NetBios" -Action Block -Direction Outbound -Protocol UDP -RemotePort 137 >$null
	Save-NetGPO -GPOSession $GpoSessionName >$null
	$_
}


###########################################################################################
# [1mm0rt41][Security](GPO,Computer) mDNS
###########################################################################################
New-GPO -Name "[1mm0rt41][Security](GPO,Computer) mDNS" -Comment "##################################`r`n`r`nProtection against Man-In-The-Middle.`r`nSide effect: Check first that dns suffix is deployed everywhere" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -ValueName "EnableMDNS" -Value 0 -Type DWord >$null
	$_
}


###########################################################################################
# [1mm0rt41][Security](GPO,Computer) IPv6
###########################################################################################
New-GPO -Name "[1mm0rt41][Security](GPO,Computer) IPv6" -Comment "##################################`r`n`r`nProtection against Man-In-The-Middle.`r`nSide effect: None" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ValueName "DisabledComponents" -Value 32 -Type DWord >$null
	$_
}


###########################################################################################
# [1mm0rt41][Security](GPO,Computer) WPAD
###########################################################################################
New-GPO -Name "[1mm0rt41][Security](GPO,Computer) WPAD" -Comment "##################################`r`n`r`nProtection against Man-In-The-Middle.`r`n`r`nRequire: Check if corp use automatic proxy settings`r`nSide effect: Can block network communication if WAD proxy is used but not deployed via GPO ou via DNS entry" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -ValueName "Start" -Value 4 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -ValueName "WpadOverride" -Value 1 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ValueName "AutoDetect" -Value 0 -Type DWord >$null
	$_
}
