# Mode test
# Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block; Sleep 5; Set-NetFirewallProfile -Enabled True -All -DefaultInboundAction Allow -DefaultOutboundAction Allow;

New-GPO -Name "[Firewall](GPO,Computer) DROP inbound&outbound" | %{
	$GpoSessionName = Open-NetGPO -PolicyStore ("{0}\{1}" -f $env:USERDNSDOMAIN,$_.DisplayName)
	Set-NetFirewallProfile -GPOSession $GpoSessionName -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block >$null
	Save-NetGPO -GPOSession $GpoSessionName >$null
	$_
}
New-GPO -Name "[Firewall](GPO,Computer) Default rules for DC" | %{
	$GpoSessionName = Open-NetGPO -PolicyStore ("{0}\{1}" -f $env:USERDNSDOMAIN,$_.DisplayName)
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * TCP except 3389" -Action Allow -Direction Inbound -LocalPort @('0-3388','3390-65535') -Protocol TCP >$null
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * UDP except 3389" -Action Allow -Direction Inbound -LocalPort @('0-3388','3390-65535') -Protocol UDP >$null
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * for admin" -Action Allow -Direction Inbound -RemoteAddress @('192.168.1.1','192.168.1.2') >$null

	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * TCP except 3389" -Action Allow -Direction Outbound -RemotePort @('0-444','446-65535') -Protocol TCP >$null
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * UDP except 3389" -Action Allow -Direction Outbound -RemotePort @('0-444','446-65535') -Protocol UDP >$null
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * for DC" -Action Allow -Direction Outbound -RemoteAddress @('192.168.1.1','192.168.1.2') >$null
	
	Set-NetFirewallProfile -ErrorAction Continue -GPOSession $GpoSessionName -All -AllowLocalFirewallRules False -LogAllowed False -LogBlocked True -LogIgnored True -LogFileName "%windir%\system32\logfiles\pfirewall.log" -LogMaxSizeKilobytes 32767
	Save-NetGPO -GPOSession $GpoSessionName >$null
	$_
}
