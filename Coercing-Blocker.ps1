# Mode test on one computer without GPO linkage
# Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Continue; Sleep 5; Set-NetFirewallProfile -Enabled True -All -DefaultInboundAction Allow -DefaultOutboundAction Allow -ErrorAction Continue;

# EventLog ID=5157 Packet dropped

<#
$gpo = '[Firewall](GPO,Computer) DROP inbound&outbound'
$ou  = 'OU=Domain Controllers,DC=corp,DC=local'

function mygpupdate {
	gpupdate /force
	Get-ADComputer -Filter * -SearchBase $ou -ErrorAction Continue | %{
		Invoke-GPUpdate -Force -RandomDelayInMinutes 0 -Computer $_.DNSHostName -ErrorAction Continue
	}	
}

New-GPLink -Name $gpo -Target $ou -LinkEnabled Yes -ErrorAction Continue;
sleep -Seconds 5;
mygpupdate
sleep -Seconds 15;
Remove-GPLink -Name $gpo -Target $ou -ErrorAction Continue;
sleep -Seconds 5;
mygpupdate
#>

$global:IP_ADMIN = @('42.42.42.42','13.37.13.37/24')
$global:IP_DC = @('192.168.1.1','192.168.1.2')

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
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * for admin" -Action Allow -Direction Inbound -RemoteAddress $global:IP_ADMIN >$null
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * for DC" -Action Allow -Inbound Outbound -RemoteAddress $global:IP_DC >$null

	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * TCP except 3389" -Action Allow -Direction Outbound -RemotePort @('0-444','446-65535') -Protocol TCP >$null
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * UDP except 3389" -Action Allow -Direction Outbound -RemotePort @('0-444','446-65535') -Protocol UDP >$null
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * for DC" -Action Allow -Direction Outbound -RemoteAddress $global:IP_DC >$null
	
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * for AATPSensor" -Action Allow -Direction Outbound -Service AATPSensor >$null
	
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * TCP except 3389" -Action Allow -Direction Outbound -RemotePort @('0-444','446-65535') -Protocol TCP >$null
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * UDP except 3389" -Action Allow -Direction Outbound -RemotePort @('0-444','446-65535') -Protocol UDP >$null
	
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * ICMP" -Action Allow -Direction Outbound -Protocol ICMPv4 >$null
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] Allow * ICMP" -Action Allow -Direction Inbound -Protocol ICMPv4 >$null
	
	Set-NetFirewallProfile -ErrorAction Continue -GPOSession $GpoSessionName -All -AllowLocalFirewallRules False -LogAllowed False -LogBlocked True -LogIgnored True -LogFileName "%windir%\system32\logfiles\pfirewall.log" -LogMaxSizeKilobytes 32767
	Save-NetGPO -GPOSession $GpoSessionName >$null
	
	$gpoId=$_.Id.ToString();
	$gpoId="{$gpoId}";
	
	$gpoPath="C:\Windows\SYSVOL\domain\Policies\$gpoId\Machine\Microsoft\Windows NT\SecEdit"
	mkdir "$gpoPath" >$null
	$inf =  "[Unicode]`r`n";
	$inf += "Unicode=yes`r`n";
	$inf += "[Version]`r`n";
	$inf += 'signature="$CHICAGO$"'+"`r`n";
	$inf += "Revision=1`r`n";
	$inf | Out-File -Encoding UTF8 "$gpoPath\GptTmpl.inf"

	$gpoPath="C:\Windows\SYSVOL\domain\Policies\$gpoId\Machine\Microsoft\Windows NT\Audit"
	mkdir "$gpoPath" >$null
	$inf =  "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`r`n";
	#$inf += ",System,Audit Filtering Platform Connection,{0cce9226-69ae-11d9-bed3-505054503030},Success,,1";
	$inf += ",System,Audit Filtering Platform Connection,{0cce9226-69ae-11d9-bed3-505054503030},Failure,,2";
	#$inf += ",System,Audit Filtering Platform Packet Drop,{0cce9225-69ae-11d9-bed3-505054503030},Success and Failure,,3";
	# Success => Packet allowed
	# Failure => Packet droped
	$inf | Out-File -Encoding UTF8 "$gpoPath\audit.csv"
	
	Get-AdObject -Filter "(objectClass -eq 'groupPolicyContainer') -and (name -eq '$gpoId')" | Set-ADObject -Replace @{gPCMachineExtensionNames="[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}][{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]"};

	$_
}
