<#

# GPO linked on all DC
New-GPO -Name "[Log](GPO,Computer) LSA & NTLM Audit Mode" -Comment "##################################`r`n`r`nWindows logs configuration:`r`n- Audit LSA protection (RunAsPPL)`r`n- Audit incoming NTLM traffic for all accounts:`r`n    to view =>`r`n    Get-WinEvent -Filterxml @'`r`n    <QueryList>`r`n     <Query Id=`"0`" Path=`"security`">`r`n      <Select Path=`"security`">`r`n       *[System[(EventID=4624)]]`r`n        and`r`n        (`r`n         *[EventData[Data[@Name='AuthenticationPackageName']!='Kerberos']]`r`n         and`r`n         *[EventData[Data[@Name='LmPackageName']!='NTLM V2']]`r`n       )`r`n      </Select>`r`n     </Query>`r`n    </QueryList>`r`n    '@`r`n    and also Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-NTLM/Operational' ; Id = 8001,8002 }            `r`n`r`nIf disabled: Lost logs information" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" -ValueName "AuditNTLMInDomain" -Value 7 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "AuditReceivingNTLMTraffic" -Value 1 -Type DWord >$null
	#$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "RestrictSendingNTLMTraffic" -Value 1 -Type DWord >$null
	#$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -ValueName "AuditLevel" -Value 8 -Type DWord >$null
 	$_ | Set-GPRegistryValue -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Value 3 -Type DWord >$null
	$_
}

# GPO linked on all computers
Get-GPO -Name "[Security](GPO,Computer) Force NTLMv2 prio but allow NTLMv1 and LM" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Value 3 -Type DWord >$null
	$_
}

#>

$xml = @'
	<QueryList>
		<Query Id="0" Path="security">
			<Select Path="security">
				*[System[(EventID=4624)]]
				and
				 *[EventData[Data[@Name='LmPackageName']='NTLM V1']]
			</Select>
		</Query>
	</QueryList>
'@
(Get-ADDomainController  -Filter *).HostName | ForEach-Object {
	Get-WinEvent -ComputerName $_ -FilterXml $xml  -ErrorAction SilentlyContinue | ForEach-Object {
		$h = @{}
		([xml]$_.Toxml()).Event.EventData.Data | ForEach-Object {
			$h.Add($_.'Name',$_.'#text')
		}
		[PSCustomObject]$h
	}
} | Out-GridView


# OR 
Get-WinEvent -FilterXml $xml  -ErrorAction SilentlyContinue | ForEach-Object {
	$h = @{}
	([xml]$_.Toxml()).Event.EventData.Data | ForEach-Object {
		$h.Add($_.'Name',$_.'#text')
	}
	[PSCustomObject]$h
} | Export-CSV -NoTypeInformation -Encoding UTF8 "C:\Windows\SYSVOL\domain\logs\$($env:COMPUTERNAME)_Events-4624_$((Get-Date).ToString('yyyyMMddHH')).csv"



# NTLMv1 and NTLMv2 client blocked audit: 
# Audit outgoing NTLM authentication traffic that would be blocked.
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-NTLM/Operational' ; Id = 8001,8002 } | ForEach-Object {
	$e = $_
	switch ($e.Id) {
		8001 {
			$Direction = 'Out'
			$TargetName = $e.Properties[0].Value ;
			$ProcessID = $e.Properties[3].Value 
			$ProcessName = $e.Properties[4].Value ;
			$Identity =  "$($e.Properties[2].Value)\$($e.Properties[1].Value)"
			break
		}
		8002 {
			$Direction = 'In'
			$TargetName = $env:COMPUTERNAME
			$ProcessID = $e.Properties[0].Value 
			$ProcessName = $e.Properties[1].Value ;
			$Identity =  "$($e.Properties[4].Value)\$($e.Properties[3].Value)"
		}
		default {}
	}
	[PSCustomObject]@{
		TargetName = $TargetName
		Direction = $Direction
		ProcessId = $ProcessID
		ProcessName  = $ProcessName
		Identity = $Identity
	}
} | Out-GridView
