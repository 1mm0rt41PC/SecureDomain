#
# Enable LDAP Sigging on client side
#
New-GPO -Name "[1mm0rt41][Security](GPO,Computer) LDAP client configuration" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\System\CurrentControlSet\Services\LDAP" -ValueName "LDAPClientIntegrity" -Value 2 -Type DWord >$null
	$_
} | New-GPLink -target "$(([ADSI]'LDAP://RootDSE').defaultNamingContext.Value)" -LinkEnabled Yes


#
# Enable LDAP Sigging on SERVER side
#
New-GPO -Name "[1mm0rt41][Security](GPO,Computer) LDAP server configuration" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" -ValueName "LDAPServerIntegrity" -Value 2 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" -ValueName "LdapEnforceChannelBinding" -Value 2 -Type DWord >$null
	$_
}


#
# Enable AUDIT LDAP Sigging (no LDAPS CB) on SERVER side
#
New-GPO -Name "[1mm0rt41][Audit](GPO,Computer) Audit LDAP SASL" -Comment "Log missing LDAP SASL => event ID of 2889 in the Directory Service log. Monitoring for LDAP Binding without Channel Binding
 => event ID 3039 in the Directory Service event log" | %{
  $_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -ValueName "16 LDAP Interface Events" -Value 2 -Type DWORD >$null
  # Directory Service log to be 32MB to start with. The default size is 1MB
  $_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service" -ValueName "MaxSize" -Value 33685504 -Type DWORD >$null
  $_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service" -ValueName "MaxSizeUpper" -Value 0 -Type DWORD >$null
  $_
}
#
# Parse logs to find info on DC
#
Get-WinEvent -FilterHashtable @{Logname='Directory Service';Id=2889; StartTime=(get-date).AddHours("-12")} | %{
	# Loop through each event and output the
	$eventXML = [xml]$_.ToXml()
	# Build Our Values
	$Id = $eventXML.Event.System.EventID
	$Client = ($eventXML.event.EventData.Data[0])
	$IPAddress = $Client.SubString(0,$Client.LastIndexOf(":")) #Accomodates for IPV6 Addresses
	$User = $eventXML.event.EventData.Data[1]
	Switch ($eventXML.event.EventData.Data[2])
    {
		0 {$BindType = "Unsigned"}
		1 {$BindType = "Simple"}
	}
	# Add Them To a Row in our Array
	$Row = "" | select IPAddress,User,BindType
	$Row.IPAddress = $IPAddress
	$Row.User = $User
	$Row.BindType = $BindType
	# Add the row to our Array
	$Row
} | Export-CSV -NoTypeInformation -Encoding UTF8 "\\DC01.corp.lo\log$\$($env:COMPUTERNAME)_Events_$((Get-Date).ToString('yyyyMMddHH')).csv"
