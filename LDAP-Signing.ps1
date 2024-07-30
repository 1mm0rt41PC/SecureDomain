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
New-GPO -Name "[1mm0rt41][Audit](GPO,Computer) Audit LDAP SASL" -Comment "##################################`r`n`r`nLog missing LDAP SASL.`r`n=> Event ID of 2889 in the Directory Service log.`r`n`r`nMonitoring for LDAP Binding without Channel Binding.`r`n=> Event ID 3039 in the Directory Service event log.`r`n`r`nPump the size of Directory Service log to 32MB. The default size is 1MB`r`n`r`n`$Hours = 24`r`n`$DCs = Get-ADDomainController -filter *`r`n`$InsecureLDAPBinds = @()`r`nForEach (`$DC in `$DCs) {`r`n`$Events = Get-WinEvent -ComputerName `$DC.Hostname -FilterHashtable @{Logname='Directory Service';Id=2889; StartTime=(Get-Date).AddHours('-`$Hours')}`r`nForEach (`$Event in `$Events) {`r`n   `$eventXML = [xml]`$Event.ToXml()`r`n   `$Client = (`$eventXML.event.EventData.Data[0])`r`n   `$IPAddress = `$Client.SubString(0,`$Client.LastIndexOf(':'))`r`n   `$User = `$eventXML.event.EventData.Data[1]`r`n   Switch (`$eventXML.event.EventData.Data[2])`r`n      {`r`n      0 {`$BindType = 'Unsigned'}`r`n      1 {`$BindType = 'Simple'}`r`n      }`r`n   `$Row = '' | select IPAddress,User,BindType`r`n   `$Row.IPAddress = `$IPAddress`r`n   `$Row.User = `$User`r`n   `$Row.BindType = `$BindType`r`n   `$InsecureLDAPBinds += `$Row`r`n   }`r`n}`r`n`$InsecureLDAPBinds | Out-Gridview" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -ValueName "16 LDAP Interface Events" -Value 2 -Type DWord >$null
	# Directory Service log to be 32MB to start with. The default size is 1MB
 	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service" -ValueName "MaxSize" -Value 33685504 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service" -ValueName "MaxSizeUpper" -Value 0 -Type DWord >$null
	# Enable LDAPS CB when supported => enable log 3039
 	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides" -ValueName "1775223437" -Value 1 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides" -ValueName "2654580365" -Value 1 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ValueName "LdapEnforceChannelBinding" -Value 1 -Type DWord >$null
	$_
}

#
# Parse logs to find info on DC
#
Get-WinEvent -FilterHashtable @{Logname='Directory Service';Id=2889; StartTime=(get-date).AddHours("-12")} | %{
	# Loop through each event and output the
	$eventXML = [xml]$_.ToXml()
	$Row = "" | select IPAddress,User,BindType
	$Client = ($eventXML.event.EventData.Data[0])
	$Row.IPAddress = $Client.SubString(0,$Client.LastIndexOf(":")) #Accomodates for IPV6 Addresses
	$Row.User = $eventXML.event.EventData.Data[1]
	Switch ($eventXML.event.EventData.Data[2])
	{
		0 {$Row.BindType = "Unsigned"}
		1 {$Row.BindType = "Simple"}
	}
	$Row
} | Export-CSV -NoTypeInformation -Encoding UTF8 "\\DC01.corp.lo\log$\$($env:COMPUTERNAME)_Events_$((Get-Date).ToString('yyyyMMddHH')).csv"


<#
For linux joined computers do not forget to configure SSSD:
root@server:~$ cat /etc/sssd/sssd.conf
[corp.lo/mycomputer.com]
id_provider = ad
auth_provider = ldap
chpass_provider = ldap
ldap_uri = ldaps://ldap.example.com
ldap_search_base = dc=example,dc=com
ldap_tls_reqcert = demand

# SASL GSSAPI settings (SASL)
ldap_sasl_mech = GSSAPI
ldap_sasl_authid = host/$(hostname -f)@EXAMPLE.COM
krb5_server = kerberos.example.com
ldap_sasl_realm = kerberos.example.com


Check logs to find any binding failure:
root@server:~$ grep -Fi sasl /var/log/sssd/*
(Fri Jul 27 18:27:44 2012) [sssd[be[ADTEST]]] [sasl_bind_send] (0x0020): ldap_sasl_bind failed (-2)[Local error]
(Fri Jul 27 18:27:44 2012) [sssd[be[ADTEST]]] [sasl_bind_send] (0x0080): Extended failure message: [SASL(-1): generic failure: GSSAPI Error: Unspecified GSS failure.  Minor code may provide more information (Cannot determine realm for numeric host address)]
#>
