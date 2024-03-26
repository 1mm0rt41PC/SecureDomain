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
