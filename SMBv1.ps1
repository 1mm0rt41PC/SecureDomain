# Enable Audit on DC
Set-SmbServerConfiguration -AuditSmb1Access $true
Get-SmbServerConfiguration | select AuditSmb1Access
# Find logs (EventID 3000)
Get-WinEvent -LogName Microsoft-Windows-SMBServer/Audit


####################################################
# Once no more 3000
New-GPO -Name "[1mm0rt41][Security](GPO,Computer) SMB server - FileServer configuration - No SMB1" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -Value 0 -Type DWord >$null	
	$_
}
