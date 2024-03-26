<#
# LOG Server
# ================================================
$logs = "C:\logs"
$domComputer='your-domain.lo\Domain computers'
$domUser='your-domain.lo\Domain users'

$acl = Get-Acl $logs
$acl.SetAccessRuleProtection($disableInheritance,$preserveInheritanceACL)
$acl | Set-Acl $logs

$acl = Get-Acl $logs
$usersid = New-Object System.Security.Principal.Ntaccount ($domUser)
$acl.PurgeAccessRules($usersid)
$acl | Set-Acl $logs

# Clean up CREATOR OWNER ACL
$acl = Get-Acl $logs
$usersid = New-Object System.Security.Principal.Ntaccount ("S-1-3-0")
$acl.PurgeAccessRules($usersid)
$acl | Set-Acl $logs

# This folder only
$acl = Get-Acl $logs
$fsar = New-Object System.Security.AccessControl.FileSystemAccessRule($domComputer, 'CreateFiles,Traverse,Synchronize', 'Allow')
$acl.SetAccessRule($fsar)
$acl | Set-Acl $logs

New-SmbShare -Name "logs$" -Path "$logs" -FullAccess $domComputer'

# DC Server
# ================================================
$script='C:\Windows\SYSVOL\domain\scripts\logger.ps1'
$domComputer='your-domain.lo\Domain computers'
$domUser='your-domain.lo\Domain users'

$acl = Get-Acl $script
$acl.SetAccessRuleProtection($disableInheritance,$preserveInheritanceACL)
$acl | Set-Acl $script

$acl = Get-Acl $script
$usersid = New-Object System.Security.Principal.Ntaccount ($domUser)
$acl.PurgeAccessRules($usersid)
$acl | Set-Acl $script

$acl = Get-Acl $script
$fsar = New-Object System.Security.AccessControl.FileSystemAccessRule('your-domain.lo\Domain computers', 'ReadAndExecute', 'Allow')
$acl.SetAccessRule($fsar)
$acl | Set-Acl $script
#>

$syslogStorage = '\\DC-SRV01\syslog$'
$hostname = $env:COMPUTERNAME
$delimiter = ','

# List local users
Write-Host "List local users"
Get-LocalUser | select @{n="HostName";e={$env:computername}},Name,AccountExpires,Enabled,PasswordChangeableDate,PasswordExpires,UserMayChangePassword,PasswordRequired,PasswordLastSet,LastLogon | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation > "$syslogStorage\LocalUser_${hostname}.csv"


# List local group members
Write-Host "List local group members"
Get-WmiObject win32_group -filter "Domain='$hostname'" | %{
	$row = '' | select HostName,Name,SID,Caption,LocalAccount,Member
	$row.HostName = $env:COMPUTERNAME
 	$row.Name = $_.Name
  	$row.SID = $_.SID
	$row.Caption = $_.Caption.Split('\')[1]
 	$row.LocalAccount = $_.LocalAccount
 	$row.Member = ''
	$_.GetRelated("Win32_Account", "Win32_GroupUser", "", "", "PartComponent", "GroupComponent", $false, $null) | %{
		$tmp = $_.ToString().Split("=");
		$dom = $tmp[1].Split('"')[1];
		$name = $tmp[2].Split('"')[1];
		$row.Member = $dom+"\"+$name
		$row
	}
} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\LocalGroup_${hostname}.csv"


# List ScheduledTask
Write-Host "List ScheduledTask"
@"
"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running"
$((schtasks.exe /query /V /FO csv)  -join "`r`n")
"@ | ConvertFrom-CSV | Where { $_.TaskName.Replace('\','').Length -eq $_.TaskName.Length-1 } | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation > "$syslogStorage\ScheduledTask_${hostname}.csv"


# List RDP Sessions
Write-Host "List RDP Sessions"
qwinsta | foreach {   
	if ($_ -NotMatch "services|console" -and $_ -match "Disc|Active|Acti|Déco") {
		$session = $($_ -Replace ' {2,}', ',').split(',')
		echo 1 | select  @{n="HostName";e={$env:computername}}, @{n="User";e={$session[1]}}, @{n="SessionID";e={$session[2]}}, @{n="Status";e={$session[3]}}
	}
} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation > "$syslogStorage\RDPSession_${hostname}.csv"


# List Firewall rules
Write-Host "List Firewall rules"
Get-NetFirewallRule -PolicyStore ActiveStore | where {$_.Enabled -eq $true } | sort Direction,Action | Select @{n="HostName";e={$env:computername}},DisplayName,Direction,DisplayGroup,Profile,Action,PolicyStoreSourceType,PolicyStoreSource,
	@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).Protocol}},
	@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).LocalPort}},
	@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).RemotePort}},
	@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter -PolicyStore ActiveStore).RemoteAddress}} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation > "$syslogStorage\FireWall_Rules_${hostname}.csv"
Get-NetFirewallProfile | select @{n="HostName";e={$env:computername}},* | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation > "$syslogStorage\FireWall_Status_${hostname}.csv"


# List local share
Write-Host "List local share"
try{
	Get-SmbShare -ErrorAction Stop | select @{n="HostName";e={$env:computername}},* | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation > "$syslogStorage\SmbShare_${hostname}.csv"
}catch{
	echo 1 | select @{n="HostName";e={$env:computername}} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation > "$syslogStorage\SmbShare_${hostname}.csv"
}


# List local ip
Write-Host "List local ip"
Get-NetIPAddress -AddressFamily IPv4 | ?{ $_.AddressState -ne 'Tentative' } | select @{n="HostName";e={$env:computername}},InterfaceAlias,IPAddress,PrefixLength,PrefixOrigin,AddressState | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation > "$syslogStorage\IpConfig_${hostname}.csv"


## List Windows Update
# Write-Host "List Windows Update"
# $updateSearcher = (new-object -com "Microsoft.Update.Session").CreateupdateSearcher()
# $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
# echo 1 | select @{n="HostName";e={$env:computername}},@{n="OSVersion";e={[System.Environment]::OSVersion.Version.ToString()}},@{n="ReleaseId";e={(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId}},@{n="DisplayVersion";e={(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion}},@{n="EditionID";e={(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID}},@{n="Nb Missing Windows Update";e={$searchResult.Updates.Count}},@{n="Missing Windows Update";e={($searchResult.Updates|select Title).Title}} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation > "$syslogStorage\General_${hostname}.csv"


# List config
Write-Host "List config"
@(
	@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL',1),
	@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','DisableRestrictedAdmin',0),
	@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','DisableRestrictedAdminOutboundCreds',1),
	@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel',5),
	@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential',0),
	@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','Negotiate',0),
	@('HKLM\Software\Policies\Microsoft Services\AdmPwd','AdmPwdEnabled',1),
	@('HKLM\Software\Policies\Microsoft Services\AdmPwd','PwdExpirationProtectionEnabled',1),
	@('HKLM\System\CurrentControlSet\Services\Netlogon\Parameters','RequireSignOrSeal',1),
	@('HKLM\System\CurrentControlSet\Services\Netlogon\Parameters','SealSecureChannel',1),
	@('HKLM\System\CurrentControlSet\Services\Netlogon\Parameters','SignSecureChannel',1),
	@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System','FilterAdministratorToken',1),
	@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System','LocalAccountTokenFilterPolicy',0),
	@('HKLM\System\CurrentControlSet\Services\LDAP','LDAPClientIntegrity',2),
	@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','SecurityLayer',1),
	@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','UserAuthentication',1),
	@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','fEncryptRPCTraffic',1),
	@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','SMB1',0),
	@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','EnableSecuritySignature',1),
	@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RequireSecuritySignature',1),
	@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','AutoShareWks',0),
	@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','AutoShareServer',0),
	@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RestrictNullSessAccess',1),
	@('HKLM\System\CurrentControlSet\Services\Rdr\Parameters','EnableSecuritySignature',1),
	@('HKLM\System\CurrentControlSet\Services\Rdr\Parameters','RequireSecuritySignature',1),
	@('HKLM\System\CurrentControlSet\Services\LanmanWorkstation','AllowInsecureGuestAuth',0),
	@('HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters','EnableSecuritySignature',1),
	@('HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters','RequireSecuritySignature',1),
	@('HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters','EnablePlainTextPassword',0),
	@('HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters','NodeType',2),
	@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient','EnableMulticast',0),
	@('HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc','Start',4),
	@('HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad','WpadOverride',0),
	@('HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings','AutoDetect',0),
	@('HKLM\System\currentcontrolset\services\tcpip6\parameters','DisabledComponents',32),
	@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate','WUServer',''),
	@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','UseWUServer',1)
) | %{
	$path=$_[0]
	$key=$_[1]
	$expected=$_[2]
	$ret = echo '' | Select hostname,key,value,expected,compliant
	$ret.hostname = $hostname
	$ret.key = "$path\$key"
	$ret.expected = "$expected"
	try{
		$ret.value = (Get-ItemPropertyValue -Path "Registry::$path" -Name $key -ErrorAction Stop).ToString()
	}catch{
		$ret.value = 'undefined'
	}
	$ret.compliant = $ret.value -eq $ret.expected
	$ret
} |  ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\Reg_${hostname}.csv"
