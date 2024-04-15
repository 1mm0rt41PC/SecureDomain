<#
# LOG Server
# ================================================
$logs = "C:\logs"
$domComputer='your-domain.lo\Domain computers'
$domUser='your-domain.lo\Domain users'

mkdir -force $logs

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


New-GPO -Name "[1mm0rt41][Audit] Syslog" | %{
	$gpoId="{{{0}}}" -f $_.Id.ToString();
	$gpoName=$_.DisplayName
	$gpoPath="C:\Windows\SYSVOL\domain\Policies\$gpoId\Machine\Preferences\ScheduledTasks";
	mkdir "$gpoPath" >$null
	( @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="[GPO] Syslog" image="0" changed="$((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))" uid="{D98A502B-7563-4A3D-A4EA-5B4EE8E63364}" ><Properties action="R" name="[GPO] Syslog" runAs="S-1-5-18" logonType="S4U"><Task version="1.2"><RegistrationInfo><Author>$($env:USERDOMAIN)\$($env:USERNAME)</Author><Description><![CDATA[This task need to run with S-1-5-18 // GPO Id: $gpoId // GPO Name: $gpoName]]></Description></RegistrationInfo><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT5M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Priority>7</Priority><RestartOnFailure><Interval>PT10M</Interval><Count>3</Count></RestartOnFailure><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable></Settings><Actions Context="Author"><Exec><Command>powershell</Command><Arguments>-exec bypass -nop -Command \\dc01.corp.lo\sysvol\dc01.corp.lo\scripts\logger.ps1</Arguments></Exec></Actions><Triggers><CalendarTrigger><StartBoundary>$((Get-Date).AddDays(1).ToString("yyyy-MM-ddT{0:d2}:00:00" -f 9))</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay><RandomDelay>PT10M</RandomDelay></CalendarTrigger></Triggers></Task></Properties></TaskV2>
</ScheduledTasks>
"@ ).Trim() | Out-File -Encoding ASCII "$gpoPath\ScheduledTasks.xml"
	Get-AdObject -Filter "(objectClass -eq 'groupPolicyContainer') -and (name -eq '$gpoId')" | Set-ADObject -Replace @{gPCMachineExtensionNames="[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"};
	$_
}
#>

$syslogStorage = '\\DC-SRV01\syslog$'
$hostname = $env:COMPUTERNAME
$delimiter = ','


New-EventLog -LogName System -Source Logger2CSV -ErrorAction SilentlyContinue;

$ErrorActionPreference = "Stop"
$log = "$($env:TMP)\$([guid]::NewGuid().ToString())"
Start-Transcript -Path $log -Force 

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
if( -not $scriptPath.StartsWith("\\") ){
	$syslogStorage = '.\output_sample\per_computer'
	mkdir -Force $syslogStorage > $null
	Write-Host -ForegroundColor White -BackgroundColor DarkRed "Mode test => Reason: the script $($MyInvocation.MyCommand.Definition) is not on a shared folder"
	Write-EventLog -LogName System -Source Logger2CSV -EntryType Warning -Event 2 -Message "Mode test => Reason: the script $($MyInvocation.MyCommand.Definition) is not on a shared folder"
}
Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Files storage: $syslogStorage\*_${hostname}.csv"


# List local users
Write-Host "List local users"
try {
	Get-LocalUser | select @{n="HostName";e={$env:computername}},Name,AccountExpires,Enabled,PasswordChangeableDate,PasswordExpires,UserMayChangePassword,PasswordRequired,PasswordLastSet,LastLogon | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\LocalUser_${hostname}.csv"
}catch{
	echo 1 | select @{n="HostName";e={$env:computername}},@{n="Name";e={"Powershell v2 only - Get-User not supported"}},AccountExpires,Enabled,PasswordChangeableDate,PasswordExpires,UserMayChangePassword,PasswordRequired,PasswordLastSet,LastLogon | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\LocalUser_${hostname}.csv"
}

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
"@ | ConvertFrom-CSV | Where { $_.TaskName.Replace('\','').Length -eq $_.TaskName.Length-1 } | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\ScheduledTask_${hostname}.csv"


# List RDP Sessions
Write-Host "List RDP Sessions"
qwinsta | foreach {   
	if ($_ -NotMatch "services|console" -and $_ -match "Disc|Active|Acti|Déco") {
		$session = $($_ -Replace ' {2,}', ',').split(',')
		echo 1 | select  @{n="HostName";e={$env:computername}}, @{n="User";e={$session[1]}}, @{n="SessionID";e={$session[2]}}, @{n="Status";e={$session[3]}}
	}
} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\RDPSession_${hostname}.csv"


# List Firewall rules
Write-Host "List Firewall rules"
try {
	Get-NetFirewallRule -PolicyStore ActiveStore | where {$_.Enabled -eq $true } | sort Direction,Action | Select @{n="HostName";e={$env:computername}},DisplayName,Direction,DisplayGroup,Profile,Action,PolicyStoreSourceType,PolicyStoreSource,
		@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).Protocol}},
		@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).LocalPort}},
		@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).RemotePort}},
		@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter -PolicyStore ActiveStore).RemoteAddress}} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\FireWallRules_${hostname}.csv"
	Get-NetFirewallProfile | select @{n="HostName";e={$env:computername}},* | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\FireWallStatus_${hostname}.csv"
}catch{
	echo 1 | select @{n="HostName";e={$env:computername}},@{n="DisplayName";e={"Powershell v2 only - FW not supported"}},Direction,DisplayGroup,Profile,Action,PolicyStoreSourceType,PolicyStoreSource,Protocol,LocalPort,RemotePort,RemoteAddress | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\FireWallStatus_${hostname}.csv"
}


# List Process
Write-Host "List Process"
Get-WmiObject Win32_Process | % {
	$p = $_
	$row = echo 1 | Select @{n="HostName";e={$env:computername}},Owner,OwnerDomain,@{n="ProcessId";e={$p.ProcessId}},@{n="ParentProcessId";e={$p.ParentProcessId}},@{n="CommandLine";e={$p.CommandLine}},@{n="Description";e={$p.Description}},@{n="ExecutablePath";e={$p.ExecutablePath}},@{n="Name";e={$p.Name}},@{n="SessionId";e={$p.SessionId}},@{n="CreationDate";e={$p.CreationDate}}
    try {
		$u = $p.GetOwner()
        $row.Owner = $u.User
        $row.OwnerDomain = $u.Domain
    } catch {
		Write-Host "err"
    }	
	return $row
} | where { $_.OwnerDomain -ne $env:computername -and $_.OwnerDomain -ne 'NT AUTHORITY' -and $_.OwnerDomain -ne 'Window Manager' -and $_.OwnerDomain -ne 'Font Driver Host' } | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\Process_${hostname}.csv"


# List local share
Write-Host "List local share"
try{
	$smb = Get-SmbShare -ErrorAction Stop | select @{n="HostName";e={$env:computername}},*
	$data = $smb | %{
		$cRow = $_
		$row = echo 1 | select @{n="HostName";e={$cRow.HostName}},@{n="Name";e={$cRow.Name}},@{n="Path";e={$cRow.Path}},@{n="Description";e={$cRow.Description}},@{n="CurrentUsers";e={$cRow.CurrentUsers}},@{n="CompressData";e={$cRow.CompressData}},@{n="EncryptData";e={$cRow.EncryptData}},smb_IdentityReference,smb_FileSystemRights,smb_AccessControlType,path_IdentityReference,path_FileSystemRights,path_AccessControlType,path_Owner
		$_.PresetPathAcl.Access | %{		
			$row.smb_AccessControlType = $_.AccessControlType
			$row.smb_FileSystemRights = $_.FileSystemRights
			$row.smb_IdentityReference = $_.IdentityReference
			$row
		}	
	}

	$data += $smb | %{
		$cRow = $_
		$row = echo 1 | select @{n="HostName";e={$cRow.HostName}},@{n="Name";e={$cRow.Name}},@{n="Path";e={$cRow.Path}},@{n="Description";e={$cRow.Description}},@{n="CurrentUsers";e={$cRow.CurrentUsers}},@{n="CompressData";e={$cRow.CompressData}},@{n="EncryptData";e={$cRow.EncryptData}},smb_IdentityReference,smb_FileSystemRights,smb_AccessControlType,path_IdentityReference,path_FileSystemRights,path_AccessControlType,path_Owner
		try{
			$acl = Get-Acl $_.Path
			$row.path_Owner = $acl.Owner
			$acl | select -ExpandProperty Access | %{		
				$row.path_AccessControlType = $_.AccessControlType
				$row.path_FileSystemRights = $_.FileSystemRights
				$row.path_IdentityReference = $_.IdentityReference
				$row
			}
		}catch{}
	}
	
	$data = $data | Sort Path | ConvertTo-Csv -NoTypeInformation | sort -Unique	
	$($data | where { $_.Contains('path_Owner') }; $data | where { -not $_.Contains('path_Owner') }) | Out-File -Encoding UTF8 "$syslogStorage\SmbShare_${hostname}.csv"
}catch{
	echo 1 | select @{n="HostName";e={$env:computername}} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\SmbShare_${hostname}.csv"
}


# List local ip
Write-Host "List local ip"
Get-WmiObject Win32_NetworkAdapterConfiguration | ?{ $_.IPEnabled -eq $true -and $_.IPAddress -ne $null -and $_.IPAddress.Count -ge 1 -and $_.IPAddress[0] -ne '' } | %{
	$row = $_
	for( $i=0; $i -lt $_.IPAddress.Count; $i++ ){
		$ret = 1 | select @{n="HostName";e={$env:computername}},@{n="InterfaceIndex";e={$row.InterfaceIndex}},@{n="MACAddress";e={$row.MACAddress}},IPAddress,IPSubnet,DefaultIPGateway,@{n="Description";e={$row.Description}},@{n="DHCPEnabled";e={$row.DHCPEnabled}},@{n="DHCPServer";e={$row.DHCPServer}},@{n="DNSDomain";e={$row.DNSDomain}},@{n="DNSServerSearchOrder";e={$row.DNSServerSearchOrder}},@{n="DNSDomainSuffixSearchOrder";e={$row.DNSDomainSuffixSearchOrder -join ","}},@{n="DomainDNSRegistrationEnabled";e={$row.DomainDNSRegistrationEnabled}},@{n="FullDNSRegistrationEnabled";e={$row.FullDNSRegistrationEnabled}},@{n="TcpipNetbiosOptions";e={$row.TcpipNetbiosOptions}},@{n="WINSPrimaryServer";e={$row.WINSPrimaryServer}}
		$ret.IPAddress = $_.IPAddress[$i]
		if( -not $ret.IPAddress.StartsWith('fe80::') ){
			$ret.IPSubnet = $_.IPSubnet[$i]
			if($_.DefaultIPGateway -ne $null -and $_.DefaultIPGateway.Count -ge 1){
				$ret.DefaultIPGateway = $_.DefaultIPGateway[0]
			}
			$ret
		}
	}
} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\IpConfig_${hostname}.csv"


# List local Services
Write-Host "List local Services"
Get-WmiObject Win32_Service | %{
	$row = $_
	echo 1 | select @{n="HostName";e={$env:computername}},@{n="DisplayName";e={$row.DisplayName}},@{n="Name";e={$row.Name}},@{n="State";e={$row.State}},@{n="UserName";e={$row.StartName}},@{n="InstallDate";e={$row.InstallDate}},@{n="Started";e={$row.Started}},@{n="Status";e={$row.Status}},@{n="ProcessId";e={$row.ProcessId}},@{n="PathName";e={$row.PathName}}
} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\Services_${hostname}.csv"


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
	@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','UseWUServer',1),
 	@('HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters','SearchList', 'suffix-dns.mycorp.local,suffix2.corp.lo'),
	@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'SearchList', 'suffix-dns.mycorp.local,suffix2.corp.lo')
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
} |  ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\Configuration_${hostname}.csv"


# Check SCCM NAA
Write-Host "List SCCM NAA"
$ret = echo '' | Select hostname,hasNAA
$ret.hostname = $hostname
try {
	$naa = Get-WmiObject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount" -ErrorAction Stop
  	if( $naa.NetworkAccessPassword.Length -gt 0 ){
		$ret.hasNAA = $true
 	}else{
		$ret.hasNAA = $false
 	}
	
}catch{
	$ret.hasNAA = $false
}
$ret | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\SCCM_${hostname}.csv"


# SecEdit
Write-Host "List SecEdit"
$tmp = "$($env:TMP)\$([guid]::NewGuid().ToString())"
SecEdit.exe /export /cfg $tmp
$lastType = ''
cat $tmp | % {
	if( $_.startswith('[') ){
		$lastType = $_
	}else{
		if( $lastType -ne '[Unicode]' -and $lastType -ne '[Version]' ){
			$tmprow = $_.replace(' = ',';').replace('=',';').split(';')
			$row = echo 1 | select hostname,category,key,val
			$row.hostname = $hostname;
			$row.category = $lastType;
			$row.key = $tmprow[0].trim('"');
			$row.val = $tmprow[1].trim('"');
			return $row
		}
	}
} | ConvertTo-Csv -NoTypeInformation -Delimiter $delimiter | Out-File -Encoding UTF8 "$syslogStorage\SecEdit_${hostname}.csv"
rm -force $tmp


# Log the activity
Stop-Transcript > $null
Write-EventLog -LogName System -Source Logger2CSV -EntryType Information -Event 1 -Message $(cat $log | Out-String)
rm -force $log


# Test if ALCs on destination are OK
try {
	ls "$syslogStorage" -ErrorAction Stop > $null
	Write-EventLog -LogName System -Source Logger2CSV -EntryType Warning -Event 3 -Message "The user $($env:USERNAME) is allowed to list files in $syslogStorage"
}catch{}
try {
	cat "$syslogStorage\Configuration_${hostname}.csv" -ErrorAction Stop > $null
	Write-EventLog -LogName System -Source Logger2CSV -EntryType Warning -Event 3 -Message "The user $($env:USERNAME) is allowed to read files in $syslogStorage"
}catch{}

