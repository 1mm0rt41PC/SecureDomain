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
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="[GPO] Syslog" image="0" changed="$((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))" uid="{D98A502B-7563-4A3D-A4EA-5B4EE8E63364}" ><Properties action="R" name="[GPO] Syslog" runAs="S-1-5-18" logonType="S4U"><Task version="1.2"><RegistrationInfo><Author>$($env:USERDOMAIN)\$($env:USERNAME)</Author><Description><![CDATA[This task need to run with S-1-5-18 // GPO Id: $gpoId // GPO Name: $gpoName]]></Description></RegistrationInfo><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT5M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Priority>7</Priority><RestartOnFailure><Interval>PT10M</Interval><Count>3</Count></RestartOnFailure><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable></Settings><Actions Context="Author"><Exec><Command>powershell</Command><Arguments>-exec bypass -nop -Command \\$($env:USERDNSDOMAIN)\NETLOGON\logger.ps1</Arguments></Exec></Actions><Triggers><CalendarTrigger><StartBoundary>$((Get-Date).AddDays(1).ToString("yyyy-MM-ddT{0:d2}:00:00" -f 9))</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay><RandomDelay>PT10M</RandomDelay></CalendarTrigger></Triggers></Task></Properties></TaskV2>
</ScheduledTasks>
"@ ).Trim() | Out-File -Encoding ASCII "$gpoPath\ScheduledTasks.xml"
	Get-AdObject -Filter "(objectClass -eq 'groupPolicyContainer') -and (name -eq '$gpoId')" | Set-ADObject -Replace @{gPCMachineExtensionNames="[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"};
	$_
}
#>

$syslogStorage = '\\DC-SRV01-Example.corp.lo\syslog$'
$hostname = $env:COMPUTERNAME
$delimiter = ','


New-EventLog -LogName System -Source Logger2CSV -ErrorAction SilentlyContinue;

$ErrorActionPreference = 'Stop'
$logFolder = 'C:\Windows\logs\logger'
mkdir -force $logFolder
$log = "$logFolder\$((get-date).ToString('yyyyMMddHms'))_$([guid]::NewGuid().ToString()).txt"
Start-Transcript -Path $log -Force

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
if( -not $scriptPath.Contains('\\') -or $syslogStorage -eq '\\DC-SRV01-Example.corp.lo\syslog$' ){
	$syslogStorage = '.\output_sample\per_computer'
	mkdir -Force $syslogStorage > $null
	Write-Host -ForegroundColor White -BackgroundColor DarkRed "Mode test => Reason: the script $($MyInvocation.MyCommand.Definition) is not on a shared folder"
	Write-EventLog -LogName System -Source Logger2CSV -EntryType Warning -Event 2 -Message "Mode test => Reason: the script $($MyInvocation.MyCommand.Definition) is not on a shared folder"
}
Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Files storage: $syslogStorage\*_${hostname}.csv"


function runTest
{
	Param
	(
		[Parameter(Mandatory=$true, Position=0)]
		[string] $Name,
		[Parameter(Mandatory=$true, Position=1)]
		[string] $Output,
		[Parameter(Mandatory=$true, Position=2)]
		[string] $ErrorMessage,
		[Parameter(Mandatory=$true, Position=3)]
		[string] $ErrorColumn,
		[Parameter(Mandatory=$true, Position=4)]
		[scriptblock] $InlineCode
	)
    Write-Host "[*] $Name"
	$obj = @()
	try{
		$obj = $InlineCode.Invoke()
	}catch{
		$err = "$Name - $ErrorMessage | Err: $($_.Exception.Message)"
		Write-EventLog -LogName System -Source Logger2CSV -EntryType Error -Event 3 -Message "$err"
		Write-Host -ForegroundColor White -BackgroundColor DarkRed "[!] $err"
		$obj = echo 1 | select @{n="HostName";e={$env:computername}},@{n="$ErrorColumn";e={$err}}
	}
	try{
		Write-Host "	> Found: $($obj.Count)"
		$obj | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\${Output}_${hostname}.csv"
		Write-Host "	> Written: $syslogStorage\${Output}_${hostname}.csv"
	}catch{
		$err = "$Name - Unable to write into >$syslogStorage\${Output}_${hostname}.csv< | Err: $($_.Exception.Message)"
		Write-EventLog -LogName System -Source Logger2CSV -EntryType Error -Event 4 -Message "$err"
		Write-Host -ForegroundColor White -BackgroundColor DarkRed "[!] $err"
	}
}


###############################################################################
# List config
$param = @{
	Name="List config";
	Output="Configuration";
	ErrorMessage=">Reg< not supported";
	ErrorColumn="DisplayName";
	InlineCode={
		$ret = @(
			@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL',2),
			@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','DisableRestrictedAdmin',0),
			@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','NoLMHash',1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','DisableRestrictedAdminOutboundCreds',1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel',5),
			@('HKLM\System\CurrentControlSet\Control\Lsa','EveryoneIncludesAnonymous',0),
			@('HKLM\System\CurrentControlSet\Control\Lsa','DisableDomainCreds',1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential',0),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','Negotiate',0),
			@('HKLM\System\CurrentControlSet\Services\Netlogon\Parameters','RequireSignOrSeal',1),
			@('HKLM\System\CurrentControlSet\Services\Netlogon\Parameters','SealSecureChannel',1),
			@('HKLM\System\CurrentControlSet\Services\Netlogon\Parameters','SignSecureChannel',1),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System','FilterAdministratorToken',1),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System','LocalAccountTokenFilterPolicy',0),
			@('HKLM\System\CurrentControlSet\Services\LDAP','LDAPClientIntegrity',2),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','SecurityLayer',2),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','UserAuthentication',1),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','fEncryptRPCTraffic',1),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','KeepAliveInterval',1),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','DeleteTempDirsOnExit',1),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','MinEncryptionLevel',1),
			@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','SMB1',0),
			@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','EnableSecuritySignature',1),
			@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RequireSecuritySignature',1),
			@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','AutoShareWks',0),
			@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','AutoShareServer',0),
			@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RestrictNullSessAccess',1),
			@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','EnablePlainTextPassword',0),
			@('HKLM\System\CurrentControlSet\Services\Rdr\Parameters','EnableSecuritySignature',1),
			@('HKLM\System\CurrentControlSet\Services\Rdr\Parameters','RequireSecuritySignature',1),
			@('HKLM\System\CurrentControlSet\Services\LanmanWorkstation','AllowInsecureGuestAuth',0),
			@('HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters','EnableSecuritySignature',1),
			@('HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters','RequireSecuritySignature',1),
			@('HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters','EnablePlainTextPassword',0),
			@('HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters','NodeType',2),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient','EnableMulticast',0), 	
			@('HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc','Start',4),
			@('HKLM\SYSTEM\CurrentControlSet\Services\WebClient','Start',4),
			@('HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc','Start',4),
			@('HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager','Start',4),
			@('HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave','Start',4),
			@('HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc','Start',4),
			@('HKLM\SYSTEM\CurrentControlSet\Services\Spooler','Start',4),
			@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer','Start',4),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad','WpadOverride',0),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings','AutoDetect',0),
			@('HKLM\System\currentcontrolset\services\tcpip6\parameters','DisabledComponents',32),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate','WUServer',''),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','UseWUServer',1),
			@('HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters','SearchList', 'suffix-dns.mycorp.local,suffix2.corp.lo'),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'SearchList', 'suffix-dns.mycorp.local,suffix2.corp.lo'),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\System', 'DontDisplayNetworkSelectionUI', 1),
			@('HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters', 'EnableMDNS', 0),
			@('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer', 'DisableCoInstallers', 1),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowBasic', 0),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowDigest', 0),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowKerberos', 1),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'CbtHardeningLevel', 'Strict'),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowNegotiate', 0),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowBasic', 0),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowDigest', 0),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowKerberos', 1),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'CbtHardeningLevel', 'Strict'),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowNegotiate', 0),
			@('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings', 'SecureProtocols', 10752),
			@('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp', 'DefaultSecureProtocols', 10752),
			@('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp', 'DefaultSecureProtocols', 10752),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client', 'DisabledByDefault', 0),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client', 'Enabled', 1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client', 'DisabledByDefault', 0),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client', 'Enabled', 1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client', 'DisabledByDefault', 1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client', 'Enabled', 0),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client', 'DisabledByDefault', 1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client', 'Enabled', 0),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server', 'DisabledByDefault', 0),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server', 'Enabled', 1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server', 'DisabledByDefault', 0),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server', 'Enabled', 1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server', 'DisabledByDefault', 1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server', 'Enabled', 0),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server', 'DisabledByDefault', 1),
			@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server', 'Enabled', 0),
			@('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0', 'AuditReceivingNTLMTraffic', 2),
			@('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0', 'RestrictSendingNTLMTraffic', 1),
			@('HKLM\System\CurrentControlSet\Services\Netlogon\Parameters', 'AuditNTLMInDomain', 7),	
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowDefaultCredentials', 0),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'ConcatenateDefaults_AllowDefault', 0),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowDefCredentialsWhenNTLMOnly', 0),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'ConcatenateDefaults_AllowDefNTLMOnly', 0),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly', '1', ''),
			@('HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefaultCredentials', '1', ''),
			@('HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots', 'value', 0),	
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'BackupDirectory', 2),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PasswordAgeDays', 30),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PasswordLength', 20),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PasswordComplexity', 4),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'ADPasswordEncryptionEnabled', 0),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'ADBackupDSRMPassword', 1),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PostAuthenticationResetDelay', 6),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PostAuthenticationActions', 3),	
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'BackupDirectory', 2),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'PasswordAgeDays', 30),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'PasswordLength', 20),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'PasswordComplexity', 4),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'ADPasswordEncryptionEnabled', 0),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'ADBackupDSRMPassword', 1),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'PostAuthenticationResetDelay', 6),
			@('HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'PostAuthenticationActions', 3),
			@('HKLM\Software\Policies\Microsoft Services\AdmPwd', 'AdmPwdEnabled', 1),
			@('HKLM\Software\Policies\Microsoft Services\AdmPwd', 'PwdExpirationProtectionEnabled', 1),
			@('HKLM\Software\Policies\Microsoft Services\AdmPwd', 'PasswordComplexity', 4),
			@('HKLM\Software\Policies\Microsoft Services\AdmPwd', 'PasswordLength', 20),
			@('HKLM\Software\Policies\Microsoft Services\AdmPwd', 'PasswordAgeDays', 30),
			@('HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}', 'ExtensionDebugLevel', 2)
		) | %{
			$path=$_[0]
			$key=$_[1]
			$expected=$_[2]
			$row = echo '' | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"$path\$key"}},Value,@{n="Expected";e={$expected}},Compliant
			try{
				$row.Value = (Get-ItemPropertyValue -Path "Registry::$path" -Name $key -ErrorAction Stop).ToString()
			}catch{
				$row.Value = 'undefined'
			}
			$row.Compliant = $row.Value -eq $row.Expected
			$row
		}
		#
		$data = winmgmt /verifyrepository
		$row_LASTEXITCODE = $LASTEXITCODE
		$ret += @(echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"wmi-repository-status"}},@{n="Value";e={$data}},@{n="Expected";e={"N/A"}},@{n="Compliant";e={"N/A"}})
		$wmiRepoSize = (Get-ChildItem -Path $env:windir\System32\Wbem\Repository | Measure-Object -Property Length -Sum).Sum
		$ret += @(echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"wmi-repository-size"}},@{n="Value";e={$wmiRepoSize/1024/1024/1024}},@{n="Expected";e={"<1"}},@{n="Compliant";e={$wmiRepoSize -lt 1*1024*1024*1024}})
		if( $row_LASTEXITCODE -eq 0 -and $wmiRepoSize -lt 1*1024*1024*1024 ){
			$row = echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"Has SCCM NAA ClearText Password"}},Value,@{n="Expected";e={$false}},Compliant
			try {
				$naa = Get-WmiObject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount" -ErrorAction Stop
				$row.Value = $naa.NetworkAccessPassword.Length -gt 0			
			}catch{
				$row.Value = $false
			}
			$row.Compliant = $row.Value -eq $row.Expected
			$ret += @($row)
			#
			$ret += @(echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"SyslogRefreshDate"}},@{n="Value";e={(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')}},@{n="Expected";e={"N/A"}},@{n="Compliant";e={"N/A"}})
			#
			$tmp = Get-WmiObject Win32_OperatingSystem
			$ret += @(echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"SystemDirectory"}},@{n="Value";e={$tmp.SystemDirectory}},@{n="Expected";e={"N/A"}},@{n="Compliant";e={"N/A"}})
			$ret += @(echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"Organization"}},@{n="Value";e={$tmp.Organization}},@{n="Expected";e={"N/A"}},@{n="Compliant";e={"N/A"}})
			$ret += @(echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"BuildNumber"}},@{n="Value";e={$tmp.BuildNumber}},@{n="Expected";e={"N/A"}},@{n="Compliant";e={"N/A"}})
			$ret += @(echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"RegisteredUser"}},@{n="Value";e={$tmp.RegisteredUser}},@{n="Expected";e={"N/A"}},@{n="Compliant";e={"N/A"}})
			$ret += @(echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"SerialNumber"}},@{n="Value";e={$tmp.SerialNumber}},@{n="Expected";e={"N/A"}},@{n="Compliant";e={"N/A"}})
			$ret += @(echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Key";e={"Version"}},@{n="Value";e={$tmp.Version}},@{n="Expected";e={"N/A"}},@{n="Compliant";e={"N/A"}})
		}
		return $ret
	}
}
runTest @param


###############################################################################
# List local users
$param = @{
	Name="List local users";
	Output="LocalUser";
	ErrorMessage="Get-LocalUser not supported";
	ErrorColumn="Name";
	InlineCode={
		return Get-LocalUser -ErrorAction Stop | select @{n="HostName";e={$env:computername}},Name,SID,AccountExpires,Enabled,PasswordChangeableDate,PasswordExpires,UserMayChangePassword,PasswordRequired,PasswordLastSet,LastLogon
	}
}
runTest @param


###############################################################################
# List local users
$param = @{
	Name="List local group members";
	Output="LocalGroup";
	ErrorMessage=">Get-WmiObject win32_group< not supported";
	ErrorColumn="Name";
	InlineCode={
		return Get-WmiObject win32_group -filter "Domain='$hostname'" -ErrorAction Stop | %{
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
		}
	}
}
runTest @param


###############################################################################
# List ScheduledTask
$param = @{
	Name="List ScheduledTask";
	Output="ScheduledTask";
	ErrorMessage=">schtasks< not supported";
	ErrorColumn="TaskName";
	InlineCode={
		return @"
"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running"
$((schtasks.exe /query /V /FO csv)  -join "`r`n")
"@ | ConvertFrom-CSV
	}
}
runTest @param


###############################################################################
# List RDP Sessions
$param = @{
	Name="List RDP Sessions";
	Output="RDPSession";
	ErrorMessage=">schtasks< not supported";
	ErrorColumn="User";
	InlineCode={
		return qwinsta | foreach {
			if ($_ -NotMatch "services|console" -and $_ -match "Disc|Active|Acti|Déco") {
				$session = $($_ -Replace ' {2,}', ',').split(',')
				echo 1 | select  @{n="HostName";e={$env:computername}}, @{n="User";e={$session[1]}}, @{n="SessionID";e={$session[2]}}, @{n="Status";e={$session[3]}}
			}
		}
	}
}
runTest @param


###############################################################################
# List Firewall rules
$param = @{
	Name="List Firewall rules";
	Output="FireWallRules";
	ErrorMessage=">Get-NetFirewallRule< not supported";
	ErrorColumn="DisplayName";
	InlineCode={
		return Get-NetFirewallRule -ErrorAction Stop -PolicyStore ActiveStore | where {$_.Enabled -eq $true } | sort Direction,Action | Select @{n="HostName";e={$env:computername}},DisplayName,Direction,DisplayGroup,Profile,Action,PolicyStoreSourceType,PolicyStoreSource,
			@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).Protocol}},
			@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).LocalPort}},
			@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).RemotePort}},
			@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter -PolicyStore ActiveStore).RemoteAddress}}
	}
}
runTest @param


###############################################################################
# List Firewall Profiles
$param = @{
	Name="List Firewall Profiles";
	Output="FireWallStatus";
	ErrorMessage=">Get-NetFirewallProfile< not supported";
	ErrorColumn="Name";
	InlineCode={
		return Get-NetFirewallProfile -ErrorAction Stop | select @{n="HostName";e={$env:computername}},Name,Profile,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules,AllowUserApps,AllowUserPorts,AllowUnicastResponseToMulticast,NotifyOnListen,EnableStealthModeForIPsec,LogMaxSizeKilobytes,LogAllowed,LogBlocked,LogIgnored,Caption,Description,ElementName,InstanceID,@{n="DisabledInterfaceAliases";e={$_.DisabledInterfaceAliases -join ','}},LogFileName
	}
}
runTest @param


###############################################################################
# List Process
$param = @{
	Name="List Process";
	Output="Process";
	ErrorMessage=">Get-Process< not supported";
	ErrorColumn="OwnerDomain";
	InlineCode={
		try{
			return Get-Process -IncludeUserName -ErrorAction Stop | Select @{n="HostName";e={$env:computername}},
				@{n="OwnerDomain";e={try{$_.UserName.split('\')[0]}catch{$_.UserName}}},
				@{n="Owner";e={try{$_.UserName.split('\')[1]}catch{$_.UserName}}},
				@{n="UserSID";e={try{(New-Object Security.Principal.NTAccount($_.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value}catch{'S-0-0-0'}}},
				IsLocalUser,
				@{n="ProcessId";e={$_.Id}},
				@{n="CommandLine";e={$_.Path}},
				@{n="Description";e={$_.Description}},
				@{n="Name";e={$_.Name}},
				@{n="SessionId";e={$_.SessionId}},
				@{n="CreationDate";e={$_.StartTime}} | Select HostName,OwnerDomain,Owner,UserSID,@{n="IsLocalUser";e={($_.UserSID.Length -le 12) -or ($_.OwnerDomain -eq $_.HostName)}},ProcessId,CommandLine,Description,Name,SessionId,CreationDate
		}catch{
			$err = "List Process - Unable to run >Get-Process -IncludeUserName< | Err: $($_.Exception.Message) | Using failover with WMI"
			Write-EventLog -LogName System -Source Logger2CSV -EntryType Error -Event 4 -Message "$err"
			Write-Host -ForegroundColor White -BackgroundColor DarkRed "[!] $err"
			
			return Get-WmiObject Win32_Process -ErrorAction Stop | %{
				$row = $_ | Select @{n="HostName";e={$env:computername}},
					OwnerDomain,
					Owner,
					UserSID,
					IsLocalUser,
					@{n="ProcessId";e={$_.ProcessId}},
					@{n="CommandLine";e={$_.CommandLine}},
					@{n="Description";e={$_.Description}},
					@{n="Name";e={$_.Name}},
					@{n="SessionId";e={$_.SessionId}},
					@{n="CreationDate";e={$_.CreationDate}}
				try {
					$u = $_.GetOwner()
					$row.Owner = $u.User
					$row.OwnerDomain = $u.Domain
					$row.UserSID = (New-Object Security.Principal.NTAccount($u.Domain,$u.User)).Translate([Security.Principal.SecurityIdentifier]).Value
				} catch {}
				$row
			} | Select HostName,OwnerDomain,Owner,UserSID,@{n="IsLocalUser";e={($_.UserSID.Length -le 12) -or ($_.OwnerDomain -eq $_.HostName)}},ProcessId,CommandLine,Description,Name,SessionId,CreationDate
		}
	}
}
runTest @param


###############################################################################
# List Firewall Profiles
$param = @{
	Name="List local share";
	Output="SmbShare";
	ErrorMessage=">Get-SmbShare< not supported";
	ErrorColumn="Name";
	InlineCode={
		if( $(Get-Service lanmanserver).Status -eq 'Stopped' ) {
			return echo 1 | select @{n="HostName";e={$env:computername}},@{n="Name";e={"Service Stopped"}}
		}
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
		return $($data | where { $_.Contains('path_Owner') }; $data | where { -not $_.Contains('path_Owner') })
	}
}
runTest @param


###############################################################################
# List local ip
$param = @{
	Name="List local ip";
	Output="IpConfig";
	ErrorMessage=">Get-WmiObject Win32_NetworkAdapterConfiguration< not supported";
	ErrorColumn="InterfaceIndex";
	InlineCode={
		return Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop | ?{ $_.IPEnabled -eq $true -and $_.IPAddress -ne $null -and $_.IPAddress.Count -ge 1 -and $_.IPAddress[0] -ne '' } | %{
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
		}
	}
}
runTest @param


###############################################################################
# List local Services
$param = @{
	Name="List local Services";
	Output="Services";
	ErrorMessage=">Get-WmiObject Win32_Service< not supported";
	ErrorColumn="DisplayName";
	InlineCode={
		return Get-WmiObject -ErrorAction Stop Win32_Service | %{
			$row = $_
			echo 1 | select @{n="HostName";e={$env:computername}},@{n="DisplayName";e={$row.DisplayName}},@{n="Name";e={$row.Name}},@{n="State";e={$row.State}},@{n="UserName";e={$row.StartName}},@{n="InstallDate";e={$row.InstallDate}},@{n="Started";e={$row.Started}},@{n="Status";e={$row.Status}},@{n="ProcessId";e={$row.ProcessId}},@{n="PathName";e={$row.PathName}}
		}
	}
}
runTest @param


## List Windows Update
# Write-Host "List Windows Update"
# $updateSearcher = (new-object -com "Microsoft.Update.Session").CreateupdateSearcher()
# $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
# echo 1 | select @{n="HostName";e={$env:computername}},@{n="OSVersion";e={[System.Environment]::OSVersion.Version.ToString()}},@{n="ReleaseId";e={(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId}},@{n="DisplayVersion";e={(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion}},@{n="EditionID";e={(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID}},@{n="Nb Missing Windows Update";e={$searchResult.Updates.Count}},@{n="Missing Windows Update";e={($searchResult.Updates|select Title).Title}} | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation > "$syslogStorage\General_${hostname}.csv"


###############################################################################
# List SecEdit
$param = @{
	Name="List SecEdit";
	Output="SecEdit";
	ErrorMessage=">SecEdit< not supported";
	ErrorColumn="Category";
	InlineCode={
		$tmp = "$($env:TMP)\$([guid]::NewGuid().ToString())"
		SecEdit.exe /export /cfg $tmp >$null 2>&1
		$lastType = ''
		$secedit = cat $tmp | % {
			if( $_.startswith('[') ){
				$lastType = $_
			}else{
				if( $lastType -ne '[Unicode]' -and $lastType -ne '[Version]' ){
					$tmprow = $_.replace(' = ',';').replace('=',';').split(';')
					return echo 1 | select @{n="HostName";e={$env:computername}},@{n="Category";e={$lastType}},@{n="Key";e={$tmprow[0].trim('"')}},@{n="Value";e={$tmprow[1].trim('"')}}
				}
			}
		}
		#
		$localSid=''
		try {
			$localSid = (New-Object System.Security.Principal.NTAccount("DefaultAccount")).Translate([System.Security.Principal.SecurityIdentifier]).Value
		}catch{
			try{
				$localSid = (New-Object System.Security.Principal.NTAccount("Administrateur")).Translate([System.Security.Principal.SecurityIdentifier]).Value
			}catch{
				try{
					$localSid = (New-Object System.Security.Principal.NTAccount("Administrator")).Translate([System.Security.Principal.SecurityIdentifier]).Value
				}catch{
					try{
						$localSid = (New-Object System.Security.Principal.NTAccount("Guest")).Translate([System.Security.Principal.SecurityIdentifier]).Value
					}catch{
						$err = "SecEdit - Unable to find local SID"
						Write-EventLog -LogName System -Source Logger2CSV -EntryType Error -Event 3 -Message "$err"
						Write-Host -ForegroundColor White -BackgroundColor DarkRed "[!] $err"
					}
				}
			}
		}
		$localSid = $localSid.split('-')
		$localSid = $localSid[0]+'-'+$localSid[1]+'-'+$localSid[2]+'-'+$localSid[3]+'-'+$localSid[4]+'-'+$localSid[5]+'-'+$localSid[6]
		#
		$PrivilegeRights=@()
		$secedit | ?{ $_.Category -eq '[Privilege Rights]' } | %{
			$priv = $_
			$_.Value.split(',') | % {
				$row = $priv | select HostName,Category,Key,Value;
				$row.Value = $_
				if( $_[0] -eq '*' ){
					try {
						$tmpval = (New-Object System.Security.Principal.SecurityIdentifier($_.Replace('*',''))).Translate([System.Security.Principal.NTAccount]).Value
						if( $tmpval -ne $null -and $tmpval -ne '' ){
							$row.Value = $tmpval + ' (' + $row.Value.Replace('*','') + ')'
						}
					}catch{}
				}else{
					try{
						$tmpval = (New-Object System.Security.Principal.NTAccount($_)).Translate([System.Security.Principal.SecurityIdentifier]).Value
						if( $tmpval -ne $null -and $tmpval -ne '' ){
							if( $row.Value.startswith($localSid) ){
								$row.Value = $row.Value + ' (' + $tmpval + ')'
							}else{
								$row.Value = '.\'+$row.Value + ' (' + $tmpval + ')'
							}
						}
					}catch{}
				}
				$PrivilegeRights += @($row)
			}
		}
		$secedit = $secedit | ?{ $_.Category -ne '[Privilege Rights]' }
		$secedit = $secedit + $PrivilegeRights
		rm -Force -ErrorAction SilentlyContinue $tmp
		return $secedit
	}
}
runTest @param


###############################################################################
# List LSA error from the last 24h
$param = @{
	Name="List LSA error from the last 24h";
	Output="Events-Microsoft-Windows-CodeIntegrity_$((Get-Date).ToString('yyyyMMddHHmmss'))";
	ErrorMessage=">Get-WinEvent< not supported";
	ErrorColumn="TimeCreated";
	InlineCode={
		# Require !
		# reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v "AuditLevel" /d 8 /t REG_DWORD /F
		$FilterXml = @'
		<QueryList>
			<Query Id="0" Path="Microsoft-Windows-CodeIntegrity/Operational">
				<Select Path="Microsoft-Windows-CodeIntegrity/Operational">
					*[System[(EventID=3065 or EventID=3066 or EventID=3033 or EventID=3063) and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]]
				</Select>
			</Query>
		</QueryList>
'@
		try{
			return Get-WinEvent -FilterXml $FilterXml -ErrorAction Stop | % {
				$ret = $_ | Select @{n="HostName";e={$env:computername}},TimeCreated,Id,UserId,LevelDisplayName,FileNameBuffer,ProcessNameBuffer,Message
				$xml = [xml]$x[0].toXML()
				$ret.FileNameBuffer = ($xml.Event.EventData.Data | ?{ $_.Name -eq 'FileNameBuffer' }).'#text'
				$ret.ProcessNameBuffer = ($xml.Event.EventData.Data | ?{ $_.Name -eq 'ProcessNameBuffer' }).'#text'
				$ret
			}
		}catch{
			return echo 1 | Select @{n="HostName";e={$env:computername}},TimeCreated,Id,UserId,LevelDisplayName,FileNameBuffer,ProcessNameBuffer,@{n="Message";e={"No Event in last 24h"}}
		}
	}
}
runTest @param


###############################################################################
# List NTLMv1 auth recived from the last 24h
$param = @{
	Name="List NTLMv1 auth recived from the last 24h";
	Output="Events-NTLMv1_$((Get-Date).ToString('yyyyMMddHHmmss'))";
	ErrorMessage=">Get-WinEvent< not supported";
	ErrorColumn="TimeCreated";
	InlineCode={
		$FilterXml = @'
			<QueryList>
				<Query Id="0" Path="security">
					<Select Path="security">
						*[System[(EventID=4624)] and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]
						and
						 *[EventData[Data[@Name='LmPackageName']='NTLM V1']]
					</Select>
				</Query>
			</QueryList>
'@
		try{
			return Get-WinEvent -FilterXml $FilterXml -ErrorAction Stop | % {
				$h = @{}
				([xml]$_.Toxml()).Event.EventData.Data | ForEach-Object {
					$h.Add($_.'Name',$_.'#text')
				}
				[PSCustomObject]$h
			}
		}catch{
			return echo 1 | Select @{n="HostName";e={$env:computername}},@{n="Message";e={"No Event in last 24h"}}
		}
	}
}
runTest @param


###############################################################################
# NTLMv1 and NTLMv2 client blocked audit: 
# Audit outgoing NTLM authentication traffic that would be blocked.
$param = @{
	Name="List outgoing NTLM authentication traffic that would be blocked from the last 24h";
	Output="Events-NTLM-Out_$((Get-Date).ToString('yyyyMMddHHmmss'))";
	ErrorMessage=">Get-WinEvent< not supported";
	ErrorColumn="TimeCreated";
	InlineCode={
		try{
			return Get-WinEvent -ErrorAction Stop -FilterHashtable @{ LogName = 'Microsoft-Windows-NTLM/Operational'; Id=8001,8002; StartTime=(get-date).AddHours("-24") } | %{
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
				$_ | Select @{n="HostName";e={$env:computername}},TimeCreated,@{n="TargetName";e={$TargetName}},@{n="Direction";e={$Direction}},@{n="ProcessId";e={$ProcessID}},@{n="ProcessName";e={$ProcessName}} ,@{n="Identity";e={$Identity}} 
			}
		}catch{
			return echo 1 | Select @{n="HostName";e={$env:computername}},@{n="TimeCreated";e={"No Event in last 24h"}}
		}
	}
}
runTest @param


###############################################################################
# List SMBv1 connection in
$param = @{
	Name="List SMBv1 connection in from the last 24h";
	Output="Events-SMBv1-In_$((Get-Date).ToString('yyyyMMddHHmmss'))";
	ErrorMessage=">Get-WinEvent< not supported";
	ErrorColumn="TimeCreated";
	InlineCode={
		try{
			# Require
			# Set-SmbServerConfiguration -AuditSmb1Access $true
			return Get-WinEvent -ErrorAction Stop -FilterHashtable @{ LogName = 'Microsoft-Windows-SMBServer/Audit'; Id=3000; StartTime=(get-date).AddHours("-24") } | %{
				$_ | Select @{n="HostName";e={$env:computername}},TimeCreated,Message
			}
		}catch{
			return echo 1 | Select @{n="HostName";e={$env:computername}},@{n="TimeCreated";e={"No Event in last 24h"}}
		}
	}
}
runTest @param


###############################################################################
# List local Software
$param = @{
	Name="List local Software";
	Output="Softwares";
	ErrorMessage=">Get-ItemProperty< not supported";
	ErrorColumn="DisplayName";
	InlineCode={
		return Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | select @{n="HostName";e={$env:computername}},DisplayName,Version,DisplayVersion,InstallDate,InstallLocation
	}
}
runTest @param




###############################################################################
###############################################################################
###############################################################################


# Log the activity
Stop-Transcript > $null
Write-EventLog -LogName System -Source Logger2CSV -EntryType Information -Event 1 -Message $(cat $log | Out-String)

$limit = (Get-Date).AddDays(-15)
Get-ChildItem -Path $logFolder -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $limit } | Remove-Item -Force

# Test if ALCs on destination are OK
try {
	ls "$syslogStorage" -ErrorAction Stop > $null
	Write-EventLog -LogName System -Source Logger2CSV -EntryType Warning -Event 3 -Message "The user $($env:USERNAME) is allowed to list files in $syslogStorage"
}catch{}
try {
	cat "$syslogStorage\Configuration_${hostname}.csv" -ErrorAction Stop > $null
	Write-EventLog -LogName System -Source Logger2CSV -EntryType Warning -Event 3 -Message "The user $($env:USERNAME) is allowed to read files in $syslogStorage"
}catch{}
