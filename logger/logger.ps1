<#
# logger.ps1 - A simple script that automates Windows collect security info
#
# Filename: logger.ps1
# Author: 1mm0rt41PC - immortal-pc.info - https://github.com/1mm0rt41PC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# Update: 2024-06-20 - Fix err on LocalGroup collector | Fix test mode
# Update: 2024-06-10 - Fix crash when non admin run
# Update: 2024-06-07 - Fix SmbShare error
# Update: 2024-06-07 - Fixed TPM rollback
# Update: 2024-06-07 - Add conf desc
#>
<#
###############################################################################
# INSTALL
###############################################################################
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

###############################################################################
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

$syslogStorage           = '\\DC-SRV01-Example.corp.lo\syslog$'
$hostname                = $env:COMPUTERNAME
$delimiter               = ','
$date                    = (Get-Date).ToString('yyyyMMddHH')
$logFolder               = 'C:\Windows\logs\logger'
$maxLogPowershellHistory = (Get-Date).AddDays(-30)# This script log
$hoursHistory            = 25# Windows EventLog
$ErrorActionPreference   = 'Stop'
$EventLogName            = 'Logger2CSV'


New-EventLog -LogName System -Source $EventLogName -ErrorAction SilentlyContinue;
function logMsg
{
	Param
	(
		[Parameter(Mandatory=$true, Position=0)]
		[int] $EventId,
		
		[Parameter(Mandatory=$true, Position=1)]
		[ValidateSet('Error','Information','FailureAudit','SuccessAudit','Warning')]
		[string[]] $EntryType,
		
		[Parameter(Mandatory=$true, Position=2)]
		[string] $Message
	)
	Write-Host -ForegroundColor White -BackgroundColor DarkRed $Message
	try{
		Write-EventLog -ErrorAction Stop -LogName System -Source $EventLogName -EntryType $EntryType -Event $EventId -Message $Message
	}catch{}
}


try{
	mkdir -ErrorAction Stop -force $logFolder
	$log = "$logFolder\${date}_$([guid]::NewGuid().ToString()).txt"
}catch{
	logMsg -EventId 2 -EntryType Error -Message "Unable to create folder $logFolder"
	$logFolder = "$($env:temp)\logger"
	mkdir -ErrorAction Stop -force $logFolder
	$log = "$logFolder\${date}_$([guid]::NewGuid().ToString()).txt"
}
Start-Transcript -Path $log -Force

if( -not $syslogStorage.Contains('\\') -or $syslogStorage -eq '\\DC-SRV01-Example.corp.lo\syslog$' ){
	$syslogStorage = '.\output_sample\per_computer'
	mkdir -Force $syslogStorage > $null
	logMsg -EntryType Warning -Event 2 -Message "Mode test => Reason: the script `$syslogStorage is not configured to point on valid SMB Share"
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
		$ColumnsList,
		[Parameter(Mandatory=$true, Position=4)]
		[scriptblock] $InlineCode
	)
    Write-Host "[*] $Name"
	$ColumnsList = $ColumnsList | Select @{n="HostName";e={$env:computername}},*,Error
	$obj = @()
	try{
		$obj = $InlineCode.Invoke($ColumnsList)
		if( $obj.Count -gt 0 -and $obj[0].HostName -eq $null ){
			$obj = $obj | Select -ExcludeProperty HostName @{n="HostName";e={$env:computername}},*
		}
		if( $obj.Count -gt 0 -and -not($obj[0].PSObject.Properties.Name -Contains "Error") ){
			$obj = $obj | Select *,Error
		}
	}catch{
		$err = "$Name - $ErrorMessage | Err: $($_.Exception.Message)"
		logMsg -EntryType Error -Event 3 -Message $err
		$obj = @($ColumnsList | Select * | %{ $_.Error=$err; $_ })
	}
	try{
		Write-Host "	> Found: $($obj.Count)"
		$obj | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\${Output}_${hostname}.csv"
		Write-Host "	> Written: $syslogStorage\${Output}_${hostname}.csv"
	}catch{
		logMsg -EntryType Error -Event 4 -Message "$Name - Unable to write into >$syslogStorage\${Output}_${hostname}.csv< | Err: $($_.Exception.Message)"
	}
}


###############################################################################
# List config
$param = @{
	Name="List config";
	Output="Configurations";
	ErrorMessage=">Reg< not supported";
	ColumnsList=1 | Select Key,Value,Expected,Compliant;
	InlineCode={
		param($ColumnsList)
		$ret = @(
			@('Audit auth - NTLM','HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0', 'AuditReceivingNTLMTraffic', 1),
			@('Audit auth - NTLM','HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0', 'RestrictSendingNTLMTraffic', 1),
			@('Audit auth - NTLM','HKLM\System\CurrentControlSet\Services\Netlogon\Parameters', 'AuditNTLMInDomain', 7),	
			@('Auth Hardening - SMB Client','HKLM\System\CurrentControlSet\Services\LanmanWorkstation','AllowInsecureGuestAuth',0),
			@('Auth Hardening - SMB Server','HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RestrictNullSessAccess',1),
			@('Auth Hardening','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential',0),
			@('Auth Hardening','HKLM\System\CurrentControlSet\Control\Lsa','DisableDomainCreds',1),
			@('Auth Hardening','HKLM\System\CurrentControlSet\Control\Lsa','EveryoneIncludesAnonymous',0),
			@('Conf info - DNSSuffix','HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'SearchList', 'suffix-dns.mycorp.local,suffix2.corp.lo'),
			@('Conf info - DNSSuffix','HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters','SearchList', 'suffix-dns.mycorp.local,suffix2.corp.lo'),
			@('Credential leak - Delegation','HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowDefCredentialsWhenNTLMOnly', 0),
			@('Credential leak - Delegation','HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowDefaultCredentials', 0),
			@('Credential leak - Delegation','HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'ConcatenateDefaults_AllowDefNTLMOnly', 0),
			@('Credential leak - Delegation','HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'ConcatenateDefaults_AllowDefault', 0),
			@('Credential leak - Delegation','HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly', '1', ''),
			@('Credential leak - Delegation','HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefaultCredentials', '1', ''),
			@('Credential leak - MITM - IPv6','HKLM\System\currentcontrolset\services\tcpip6\parameters','DisabledComponents',32),
			@('Credential leak - MITM - LLMNR','HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient','EnableMulticast',0), 	
			@('Credential leak - MITM - NBNS','HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters','NodeType',2),
			@('Credential leak - MITM - WPAD','HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc','Start',4),
			@('Credential leak - MITM - WPAD','HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings','AutoDetect',0),
			@('Credential leak - MITM - WPAD','HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad','WpadOverride',0),
			@('Credential leak - MITM - mDNS','HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters', 'EnableMDNS', 0),
			@('Credential leak - Network configuration','HKLM\SOFTWARE\Policies\Microsoft\Windows\System', 'DontDisplayNetworkSelectionUI', 1),
			@('Credential leak - WiFi','HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots', 'value', 0),	
			@('Credentials Encryption - SMB Server','HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','EnablePlainTextPassword',0),
			@('Credentials Encryption','HKLM\SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel',5),
			@('Credentials Encryption','HKLM\SYSTEM\CurrentControlSet\Control\Lsa','NoLMHash',1),
			@('Credentials Protection','HKLM\SYSTEM\CurrentControlSet\Control\Lsa','DisableRestrictedAdmin',0),
			@('Credentials Protection','HKLM\SYSTEM\CurrentControlSet\Control\Lsa','DisableRestrictedAdminOutboundCreds',1),
			@('Credentials Protection','HKLM\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL',2),
			@('Credentials Protection','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','Negotiate',0),
			@('Credentials Protection','HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System','FilterAdministratorToken',1),
			@('Credentials Protection','HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System','LocalAccountTokenFilterPolicy',0),
			@('Credentials Relay - LDAP Client','HKLM\System\CurrentControlSet\Services\LDAP','LDAPClientIntegrity',2),
			@('Credentials Relay - LDAP Server','HKLM\System\CurrentControlSet\Services\NTDS\Parameters','LDAPClientIntegrity',2),
			@('Credentials Relay - LDAP Server','HKLM\System\CurrentControlSet\Services\NTDS\Parameters','LdapEnforceChannelBinding',2),
			@('Credentials Relay - SMB Client - WinNT4 SP3+','HKLM\System\CurrentControlSet\Services\Rdr\Parameters','EnableSecuritySignature',1),
			@('Credentials Relay - SMB Client - WinNT4 SP3+','HKLM\System\CurrentControlSet\Services\Rdr\Parameters','RequireSecuritySignature',1),
			@('Credentials Relay - SMB Client','HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters','EnablePlainTextPassword',0),
			@('Credentials Relay - SMB Client','HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters','EnableSecuritySignature',1),
			@('Credentials Relay - SMB Client','HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters','RequireSecuritySignature',1),
			@('Credentials Relay - SMB Client','HKLM\System\CurrentControlSet\Services\Netlogon\Parameters','RequireSignOrSeal',1),
			@('Credentials Relay - SMB Client','HKLM\System\CurrentControlSet\Services\Netlogon\Parameters','SealSecureChannel',1),
			@('Credentials Relay - SMB Client','HKLM\System\CurrentControlSet\Services\Netlogon\Parameters','SignSecureChannel',1),
			@('Credentials Relay - SMB Server','HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','EnableSecuritySignature',1),
			@('Credentials Relay - SMB Server','HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RequireSecuritySignature',1),
			@('Credentials Relay - WebClient redirector for SharePoint','HKLM\SYSTEM\CurrentControlSet\Services\WebClient','Start',4),
			@('Lateral movement - LAPS Legacy - Debug','HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}', 'ExtensionDebugLevel', 2),
			@('Lateral movement - LAPS Legacy','HKLM\Software\Policies\Microsoft Services\AdmPwd', 'AdmPwdEnabled', 1),
			@('Lateral movement - LAPS Legacy','HKLM\Software\Policies\Microsoft Services\AdmPwd', 'PasswordAgeDays', 30),
			@('Lateral movement - LAPS Legacy','HKLM\Software\Policies\Microsoft Services\AdmPwd', 'PasswordComplexity', 4),
			@('Lateral movement - LAPS Legacy','HKLM\Software\Policies\Microsoft Services\AdmPwd', 'PasswordLength', 20),
			@('Lateral movement - LAPS Legacy','HKLM\Software\Policies\Microsoft Services\AdmPwd', 'PwdExpirationProtectionEnabled', 1),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'ADBackupDSRMPassword', 1),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'ADPasswordEncryptionEnabled', 0),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'BackupDirectory', 2),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'PasswordAgeDays', 30),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'PasswordComplexity', 4),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'PasswordLength', 20),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'PostAuthenticationActions', 3),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'PostAuthenticationResetDelay', 6),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'ADBackupDSRMPassword', 1),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'ADPasswordEncryptionEnabled', 0),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'BackupDirectory', 2),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PasswordAgeDays', 30),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PasswordComplexity', 4),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PasswordLength', 20),
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PostAuthenticationActions', 3),	
			@('Lateral movement - LAPS v2','HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PostAuthenticationResetDelay', 6),
			@('Lateral movement - SMB Server','HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer','Start',4),
			@('OutDated Protocol - SMB Server','HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','SMB1',0),
			@('PrivEsc - Drivers auto install','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer', 'DisableCoInstallers', 1),
			@('PrivEsc - Spooler','HKLM\SYSTEM\CurrentControlSet\Services\Spooler','Start',4),
			@('PrivEsc - WSUS Client','HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate','WUServer',''),
			@('PrivEsc - WSUS Client','HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','UseWUServer',1),
			@('RDP Server','HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','DeleteTempDirsOnExit',1),
			@('RDP Server','HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','MinEncryptionLevel',1),
			@('RDP Server','HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','SecurityLayer',2),
			@('RDP Server','HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','UserAuthentication',1),
			@('RDP Server','HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','fEncryptRPCTraffic',1),
			@('SMB Server - C$','HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','AutoShareServer',0),
			@('SMB Server - C$','HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','AutoShareWks',0),
			@('SSL - Web Client','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings', 'SecureProtocols', 10752),
			@('SSL - Web Client','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp', 'DefaultSecureProtocols', 10752),
			@('SSL - Web Client','HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp', 'DefaultSecureProtocols', 10752),
			@('SSL - Web Client','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client', 'DisabledByDefault', 1),
			@('SSL - Web Client','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client', 'Enabled', 0),
			@('SSL - Web Client','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client', 'DisabledByDefault', 1),
			@('SSL - Web Client','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client', 'Enabled', 0),
			@('SSL - Web Client','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client', 'DisabledByDefault', 0),
			@('SSL - Web Client','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client', 'Enabled', 1),
			@('SSL - Web Client','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client', 'DisabledByDefault', 0),
			@('SSL - Web Client','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client', 'Enabled', 1),
			@('SSL - Web Server','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server', 'DisabledByDefault', 1),
			@('SSL - Web Server','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server', 'Enabled', 0),
			@('SSL - Web Server','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server', 'DisabledByDefault', 1),
			@('SSL - Web Server','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server', 'Enabled', 0),
			@('SSL - Web Server','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server', 'DisabledByDefault', 0),
			@('SSL - Web Server','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server', 'Enabled', 1),
			@('SSL - Web Server','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server', 'DisabledByDefault', 0),
			@('SSL - Web Server','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server', 'Enabled', 1),
			@('UseLess App','HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager','Start',4),
			@('UseLess App','HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave','Start',4),
			@('UseLess App','HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc','Start',4),
			@('UseLess App','HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc','Start',4),
			@('WinRM Client','HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowBasic', 0),
			@('WinRM Client','HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowDigest', 0),
			@('WinRM Client','HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowKerberos', 1),
			@('WinRM Client','HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowNegotiate', 0),
			@('WinRM Client','HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'CbtHardeningLevel', 'Strict'),
			@('WinRM Server','HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowBasic', 0),
			@('WinRM Server','HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowDigest', 0),
			@('WinRM Server','HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowKerberos', 1),
			@('WinRM Server','HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowNegotiate', 0),
			@('WinRM Server','HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'CbtHardeningLevel', 'Strict')
		) | %{
			$row = $ColumnsList | Select *
			$desc=$_[0]
			$path=$_[1]
			$key=$_[2]
			$row.Key = "$desc | $path\$key"
			$row.Expected = $_[3]
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
		$ret += @($ColumnsList | Select * | %{ $_.Key='wmi-repository-status'; $_.Value=$data; $_.Expected='N/A'; $_.Compliant='N/A'; $_ })
		$wmiRepoSize = (Get-ChildItem -Path $env:windir\System32\Wbem\Repository | Measure-Object -Property Length -Sum).Sum
		$ret += @($ColumnsList | Select * | %{ $_.Key='wmi-repository-size'; $_.Value=$wmiRepoSize/1024/1024/1024; $_.Expected='<1'; $_.Compliant=$_.Value -lt 1.0; $_ })
		if( $row_LASTEXITCODE -eq 0 -and $wmiRepoSize -lt 1*1024*1024*1024 ){
			$row = $ColumnsList | Select * | %{ $_.Key="Has SCCM NAA ClearText Password"; $_.Expected=$false; $_ }
			try {
				$naa = Get-WmiObject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount" -ErrorAction Stop
				$row.Value = $naa.NetworkAccessPassword.Length -gt 0			
			}catch{
				$row.Value = $false
			}
			$row.Compliant = $row.Value -eq $row.Expected
			$ret += @($row)
			#
			$ret += @($ColumnsList | Select * | %{$_.Key="SyslogRefreshDate"; $_.Value=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			#
			$tmp = Get-WmiObject Win32_OperatingSystem
			$ret += @($ColumnsList | Select * | %{$_.Key="SystemDirectory"; $_.Value=$tmp.SystemDirectory; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Organization"; $_.Value=$tmp.Organization; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="BuildNumber"; $_.Value=$tmp.BuildNumber; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="RegisteredUser"; $_.Value=$tmp.RegisteredUser; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="SerialNumber"; $_.Value=$tmp.SerialNumber; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Version"; $_.Value=$tmp.Version; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
		}
		try{
			$tpm = Get-TPM
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-Present"; $_.Value=$tpm.TpmPresent; $_.Expected=$true; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-Ready"; $_.Value=$tpm.TpmReady; $_.Expected=$true; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-Enabled"; $_.Value=$tpm.TpmEnabled; $_.Expected=$true; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-Activated"; $_.Value=$tpm.TpmActivated; $_.Expected=$true; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-Owned"; $_.Value=$tpm.TpmOwned; $_.Expected=$true; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-RestartPending"; $_.Value=$tpm.RestartPending; $_.Expected=$false; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-ManufacturerId"; $_.Value=$tpm.ManufacturerId; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-ManufacturerId"; $_.Value=$tpm.ManufacturerId; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-ManufacturerIdTxt"; $_.Value=$tpm.ManufacturerIdTxt; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-ManufacturerVersion"; $_.Value=$tpm.ManufacturerVersion; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-ManufacturerVersionFull20"; $_.Value=$tpm.ManufacturerVersionFull20; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-OwnerAuth"; $_.Value=$tpm.OwnerAuth; $_.Expected=$true; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-OwnerClearDisabled"; $_.Value=$tpm.OwnerClearDisabled; $_.Expected=$true; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-ManagedAuthLevel"; $_.Value=$tpm.ManagedAuthLevel; $_.Expected="Full"; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-AutoProvisioning"; $_.Value=$tpm.AutoProvisioning; $_.Expected="Enabled"; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-LockedOut"; $_.Value=$tpm.LockedOut; $_.Expected=$false; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-LockoutHealTime"; $_.Value=$tpm.LockoutHealTime; $_.Expected="2 hours"; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-LockoutCount"; $_.Value=$tpm.LockoutCount; $_.Expected=0; $_.Compliant=$_.Expected -eq $_.Value; $_})
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-LockoutMax"; $_.Value=$tpm.LockoutMax; $_.Expected=5; $_.Compliant=$_.Expected -eq $_.Value; $_})
		}catch{
			$err = $_.Exception.Message
			$ret += @($ColumnsList | Select * | %{$_.Key="Tpm-Present"; $_.Value=$err; $_.Expected=$true; $_.Compliant=$_.Expected -eq $_.Value; $_.Error=$err; $_})
		}
		try{
			Get-BitLockerVolume | %{
				$bitlocker=$_
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-MountPoint"; $_.Value=$bitlocker.MountPoint; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-EncryptionMethod_"+$bitlocker.MountPoint; $_.Value=$bitlocker.EncryptionMethod; $_.Expected="XtsAes256"; $_.Compliant=$_.Value -eq $_.Expected; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-AutoUnlockEnabled_"+$bitlocker.MountPoint; $_.Value=$bitlocker.AutoUnlockEnabled; $_.Expected=$false; $_.Compliant=$_.Value -eq $_.Expected; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-AutoUnlockKeyStored_"+$bitlocker.MountPoint; $_.Value=$bitlocker.AutoUnlockKeyStored; $_.Expected=$false; $_.Compliant=$_.Value -eq $_.Expected; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-VolumeStatus_"+$bitlocker.MountPoint; $_.Value=$bitlocker.VolumeStatus; $_.Expected="FullyEncrypted"; $_.Compliant=$_.Value -eq $_.Expected; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-ProtectionStatus_"+$bitlocker.MountPoint; $_.Value=$bitlocker.ProtectionStatus; $_.Expected="On"; $_.Compliant=$_.Value -eq $_.Expected; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-LockStatus_"+$bitlocker.MountPoint; $_.Value=$bitlocker.LockStatus; $_.Expected="Unlocked"; $_.Compliant=$_.Value -eq $_.Expected; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-EncryptionPercentage_"+$bitlocker.MountPoint; $_.Value=$bitlocker.EncryptionPercentage; $_.Expected=100; $_.Compliant=$_.Value -eq $_.Expected; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-WipePercentage_"+$bitlocker.MountPoint; $_.Value=$bitlocker.WipePercentage; $_.Expected=0; $_.Compliant=$_.Value -eq $_.Expected; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-VolumeType_"+$bitlocker.MountPoint; $_.Value=$bitlocker.VolumeType; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-CapacityGB_"+$bitlocker.MountPoint; $_.Value=$bitlocker.CapacityGB; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
				$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-KeyProtector_"+$bitlocker.MountPoint; $_.Value=$bitlocker.KeyProtector -Join ','; $_.Expected="N/A"; $_.Compliant="N/A"; $_})
			}
			$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-Supported"; $_.Value=$true; $_.Expected=$true; $_.Compliant=$_.Expected -eq $_.Value; $_})
		}catch{
			$err = $_.Exception.Message
			$ret += @($ColumnsList | Select * | %{$_.Key="BitLocker-Supported"; $_.Value=$err; $_.Expected=$true; $_.Compliant=$_.Expected -eq $_.Value; $_.Error=$err; $_})
		}
		return $ret
	}
}
runTest @param


###############################################################################
# List local users
$param = @{
	Name="List local users";
	Output="LocalUsers";
	ErrorMessage="Get-LocalUser not supported";
	ColumnsList=1 | Select Name,SID,AccountExpires,Enabled,PasswordChangeableDate,PasswordExpires,UserMayChangePassword,PasswordRequired,PasswordLastSet,LastLogon;
	InlineCode={
		param($ColumnsList)
		return Get-LocalUser -ErrorAction Stop | Select Name,SID,AccountExpires,Enabled,PasswordChangeableDate,PasswordExpires,UserMayChangePassword,PasswordRequired,PasswordLastSet,LastLogon
	}
}
runTest @param


###############################################################################
# List local groups
$param = @{
	Name="List local group members";
	Output="LocalGroups";
	ErrorMessage=">Get-WmiObject win32_group< not supported";
	ColumnsList=1 | Select Name,SID,Caption,LocalAccount,Member;
	InlineCode={
		param($ColumnsList)
		$ret = @()
		Get-WmiObject win32_group -filter "Domain='$hostname'" -ErrorAction Stop | %{
			$row = $ColumnsList | Select *
			$row.Name = $_.Name
			$row.SID = $_.SID
			$row.Caption = $_.Caption.Split('\')[1]
			$row.LocalAccount = $_.LocalAccount
			$row.Member = '(Empty)'
			$members = $_.GetRelated("Win32_Account", "Win32_GroupUser", "", "", "PartComponent", "GroupComponent", $false, $null) | %{
				$tmp = $_.ToString().Split("=");
				$dom = $tmp[1].Split('"')[1];
				$name = $tmp[2].Split('"')[1];
				$row.Member = $dom+"\"+$name
				$ret += @($row | select *)
				$_
			}
			if( $members.Count -eq 0 ){
				$ret += @($row | select *)
			}
		}
		return $ret
	}
}
runTest @param


###############################################################################
# List ScheduledTask
function SerializeWMIObject
{
	Param( [Parameter(Mandatory = $true, ValueFromPipeline = $true)] $WMI )
	if( $WMI -eq $null -or $WMI.Count -eq 0 ){
		return @()
	}
	return $WMI | %{
		$ret = 1 | Select __IGNORE
		$_.Properties | Select Name,Value,Type | ?{$_.Value -ne $null} | %{
			$r = $_
			if( $r.Type -eq 'Object' ){
				$ret = $ret | Select *,@{n=$r.Name;e={ SerializeWMIObject -WMI $r.Value }}
			}else{			
				if( -not $r.Name.StartsWith('_') ){
					$ret = $ret | Select *,@{n=$r.Name;e={$r.Value}}
				}
			}
		}
		return $ret | Select -ExcludeProperty __IGNORE * 
	}	
}

$param = @{
	Name="List ScheduledTask";
	Output="ScheduledTasks";
	ErrorMessage=">schtasks< not supported";
	ColumnsList=1 | Select URI,Author,Date,LogonType,State,UserId,Actions,Triggers,LastRunTime,LastTaskResult,NextRunTime,NumberOfMissedRuns;
	InlineCode={
		param($ColumnsList)
		Get-WmiObject -Namespace "Root\Microsoft\Windows\TaskScheduler" -Query "Select * from MSFT_ScheduledTask" | %{
			if( $_.Actions -ne $null -and $_.Actions.Count -gt 0 ){
				$actions = (SerializeWMIObject $_.Actions | ConvertTo-Json -Compress).Replace('"',"'")
			}else{
				$actions = '[]'
			}
			if( $_.Triggers -ne $null -and $_.Triggers.Count -gt 0 ){
				$triggers = (SerializeWMIObject $_.Triggers | ConvertTo-Json -Compress).Replace('"',"'")
			}else{
				$triggers = '[]'
			}
			
			$row = $_ | Select URI,Author,Date,
				@{n="LogonType";e={
					switch($_.Principal.LogonType){
						0 {'None'}
						1 {'Hardcoded Password'}
						2 {'Service 4 Users'}
						3 {'Interactive (User Must be logged in)'}
						4 {'Group'}
						5 {'Local Service/System or Network Service'}
						6 {'Interactive Token then Try Password'}
					}
				}},
				@{n="State";e={if( $_.State -eq 1 ){'Disabled'}else{'Enabled'}}},
				@{n="UserId";e={$_.Principal.UserId}},
				@{n="Actions";e={$actions}},
				@{n="Triggers";e={$triggers}},
				@{n="LastRunTime";e={"?"}},
				@{n="LastTaskResult";e={"?"}},
				@{n="NextRunTime";e={"?"}},
				@{n="NumberOfMissedRuns";e={"?"}}
			try{
				$info = Get-ScheduledTaskInfo -ErrorAction Stop -TaskName $_.TaskName -TaskPath $_.TaskPath
				$row.LastRunTime = $info.LastRunTime
				$row.LastTaskResult = $info.LastTaskResult
				$row.NextRunTime = $info.NextRunTime
				$row.NumberOfMissedRuns = $info.NumberOfMissedRuns
			}catch{}
			if( $row.Actions -ne $null -and $row.Actions.Count -gt 0 ){
				$row
			}
		}
	}
}
runTest @param


###############################################################################
# List RDP Sessions
$param = @{
	Name="List RDP Sessions";
	Output="RDPSessions";
	ErrorMessage=">schtasks< not supported";
	ColumnsList=1 | Select User,SessionID,Status;
	InlineCode={
		param($ColumnsList)
		$qwinsta = qwinsta 2>&1
		if( $LASTEXITCODE -eq 0 ){
			return $qwinsta | foreach {
				if ($_ -NotMatch "services|console" -and $_ -match "Disc|Active|Acti|Déco") {
					$session = $($_ -Replace ' {2,}', ',').split(',')
					$ColumnsList | select HostName,@{n="User";e={$session[1]}}, @{n="SessionID";e={$session[2]}}, @{n="Status";e={$session[3]}},Error
				}
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
	ColumnsList=1 | Select DisplayName,Direction,DisplayGroup,Profile,Action,PolicyStoreSourceType,PolicyStoreSource,Protocol,LocalPort,RemotePort,RemoteAddress;
	InlineCode={
		param($ColumnsList)
		return Get-NetFirewallRule -ErrorAction Stop -PolicyStore ActiveStore | where {$_.Enabled -eq $true } | sort Direction,Action | Select DisplayName,Direction,DisplayGroup,Profile,Action,PolicyStoreSourceType,PolicyStoreSource,
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
	ColumnsList=1 | Select Name,Profile,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules,AllowUserApps,AllowUserPorts,AllowUnicastResponseToMulticast,NotifyOnListen,EnableStealthModeForIPsec,LogMaxSizeKilobytes,LogAllowed,LogBlocked,LogIgnored,Caption,Description,ElementName,InstanceID,DisabledInterfaceAliases,LogFileName;
	InlineCode={
		param($ColumnsList)
		return Get-NetFirewallProfile -ErrorAction Stop | select Name,Profile,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules,AllowUserApps,AllowUserPorts,AllowUnicastResponseToMulticast,NotifyOnListen,EnableStealthModeForIPsec,LogMaxSizeKilobytes,LogAllowed,LogBlocked,LogIgnored,Caption,Description,ElementName,InstanceID,@{n="DisabledInterfaceAliases";e={$_.DisabledInterfaceAliases -join ','}},LogFileName
	}
}
runTest @param


###############################################################################
# List Process
$param = @{
	Name="List Process";
	Output="Process";
	ErrorMessage=">Get-Process< not supported";
	ColumnsList=1 | Select OwnerDomain,Owner,UserSID,IsLocalUser,ProcessId,CommandLine,Description,Name,SessionId,CreationDate;
	InlineCode={
 		param($ColumnsList)
		try{			
			return Get-Process -IncludeUserName -ErrorAction Stop | Select @{n="OwnerDomain";e={try{$_.UserName.split('\')[0]}catch{$_.UserName}}},
				@{n="Owner";e={try{$_.UserName.split('\')[1]}catch{$_.UserName}}},
				@{n="UserSID";e={try{(New-Object Security.Principal.NTAccount($_.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value}catch{'S-0-0-0'}}},
				IsLocalUser,
				@{n="ProcessId";e={$_.Id}},
				@{n="CommandLine";e={$_.Path}},
				@{n="Description";e={$_.Description}},
				@{n="Name";e={$_.Name}},
				@{n="SessionId";e={$_.SessionId}},
				@{n="CreationDate";e={$_.StartTime}} | Select OwnerDomain,Owner,UserSID,@{n="IsLocalUser";e={($_.UserSID.Length -le 12) -or ($_.OwnerDomain -eq $env:computername)}},ProcessId,CommandLine,Description,Name,SessionId,CreationDate
		}catch{
			logMsg -EntryType Error -Event 4 -Message "List Process - Unable to run >Get-Process -IncludeUserName< | Err: $($_.Exception.Message) | Using failover with WMI"
			
			return Get-WmiObject Win32_Process -ErrorAction Stop | %{
				$row = $_ | Select OwnerDomain,
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
			} | Select OwnerDomain,Owner,UserSID,@{n="IsLocalUser";e={($_.UserSID.Length -le 12) -or ($_.OwnerDomain -eq $env:computername)}},ProcessId,CommandLine,Description,Name,SessionId,CreationDate
		}
	}
}
runTest @param


###############################################################################
# List Firewall Profiles
$param = @{
	Name="List local share";
	Output="SmbShares";
	ErrorMessage=">Get-SmbShare< not supported";
	ColumnsList=1 | Select Name,Path,Description,CurrentUsers,CompressData,EncryptData,'Type',IdentityReference,FileSystemRights,AccessControlType;
	InlineCode={
		param($ColumnsList)
		if( $(Get-Service lanmanserver).Status -eq 'Stopped' ) {
			return @($ColumnsList | Select * | %{ $_.Error="Service Stopped"; $_ })
		}
		$data = @()
		Get-SmbShare -ErrorAction Stop | %{
			$cRow = $_
			try{
				$cRow.PresetPathAcl.Access | %{
					$acl = $_
					$row = $cRow | select Name,Path,Description,CurrentUsers,CompressData,EncryptData,
						@{n="Type";e={"SMB ACL"}},
						@{n="IdentityReference";e={$acl.IdentityReference}},
						@{n="FileSystemRights";e={$acl.FileSystemRights}},
						@{n="AccessControlType";e={$acl.AccessControlType}}
					$data += @($row)
				}
			}catch{}
			
			try{
				$acl = Get-Acl $cRow.Path
				$row = $cRow | select Name,Path,Description,CurrentUsers,CompressData,EncryptData,
					@{n="Type";e={"PATH ACL"}},
					@{n="IdentityReference";e={$acl.Owner}},
					@{n="FileSystemRights";e={"Owner"}},
					@{n="AccessControlType";e={"Owner"}}
				$data += @($row)
				$acl | select -ExpandProperty Access | %{		
					$pacl = $_
					$row = $cRow | select Name,Path,Description,CurrentUsers,CompressData,EncryptData,
						@{n="Type";e={"PATH ACL"}},
						@{n="IdentityReference";e={$pacl.IdentityReference}},
						@{n="FileSystemRights";e={$pacl.FileSystemRights}},
						@{n="AccessControlType";e={$pacl.AccessControlType}}
					$data += @($row)
				}
			}catch{}
		}
		$data = $data | ?{ -not [string]::IsNullOrEmpty($_.IdentityReference) } | Sort-Object -Unique Path,Type,IdentityReference,FileSystemRights,AccessControlType
		$data = $data | %{
			if( $_.FileSystemRights -eq 268435456 ){
				$_.FileSystemRights = 'FullControl'
			}elseif( $_.FileSystemRights -eq -536805376 ){
				$_.FileSystemRights = 'Modify, Synchronize'
			}elseif( $_.FileSystemRights -eq -1610612736 ){
				$_.FileSystemRights = 'ReadAndExecute, Synchronize'
			}
			$_
		}
		return $data
	}
}
runTest @param


###############################################################################
# List local ip
$param = @{
	Name="List local ip";
	Output="IpConfig";
	ErrorMessage=">Get-WmiObject Win32_NetworkAdapterConfiguration< not supported";
	ColumnsList=1 | Select InterfaceIndex,MACAddress,IPAddress,IPSubnet,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,DNSDomain,DNSServerSearchOrder,DNSDomainSuffixSearchOrder,DomainDNSRegistrationEnabled,TcpipNetbiosOptions,WINSPrimaryServer;
	InlineCode={
		param($ColumnsList)
		return Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop | ?{ $_.IPEnabled -eq $true -and $_.IPAddress -ne $null -and $_.IPAddress.Count -ge 1 -and $_.IPAddress[0] -ne '' } | %{
			$row = $_ | Select InterfaceIndex,MACAddress,IPAddress,IPSubnet,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,DNSDomain,DNSServerSearchOrder,@{n="DNSDomainSuffixSearchOrder";e={$row.DNSDomainSuffixSearchOrder -join ","}},DomainDNSRegistrationEnabled,FullDNSRegistrationEnabled,TcpipNetbiosOptions,WINSPrimaryServer
			for( $i=0; $i -lt $_.IPAddress.Count; $i++ ){
				$ret = $row | Select *
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
	ColumnsList=1 | Select DisplayName,Name,State,UserName,InstallDate,Started,Status,ProcessId,PathName;
	InlineCode={
		param($ColumnsList)
		return Get-WmiObject -ErrorAction Stop Win32_Service | Select DisplayName,Name,State,@{n="UserName";e={$row.StartName}},InstallDate,Started,Status,ProcessId,PathName
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
	ColumnsList=1 | Select Category,Key,Value;
	InlineCode={
		param($ColumnsList)
		$tmp = "$($env:TMP)\$([guid]::NewGuid().ToString())"
		$err=SecEdit.exe /export /cfg $tmp 2>&1
		if( $LASTEXITCODE -ne 0 ){
			$err = $err -join '. '
			return @($ColumnsList | Select * | %{ $_.Error="Unable to run SecEdit.exe /export /cfg $tmp | Got error: $err"; $_ });
		}
		$lastType = ''
		$secedit = cat $tmp | % {
			if( $_.startswith('[') ){
				$lastType = $_
			}else{
				if( $lastType -ne '[Unicode]' -and $lastType -ne '[Version]' ){
					$tmprow = $_.replace(' = ',';').replace('=',';').split(';')
					$ret = $ColumnsList | Select *
					$ret.Category = $lastType
					$ret.Key = $tmprow[0].trim('"')
					$ret.Value = $tmprow[1].trim('"')
					return $ret
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
						logMsg -EntryType Error -Event 3 -Message "SecEdit - Unable to find local SID"
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
				$row = $priv | Select *;
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
	ColumnsList=1 | Select TimeCreated,Id,UserId,LevelDisplayName,FileNameBuffer,ProcessNameBuffer,Message;
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
		return Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id=3065,3066,3033,3063; StartTime=(get-date).AddHours(-1*$hoursHistory) } -ErrorAction Stop | % {
			$ret = $_ | Select TimeCreated,Id,UserId,LevelDisplayName,FileNameBuffer,ProcessNameBuffer,Message
			$xml = [xml]$_.toXML()
			$ret.FileNameBuffer = ($xml.Event.EventData.Data | ?{ $_.Name -eq 'FileNameBuffer' }).'#text'
			$ret.ProcessNameBuffer = ($xml.Event.EventData.Data | ?{ $_.Name -eq 'ProcessNameBuffer' }).'#text'
			$ret
		}
	}
}
runTest @param


###############################################################################
# List NTLMv1 auth recived from the last 24h
<#
$param = @{
	Name="List NTLMv1 auth recived from the last 24h";
	Output="Events-NTLMv1_$((Get-Date).ToString('yyyyMMddHHmmss'))";
	ErrorMessage=">Get-WinEvent< not supported";
	ColumnsList=1 | Select TimeCreated,Message,SubjectUserSid,SubjectLogonId,AuthenticationPackageName,TargetOutboundUserName,ImpersonationLevel,LogonProcessName,TargetDomainName,IpPort,IpAddress,LmPackageName,SubjectDomainName,ProcessName,TransmittedServices,ProcessId,SubjectUserName,TargetOutboundDomainName,TargetLogonId,TargetUserName,RestrictedAdminMode,LogonGuid,LogonType,TargetLinkedLogonId,VirtualAccount,TargetUserSid,ElevatedToken;
	InlineCode={
		$FilterXml = @'
			<QueryList>
				<Query Id="0" Path="security">
					<Select Path="security">
						*[System[(EventID=4624)] and TimeCreated[timediff(@SystemTime) &lt;= XXX_TIME_IN_SECONDS_XXX]]
						and
						 *[EventData[Data[@Name='LmPackageName']='NTLM V1']]
					</Select>
				</Query>
			</QueryList>
'@
		$xml = $xml.Replace('XXX_TIME_IN_SECONDS_XXX', $hoursHistory*60*60*1000)
		return Get-WinEvent -FilterXml $FilterXml -ErrorAction Stop | % {
			$h = @{}
			$h.Add("TimeCreated",$_.TimeCreated)
			([xml]$_.Toxml()).Event.EventData.Data | ForEach-Object {
				$h.Add($_.'Name',$_.'#text')
			}
			[PSCustomObject]$h
		} | Select TimeCreated,Message,SubjectUserSid,SubjectLogonId,AuthenticationPackageName,TargetOutboundUserName,ImpersonationLevel,LogonProcessName,TargetDomainName,IpPort,IpAddress,LmPackageName,SubjectDomainName,ProcessName,TransmittedServices,ProcessId,SubjectUserName,TargetOutboundDomainName,TargetLogonId,TargetUserName,RestrictedAdminMode,LogonGuid,LogonType,TargetLinkedLogonId,VirtualAccount,TargetUserSid,ElevatedToken
	}
}
runTest @param
#>


###############################################################################
# List auth recived from the last 24h
$param = @{
	Name="List auth recived from the last 24h";
	Output="Events-Auth_$((Get-Date).ToString('yyyyMMddHHmmss'))";
	ErrorMessage=">Get-WinEvent< not supported";
	ColumnsList=1 | Select TimeCreated,Message,SubjectUserSid,SubjectLogonId,AuthenticationPackageName,TargetOutboundUserName,ImpersonationLevel,LogonProcessName,TargetDomainName,IpPort,IpAddress,LmPackageName,SubjectDomainName,ProcessName,TransmittedServices,ProcessId,SubjectUserName,TargetOutboundDomainName,TargetLogonId,TargetUserName,RestrictedAdminMode,LogonGuid,LogonType,TargetLinkedLogonId,VirtualAccount,TargetUserSid,ElevatedToken;
	InlineCode={
		return Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id=4624; StartTime=(get-date).AddHours(-1*$hoursHistory) } -ErrorAction Stop | % {
			$h = @{}
			$h.Add("TimeCreated",$_.TimeCreated)
			([xml]$_.Toxml()).Event.EventData.Data | ForEach-Object {
				$h.Add($_.'Name',$_.'#text')
			}
			[PSCustomObject]$h
		} | Select TimeCreated,Message,SubjectUserSid,SubjectLogonId,AuthenticationPackageName,TargetOutboundUserName,ImpersonationLevel,LogonProcessName,TargetDomainName,IpPort,IpAddress,LmPackageName,SubjectDomainName,ProcessName,TransmittedServices,ProcessId,SubjectUserName,TargetOutboundDomainName,TargetLogonId,TargetUserName,RestrictedAdminMode,LogonGuid,LogonType,TargetLinkedLogonId,VirtualAccount,TargetUserSid,ElevatedToken
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
	ColumnsList=1 | Select TimeCreated,TargetName,Direction,ProcessId,ProcessName,Identity;
	InlineCode={
		return Get-WinEvent -ErrorAction Stop -FilterHashtable @{ LogName = 'Microsoft-Windows-NTLM/Operational'; Id=8001,8002; StartTime=(get-date).AddHours(-1*$hoursHistory) } | %{
			$row = $_
			$ret = $_ | Select TimeCreated,TargetName,Direction,ProcessID,ProcessName,Identity
			switch ($_.Id) {
				8001 {
					$ret.Direction   = 'Out'
					$ret.TargetName  = $row.Properties[0].Value
					$ret.ProcessID   = $row.Properties[3].Value
					$ret.ProcessName = $row.Properties[4].Value
					$ret.Identity    = "$($row.Properties[2].Value)\$($row.Properties[1].Value)"
					break
				}
				8002 {
					$ret.Direction   = 'In'
					$ret.TargetName  = $env:COMPUTERNAME
					$ret.ProcessID   = $row.Properties[0].Value 
					$ret.ProcessName = $row.Properties[1].Value
					$ret.Identity    ="$($row.Properties[4].Value)\$($row.Properties[3].Value)"
					break
				}
				default {}
			}
			return $ret
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
	ColumnsList=1 | Select TimeCreated,Message;
	InlineCode={
		param($ColumnsList)
		# Require
		# Set-SmbServerConfiguration -AuditSmb1Access $true
		$ret = @()
		if( $(Get-Service lanmanserver).Status -eq 'Stopped' ) {
			return @($ColumnsList | Select * | %{ $_.Error="Service Stopped"; $_ })
		}
		try{
			if( (Get-SmbServerConfiguration -ErrorAction Stop).AuditSmb1Access -eq $false ){
				return @($ColumnsList | Select * | %{ $_.Error="AuditSmb1Access is disabled" ;$_})
			}
		}catch{
			$ret += @($ColumnsList | Select * | %{ $_.Error="Unable to check if AuditSmb1Access is enabled" ;$_})
		}
		try{
			$ret += Get-WinEvent -ErrorAction Stop -FilterHashtable @{ LogName = 'Microsoft-Windows-SMBServer/Audit'; Id=3000; StartTime=(get-date).AddHours(-1*$hoursHistory) } | %{
				$row = $ColumnsList | Select *
				$row.TimeCreated = $_.TimeCreated
				$row.Message = $_.Message
				return $row
			}
		}catch{
			$err = "List SMBv1 connection in from the last 24h - >Get-WinEvent< not supported | Err: $($_.Exception.Message)"
			logMsg -EntryType Error -Event 3 -Message $err
			$ret += @($ColumnsList | Select * | %{ $_.Error=$err; $_ })
		}
		return $ret
	}
}
runTest @param


###############################################################################
# List local Software
$param = @{
	Name="List local Software";
	Output="Softwares";
	ErrorMessage=">Get-ItemProperty< not supported";
	ColumnsList=1 | Select DisplayName,Version,DisplayVersion,InstallDate,InstallLocation;
	InlineCode={
		return Get-ItemProperty -ErrorAction Stop HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,Version,DisplayVersion,InstallDate,InstallLocation
	}
}
runTest @param


###############################################################################
###############################################################################
###############################################################################


# Delete files older than the $maxLogPowershellHistory.
Get-ChildItem -ErrorAction SilentlyContinue -Path $logFolder -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $maxLogPowershellHistory } | Remove-Item -ErrorAction Continue -Force

# Log the activity
Stop-Transcript > $null


# Test if ALCs on destination are OK
try {
	ls "$syslogStorage" -ErrorAction Stop > $null	
	logMsg -EntryType Warning -Event 3 -Message "The user $($env:USERNAME) is allowed to list files in $syslogStorage"
}catch{}
try {
	cat "$syslogStorage\Configuration_${hostname}.csv" -ErrorAction Stop > $null
	logMsg -EntryType Warning -Event 3 -Message "The user $($env:USERNAME) is allowed to read files in $syslogStorage"
}catch{}
