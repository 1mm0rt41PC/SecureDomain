Import-Module 'config.ps1'
Import-Module 'Function_New-GPOSchTask.ps1'
Import-Module 'Function_FWRule.ps1'


###############################################################################
# Basic configuration
$IP_SRV   = $IP_AD
$ComputerName   = 'DC-SRV01'

###############################################################################
# AD-SRV01
Rename-Computer -NewName $ComputerName
New-NetIPAddress -IPAddress $IP_AD -DefaultGateway $IP_GATEWAY -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex
netsh interface ipv4 set address name="$((Get-NetAdapter).Name)" static $IP_AD 255.255.255.0 $IP_GATEWAY
netsh interface ipv4 set dns name="$((Get-NetAdapter).Name)" static 8.8.8.8
#netsh interface ipv4 set address name="$((Get-NetAdapter).Name)" source=dhcp
#Set-DNSClientServerAddress –InterfaceIndex (Get-NetAdapter).InterfaceIndex –ServerAddresses $IP_DNS
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName $domain -DomainNetBIOSName $domain_netbios -InstallDNS:$true -DomainMode WinThreshold -ForestMode WinThreshold -Force:$true
Import-Module ActiveDirectory
Enable-ADOptionalFeature -Identity "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$LDAP_DN" -Scope ForestOrConfigurationSet -Target "$domain"

# Password policy
$Policies= @{
	Identity=$domain;
	LockoutDuration='00:30:00';
	LockoutThreshold=5;
	LockoutObservationWindow='00:20:00';
	ComplexityEnabled=$true;
	ReversibleEncryptionEnabled=$False;
	MaxPasswordAge='180.00:00:00';
	MinPasswordLength=15;
	PasswordHistoryCount=10;
}
Set-ADDefaultDomainPasswordPolicy @Policies


###############################################################################
# GPO creator for registry
function GPO_reg( $gpoName, $param )
{
	$gpo = New-GPO -Name $gpoName
	if( $gpo -eq $null ){
		$gpo = Get-GPO -Name $gpoName
	}
	$param.Keys | foreach {
		$Key = $_
		$param[$Key].Keys | foreach {
			$ValueName = $_
			$Value = $param[$Key][$_]
			Write-Host ('Set-GPRegistryValue -Name "{0}" -Key "{1}" -ValueName "{2}" -Value "{3}" -Type DWord' -f $gpoName,$Key,$ValueName,$Value)
			$gpo | Set-GPRegistryValue -Key $key -ValueName $ValueName -Value $Value -Type DWord
		}
	}
}



###############################################################################
# Fix pingcastle A-PreWin2000Other
# DistinguishedName : CN=Accès compatible pré-Windows 2000,CN=Builtin,DC=Earth,DC=lo
# GroupCategory	 : Security
# GroupScope		: DomainLocal
# Name			  : Accès compatible pré-Windows 2000
# SamAccountName	: Accès compatible pré-Windows 2000
# SID			   : S-1-5-32-554
$preWin200 = Get-ADGroup -Filter * | where { $_.SID -eq 'S-1-5-32-554' }
$preWin200 | get-ADGroupMember | foreach { $preWin200 | Remove-ADGroupMember -Members $_.SamAccountName }


###############################################################################
# Create OU
New-ADOrganizationalUnit -Name "AllUsers" -Path "$LDAP_DN"
New-ADOrganizationalUnit -Name "__DomainAdministrators__" -Path "OU=AllUsers,$LDAP_DN"
New-ADOrganizationalUnit -Name "__LocalAdministrators__" -Path "OU=AllUsers,$LDAP_DN"
New-ADOrganizationalUnit -Name "ComputerEnrollement" -Path "OU=__LocalAdministrators__,OU=AllUsers,$LDAP_DN"
New-ADOrganizationalUnit -Name "ALL" -Path "OU=__LocalAdministrators__,OU=AllUsers,$LDAP_DN"
New-ADOrganizationalUnit -Name "DBA" -Path "OU=__LocalAdministrators__,OU=AllUsers,$LDAP_DN"
New-ADOrganizationalUnit -Name "__EXTERNAL__" -Path "OU=AllUsers,$LDAP_DN"
New-ADOrganizationalUnit -Name "__Groups__" -Path "OU=AllUsers,$LDAP_DN"
New-ADGroup -Name PRIV_DBA_ADMIN -Path "OU=AllUsers,$LDAP_DN"
New-ADGroup -Name PRIV_INTERACT_LAPTOP -Path "OU=AllUsers,$LDAP_DN"
New-ADGroup -Name PRIV_INTERACT_WORKSTATION -Path "OU=AllUsers,$LDAP_DN"
New-ADGroup -Name PRIV_LOCAL_ADM -Path "OU=AllUsers,$LDAP_DN"
New-ADGroup -Name PRIV_ENROLL_MACHINE -Path "OU=AllUsers,$LDAP_DN"
New-ADOrganizationalUnit -Name "AllComputers" -Path "$LDAP_DN"
New-ADOrganizationalUnit -Name "Laptops" -Path "OU=AllComputers,$LDAP_DN"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=AllComputers,$LDAP_DN"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=AllComputers,$LDAP_DN"
New-ADOrganizationalUnit -Name "Database" -Path "OU=Servers,OU=AllComputers,$LDAP_DN"
New-ADOrganizationalUnit -Name "DHCP" -Path "OU=Servers,OU=AllComputers,$LDAP_DN"
New-ADOrganizationalUnit -Name "DNS" -Path "OU=Servers,OU=AllComputers,$LDAP_DN"
New-ADOrganizationalUnit -Name "FileServer" -Path "OU=Servers,OU=AllComputers,$LDAP_DN"
New-ADOrganizationalUnit -Name "IIS-HTTP" -Path "OU=Servers,OU=AllComputers,$LDAP_DN"
New-ADOrganizationalUnit -Name "ServerWithJobInBackgroundWithoutOpenPort" -Path "OU=Servers,OU=AllComputers,$LDAP_DN"
New-ADOrganizationalUnit -Name "TerminalServer" -Path "OU=Servers,OU=AllComputers,$LDAP_DN"

redircmp OU=AllComputers,$LDAP_DN
redirusr OU=AllUsers,$LDAP_DN

###############################################################################
# Deploy LAPS
# Do not forget to run only these commands on the server with FSMO `SchemaMaster` => `Get-ADForest | Select-Object SchemaMaster`
if( -not (get-command choco.exe -ErrorAction SilentlyContinue) ){
	try {
		iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
	} catch {
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
		iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
	}
	set-alias -name choco -Value 'C:\ProgramData\chocolatey\bin\choco.exe'
}
# Installation of LAPS & LAPS UI on the DC
choco install laps --params='/ALL' -y
# Update the schema of the AD
Import-module AdmPwd.PS
Update-AdmPwdADSchema
# Set ACLs to set passwords in ms-Mcs-AdmPwd by SELF (computers)
Set-AdmPwdComputerSelfPermission -Identity AllComputers # <Base OU with computers>
# Create LAPS auto deployement
New-GPOSchTask -GPOName "[SD][Choco] LAPS" -TaskName "[SD][Choco] LAPS" -TaskType ImmediateTask -Command 'C:\ProgramData\chocolatey\bin\choco.exe' -CommandArguments 'install -y laps'
# One line full deploy New-GPOSchTask -GPOName "[SD][Choco] LAPS" -TaskName "[SD][Choco] LAPS" -TaskType ImmediateTask -Command "powershell.exe" -CommandArguments '-exec bypass -nop -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex; C:\ProgramData\chocolatey\bin\choco.exe install -y laps"'
# Enable local admin password management
Set-GPRegistryValue -Name "[SD][Choco] LAPS" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName "AdmPwdEnabled" -Value 1 -Type Dword
# Do not allow password expiration time longer than required by policy
Set-GPRegistryValue -Name "[SD][Choco] LAPS" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName "PwdExpirationProtectionEnabled" -Value 1 -Type Dword
# Set password policy
Set-GPRegistryValue -Name "[SD][Choco] LAPS" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName "PasswordComplexity" -Value 4 -Type Dword
Set-GPRegistryValue -Name "[SD][Choco] LAPS" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName "PasswordLength" -Value 16 -Type Dword
Set-GPRegistryValue -Name "[SD][Choco] LAPS" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName "PasswordAgeDays" -Value 30 -Type Dword
Get-GPO -Name "[SD][Choco] LAPS" | New-GPLink -target "OU=AllComputers,$LDAP_DN" -LinkEnabled Yes

New-GPO -Name "[SD] WindowsUpdate for servers" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "SetActiveHoursMaxRange" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ActiveHoursMaxRange" -Value 18 -Type DWord
	# Auto download and schedule the install
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Value 4 -Type DWord
	# Install during automatic maintenance
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AutomaticMaintenanceEnabled" -Value 1 -Type DWord
	# Scheduled install day: Every day
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallDay" -Value 0 -Type DWord
	# Install at 03:00 AM
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallTime" -Value 3 -Type DWord
	# If you have selected "4 – Auto download and schedule the install" for your scheduled install day and specified a schedule, you also have the option to limit updating to a weekly, bi-weekly or monthly occurrence, using the options below: Every week
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallEveryWeek" -Value 1 -Type DWord
	# Install updates for other Microsoft products
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AllowMUUpdateService" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AutoInstallMinorUpdates" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "IncludeRecommendedUpdates" -Value 1 -Type DWord
}
New-GPO -Name "[SD] WindowsUpdate for users" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "SetAutoRestartDeadline" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "AutoRestartDeadlinePeriodInDays" -Value 3 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "AutoRestartDeadlinePeriodInDaysForFeatureUpdates" -Value 3 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "SetComplianceDeadline" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ConfigureDeadlineForQualityUpdates" -Value 3 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ConfigureDeadlineGracePeriod" -Value 2 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ConfigureDeadlineForFeatureUpdates" -Value 3 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ConfigureDeadlineGracePeriodForFeatureUpdates" -Value 2 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ConfigureDeadlineNoAutoReboot" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "SetActiveHoursMaxRange" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ActiveHoursMaxRange" -Value 18 -Type DWord
	# Auto download and schedule the install
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Value 4 -Type DWord
	# Install during automatic maintenance
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AutomaticMaintenanceEnabled" -Value 1 -Type DWord
	# Scheduled install day: Every day
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallDay" -Value 0 -Type DWord
	# Install at 012:00 AM
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallTime" -Value 12 -Type DWord
	# If you have selected "4 – Auto download and schedule the install" for your scheduled install day and specified a schedule, you also have the option to limit updating to a weekly, bi-weekly or monthly occurrence, using the options below: Every week
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallEveryWeek" -Value 1 -Type DWord
	# Install updates for other Microsoft products
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AllowMUUpdateService" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AutoInstallMinorUpdates" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "IncludeRecommendedUpdates" -Value 1 -Type DWord
}

GPO_reg "[SD][Hardening] Machine Password Rotation" @{
	'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters'=@{
		'DisablePasswordChange'=0;
		'MaximumPasswordAge'=30;
	}
}

###################################################################################################
New-GPO -Name "[SD] Unlimited Path length" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" -ValueName "LongPathsEnabled" -Value 1 -Type Dword
}

###################################################################################################
# NTLM hardening
GPO_reg "[SD][Hardening] Network security: Restrict NTLM: Incoming/outgoing NTLM traffic" @{
	'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0'=@{
		'RestrictReceivingNTLMTraffic'=2;
		'RestrictSendingNTLMTraffic'=2;
	};
	'HKLM\System\CurrentControlSet\Control\Lsa'=@{
		'LmCompatibilityLevel'=5;# 2.3.11.7 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
		#'UseMachineId'=1;# Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM PROTECTION AGAINST COERCING/PETITPOTAM. FORCE USAGE OF KERBEROS
	};
	## 2.3.11.9 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
	#	  - 'r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> NTLMMinClientSec -> 537395200'
	## 2.3.11.10 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
	#	  - 'r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> NTLMMinServerSec -> 537395200'
	#		'Require NTLMv2 session security'	= '524288' 
	#		'Require 128-bit encryption'		= '536870912' 
	#		'Both options checked'				= '537395200'
	#'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'=@{
	#	'SupportedEncryptionTypes'=16;
	#		#DES_CBC_CRC  = '1'
	#		#DES_CBC_MD5  = '2'
	#		#RC4_HMAC_MD5 = '4'
	#		#AES128_HMAC_SHA1  = '8'
	#		#AES256_HMAC_SHA1  = '16'
	#};
}

GPO_reg "[SD][Hardening] Encryption & sign communications" @{
	'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters'=@{
		'RequireSignOrSeal'=1;# Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always
		'SealSecureChannel'=1;# Domain_member_Digitally_encrypt_secure_channel_data_when_possible
		'SignSecureChannel'=1;# Domain_member_Digitally_sign_secure_channel_data_when_possible
	};
}


###################################################################################################
# UAC hardening
New-GPO -Name "[SD][Hardening] UAC configuration" | %{
	# 2.3.17.1 UAC - Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "FilterAdministratorToken" -Value 1 -Type DWord
	# 18.3.1 Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
	# 0=This value builds a filtered token. It's the default value. The administrator credentials are removed.
	# 1=This value builds an elevated token.
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord
}

###################################################################################################
# LDAP client
# 2.3.11.8 Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
New-GPO -Name "[SD][Hardening] LDAP client configuration" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\System\CurrentControlSet\Services\LDAP" -ValueName "LDAPClientIntegrity" -Value 2 -Type DWord
}


###################################################################################################
# LDAP Server
GPO_reg "[SD][Hardening] LDAP server configuration" @{
	'HKLM\System\CurrentControlSet\Services\NTDS\Parameters'=@{
		'LDAPServerIntegrity'=2;# Domain controller LDAP server signing requirements
		'LdapEnforceChannelBinding'=2;# 18.3.5 (L1) Ensure 'Extended Protection for LDAP Authentication (Domain Controllers only)' is set to 'Enabled: Enabled, always (recommended)' (DC Only) (Scored)
	};
}

###################################################################################################
GPO_reg "[SD][PasswordPolicy] Prompt user to change password before expiration 1 day before" @{
	'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'=@{
		'PasswordExpiryWarning'=1;
	};
}
GPO_reg "[SD][Hardening] Auto lock session after 15min" @{
	'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System'=@{
		'InactivityTimeoutSecs'=900;# 2.3.7.3 Interactive logon: Machine inactivity limit (Scored)
	};
}

###################################################################################################
New-GPO -Name "[SD][Hardening] LSASS Protection (Mimikatz)" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "UseLogonCredential" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "Negotiate" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Control\LSA" -ValueName "RunAsPPL" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Control\LSA" -ValueName "DisableRestrictedAdmin" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Control\LSA" -ValueName "DisableRestrictedAdminOutboundCreds" -Value 1 -Type DWord
}

###################################################################################################
# Block CobaltStrike from using \\evil.kali\tmp$\becon.exe
New-GPO -Name "[SD][Hardening] Deny anonymous SMB (Block CobaltStrike from using \\evil.kali\tmp$\becon.exe)" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "AllowInsecureGuestAuth" -Value 0 -Type DWord
}

###################################################################################################
# Harden Wifi
New-GPO -Name "[SD][Hardening] WIFI-Protection" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DontDisplayNetworkSelectionUI" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -ValueName "value" -Value 0 -Type DWord
}

###################################################################################################
# Disable print spooler
New-GPO -Name "[SD][Hardening] Disable print spooler" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" -ValueName "Start" -Value 4 -Type DWord
}

###################################################################################################
# LogSystem
$inf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic=4,2
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain=4,7
'@
New-GPO -Name "[SD] LogSystem" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ValueName "EnableModuleLogging" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "EnableTranscripting" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "EnableInvocationHeader" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "OutputDirectory" -Value "C:\Windows\Powershell.log" -Type ExpandString
	$_ | Set-GPRegistryValue -Key "HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcp-Client/Operational" -ValueName "Enabled" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcpv6-Client/Operational" -ValueName "Enabled" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" -ValueName "Enabled" -Value 1 -Type DWord

	# Audit incoming NTLM traffic: Enable auditing for all accounts
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "AuditReceivingNTLMTraffic" -Value 2 -Type DWord
	# Audit NTLM Authentication in this domain: Enable all
	$_ | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" -ValueName AuditNTLMInDomain -Value 7 -Type DWord
	
	$id = $_.Id.ToString()
	mkdir "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit"
	$inf > "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
}

###################################################################################################
# RDP hardening
GPO_reg "[SD][Hardening] RDP server configuration" @{
	'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'=@{
		'KeepAliveInterval'=1;
		# 18.9.59.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled' (Scored)
		'DeleteTempDirsOnExit'=1;
		# 18.9.59.3.9.3 (L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL' (Scored)
		'SecurityLayer'=2;
		# Require user authentication for remote connections by using Network Level Authentication
		'UserAuthentication'=1;
		'MaxIdleTime'=900000;
		# 18.9.59.3.10.2 Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 15 minute'
		'MaxDisconnectionTime'=900000;
		'RemoteAppLogoffTimeLimit'=300000;
		# Require secure RPC communication
		'fEncryptRPCTraffic'=1;
		# 18.9.59.3.9.5 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level' (Scored)
		'MinEncryptionLevel'=3;
		# Client applications which use CredSSP will not be able to fall back to the insecure versions and services using CredSSP will not accept unpatched clients.
		'AllowEncryptionOracle'=0;
	};	
	'HKLM\System\CurrentControlSet\Control\Lsa'=@{
		# Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication
		'DisableDomainCreds'=1;
	};
}

###################################################################################################
# SMB server - FileServer
GPO_reg "[SD][Hardening] SMB server - FileServer configuration" @{
	'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'=@{
		'SMB1'=0;
		'EnableSecuritySignature'=1;
		# 2.3.9.2 Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
		'RequireSecuritySignature'=1;
		'AutoShareWks'=0;
		'AutoShareServer'=0;
		# Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session
		'AutoDisconnect'=60;
		# Network_access_Shares_that_can_be_accessed_anonymously
		'RestrictNullSessAccess'=1;
	};
	'HKLM\System\CurrentControlSet\Services\Rdr\Parameters'=@{
		'EnableSecuritySignature'=1;
		'RequireSecuritySignature'=1;
	};
	'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'=@{
		'AllowInsecureGuestAuth'=0;
	}
}


###################################################################################################
# SMB client
New-GPO -Name "[SD][Hardening] SMB client configuration" | %{
	# 2.3.8.2 Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
	$_ | Set-GPRegistryValue -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "EnableSecuritySignature" -Value 1 -Type DWord
	# Microsoft_network_client_Digitally_sign_communications_always
	$_ | Set-GPRegistryValue -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Value 1 -Type DWord
	# Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers
	$_ | Set-GPRegistryValue -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "EnablePlainTextPassword" -Value 0 -Type DWord
}

###################################################################################################
New-GPO -Name "[SD][Hardening] Bitlocker" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\FVE" -ValueName "ActiveDirectoryBackup" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\FVE" -ValueName "RequireActiveDirectoryBackup" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\FVE" -ValueName "ActiveDirectoryInfoToStore" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\FVE" -ValueName "EncryptionMethodWithXtsOs" -Value 7 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\FVE" -ValueName "EncryptionMethodWithXtsFdv" -Value 7 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\FVE" -ValueName "EncryptionMethodWithXtsRdv" -Value 7 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\FVE" -ValueName "EncryptionMethodNoDiffuser" -Value 4 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\FVE" -ValueName "EncryptionMethod" -Value 2 -Type DWord
}

###################################################################################################
New-GPO -Name "[SD] Windows defender" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -ValueName "ASSignatureDue" -Value 2 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -ValueName "AVSignatureDue" -Value 2 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -ValueName "DisableUpdateOnStartupWithoutEngine" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -ValueName "ForceUpdateFromMU" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -ValueName "RealtimeSignatureDelivery" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -ValueName "ScheduleDay" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -ValueName "SignatureUpdateInterval" -Value 12 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -ValueName "UpdateOnStartUp" -Value 1 -Type DWord

	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender" -ValueName "DisableRoutinelyTakingAction" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender" -ValueName "PUAProtection" -Value 1 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableBehaviorMonitoring" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableIOAVProtection" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableOnAccessProtection" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRawWriteNotification" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableScanOnRealtimeEnable" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "RealtimeScanDirection" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" -ValueName "DisableHeuristics" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" -ValueName "DisablePackedExeScanning" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -ValueName "DisableUpdateOnStartupWithoutEngine" -Value 0 -Type DWord
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "ExploitGuard_ASR_Rules" -Value 1 -Type DWord
	# Block Office applications from injecting code into other processes
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" -Type String -Value 1
	# Block Office applications from creating child processes
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" -Type String -Value 1
	# Block Win32 API calls from Office macro
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" -Type String -Value 1
	# Block Office applications from creating executable content
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "3B576869-A4EC-4529-8536-B80A7769E899" -Type String -Value 1
	# Block execution of potentially obfuscated scripts
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" -Type String -Value 1
	# Block executable content from email client and webmail
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" -Type String -Value 1
	# Block JavaScript or VBScript from launching downloaded executable content
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "D3E037E1-3EB8-44C8-A917-57927947596D" -Type String -Value 1
	# Use advanced protection against ransomware
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "C1DB55AB-C21A-4637-BB3F-A12568109D35" -Type String -Value 1
	# Block untrusted and unsigned processes that run from USB
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" -Type String -Value 1
	$_ | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -ValueName "EnableNetworkProtection" -Value 1 -Type DWord
}

###############################################################################
# Groups allowed to link new computers to the domain (PRIV_ENROLL_MACHINE)
# Version GUI https://www.danielengberg.com/domain-join-permissions-delegate-active-directory/
$UID__PRIV_ENROLL_MACHINE = (New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, "PRIV_ENROLL_MACHINE")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$inf=@"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeMachineAccountPrivilege = *$UID__PRIV_ENROLL_MACHINE
"@
New-GPO -Name "[SD][Priv] Groups allowed to link new computers to the domain (PRIV_ENROLL_MACHINE)" | %{
	$id = $_.Id.ToString()
	mkdir "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit"
	$inf > "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

}

###############################################################################
# [Priv] Allow session for groups PRIV_INTERACT_WORKSTATION,PRIV_LOCAL_ADM
# S-1-5-32-544=Local administors
$UID__PRIV_LOCAL_ADM = (New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, "PRIV_LOCAL_ADM")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$UID__PRIV_INTERACT_WORKSTATION = (New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, "PRIV_INTERACT_WORKSTATION")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$inf=@"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544,*$UID__PRIV_LOCAL_ADM,*$UID__PRIV_INTERACT_WORKSTATION
"@
New-GPO -Name "[SD][Priv] Allow session for groups PRIV_INTERACT_WORKSTATION,PRIV_LOCAL_ADM" | %{
	$id = $_.Id.ToString()
	mkdir "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit"
	$inf > "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
}

###############################################################################
# [Priv] Allow session for groups PRIV_INTERACT_LAPTOP,PRIV_LOCAL_ADM
# S-1-5-32-544=Local administors
$UID__PRIV_LOCAL_ADM = (New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, "PRIV_LOCAL_ADM")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$UID__PRIV_INTERACT_LAPTOP = (New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, "PRIV_INTERACT_LAPTOP")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$inf=@"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544,*$UID__PRIV_LOCAL_ADM,*$UID__PRIV_INTERACT_LAPTOP
"@
New-GPO -Name "[SD][Priv] Allow session for groups PRIV_INTERACT_LAPTOP,PRIV_LOCAL_ADM" | %{
	$id = $_.Id.ToString()
	mkdir "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit"
	$inf > "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
}

###############################################################################
# [Priv] Allow RDP for group PRIV_REMOTE_TS
# S-1-5-32-544=Local administors
$UID__PRIV_LOCAL_ADM = (New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, "PRIV_LOCAL_ADM")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$UID__PRIV_REMOTE_TS = (New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, "PRIV_REMOTE_TS")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$inf=@"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544,*$UID__PRIV_REMOTE_TS,*$UID__PRIV_LOCAL_ADM
SeNetworkLogonRight = *S-1-5-32-544,*$UID__PRIV_REMOTE_TS,*$UID__PRIV_LOCAL_ADM
"@
New-GPO -Name "[SD][Priv] Allow RDP for group PRIV_REMOTE_TS" | %{
	$id = $_.Id.ToString()
	mkdir "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit"
	$inf > "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
}

###############################################################################
# [Priv] AdminLocal for group PRIV_LOCAL_ADM
# S-1-5-32-544=Local administors group
# S-1-5-114=LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP
$UID__PRIV_LOCAL_ADM = (New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, "PRIV_LOCAL_ADM")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$inf=@"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Group Membership]
*S-1-5-32-544__Memberof =
*S-1-5-32-544__Members = *S-1-5-114,*$UID__PRIV_LOCAL_ADM
"@
New-GPO -Name "[SD][Priv] AdminLocal for group PRIV_LOCAL_ADM" | %{
	$id = $_.Id.ToString()
	mkdir "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit"
	$inf > "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
}

###############################################################################
# [Hardening] DomainAdmin not allowed to connect
$UID__DOMAIN = (Get-ADDomain).DomainSID.Value
$inf=@"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-32-546,*$UID__DOMAIN-514,*$UID__DOMAIN-501,*$UID__DOMAIN-512,*$UID__DOMAIN-519,admin
SeDenyInteractiveLogonRight = *$UID__DOMAIN-512,*$UID__DOMAIN-519
SeDenyServiceLogonRight = *$UID__DOMAIN-512
SeDenyBatchLogonRight = *$UID__DOMAIN-512
SeDenyRemoteInteractiveLogonRight = *$UID__DOMAIN-512
"@
New-GPO -Name "[SD][Hardening] DomainAdmin not allowed to connect" | %{
	$id = $_.Id.ToString()
	mkdir "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit"
	$inf > "C:\Windows\SYSVOL\domain\Policies\{$id}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
}



###################################################################################################
# Software library
New-GPOSchTask -GPOName "[SD][Choco] Upgrade all" -TaskName "[SD][Choco] Upgrade all" -TaskType Task -StartEveryDayAt 9 -Command 'powershell.exe' -CommandArguments @'
-exec bypass -nop -Command "if(-not [System.IO.File]::Exists('C:\ProgramData\chocolatey\bin\choco.exe')){ iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex ; gpupdate /force ; } ; C:\ProgramData\chocolatey\bin\choco.exe upgrade all -y"
'@
New-GPOSchTask -GPOName "[SD][Choco] VCredist-all" -TaskName "[SD][Choco] VCredist-all" -TaskType ImmediateTask -Command 'C:\ProgramData\chocolatey\bin\choco.exe' -CommandArguments 'install -y vcredist-all'
New-GPOSchTask -GPOName "[SD][Choco] 7zip" -TaskName "[SD][Choco] 7zip" -TaskType ImmediateTask -Command 'C:\ProgramData\chocolatey\bin\choco.exe' -CommandArguments 'install -y 7zip.install'
New-GPOSchTask -GPOName "[SD][Choco] Greenshot" -TaskName "[SD][Choco] Greenshot" -TaskType ImmediateTask -Command 'C:\ProgramData\chocolatey\bin\choco.exe' -CommandArguments 'install -y greenshot'
New-GPOSchTask -GPOName "[SD][Choco] Notepad++" -TaskName "[SD][Choco] Notepad++" -TaskType ImmediateTask -Command 'C:\ProgramData\chocolatey\bin\choco.exe' -CommandArguments 'install -y notepadplusplus.install'
New-GPOSchTask -GPOName "[SD][Choco] keepassxc" -TaskName "[SD][Choco] keepassxc" -TaskType ImmediateTask -Command 'C:\ProgramData\chocolatey\bin\choco.exe' -CommandArguments 'install -y keepassxc'
New-GPOSchTask -GPOName "[SD][Choco] git" -TaskName "[SD][Choco] git" -TaskType ImmediateTask -Command 'C:\ProgramData\chocolatey\bin\choco.exe' -CommandArguments 'install -y git'
New-GPOSchTask -GPOName "[SD][Choco] FortiClientVpn" -TaskName "[SD][Choco] FortiClientVpn" -TaskType ImmediateTask -Command 'C:\ProgramData\chocolatey\bin\choco.exe' -CommandArguments 'install -y forticlientvpn'
New-GPOSchTask -GPOName "[SD][Choco] Microsoft-Teams" -TaskName "[SD][Choco] Microsoft-Teams" -TaskType ImmediateTask -Command 'C:\ProgramData\chocolatey\bin\choco.exe' -CommandArguments 'install -y microsoft-teams.install --params "/AllUsers /NoAutoStart /ADDDESKTOPICON /ADDSTARTMENU"'

#BGInfo
[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('CwAAAEJhY2tncm91bmQABAAAAAQAAAAAAAAACQAAAFBvc2l0aW9uAAQAAAAEAAAA/gMAAAgAAABNb25pdG9yAAQAAAAEAAAAXAQAAA4AAABUYXNrYmFyQWRqdXN0AAQAAAAEAAAAAQAAAAsAAABUZXh0V2lkdGgyAAQAAAAEAAAAwHsAAAsAAABPdXRwdXRGaWxlAAEAAAASAAAAJVRlbXAlXEJHSW5mby5ibXAACQAAAERhdGFiYXNlAAEAAAABAAAAAAwAAABEYXRhYmFzZU1SVQABAAAAAgAAAAAACgAAAFdhbGxwYXBlcgABAAAAKQAAAGM6XHdpbmRvd3Ncd2ViXHdhbGxwYXBlclx0aGVtZTFcaW1nMS5qcGcADQAAAFdhbGxwYXBlclBvcwAEAAAABAAAAAIAAAAOAAAAV2FsbHBhcGVyVXNlcgAEAAAABAAAAAEAAAANAAAATWF4Q29sb3JCaXRzAAQAAAAEAAAAAAAAAAwAAABFcnJvck5vdGlmeQAEAAAABAAAAAAAAAALAAAAVXNlclNjcmVlbgAEAAAABAAAAAEAAAAMAAAATG9nb25TY3JlZW4ABAAAAAQAAAABAAAADwAAAFRlcm1pbmFsU2NyZWVuAAQAAAAEAAAAAQAAAA4AAABPcGFxdWVUZXh0Qm94AAQAAAAEAAAAAAAAAAQAAABSVEYAAQAAAAAFAAB7XHJ0ZjFcYW5zaVxhbnNpY3BnMTI1MlxkZWZmMFxub3VpY29tcGF0XGRlZmxhbmc0MTA4e1xmb250dGJse1xmMFxmbmlsXGZjaGFyc2V0MCBBcmlhbDt9fQ0Ke1xjb2xvcnRibCA7XHJlZDI1NVxncmVlbjI1NVxibHVlMjU1O30NCntcKlxnZW5lcmF0b3IgUmljaGVkMjAgMTAuMC4xNzc2M31cdmlld2tpbmQ0XHVjMSANClxwYXJkXGZpLTI4ODBcbGkyODgwXHR4Mjg4MFxjZjFcYlxmczI0IEhvc3QgTmFtZTpcdGFiXHByb3RlY3QgPEhvc3QgTmFtZT5ccHJvdGVjdDBccGFyDQpVc2VyIE5hbWU6XHRhYlxwcm90ZWN0IDxVc2VyIE5hbWU+XHByb3RlY3QwXHBhcg0KQm9vdCBUaW1lOlx0YWJccHJvdGVjdCA8Qm9vdCBUaW1lPlxwcm90ZWN0MFxwYXINClxwYXINCklQIEFkZHJlc3M6XHRhYlxwcm90ZWN0IDxJUCBBZGRyZXNzPlxwcm90ZWN0MFxwYXINClN1Ym5ldCBNYXNrOlx0YWJccHJvdGVjdCA8U3VibmV0IE1hc2s+XHByb3RlY3QwXHBhcg0KRGVmYXVsdCBHYXRld2F5Olx0YWJccHJvdGVjdCA8RGVmYXVsdCBHYXRld2F5Plxwcm90ZWN0MFxwYXINCkRIQ1AgU2VydmVyOlx0YWJccHJvdGVjdCA8REhDUCBTZXJ2ZXI+XHByb3RlY3QwXHBhcg0KRE5TIFNlcnZlcjpcdGFiXHByb3RlY3QgPEROUyBTZXJ2ZXI+XHByb3RlY3QwXHBhcg0KTUFDIEFkZHJlc3M6XHRhYlxwcm90ZWN0IDxNQUMgQWRkcmVzcz5ccHJvdGVjdDBccGFyDQpccGFyDQpGcmVlIFNwYWNlOlx0YWJccHJvdGVjdCA8RnJlZSBTcGFjZT5ccHJvdGVjdDBccGFyDQpWb2x1bWVzOlx0YWJccHJvdGVjdCA8Vm9sdW1lcz5ccHJvdGVjdDBccGFyDQpccGFyDQpMb2dvbiBEb21haW46XHRhYlxwcm90ZWN0IDxMb2dvbiBEb21haW4+XHByb3RlY3QwXHBhcg0KTG9nb24gU2VydmVyOlx0YWJccHJvdGVjdCA8TG9nb24gU2VydmVyPlxwcm90ZWN0MFxwYXINCk1hY2hpbmUgRG9tYWluOlx0YWJccHJvdGVjdCA8TWFjaGluZSBEb21haW4+XHByb3RlY3QwXHBhcg0KXHBhcg0KQ1BVOlx0YWJccHJvdGVjdCA8Q1BVPlxwcm90ZWN0MFxwYXINCk1lbW9yeTpcdGFiXHByb3RlY3QgPE1lbW9yeT5ccHJvdGVjdDBccGFyDQpPUyBWZXJzaW9uOlx0YWJccHJvdGVjdCA8T1MgVmVyc2lvbj5ccHJvdGVjdDBccGFyDQpTZXJ2aWNlIFBhY2s6XHRhYlxwcm90ZWN0IDxTZXJ2aWNlIFBhY2s+XHByb3RlY3QwXHBhcg0KU25hcHNob3QgVGltZTpcdGFiXHByb3RlY3QgPFNuYXBzaG90IFRpbWU+XHByb3RlY3QwXHBhcg0KU3lzdGVtIFR5cGU6XHRhYlxwcm90ZWN0IDxTeXN0ZW0gVHlwZT5ccHJvdGVjdDBccGFyDQp9DQoAAAsAAABVc2VyRmllbGRzAACAAIAAAAAAAQAAAAABgACAAAAAAA==')) | Out-File -Encoding ASCII "\\$($env:USERDNSDOMAIN)\SYSVOL\$($env:USERDNSDOMAIN)\scripts\bginfo.bgi"
New-GPOSchTask -GPOName "[SD][Choco] bginfo - SetWallpaper" -TaskName "[SD][Choco] bginfo" -TaskType ImmediateTask -Command 'C:\ProgramData\chocolatey\bin\choco.exe' -CommandArguments 'install -y bginfo'
New-GPOSchTask -GPOName "[SD][Choco] bginfo - SetWallpaper" -TaskName "[SD][Choco] bginfo - link" -TaskType ImmediateTask -Command 'powershell.exe' -CommandArguments @'
-exec bypass -nop -command "$f='C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\bginfo.lnk'; rm -f $f ; $Shortcut=(New-Object -ComObject WScript.Shell).CreateShortcut($f);$Shortcut.TargetPath='bginfo.exe';$Shortcut.Arguments='\\%USERDNSDOMAIN%\SYSVOL\%USERDNSDOMAIN%\scripts\bginfo.bgi /timer:0 /silent /nolicprompt';$Shortcut.Save();"
'@
Set-GPRegistryValue -Name "[SD][Choco] bginfo - SetWallpaper" -Key "HKCU\Software\Policies\Microsoft\Windows\Personalization" -ValueName "ThemeFile" -Value 'C:\Windows\Resources\Themes\theme1.theme' -Type ExpandString

New-GPOSchTask -GPOName "[SD][Hardening] Block psexec" -TaskName "[SD][Choco] Block psexec" -TaskType ImmediateTask -Command 'powershell.exe' -CommandArguments @'
-exec bypass -nop -Command "$tmp=(sc.exe sdshow scmanager).split('`r`n')[1].split(':')[1]; if( -not $tmp.Contains('(D;;GA;;;NU)') -and -not $tmp.Contains('(D;;KA;;;NU)') ){ sc.exe sdset scmanager ('D:(D;;GA;;;NU){0}' -f $tmp) ; }"
'@
New-GPOSchTask -GPOName "[SD][Hardening] Remove Administrator home folder" -TaskName "[SD][Hardening] Remove Administrator home folder" -TaskType Task -StartEveryDayAt 9 -Command 'powershell.exe' -CommandArguments @'
-exec bypass -nop -Command "if( [string]::IsNullOrEmpty( $(query user | findstr /I admini) ) ){ Get-ChildItem C:\Users\Administrat* | Remove-Item -Force -Recurse -verbose ; } ; Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21*' | foreach { if( -not (Test-Path -Path $_.GetValue('ProfileImagePath')) ){ reg.exe DELETE $_.Name /f ; } }"
'@
New-GPOSchTask -GPOName "[SD][Hardening] Reset ACL on all computers to avoid weak ACL" -TaskName "[SD][Hardening] Reset ACL on all computers to avoid weak ACL" -TaskType Task -StartEveryDayAt 9 -Command 'powershell.exe' -CommandArguments '-exec bypass -nop -Command "dsquery computer | foreach { DSACLS $_ /resetDefaultDACL | Out-Null }"'



###############################################################################
# CVE
New-GPO -Name "[SD][CVE] Fix-exploit-kerberos-samaccountname-spoofing #CVE-2021-42287 #CVE-2021-42278" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\System\CurrentControlSet\Services\Kdc" -ValueName "PacRequestorEnforcement" -Value 2 -Type DWord
}
#To find any computer accounts that have a invalid SamAccountName property use this query
# Get-ADComputer -Filter { samAccountName -notlike "*$" }

New-GPOSchTask -GPOName "[SD][CVE] Block PetitPotam" -TaskName "[SD][CVE] Block PetitPotam" -TaskType ImmediateTask -Command 'powershell.exe' -CommandArguments '-exec bypass -nop -enc JAByAHIAIAA9ACAAKABuAGUAdABzAGgAIAByAHAAYwAgAGYAaQBsAHQAZQByACAAcwBoAG8AdwAgAGYAaQBsAHQAZQByACkALgBSAGUAcABsAGEAYwBlACgAJwAgACcALAAnACcAKQAgADsADQAKAGkAZgAoACAALQBuAG8AdAAgACgAJAByAHIAIAAtAEwAaQBrAGUAIAAiACoAYwA2ADgAMQBkADQAOAA4ACoAIgAgAC0ATwByACAAJAByAHIAIAAtAEwAaQBrAGUAIAAiACoAZABmADEAOQA0ADEAYwA1ACoAIgApACAAKQB7AA0ACgBAACcADQAKAHIAcABjAA0ACgBmAGkAbAB0AGUAcgANAAoAYQBkAGQAIAByAHUAbABlACAAbABhAHkAZQByAD0AdQBtACAAYQBjAHQAaQBvAG4AdAB5AHAAZQA9AHAAZQByAG0AaQB0AA0ACgBhAGQAZAAgAGMAbwBuAGQAaQB0AGkAbwBuACAAZgBpAGUAbABkAD0AaQBmAF8AdQB1AGkAZAAgAG0AYQB0AGMAaAB0AHkAcABlAD0AZQBxAHUAYQBsACAAZABhAHQAYQA9AGMANgA4ADEAZAA0ADgAOAAtAGQAOAA1ADAALQAxADEAZAAwAC0AOABjADUAMgAtADAAMABjADAANABmAGQAOQAwAGYANwBlAA0ACgBhAGQAZAAgAGMAbwBuAGQAaQB0AGkAbwBuACAAZgBpAGUAbABkAD0AcgBlAG0AbwB0AGUAXwB1AHMAZQByAF8AdABvAGsAZQBuACAAbQBhAHQAYwBoAHQAeQBwAGUAPQBlAHEAdQBhAGwAIABkAGEAdABhAD0ARAA6ACgAQQA7ADsAQwBDADsAOwA7AEQAQQApAA0ACgBhAGQAZAAgAGYAaQBsAHQAZQByAA0ACgBhAGQAZAAgAHIAdQBsAGUAIABsAGEAeQBlAHIAPQB1AG0AIABhAGMAdABpAG8AbgB0AHkAcABlAD0AYgBsAG8AYwBrAA0ACgBhAGQAZAAgAGMAbwBuAGQAaQB0AGkAbwBuACAAZgBpAGUAbABkAD0AaQBmAF8AdQB1AGkAZAAgAG0AYQB0AGMAaAB0AHkAcABlAD0AZQBxAHUAYQBsACAAZABhAHQAYQA9AGMANgA4ADEAZAA0ADgAOAAtAGQAOAA1ADAALQAxADEAZAAwAC0AOABjADUAMgAtADAAMABjADAANABmAGQAOQAwAGYANwBlAA0ACgBhAGQAZAAgAGYAaQBsAHQAZQByAA0ACgBhAGQAZAAgAHIAdQBsAGUAIABsAGEAeQBlAHIAPQB1AG0AIABhAGMAdABpAG8AbgB0AHkAcABlAD0AcABlAHIAbQBpAHQADQAKAGEAZABkACAAYwBvAG4AZABpAHQAaQBvAG4AIABmAGkAZQBsAGQAPQBpAGYAXwB1AHUAaQBkACAAbQBhAHQAYwBoAHQAeQBwAGUAPQBlAHEAdQBhAGwAIABkAGEAdABhAD0AZABmADEAOQA0ADEAYwA1AC0AZgBlADgAOQAtADQAZQA3ADkALQBiAGYAMQAwAC0ANAA2ADMANgA1ADcAYQBjAGYANAA0AGQADQAKAGEAZABkACAAYwBvAG4AZABpAHQAaQBvAG4AIABmAGkAZQBsAGQAPQByAGUAbQBvAHQAZQBfAHUAcwBlAHIAXwB0AG8AawBlAG4AIABtAGEAdABjAGgAdAB5AHAAZQA9AGUAcQB1AGEAbAAgAGQAYQB0AGEAPQBEADoAKABBADsAOwBDAEMAOwA7ADsARABBACkADQAKAGEAZABkACAAZgBpAGwAdABlAHIADQAKAGEAZABkACAAcgB1AGwAZQAgAGwAYQB5AGUAcgA9AHUAbQAgAGEAYwB0AGkAbwBuAHQAeQBwAGUAPQBiAGwAbwBjAGsADQAKAGEAZABkACAAYwBvAG4AZABpAHQAaQBvAG4AIABmAGkAZQBsAGQAPQBpAGYAXwB1AHUAaQBkACAAbQBhAHQAYwBoAHQAeQBwAGUAPQBlAHEAdQBhAGwAIABkAGEAdABhAD0AZABmADEAOQA0ADEAYwA1AC0AZgBlADgAOQAtADQAZQA3ADkALQBiAGYAMQAwAC0ANAA2ADMANgA1ADcAYQBjAGYANAA0AGQADQAKAGEAZABkACAAZgBpAGwAdABlAHIADQAKAHEAdQBpAHQADQAKACcAQAAgAHwAIABPAHUAdAAtAEYAaQBsAGUAIAAtAEUAbgBjAG8AZABpAG4AZwAgAEEAUwBDAEkASQAgAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAcgByAC4AdAB4AHQADQAKAG4AZQB0AHMAaAAgAC0AZgAgAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAcgByAC4AdAB4AHQADQAKAHcAcgBpAHQAZQAtAEgAbwBzAHQAIAAnAFAAYQB0AGMAaABpAG4AZwAnAA0ACgB9AA0ACgB3AHIAaQB0AGUALQBIAG8AcwB0ACAAJwBQAGEAdABjAGgAZQBkACcA'


###############################################################################
# Firewall
New-GPOSchTask -GPOName "[SD][GPO] FW-ClearlocalRuleThatDoesntContain[SD]" -TaskName "[SD][GPO] FW-ClearlocalRuleThatDoesntContain[SD]" -TaskType Task -StartEveryDayAt 9 -Command 'powershell.exe' -CommandArguments @'
-exec bypass -nop -Command "@( 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules', 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System', 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules' ) | foreach { Write-Host ('Working on {0}' -f $_) ; $hive = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($_ -Replace 'HKLM\:\\', ''), $true); if( $hive -eq $null ){ continue; } ; $hive.GetValueNames() | where { -not $hive.GetValue($_).Contains(('[SD-{0}]' -f $date)) -and -not $hive.GetValue($_).Contains('[SD]') } | foreach { $v = $hive.GetValue($_) ; Write-Host ('Delete {0} => {1}' -f $_,$v) ; $hive.DeleteValue($_) ; } ; }"
'@

# Enable localfirewall
New-GPOSchTask -GPOName "[SD][FW] Enable-and-Log-ALLOW-VPN-ADMIN" -TaskName "[SD][FW] Enable-and-Log-ALLOW-VPN-ADMIN" -TaskType ImmediateTask -Command 'cmd.exe' -CommandArguments '/C "mkdir %windir%\system32\logfiles\firewall 2>NUL"'
$GpoSessionName = Open-NetGPO –PolicyStore ("{0}\[SD][FW] Enable-and-Log-ALLOW-VPN-ADMIN" -f $env:USERDNSDOMAIN)
Set-NetFirewallProfile -GPOSession $GpoSessionName -PolicyStore "[SD][FW] Enable-and-Log-ALLOW-VPN-ADMIN" -All -Enabled True -NotifyOnListen False -DefaultOutboundAction Allow -DefaultInboundAction Block -AllowInboundRules True -AllowLocalFirewallRules False -AllowLocalIPsecRules True -AllowUnicastResponseToMulticast True -LogAllowed True -LogBlocked True -LogIgnored False -LogFileName "%windir%\system32\logfiles\firewall\pfirewall.log" -LogMaxSizeKilobytes 32767
Save-NetGPO -GPOSession $GpoSessionName
FWRule @{
	GpoName='[FW] Enable-and-Log-ALLOW-VPN-ADMIN'; Action='Allow'; Direction='Inbound'; Name='VPN-AllowAll';
	Group='VPN';
	RemoteAddress=$IP_VPN_ADMIN;
}
# FORTI - [FW] VPN
$domainDontrollerList = (Get-DnsClientGlobalSetting).SuffixSearchList | foreach {
	Resolve-DnsName -Type ALL -Name _ldap._tcp.dc._msdcs.$_
} | foreach {
	$_.IP4Address
} | sort -unique
FWRule @{
	GpoName='[FW] DC-INTERCOMMUNICATION'; Action='Allow'; Direction='Inbound'; Name='DC-INTERCOMMUNICATION in';
	Group='DC-INTERCOMMUNICATION';	
	RemoteAddress=$domainDontrollerList;
}
FWRule @{
	GpoName='[FW] DC-INTERCOMMUNICATION'; Action='Allow'; Direction='Outbound'; Name='DC-INTERCOMMUNICATION out';
	Group='DC-INTERCOMMUNICATION';	
	RemoteAddress=$domainDontrollerList;
}
FWRule @{
	GpoName='[FW] DC-ALLOW-LAMBA-USER'; Action='Allow'; Direction='Inbound'; Name='USERS-ACCESS-TCP';
	Group='USERS-ACCESS';	
	Protocol='TCP';
	LocalPort=@(88,389,445,464,636,3269,3268,9389);
}
FWRule @{
	GpoName='[FW] DC-ALLOW-LAMBA-USER'; Action='Allow'; Direction='Inbound'; Name='USERS-ACCESS-UDP';
	Group='USERS-ACCESS';
	Protocol='UDP';
	LocalPort=@(123,88,389,500,2535,67,68);
}
FWRule @{
	GpoName='[FW] DC-ALLOW-LAMBA-USER'; Action='Allow'; Direction='Inbound'; Name='USERS-ACCESS-RPC';
	Group='USERS-ACCESS';
	Protocol='Any';
	LocalPort='RPC';
}
FWRule @{
	GpoName='[FW] DC-ALLOW-LAMBA-USER'; Action='Allow'; Direction='Inbound'; Name='USERS-ACCESS-RPC-EPMAP';
	Group='USERS-ACCESS';
	Protocol='Any';
	LocalPort='RPC-EPMAP';
}

# Avoir coercing
FWRule @{
	GpoName='[FW] COERCING-PROTECTION';
	Action='Allow'; Direction='Outbound'; Name='Allow all TCP except 445 to users => Block Coercing like PrintNightMare,PetitPotam,...';
	Protocol='TCP';
	RemotePort=@('0-444','446-3388','3390-65535')
}
# DNS, DHCP, SNMP, Kerberos, Time, ...
FWRule @{
	GpoName='[FW] COERCING-PROTECTION';
	Action='Allow'; Direction='Outbound'; Name='Allow all UDP output';
	Protocol='UDP';
}
# DNS, DHCP, SNMP, Kerberos, Time, ...
FWRule @{
	GpoName='[FW] COERCING-PROTECTION';
	Action='Allow'; Direction='Outbound'; Name='Allow all proto to DC for SYSVOL & Sync Cert';
	RemoteAddress=$IP_AD;
}
# HTTP
FWRule @{
	GpoName='[FW] HTTPServer 80, 443 for everybody';
	Action='Allow'; Direction='Inbound';
	Protocol='TCP';
	LocalPort=@(80,443);
}
# MsSQL
FWRule @{
	GpoName='[FW] MsSQL 1433 for everybody';
	Action='Allow'; Direction='Inbound';
	Protocol='TCP';
	LocalPort=1433;
}
# SMB
FWRule @{
	GpoName='[FW] FileServer 445 for everybody';
	Action='Allow'; Direction='Inbound';
	Protocol='TCP';
	LocalPort=445;
}
# DNS
FWRule @{
	GpoName='[FW] DNSServer 53 for everybody';
	Action='Allow'; Direction='Inbound';
	Protocol='TCP';
	LocalPort=53;
}
FWRule @{
	GpoName='[FW] DNSServer 53 for everybody';
	Action='Allow'; Direction='Inbound';
	Protocol='UDP';
	LocalPort=53;
}
# TerminalServer
FWRule @{
	GpoName='[FW] TerminalServer 3389 for everybody';
	Action='Allow'; Direction='Inbound';
	Protocol='TCP';
	LocalPort=3389;
}
# DHCPServer
FWRule @{
	GpoName='[FW] DHCPServer for everybody';
	Action='Allow'; Direction='Inbound';
	Protocol='UDP';
	LocalPort=@(67,2535);
}
# PKI / ADCS
FWRule @{
	GpoName='[FW] PKI / ADCS for everybody';
	Action='Allow'; Direction='Inbound';
	Protocol='TCP';
	LocalPort='RPCEPMap';
}
FWRule @{
	GpoName='[FW] PKI / ADCS for everybody';
	Action='Allow'; Direction='Inbound';
	Protocol='TCP';
	LocalPort='RPC';
}


FWRule @{
	GpoName='[FW] Deny Internet for old IE';
	Action='Block'; Direction='Outbound';
	Program='C:\Program Files\Internet Explorer\iexplore.exe';
	RemoteAddress=$IPForInternet
}
FWRule @{
	GpoName='[FW] Deny Internet for old IE';
	Action='Block'; Direction='Outbound';
	Program='C:\Program Files (x86)\Internet Explorer\iexplore.exe';
	RemoteAddress=$IPForInternet
}

# Block IPv6
FWRule @{ GpoName='[FW] Block-IPv6'; Action='Block'; Direction='Outbound'; Group='GPO-IPv6'; Protocol=41;	Name='IPv6'; }
FWRule @{ GpoName='[FW] Block-IPv6'; Action='Block'; Direction='Outbound'; Group='GPO-IPv6'; Protocol=43;	Name='IPv6-Route'; }
FWRule @{ GpoName='[FW] Block-IPv6'; Action='Block'; Direction='Outbound'; Group='GPO-IPv6'; Protocol=44;	Name='IPv6-Frag'; }
FWRule @{ GpoName='[FW] Block-IPv6'; Action='Block'; Direction='Outbound'; Group='GPO-IPv6'; Protocol=59;	Name='IPv6-NoNxt'; }
FWRule @{ GpoName='[FW] Block-IPv6'; Action='Block'; Direction='Outbound'; Group='GPO-IPv6'; Protocol=60;	Name='IPv6-Opts'; }
FWRule @{ GpoName='[FW] Block-IPv6'; Action='Block'; Direction='Outbound'; Group='GPO-IPv6'; Protocol=58;	Name='ICMPv6'; }
FWRule @{ GpoName='[FW] Block-IPv6'; Action='Block'; Direction='Outbound'; Group='GPO-IPv6'; Protocol='UDP'; Name='DHCPv6'; RemotePort=547 }
# Block LLMNR
FWRule @{ GpoName='[FW] Block-LLMNR'; Action='Block'; Direction='Outbound'; Group='GPO-LLMNR'; Protocol='UDP'; Name='LLMNR'; RemotePort=5355 }
Set-GPRegistryValue -Name "[SD] [FW] Block-LLMNR" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Value 0 -Type Dword
# Block NetBios
FWRule @{ GpoName="[FW] Block-NetBios"; Action='Block'; Direction='Outbound'; Group='GPO-NetBios'; Protocol='UDP'; Name='NetBios-UDP'; RemotePort=137 }
FWRule @{ GpoName="[FW] Block-NetBios"; Action='Block'; Direction='Outbound'; Group='GPO-NetBios'; Protocol='TCP'; Name='NetBios-TCP'; RemotePort=139 }
Set-GPRegistryValue -Name "[SD] [FW] Block-NetBios" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -ValueName "NodeType" -Value 2 -Type Dword
# Block WPAD
# => Disable wpad service
Set-GPRegistryValue -Name "[SD] Disable-WPAD" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -ValueName "Start" -Value 4 -Type Dword
Set-GPRegistryValue -Name "[SD] Disable-WPAD" -Key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -ValueName "WpadOverride" -Value 1 -Type Dword
# https://web.archive.org/web/20160301201733/http://blog.raido.be/?p=426
Set-GPRegistryValue -Name "[SD] Disable-WPAD" -Key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ValueName "AutoDetect" -Value 0 -Type Dword
# Allow ICMPv4
FWRule @{ GpoName='ICMPv4'; Action='Allow'; Direction='Inbound'; Group='GPO-ICMP'; Protocol='ICMPv4'; Name='ICMP in' }
FWRule @{ GpoName='ICMPv4'; Action='Allow'; Direction='Outbound'; Group='GPO-ICMP'; Protocol='ICMPv4'; Name='ICMP out' }

# Hardened UNC Paths
# https://www.pentestpartners.com/security-blog/windows-server-settings-administrative-templates-network-items-a-security-how-to/#hardunc
# https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.NetworkProvider::Pol_HardenedPaths
Set-GPRegistryValue -Name "[SD] Hardened UNC Paths" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -ValueName "1" -Value "\\*\NETLOGON RequireMutualAuthentication=1, RequireIntegrity=1" -Type String
Set-GPRegistryValue -Name "[SD] Hardened UNC Paths" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -ValueName "1" -Value "\\*\SYSVOL RequireMutualAuthentication=1, RequireIntegrity=1" -Type String



New-GPO -Name "[SD][Hardening] DomainAdmin not allowed to connect"
New-GPO -Name "[SD][Hardening] DomainAdmin only are allowed to connect"
New-GPO -Name "[SD][Hardening] Force LDAP&SMB signing and force NTLMv2"
New-GPO -Name "[SD][Priv] AdminLocal for group PRIV_LOCAL_ADM"
New-GPO -Name "[SD] Certificates"



# https://gpsearch.azurewebsites.net/#4624
# https://blog.netwrix.com/2018/06/07/how-to-create-new-active-directory-users-with-powershell/
# https://sdmsoftware.com/tips-tricks/group-policy-preferences-in-the-local-gpo-yes/
# dsregcmd /status
# rsop.msc


dsquery computer | foreach { DSACLS $_ /resetDefaultDACL > NUL }
