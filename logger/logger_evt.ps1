<#
# LOG Server
# ================================================
$logs = "C:\Windows\SYSVOL\domain\logs"
$domComputer='your-domain.lo\Domain computers'
$domDC='your-domain.lo\Domain Controllers'
$domUser='your-domain.lo\Domain users'

$acl = Get-Acl $logs
$acl.SetAccessRuleProtection($disableInheritance,$preserveInheritanceACL)
$acl | Set-Acl $logs

$acl = Get-Acl $logs
$usersid = New-Object System.Security.Principal.Ntaccount ($domUser)
$acl.PurgeAccessRules($usersid)
$acl | Set-Acl $logs

$acl = Get-Acl $logs
$usersid = New-Object System.Security.Principal.Ntaccount ($domComputer)
$acl.PurgeAccessRules($usersid)
$acl | Set-Acl $logs

# Clean up CREATOR OWNER ACL
$acl = Get-Acl $logs
$usersid = New-Object System.Security.Principal.Ntaccount ("S-1-3-0")
$acl.PurgeAccessRules($usersid)
$acl | Set-Acl $logs

# This folder only
$acl = Get-Acl $logs
$fsar = New-Object System.Security.AccessControl.FileSystemAccessRule($domDC, 'FullControl', 'Allow')
$acl.SetAccessRule($fsar)
$acl | Set-Acl $logs
#>

$syslogStorage = 'C:\Windows\SYSVOL\domain\logs'
$hostname = $env:COMPUTERNAME
$delimiter = ','
$date = (Get-Date).ToString('yyyyMMddHH')
$hoursHistory = 2

New-EventLog -LogName System -Source Logger2CSV -ErrorAction SilentlyContinue;

$ErrorActionPreference = "Stop"
$log = (New-TemporaryFile).FullName
Start-Transcript -Path $log -Force 

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
if( -not $scriptPath.StartsWith("\\") ){
	$syslogStorage = '.\output_sample\per_computer'
	mkdir -Force $syslogStorage > $null
	Write-Host -ForegroundColor White -BackgroundColor DarkRed "Mode test => Reason: the script $($MyInvocation.MyCommand.Definition) is not on a shared folder"
	Write-EventLog -LogName System -Source Logger2CSV -EntryType Warning -Event 2 -Message "Mode test => Reason: the script $($MyInvocation.MyCommand.Definition) is not on a shared folder"
}
Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Files storage: $syslogStorage\*_${hostname}.csv"


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
# Get-WinEvent -FilterXml $xml -ErrorAction SilentlyContinue
Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{LogName='Security'; Id=4624; 'LmPackageName'='NTLM V1'; StartTime=(get-date).AddHours(-1*$hoursHistory)} | ForEach-Object {
	$h = @{}
	([xml]$_.Toxml()).Event.EventData.Data | ForEach-Object {
		$h.Add($_.'Name',$_.'#text')
	}
	[PSCustomObject]$h
} | Export-CSV -NoTypeInformation -Encoding UTF8 "$syslogStorage\Events-NTLMv1_${hostname}_${date}.csv"


###############################################################################
Get-WinEvent -FilterHashtable @{Logname='Directory Service';Id=2889; StartTime=(get-date).AddHours(-1*$hoursHistory)} | %{
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
} | Export-CSV -NoTypeInformation -Encoding UTF8 "$syslogStorage\Events-LDAP-Signing_${hostname}_${date}.csv"


# Log the activity
Stop-Transcript > $null
Write-EventLog -LogName System -Source Logger2CSV -EntryType Information -Event 1 -Message $(cat $log | Out-String)
rm -force $log
