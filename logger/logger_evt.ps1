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

$syslogStorage           = 'C:\Windows\SYSVOL\domain\logs'
$hostname                = $env:COMPUTERNAME
$delimiter               = ','
$date                    = (Get-Date).ToString('yyyyMMddHH')
$hoursHistory            = 2
$maxLogPowershellHistory = (Get-Date).AddDays(-30)
$logFolder               = 'C:\Windows\logs\logger'
$ErrorActionPreference   = 'Stop'


New-EventLog -LogName System -Source Logger2CSV -ErrorAction SilentlyContinue;


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
		Write-EventLog -ErrorAction Stop -LogName System -Source Logger2CSV -EntryType $EntryType -Event $EventId -Message $Message
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

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
if( -not (Test-Path $syslogStorage) ){
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
# Require Powershellv6 : https://learn.microsoft.com/fr-fr/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable?view=powershell-7.4#code-try-3
# Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{LogName='Security'; Id=4624; 'LmPackageName'='NTLM V1'; StartTime=(get-date).AddHours(-1*$hoursHistory)}
Get-WinEvent -FilterXml $xml -ErrorAction SilentlyContinue | ForEach-Object {
	$h = @{}
	([xml]$_.Toxml()).Event.EventData.Data | ForEach-Object {
		$h.Add($_.'Name',$_.'#text')
	}
	[PSCustomObject]$h
} | Export-CSV -NoTypeInformation -Encoding UTF8 "$syslogStorage\Events-NTLMv1_${hostname}_${date}.csv"


###############################################################################
Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{Logname='Directory Service';Id=2889; StartTime=(get-date).AddHours(-1*$hoursHistory)} | %{
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


# Delete files older than the $maxLogPowershellHistory.
Get-ChildItem -ErrorAction SilentlyContinue -Path $logFolder -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $maxLogPowershellHistory } | Remove-Item -ErrorAction Continue -Force

# Log the activity
Stop-Transcript > $null
Write-EventLog -LogName System -Source Logger2CSV -EntryType Information -Event 1 -Message $(cat $log | Out-String)
