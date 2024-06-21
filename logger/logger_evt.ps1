<#
# logger_evt.ps1 - A simple script that automates Windows collect events info
#
# Filename: logger_evt.ps1
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
# Update: 2024-06-21 - Add auto cleanup
#>
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

if( -not (Test-Path $syslogStorage) ){
	$syslogStorage = '.\output_sample\per_computer'
	mkdir -Force $syslogStorage > $null
 	logMsg -EntryType Warning -Event 2 -Message "Mode test => Reason: the script can not write into $syslogStorage"
}
Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Files storage: $syslogStorage\*_${hostname}.csv"


$xml = @'
	<QueryList>
		<Query Id="0" Path="security">
			<Select Path="security">
				*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= XXX_TIME_IN_SECONDS_XXX]]]
				and
				 *[EventData[Data[@Name='LmPackageName']='NTLM V1']]
			</Select>
		</Query>
	</QueryList>
'@
$xml = $xml.Replace('XXX_TIME_IN_SECONDS_XXX', $hoursHistory*60*60*1000)
# Require Powershellv6 : https://learn.microsoft.com/fr-fr/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable?view=powershell-7.4#code-try-3
# Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{LogName='Security'; Id=4624; 'LmPackageName'='NTLM V1'; StartTime=(get-date).AddHours(-1*$hoursHistory)}
Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Reading event 4624 for NTLMv1 auth"
Get-WinEvent -FilterXml $xml -ErrorAction SilentlyContinue | ForEach-Object {
	$h = @{}
	([xml]$_.Toxml()).Event.EventData.Data | ForEach-Object {
		$h.Add($_.'Name',$_.'#text')
	}
	[PSCustomObject]$h
} | Export-CSV -NoTypeInformation -Encoding UTF8 "$syslogStorage\Events-NTLMv1_${hostname}_${date}.csv"


###############################################################################
Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Reading event 2889 for LDAP signing"
Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{Logname='Directory Service';Id=2889; StartTime=(get-date).AddHours(-1*$hoursHistory)} | %{
	# Loop through each event and output the
	$eventXML = [xml]$_.ToXml()
	$Row = 1 | Select IPAddress,User,BindType
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


###############################################################################
# Get all 4776 to track authentification
Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Reading event 4776 for credz validation to track auth"
Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{LogName='Security'; ID=4776; StartTime=(get-date).AddHours(-1*$hoursHistory);} | %{
    $eventXML = [xml]$_.ToXml()
    $row = 1 | Select HostName,TimeCreated,Username,Workstation
    $row.Workstation = ($eventXML.Event.EventData.ChildNodes | ?{$_.Name -eq 'Workstation'}).'#text'
    $row.Username = ($eventXML.Event.EventData.ChildNodes | ?{$_.Name -eq 'TargetUserName'}).'#text'
    $row.TimeCreated = $_.TimeCreated
    $row.HostName = $hostname
    $row
} | Export-CSV -NoTypeInformation -Encoding UTF8 "$syslogStorage\Events-Auth-4776_${hostname}_${date}.csv"


# Delete files older than the $maxLogPowershellHistory.
Get-ChildItem -ErrorAction SilentlyContinue -Path $logFolder -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $maxLogPowershellHistory } | Remove-Item -ErrorAction Continue -Force

# Log the activity
Stop-Transcript > $null
$logData = cat $log | Out-String
$loop = [Math]::Ceiling($logData.Length / 32000)
0..$loop | %{
	$size = if( $_*32000+32000 -gt $logData.Length ){ $logData.Length-($_*32000) }else{ 32000 }
	if( $size -gt 0 ){
		Write-Host "Writting Part $_"
		Write-EventLog -LogName System -Source LoggerMerger -EntryType Information -Event 1 -Message $logData.SubString($_*32000, $size)
	}
}
