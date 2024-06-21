$syslogStorage = '\\DC-SRV01\syslog$'
$syslogStorageTemp = 'C:\logs\tmp_log'
$syslogStorageFinale = 'C:\logs\merge'
$date = (Get-Date -Format "yyyyMMddHHmm")
$logFolder = "C:\Windows\logs\logger"
$maxLogPowershellHistory = (Get-Date).AddDays(-30)
$ErrorActionPreference = "Stop"

<#
# Install

$TaskName = "[SD] Syslog-parser";

mkdir -force "$syslogStorageFinale\logs-activities"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec bypass -nop -File $baseFolder\logger_merger.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 1 -RandomDelay (New-TimeSpan -Minutes 30) -At "09:00:00"
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName "$TaskName" -Trigger $trigger -User "S-1-5-18" -Action $action -RunLevel Highest -Settings $settings -Force

#>

New-EventLog -LogName System -Source LoggerMerger -ErrorAction SilentlyContinue;
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

if( $syslogStorage -eq '\\DC-SRV01\syslog$' -and -not (Test-Path $syslogStorage) ){
	$syslogStorage = '.\output_sample\per_computer'
	mkdir -Force $syslogStorage > $null
	$syslogStorageFinale = '.\output_sample\merge'	
 	$syslogStorageTemp = '.\output_sample\tmp_log'
	Write-Host -ForegroundColor White -BackgroundColor DarkRed "Mode test => Reason: the script not configured"
	Write-EventLog -LogName System -Source LoggerMerger -EntryType Warning -Event 2 -Message "Mode test => Reason: the script is not configured"
}
mkdir -Force $syslogStorageTemp > $null
mkdir -Force $syslogStorageFinale > $null

Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Files Source        : $syslogStorage"
Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Files Merging output: $syslogStorageFinale"

Move-Item -ErrorAction SilentlyContinue -Force -Path "$syslogStorage\*.csv" -Destination "$syslogStorageTemp\"
$work = Get-Item -Path "$syslogStorageTemp\*.csv"

if( $work.Count -gt 0 ){
	rm -Force "$syslogStorageFinale\*.csv"

	$work | %{
		$tmp = $_.Name -Split '_'
		$type = $tmp[0]
		Write-Host "Working on $($_.Name)"
		if( [System.IO.File]::Exists("$syslogStorageFinale\${date}_${type}.csv") ){
			cat $_.FullName | Select-Object -Skip 1 | Out-File -Encoding UTF8 -Append "$syslogStorageFinale\${date}_${type}.csv"
		}else{
			cat $_.FullName | Out-File -Encoding UTF8 -Append "$syslogStorageFinale\${date}_${type}.csv"
		}
	}
}else{
	Write-Host -ForegroundColor White -BackgroundColor DarkRed "No work todo... EXIT"
}

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
