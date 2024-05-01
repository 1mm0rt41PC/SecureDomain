$syslogStorage = '\\DC-SRV01\syslog$'
$syslogStorageTemp = 'C:\logs\tmp_log'
$syslogStorageFinale = 'C:\logs\merge'

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

$ErrorActionPreference = "Stop"
$log = (New-TemporaryFile).FullName
Start-Transcript -Path $log -Force


$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
if( -not $scriptPath.Contains("\\") -and -not $MyInvocation.MyCommand.Definition.Contains("\\") ){
	$syslogStorage = '.\output_sample\per_computer'
	mkdir -Force $syslogStorage > $null
	$syslogStorageFinale = '.\output_sample\merge'
	mkdir -Force $syslogStorageFinale > $null
 	$syslogStorageTemp = '.\output_sample\tmp_log'
  	mkdir -Force $syslogStorageTemp > $null
	Write-Host -ForegroundColor White -BackgroundColor DarkRed "Mode test => Reason: the script $($MyInvocation.MyCommand.Definition) is not on a shared folder"
	Write-EventLog -LogName System -Source LoggerMerger -EntryType Warning -Event 2 -Message "Mode test => Reason: the script $($MyInvocation.MyCommand.Definition) is not on a shared folder"
}
Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Files Source        : $syslogStorage"
Write-Host -ForegroundColor White -BackgroundColor DarkBlue "Files Merging output: $syslogStorageFinale"

Move-Item -Force -Path "$syslogStorage\*.csv" -Destination "$syslogStorageTemp\"
$work = Get-Item -Path "$syslogStorageTemp\*.csv"

if( $work.Count -gt 0 ){
	rm -Force "$syslogStorageFinale\*.csv"

	$work | %{
		$tmp = $_.Name -Split '_'
		$type = $tmp[0]
		Write-Host "Working on $($_.Name)"
		if( [System.IO.File]::Exists("$syslogStorageFinale\${type}.csv") ){
			cat $_.FullName | Select-Object -Skip 1 | Out-File -Encoding UTF8 -Append "$syslogStorageFinale\${type}.csv"
		}else{
			cat $_.FullName | Out-File -Encoding UTF8 -Append "$syslogStorageFinale\${type}.csv"
		}
	}
}else{
	Write-Host -ForegroundColor White -BackgroundColor DarkRed "No work todo... EXIT"
}

# Log the activity
Stop-Transcript > $null

$logData = cat $log | Out-String
$loop = $logData.Length % 32000
0..$loop | %{
	Write-EventLog -LogName System -Source LoggerMerger -EntryType Information -Event 1 -Message $logData.SubString($_*32000, 32000)
}

rm -force $log
