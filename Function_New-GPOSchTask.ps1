function New-GPOSchTask
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]
		[ValidateNotNullOrEmpty()]
		$TaskName,
		
		[Parameter(Mandatory = $True)]
		[String]
		[ValidateNotNullOrEmpty()]
		$GPOName,

		[String]
		[ValidateNotNullOrEmpty()]
		$Command = 'powershell',
		
		[String]
		[ValidateNotNullOrEmpty()]
		$CommandArguments,

		[String]
		[ValidateNotNullOrEmpty()]
		$RunAs = 'S-1-5-18',
		
		[String]
		[ValidateSet('ImmediateTask','Task')]
		$TaskType='ImmediateTask',
		
		[String]
		[ValidateSet('Create','Replace','Update','Delete')]
		$TaskAction='Replace',
		
		[String]
		[ValidateSet('User','Machine')]
		$Context='Machine',
		
		[ValidateRange(0,23)]
		[Int]
		$StartEveryDayAt=9
	)
	Write-Host "[*] Create temp GPO"
	New-GPO Temp_SchTaskMaker | Out-Null
	md -ErrorAction SilentlyContinue "C:\Windows\Temp\Temp_SchTaskMaker\"  | Out-Null
	$bkpInfo = Backup-GPO -Path C:\Windows\Temp\Temp_SchTaskMaker\ Temp_SchTaskMaker
	Remove-GPO Temp_SchTaskMaker | Out-Null
	$backupId = $bkpInfo.Id
	
	Write-Host "[*] Edit Backup.xml"
	$backupXmlContent = [IO.file]::ReadAllText("C:\Windows\Temp\Temp_SchTaskMaker\{$backupId}\Backup.xml")
	$backupXmlContent.Replace('bkp:DescName="Unknown Extension"/>',( @"
	bkp:DescName="Unknown Extension"><FSObjectDir bkp:Path="%GPO_MACH_FSPATH%\Preferences" bkp:SourceExpandedPath="\\$($env:USERDNSDOMAIN)\sysvol\$($env:USERDOMAIN)\Policies\{E1AFAE1C-C44E-4197-8DB5-1FC894A997AA}\$Context\Preferences" bkp:Location="DomainSysvol\GPO\$Context\Preferences"/>
<FSObjectDir bkp:Path="%GPO_MACH_FSPATH%\Preferences\ScheduledTasks" bkp:SourceExpandedPath="\\$($env:USERDNSDOMAIN)\sysvol\$($env:USERDOMAIN)\Policies\{E1AFAE1C-C44E-4197-8DB5-1FC894A997AA}\$Context\Preferences\ScheduledTasks" bkp:Location="DomainSysvol\GPO\$Context\Preferences\ScheduledTasks"/>
<FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\Preferences\ScheduledTasks\ScheduledTasks.xml" bkp:SourceExpandedPath="\\$($env:USERDNSDOMAIN)\sysvol\$($env:USERDOMAIN)\Policies\{E1AFAE1C-C44E-4197-8DB5-1FC894A997AA}\$Context\Preferences\ScheduledTasks\ScheduledTasks.xml" bkp:Location="DomainSysvol\GPO\$Context\Preferences\ScheduledTasks\ScheduledTasks.xml"/>
</GroupPolicyExtension>	
"@
).Trim() ) | Out-File -Encoding ASCII "C:\Windows\Temp\Temp_SchTaskMaker\{$backupId}\Backup.xml"

	Write-Host "[*] Forge a $TaskType in ScheduledTasks.xml in context $Context"
	$DeleteExpiredTaskAfter = ''
	$TaskProperties = ''
	if( $TaskType -eq 'ImmediateTask' ){
		$clsid='9756B581-76EC-4169-9AFC-0CA8D43ADB5F'
		$DeleteExpiredTaskAfter = '<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>'
		$TaskProperties = 'userContext="0" removePolicy="0"'
		$Triggers='<TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger>'
	}else{
		$clsid='D8896631-B747-47a7-84A6-C155337F3BC8'
		$date=(Get-Date).AddDays(1).ToString("yyyy-MM-ddT{0:d2}:00:00" -f $StartEveryDayAt)
		$Triggers='<CalendarTrigger><StartBoundary>{0}</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>' -f $date
	}
	md "C:\Windows\Temp\Temp_SchTaskMaker\{$backupId}\DomainSysvol\GPO\$Context\Preferences\ScheduledTasks\" | Out-Null
$date=(Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
( @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><$($TaskType)V2 clsid="{$clsid}" name="$TaskName" image="0" changed="$date" uid="{D98A502B-7563-4A3D-A4EA-5B4EE8E63364}" $TaskProperties><Properties action="$($TaskAction[0])" name="$TaskName" runAs="$RunAs" logonType="S4U"><Task version="1.2"><RegistrationInfo><Author>$($env:USERDOMAIN)\$($env:USERNAME)</Author><Description>This task need to run with $RunAs</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>$RunAs</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT5M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><ExecutionTimeLimit>PT2H</ExecutionTimeLimit><Priority>7</Priority>$DeleteExpiredTaskAfter<RestartOnFailure><Interval>PT5M</Interval><Count>3</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>$Command</Command><Arguments>$CommandArguments</Arguments></Exec></Actions><Triggers>$Triggers</Triggers></Task></Properties></$($TaskType)V2>
</ScheduledTasks>
"@ ).Trim() | Out-File -Encoding ASCII "C:\Windows\Temp\Temp_SchTaskMaker\{$backupId}\DomainSysvol\GPO\$Context\Preferences\ScheduledTasks\ScheduledTasks.xml"
	$gpo=Import-GPO -CreateIfNeeded -Path 'C:\Windows\Temp\Temp_SchTaskMaker\' -TargetName $GPOName -BackupId $backupId
	$gpoId=$gpo.Id.ToString()
	$gpoId="{$gpoId}"
	rm -force -Recurse 'C:\Windows\Temp\Temp_SchTaskMaker\'
	Get-AdObject -Filter "(objectClass -eq 'groupPolicyContainer') -and (name -eq '$gpoId')" | Set-ADObject -Replace @{gPCMachineExtensionNames="[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"};
}
