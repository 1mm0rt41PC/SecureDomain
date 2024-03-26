$syslogStorage = '\\DC-SRV01\syslog$'
$hostname = $env:COMPUTERNAME

# List local users
Get-LocalUser | select @{n="HostName";e={$env:computername}},Name,AccountExpires,Enabled,PasswordChangeableDate,PasswordExpires,UserMayChangePassword,PasswordRequired,PasswordLastSet,LastLogon | ConvertTo-Csv -NoTypeInformation > "$syslogStorage\LocalUser_${hostname}.csv"


# List local group members
Get-WmiObject win32_group -filter "Domain='$hostname'" | %{
	$row = New-Object PSObject
	Add-Member -InputObject $row -MemberType NoteProperty -Name HostName -Value $env:COMPUTERNAME
	Add-Member -InputObject $row -MemberType NoteProperty -Name Name -Value $_.Name
	Add-Member -InputObject $row -MemberType NoteProperty -Name SID -Value $_.SID
	Add-Member -InputObject $row -MemberType NoteProperty -Name Caption -Value $_.Caption.Split('\')[1]
	Add-Member -InputObject $row -MemberType NoteProperty -Name LocalAccount -Value $_.LocalAccount
	Add-Member -InputObject $row -MemberType NoteProperty -Name Member -Value ""

	$_.GetRelated("Win32_Account", "Win32_GroupUser", "", "", "PartComponent", "GroupComponent", $false, $null) | %{
		$tmp = $_.ToString().Split("=");
		$dom = $tmp[1].Split('"')[1];
		$name = $tmp[2].Split('"')[1];
		$row.Member = $dom+"\"+$name
		$row
	}
} | ConvertTo-Csv -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\LocalGroup_${hostname}.csv"


# List ScheduledTask
@"
"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running"
$((schtasks.exe /query /V /FO csv)  -join "`r`n")
"@ | ConvertFrom-CSV | Where { $_.TaskName.Replace('\','').Length -eq $_.TaskName.Length-1 } | ConvertTo-Csv -NoTypeInformation > "$syslogStorage\ScheduledTask_${hostname}.csv"


# List RDP Sessions
qwinsta | foreach {   
	if ($_ -NotMatch "services|console" -and $_ -match "Disc|Active|Acti|Déco") {
		$session = $($_ -Replace ' {2,}', ',').split(',')
		echo 1 | select  @{n="HostName";e={$env:computername}}, @{n="User";e={$session[1]}}, @{n="SessionID";e={$session[2]}}, @{n="Status";e={$session[3]}}
	}
} | ConvertTo-Csv -NoTypeInformation > "$syslogStorage\RDPSession_${hostname}.csv"


# List Firewall rules
Get-NetFirewallRule -PolicyStore ActiveStore | where {$_.Enabled -eq $true } | sort Direction,Action | Select @{n="HostName";e={$env:computername}},DisplayName,Direction,DisplayGroup,Profile,Action,PolicyStoreSourceType,PolicyStoreSource,
	@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).Protocol}},
	@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).LocalPort}},
	@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter -PolicyStore ActiveStore).RemotePort}},
	@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter -PolicyStore ActiveStore).RemoteAddress}} | ConvertTo-Csv -NoTypeInformation > "$syslogStorage\FireWall_Rules_${hostname}.csv"
Get-NetFirewallProfile | select @{n="HostName";e={$env:computername}},* | ConvertTo-Csv -NoTypeInformation > "$syslogStorage\FireWall_Status_${hostname}.csv"

Get-SmbShare | select @{n="HostName";e={$env:computername}},* | ConvertTo-Csv -NoTypeInformation > "$syslogStorage\SmbShare_${hostname}.csv"

$updateSearcher = (new-object -com "Microsoft.Update.Session").CreateupdateSearcher()
$searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
echo 1 | select @{n="HostName";e={$env:computername}},@{n="OSVersion";e={[System.Environment]::OSVersion.Version.ToString()}},@{n="ReleaseId";e={(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId}},@{n="DisplayVersion";e={(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion}},@{n="EditionID";e={(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID}},@{n="Nb Missing Windows Update";e={$searchResult.Updates.Count}},@{n="Missing Windows Update";e={($searchResult.Updates|select Title).Title}} | ConvertTo-Csv -NoTypeInformation > "$syslogStorage\General_${hostname}.csv"


@(
	@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL',1),
	@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','DisableRestrictedAdmin',0),
	@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','DisableRestrictedAdminOutboundCreds',1),
	@('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential',0)
) | %{
	$path=$_[0]
	$key=$_[1]
	$expected=$_[2]
	$ret = echo '' | Select hostname,key,value,expected
	$ret.hostname = $hostname
	$ret.key = "$path\$key"
	$ret.expected = "$expected"
	try{
		$ret.value = (Get-ItemPropertyValue -Path "Registry::$path" -Name $key).ToString()
	}catch{
		$ret.value = 'undefined'
	}
	$ret
} |  ConvertTo-Csv -NoTypeInformation | Out-File -Encoding UTF8 "$syslogStorage\Reg_${hostname}.csv"


