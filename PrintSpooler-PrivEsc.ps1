###########################################################################################
# [1mm0rt41][Hardening](GPO,Computer) Print spooler configuration
###########################################################################################
New-GPO -Name "[1mm0rt41][Hardening](GPO,Computer) Print spooler configuration" -Comment "##################################`r`n`r`nConfigure spooler to avoid priviledge escalation.`r`n`r`nSide effect: Block installation of new printers ! Package your printer drivers in the image or via WSUS/SCCM`r`nIf disabled: Lost logs information" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "NoWarningNoElevationOnInstall" -Value 0 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "UpdatePromptSettings" -Value 0 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "InForest" -Value 0 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "TrustedServers" -Value 1 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint" -ValueName "PackagePointAndPrintOnly" -Value 1 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint" -ValueName "PackagePointAndPrintServerList" -Value 1 -Type DWord >$null
	$_
}
