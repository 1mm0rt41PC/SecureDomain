# 1) Add SSL support for WSUS Server:
#	Create certificate via PKI
# 2) Configure IIS "WSUS Administration" > Bindings
#	- Add https with port 8531
#	- Set hostname to FQDN hostname
#	- Set SSL Certi to a machine certificate "Web Server"
# Tips to trigger Windows Update Check:
<#
Stop-Service -ErrorAction Continue 'Windows Update' -Force
Stop-Service -ErrorAction Continue  cryptSvc -Force
Stop-Service -ErrorAction Continue  DoSvc -Force
Stop-Service -ErrorAction Continue  bits -Force
Stop-Service -ErrorAction Continue  msiserver -Force
Start-Service cryptSvc
Start-Service 'Windows Update'
wuauclt /detectnow
wuauclt /reportnow
usoclient StartScan
wuauclt /updatenow

$BaseCriteria = "IsInstalled=0 and IsHidden=0 and AutoSelectOnWebSites=1"
$Searcher = New-Object -ComObject Microsoft.Update.Searcher
$SearchResult = $Searcher.Search($Criteria).Updates
$SearchResult.Count

Get-WinEvent -FilterHashtable @{
	LogName='Microsoft-Windows-WindowsUpdateClient/Operational'
	Id=19;
	StartTime=(get-date).AddHours(-1)
} -MaxEvents 10
#>
New-GPO -Name "[1mm0rt41][Hardening](GPO,Computer) WSUS - Configuration with HTTPS" -Comment "##################################`r`n`r`nWSUS configuration:`r`n- Force HTTPS`r`n`r`nIf disabled: Restore WSUS default configuration" | %{
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "WUServer" -Value "https://xxxxx.corp.lo:8531" -Type String >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "WUStatusServer" -Value "https://xxxxx.corp.lo:8531" -Type String >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "UseWUServer" -Value 1 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Value 0 -Type DWord >$null
	$_ | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Value 2 -Type DWord >$null
	$_
}

# Test WSUS HTTPS config
$wsusServer = "your-wsus-server:8531"
@(
    "https://$wsusServer/selfupdate/wuident.cab",
    "https://$wsusServer/SimpleAuthWebService/SimpleAuth.asmx",
    "https://$wsusServer/ClientWebService/client.asmx",
    "https://$wsusServer/DssAuthWebService/DssAuth.asmx",
    "https://$wsusServer/ServerSyncWebService/ServerSync.asmx",
    "https://$wsusServer/ReportingWebService/ReportingWebService.asmx"
) | %{
	$url = $_
	try {
		$response = Invoke-WebRequest -Uri $_ -UseBasicParsing -TimeoutSec 10
		if ($response.StatusCode -eq 200) {
			Write-Host "URL is accessible: $url" -ForegroundColor Green
		} else {
			Write-Host "Failed to access URL: $url (Status Code: $($response.StatusCode))" -ForegroundColor Red
		}
	} catch {
		Write-Host "Error accessing URL: $url ($($_.Exception.Message))" -ForegroundColor Red
	}
}
