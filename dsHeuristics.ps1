$dsHeuristics = (Get-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName) -Properties dsHeuristics).dsHeuristics
if(($dsHeuristics -eq "") -or ($dsHeuristics.Length -lt 7)){
	$msg = "[+] Anonymous access is already disable ! (dsHeuristics=$dsHeuristics)"
}elseif(($ValuedsHeuristics.Length -ge 7) -and ($ValuedsHeuristics[6] -eq "2")){
	$msg = "[!] Anonymous access is enabled (dsHeuristics=$dsHeuristics)"
}
Write-Host "$msg"
$msg | Out-File -Encoding ASCII dsHeuristics.log
Write-Host "Do it on all domain"
