function FWRule( $param )
{
	$GpoName_raw=$param['GpoName']
	$GpoName = ("[SD] {0}" -f $param['GpoName']) -replace '\] \[', ']['
	$param.remove('GpoName')
	New-GPO -Name $GpoName -ErrorAction SilentlyContinue
	$GpoSessionName = Open-NetGPO –PolicyStore ("{0}\{1}" -f $env:USERDNSDOMAIN,$GpoName)
	$param['GPOSession']  = $GpoSessionName;
	$param['PolicyStore'] = $GpoName;
	$param['DisplayName'] = ("[GPO] {0}" -f $GpoName_raw) -Replace '\] \[', '][';
	$param.remove('Name')
	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue @param
	Save-NetGPO -GPOSession $GpoSessionName
}
$IPForInternet=@('1.0.0.0-9.255.255.255',
'11.0.0.0-100.63.255.255',
'100.128.0.0-126.255.255.255',
'128.0.0.0-169.253.255.255',
'169.255.0.0-172.15.255.255',
'172.32.0.0-191.255.255.255',
'192.0.1.0-192.0.1.255',
'192.0.3.0-192.167.255.255',
'192.169.0.0-198.17.255.255',
'198.20.0.0-198.51.99.255',
'198.51.101.0-203.0.112.255',
'203.0.114.0-255.255.255.254')