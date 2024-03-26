$syslogStorage = '\\DC-SRV01\syslog$'
$syslogStorageFinale = 'C:\temp'

rm -Force "$syslogStorageFinale\*.csv"

Get-Item -Path "$syslogStorage\*.csv" | %{
	$tmp = $_.Name -Split '_'
	$type = $tmp[0]
	if( [System.IO.File]::Exists("$syslogStorageFinale\${type}.csv") ){
		cat $_.FullName | Select-Object -Skip 1 | Out-File -Encoding UTF8 -Append "$syslogStorageFinale\${type}.csv"
	}else{
		cat $_.FullName | Out-File -Encoding UTF8 -Append "$syslogStorageFinale\${type}.csv"
	}
}

rm -Force "$syslogStorage\*.csv"
