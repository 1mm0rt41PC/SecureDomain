$IP_DHCP  		= '10.0.0.0'
$IP_DNS   		= '10.0.0.2'
$IP_AD    		= '10.0.0.1'
$IP_GATEWAY     = '10.0.0.254'
$IP_VPN         = '10.100.0.0/24'
$IP_VPN_ADMIN   = '10.200.0.0/24'
$domain         = 'earth.lo'
$domain_netbios = 'earth'
# Please use a real secure password that you save in a KeePass
$SafeModeAdministratorPassword = -join ((33..126) | Get-Random -Count 32 | % {[char]$_})
$LDAP_DN        = ( [ADSI]"LDAP://RootDSE" ).defaultNamingContext.Value

tzutil /s 'W. Europe Standard Time'
reg add "HKCU\Control Panel\International" /v sLongDate /d "dddd, MMMM d, yyyy" /t REG_SZ /f
reg add "HKCU\Control Panel\International" /v sShortDate /d "MM/dd/yyyy" /t REG_SZ /f
reg add "HKCU\Control Panel\International" /v sShortTime /d "HH:mm" /t REG_SZ /f
reg add "HKCU\Control Panel\International" /v sTimeFormat /d "HH:mm:ss" /t REG_SZ /f
reg add "HKCU\Control Panel\International" /v sYearMonth /d "MMMM yyyy" /t REG_SZ /f
reg add "HKCU\Control Panel\International" /v iFirstDayOfWeek /d "0" /t REG_SZ /f

reg add "HKEY_USERS\.DEFAULT\Control Panel\International" /v sLongDate /d "dddd, MMMM d, yyyy" /t REG_SZ /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\International" /v sShortDate /d "MM/dd/yyyy" /t REG_SZ /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\International" /v sShortTime /d "HH:mm" /t REG_SZ /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\International" /v sTimeFormat /d "HH:mm:ss" /t REG_SZ /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\International" /v sYearMonth /d "MMMM yyyy" /t REG_SZ /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\International" /v iFirstDayOfWeek /d "0" /t REG_SZ /f