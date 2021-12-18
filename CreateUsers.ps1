$Users = Import-CSV Users.csv

$defaultPassword=$(Read-Host "Enter password" -AsSecureString)
$accountProperties = @{
	AccountPassword=$defaultPassword;
	Enabled=$true;
	ChangePasswordAtLogon=$true;
	AllowReversiblePasswordEncryption=$false;
	AccountNotDelegated=$true	
}

$Users | foreach {
	$row=$_
	$prefix=''
	$accountProperties['UserPrincipalName'] = $row['EmailAddress']
	$accountProperties['EmailAddress'] = $row['EmailAddress']
	$Corp = $row['EmailAddress'].Split('@')[1]
	if( $row['sam'].StartWith('ext_') ){
		$prefix=('EXT {0} - ' -f )
		$accountProperties.remove('UserPrincipalName')
		$accountProperties.remove('EmailAddress')
	}
	$row['ExtraRole'] -Split '/' | foreach {
		if( $_ -eq 'DA' ){
			$role = 'Domain Admin'
			$Admin_OU = '__DomainAdministrators__'
		}elseif( $_ -eq 'ADM' ){
			$role = 'Local Admin'
			$Admin_OU = '__LocalAdministrators__'
		}elseif( $_ -eq 'EXTERNAL' ){
			$_ = ''
			$role = ''
			$Admin_OU = '__EXTERNAL__'
		}else{
			New-ADUser @accountProperties -SamAccountName $row['sam'] -Name ("{1}{2} {3}" -f $prefix,$row['Firstname'],$row['Lastname']) -Description "$prefix$role" -Company $row['EmailAddress'].Split('@')[1] -Path "OU=$_,OU=AllUsers,$LDAP_DN"
		}
		New-ADUser @accountProperties -SamAccountName ('{0}_{1}' -f $_.ToLower(),$row['sam']) -Name ("{0} - {1}{2} {3}" -f $_,$prefix,$row['Firstname'],$row['Lastname']) -Description "$prefix$role" -Company $Corp -Path "OU=$Admin_OU,OU=AllUsers,$LDAP_DN"
	}
}