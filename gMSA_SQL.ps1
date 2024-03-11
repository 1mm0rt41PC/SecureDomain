$groupName       = 'T-SQL' # 15 char max !!!!!!!
$targetServer    = 'sql-<instance>'
$portOrInstance  = '<instance>'
$databaseDir     = 'D:\MSSQL1337'
$gmsaSAN         = "T-SQL-<id>"
$serviceName     = 'myService' 

$OU              = "OU=OU_of_Group,DC=domain,DC=lan"
$targetServiceClass = 'MSSQLSvc'
$domain          = $env:USERDNSDOMAIN
$targetService   = "${targetServiceClass}/${targetServer}:${portOrInstance}","${targetServiceClass}/${targetServer}.${domain}:${portOrInstance}"


###############################################################################
# On Domain Controller
###############################################################################
# Create Group that is allowed to retrive gmsa password
New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Path $OU
# Create GMSA account
New-ADServiceAccount -name $gmsaSAN -enabled $true -DNSHostName "${gmsaSAN}.${domain}" -PrincipalsAllowedToRetrieveManagedPassword $groupName -ServicePrincipalName $targetService -KerberosEncryptionType AES128,AES256


###############################################################################
# On server
###############################################################################
Install-ADServiceAccount $gmsaSAN
Test-ADServiceAccount $gmsaSAN

# Update password for the service
$ServiceObject = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'" 
$ServiceObject.StopService() | out-null
# Change logon as settings
$ServiceObject.Change($null, $null, $null, $null, $null, $null, "$domain\$gmsaSAN`$", $null, $null, $null, $null)
$ServiceObject.StartService()

# Update filsystem to allow database to access to db files
$acl = Get-Acl $databaseDir
$fsar = New-Object System.Security.AccessControl.FileSystemAccessRule($gmsaSAN, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.SetAccessRule($fsar)
$acl | Set-Acl $databaseDir
# [OPTIONAL] Change owner of the folder to the gmsa account
$acl = Get-Acl $databaseDir
$acl.SetOwner([System.Security.Principal.NTAccount]$gmsaSAN)
$acl.SetAccessRule($fsar)
$acl | Set-Acl $databaseDir
