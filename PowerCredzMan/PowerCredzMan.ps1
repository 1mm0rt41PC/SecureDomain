<#
# PowerCredzMan.ps1 - A simple script that automates Windows Credz management in Tiering System
#
# Filename: PowerCredzMan.ps1
# Author: 1mm0rt41PC - immortal-pc.info - https://github.com/1mm0rt41PC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# Update: 2024-10-17 - Creation
#>
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$global:Credentialz = @{}
$global:LastComputer = ''
$global:LambdaAccount = $null
$global:DefaultDomainName = $env:USERDNSDOMAIN
$global:NotifyIcon = $null
$global:EnableLog = $true


<##################################################################################################
.SYNOPSIS
	Logs a message to the console or a log file.

.DESCRIPTION
	The MyLog function takes a message as input and logs it to the console or a specified log file.
	This can be useful for debugging or tracking the execution of scripts.

.PARAMETER Msg
	The message to be logged. This can be any string that you want to record.

.EXAMPLE
	MyLog "This is a test message"
	Logs the message "This is a test message" to the console or log file.

.NOTES
	Ensure that the logging mechanism (console or file) is properly configured before using this function.
#>
Function MyLog( $Msg ){
	if( $global:EnableLog ){
		Write-Host $Msg
	}
}


<##################################################################################################
.SYNOPSIS
Sets the cached credentials tiering for the specified domain.

.DESCRIPTION
The Set-CachedCredzTiering function configures the tiering of cached credentials for a given domain. This is useful for managing and securing credential storage in a domain environment.

.PARAMETER Domain
Specifies the domain for which the cached credentials tiering is to be set.

.PARAMETER Tier
Specifies the tier level for the cached credentials. Valid values are typically defined by the organization's security policy.

.EXAMPLE
Set-CachedCredzTiering -Domain "example.com" -Tier 1
This example sets the cached credentials tiering to level 1 for the domain "example.com".
#>
Function Set-CachedCredzTiering
{
	Param(
		[string]$AccountName,
		[string]$AccountPassword,
		[string]$TierLevel
	)
	if( -not ($AccountName -is [string]) ){
		throw "AccountName is not a String type => $AccountName"
	}
	if( -not ($AccountPassword -is [string]) ){
		throw "AccountPassword is not a String type"
	}
	if( -not ($TierLevel -is [string]) ){
		throw "TierLevel is not a String type => $TierLevel"
	}
	if( $AccountName -eq $null -or $AccountName -eq "" -or $AccountPassword -eq $null -or $AccountPassword -eq "" -or $TierLevel -eq $null -or $TierLevel -eq "" ){
		throw "AccountName, AccountPassword or TierLevel is empty"
	}
	$TierLevel = $TierLevel.ToUpper()
	MyLog "DEBUG: Adding to cache AccountName=$AccountName with TierLevel=$TierLevel" | Out-Null
	Show-Notification -Title "PowerCredzMan" -Message "Added credz $accountName to the local memcache with level $TierLevel" | Out-Null
	$global:Credentialz[$TierLevel] = $AccountName,$AccountPassword
}


<##################################################################################################
.SYNOPSIS
Retrieves cached credentials and their associated tiering information.

.DESCRIPTION
The Get-CachedCredzTiering function is designed to fetch cached credentials from the system and provide details about their tiering. This can be useful for security assessments and understanding the distribution of credentials across different tiers.

.EXAMPLE
PS C:\> Get-CachedCredzTiering

This command retrieves and displays the cached credentials along with their tiering information.
#>
Function Get-CachedCredzTiering
{
	Param(
		[string] $TierLevel
	)
	if( -not ($TierLevel -is [string]) ){
		throw "TierLevel is not a String type => $TierLevel"
	}
	if( $TierLevel -eq $null -or $TierLevel -eq "" ){
		throw "TierLevel is empty"
	}
	$TierLevel = $TierLevel.ToUpper()
	MyLog "DEBUG: Requesting for credz of level $TierLevel"
	if( $global:Credentialz[$TierLevel] -eq $null -or $global:Credentialz[$TierLevel].Count -ne 2 ){
		MyLog "	DEBUG: => Not found"
		return $null
	}
	$accountName = $global:Credentialz[$TierLevel][0]
	$accountPassword = $global:Credentialz[$TierLevel][1]
	MyLog "	DEBUG: => Found account $accountName"
	if( $accountPassword -eq $null -or $accountPassword -eq "" ){
		MyLog "	DEBUG: => Found but empty password"
		return @($accountName,$null)
	}
	Show-Notification -Title "PowerCredzMan" -Message "Using credz $accountName from the local memcache" | Out-Null
	MyLog "	DEBUG: => Found !" | Out-Null
	return @($accountName,$accountPassword)
}


<##################################################################################################
.SYNOPSIS
Removes cached credentials for tiering.

.DESCRIPTION
The Remove-CachedCredzTiering function is designed to clear cached credentials that are used for tiering purposes. This can help in maintaining security by ensuring that old or unused credentials are not stored in the system.

.EXAMPLE
Remove-CachedCredzTiering

This command will remove all cached credentials related to tiering.
#>
Function Remove-CachedCredzTiering
{
	Param(
		[string]$AccountName
	)
	if( -not ($AccountName -is [string]) ){
		throw "AccountName is not a String type => $AccountName"
	}
	MyLog "DEBUG: Removing credz $AccountName" | Out-Null
	$toDelete = @()
	$global:Credentialz.Keys | %{ 
		if( $global:Credentialz[$_] -ne $null -and $global:Credentialz[$_][0] -eq $AccountName ){
			MyLog "	DEBUG: => Removed" | Out-Null
			$toDelete += @($_)
		}
	}
	$toDelete | %{
		$global:Credentialz.Remove($_)
	}
}


<##################################################################################################
.SYNOPSIS
Retrieves the tier membership of a specified account.

.PARAMETER AccountName
The name of the account for which to retrieve the tier membership.

.PARAMETER Credential
Optional. An array of credentials to use for authentication.

.EXAMPLE
Get-TierMemberShip -AccountName "User1"

.EXAMPLE
Get-TierMemberShip -AccountName "User1" -Credential @('dom\user','passw')
#>
Function Get-TierMemberShip {
	param (
		[string] $AccountName,
		[string[]] $Credential = $null
	)
	if( -not ($AccountName -is [string]) ){
		throw "AccountName is not a String type => $AccountName"
	}
	if( $AccountName -eq $null -or $AccountName -eq "" ){
		throw "AccountName is empty"
	}
	if( $AccountName.ToUpper() -match '^T[0-9\.]+[_\-]?' ){
		return $AccountName.Split('_')[0].ToUpper().Split('-')[0]
	}
	if( $AccountName.ToUpper() -match '\\T[0-9\.]+[_\-]?' ){
		return $AccountName.Split('\')[1].Split('_')[0].ToUpper().Split('-')[0]
	}

	$usr = Get-ADSIObject $AccountName -Credential $Credential

	return Get-ADSIMemberOfTransitive -DistenquishedName $usr.distinguishedName -Credential $Credential | % {
		$distinguishedName = $_
		if( $distinguishedName.ToUpper() -match '^CN=T[0-9\.]+[_\-]?' ){
			return $distinguishedName.Split('_')[0].Split('=')[1].ToUpper().Split('-')[0]
		}
		$directoryEntry = Get-LdapConnection -DistenquishedName $distinguishedName -Credential $Credential
		if( $directoryEntry.sAMAccountName.ToUpper() -match $_ -match '^T[0-9\.]+[_\-]?' ){
			return $_.Split('_')[0].ToUpper().Split('-')[0]
		}
		return
	}
}


<##################################################################################################
.SYNOPSIS
Retrieves valid credentials from a specified source.

.DESCRIPTION
The Get-ValidCredentials function is designed to fetch and return valid credentials. 
It can be used in various scenarios where credential validation is required.

.EXAMPLE
PS C:\> Get-ValidCredentials

This command retrieves and displays valid credentials.
#>
Function Get-ValidCredentials
{
	Param(
		[Parameter(Mandatory = $true)][string]$UserName,
		[Parameter(Mandatory = $true)][string]$Message,
		[string]$TierLevel
	)
	if( -not ($UserName -is [string]) ){
		throw "UserName is not a String type => $UserName"
	}
	if( -not ($Message -is [string]) ){
		throw "Message is not a String type => $Message"
	}
	if( $TierLevel -ne $null -and -not ($TierLevel -is [string]) ){
		throw "TierLevel is not a String type => $TierLevel"
	}
	if( $UserName -eq $null -or $UserName -eq "" ){
		throw "UserName is empty"
	}
	if( $Message -eq $null -or $Message -eq "" ){
		throw "Message is empty"
	}
	while($true){
		MyLog "DEBUG (Get-ValidCredentials): Asking for credz via Windows UI" | Out-Null
		$credz = Get-Credential -UserName $UserName -Message $Message
		if( $credz -eq $null ){
			return $null
		}
		$accountName = $credz.UserName.ToLower()
		$UserName = $accountName
		$accountPassword = $credz.GetNetworkCredential().password
		try {
			$adUser = Get-ADSIObject $username -ObjectClass User -Credential $accountName,$accountPassword | Out-Null
			$memberShip = Get-TierMemberShip -AccountName $accountName -Credential $accountName,$accountPassword

			if( $memberShip -eq $null -or $memberShip -eq "" -or $memberShip.Count -lt 1 ){
				[System.Windows.Forms.MessageBox]::Show("Invalid $accountName credentials or not in a Tiering group", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
				continue
			}

			if( $TierLevel -ne "" -and $TierLevel -ne $memberShip -and -not ($TierLevel -in $memberShip) ){
				[System.Windows.Forms.MessageBox]::Show("$accountName is not in the correct Tier Level", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
				continue
			}
			if( $TierLevel -eq "" ){
				$TierLevel = $memberShip
			}
			if( $TierLevel -ne "" ){
				Set-CachedCredzTiering -AccountName $accountName -AccountPassword $accountPassword -TierLevel $TierLevel | Out-Null
			}			
			MyLog "DEBUG (Get-ValidCredentials): accountName=$accountName" | Out-Null
			return @($accountName,$accountPassword)
		}catch{
			MyLog $($_ |Out-String) | Out-Null
			MyLog $($_ | Format-List * -Force | Out-String) | Out-Null
			[System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
		}	
	}
}


<##################################################################################################
.SYNOPSIS
Displays a notification message to the user.

.DESCRIPTION
The Show-Notification function is used to display a notification message to the user. This can be useful for alerting the user to important information or updates.

.PARAMETER Message
The message to be displayed in the notification.

.PARAMETER Title
The title of the notification window.

.EXAMPLE
Show-Notification -Message "Task completed successfully" -Title "Task Status"
This example displays a notification with the message "Task completed successfully" and the title "Task Status".
#>
function Show-Notification {
	param (
		[string]$Title = "PowerCredzMan",
		[string]$Message = "Ceci est une notification.",
		[System.Windows.Forms.ToolTipIcon]$Icon = [System.Windows.Forms.ToolTipIcon]::Info,
		[int]$Timeout = 5000 # Durée en millisecondes (5 secondes par défaut)
	)
	if( $global:NotifyIcon -eq $null ){
		return
	}
	$global:NotifyIcon.BalloonTipTitle = $Title
	$global:NotifyIcon.BalloonTipText = $Message
	$global:NotifyIcon.BalloonTipIcon = $Icon
	$global:NotifyIcon.ShowBalloonTip($Timeout) | Out-Null
}


<##################################################################################################
.SYNOPSIS
Establishes a connection to an LDAP server.

.DESCRIPTION
The Get-LdapConnection function creates a connection to an LDAP server using the provided distinguished name and credentials. 
It supports secure, encrypted, read-only, and signed connections.

.PARAMETER DistenquishedName
The distinguished name (DN) to connect to within the LDAP server. If provided, it will be prefixed with a '/'.

.PARAMETER Credential
An array of strings containing the LDAP URI, username, and password. The function retrieves these values using the Get-LDAPUri function.

.RETURNS
Returns a DirectoryEntry object representing the LDAP connection.

.EXAMPLE
$credential = @("dom\username", "password")
$dn = "CN=Users,DC=example,DC=com"
$ldapConnection = Get-LdapConnection -DistenquishedName $dn -Credential $credential

.NOTES
If the distinguished name is null or empty, it will not be included in the connection string.
If the username is null, the connection will be made anonymously.
If an error occurs during the connection attempt, an exception will be thrown with a message indicating the failure reason.
#>
Function Get-LdapConnection {
	param (
		[string]$DistenquishedName,
		[string[]]$Credential
	)
	try{
		if( $DistenquishedName -ne $null -and $DistenquishedName -ne "" ){
			$DistenquishedName = "/"+$DistenquishedName
		}
		$authType = [System.DirectoryServices.AuthenticationTypes]::Secure + [System.DirectoryServices.AuthenticationTypes]::Encryption + [System.DirectoryServices.AuthenticationTypes]::ReadonlyServer + [System.DirectoryServices.AuthenticationTypes]::Signing
		$authType = $null
		$uri,$username,$password = Get-LDAPUri $Credential
		if( $username -ne $null ){
			$directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("$uri$DistenquishedName", $username, $password)
		}else{
			$directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("$uri$DistenquishedName")
		}
		$directoryEntry.ToString() | Out-Null
		return $directoryEntry
	}catch{
		$err = $_.Exception.Message
		if( $err.Contains('ToString":') ){
			$err = ($err -Split 'ToString":')[1].Trim("`r`n\r\n. `"")
		}
		throw "Unable to connect to LDAP server: $err"
	}
	return $null
}


<##################################################################################################
.SYNOPSIS
Retrieves an Active Directory Service Interfaces (ADSI) object.

.PARAMETER Name
The name of the ADSI object to retrieve.

.PARAMETER ObjectClass
The class of the ADSI object to retrieve. Defaults to "*".

.PARAMETER Credential
An array of credentials to use for the ADSI object retrieval. Defaults to $null.

.EXAMPLE
Get-ADSIObject -AccountName "CN=John Doe,OU=Users,DC=example,DC=com" -Credential 'dom\user','password'
Get-ADSIObject -AccountName "John Doe" -ObjectClass Group -Credential 'dom\user','password'
#>
function Get-ADSIObject {
	param (
		[string]$AccountName,
		[string]$ObjectClass	  = "*",
		[string[]]$Credential	 = $null
	)
	if( -not ($AccountName -is [string]) ){
		throw "AccountName is not a String type => $AccountName"
	}
	if( $AccountName -eq $null -or $AccountName -eq "" ){
		throw "AccountName is empty"
	}
	$ObjectClass = $ObjectClass.ToLower()
	# Définir le chemin LDAP en fonction du type
	switch ($ObjectClass) {
		"computer" { $ObjectClass = "computer" }
		"user"	 { $ObjectClass = "user" }
		"group"	 { $ObjectClass = "group" }
		"*"	 { $ObjectClass = "*" }
		default	{ throw "Invalid type. Use 'Computer' or 'User' or  'Group'." }
	}
	if( $AccountName.Contains('\') ){
		$AccountName = $AccountName.Split('\')[1]
	}
	if( $AccountName.Contains('@') ){
		$AccountName = $AccountName.Split('@')[0]
	}
	
	try {
		$directoryEntry = Get-LdapConnection -Credential $Credential
		
		# Créer un objet DirectorySearcher
		$searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
		$searcher.Filter = "(&(objectClass=$ObjectClass)(|(samAccountName=$AccountName)(name=$AccountName)(distinguishedName=$AccountName)))"
		$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
		$searcher.PropertiesToLoad.Add("name") | Out-Null
		$searcher.PropertiesToLoad.Add("memberOf") | Out-Null
		if( $ObjectClass -eq "computer" ){
			$searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd") | Out-Null
			$searcher.PropertiesToLoad.Add("ms-LAPS-Password") | Out-Null
			$searcher.PropertiesToLoad.Add("ms-LAPS-EncryptedPassword") | Out-Null
		}

		# Effectuer la recherche
		$result = $searcher.FindOne()

		if ($result -ne $null) {
			return $result.GetDirectoryEntry()
		}
		return $null
	}catch {
		MyLog "Erreur lors de la recherche de l'objet AD: $_" | Out-Null
		MyLog $($_ |Out-String) | Out-Null
		MyLog $($_ | Format-List * -Force | Out-String) | Out-Null
		throw $_
	}
}


<##################################################################################################
.SYNOPSIS
Retrieves the LDAP URI along with the username and password based on the provided credentials or global variables.

.PARAMETER Credential
An optional array containing the username and password. The username can be in the format of domain\user, user@domain, or domain\user@dc-ip.

.DESCRIPTION
The Get-LDAPUri function constructs an LDAP URI using the provided credentials or global variables. It handles different username formats and determines if the domain is an IP address or a domain name. If no credentials are provided, it attempts to use the global LambdaAccount variable.

.INPUTS
[string[]] $Credential
An optional array containing the username and password.

.OUTPUTS
[string] $LDAPUri
[string] $username
[string] $password

.EXAMPLE
PS> Get-LDAPUri -Credential @("domain\user", "password")
Returns the LDAP URI, username, and password based on the provided credentials.

.EXAMPLE
PS> Get-LDAPUri
Returns the LDAP URI, username, and password based on the global LambdaAccount variable or the current user's domain.

.NOTES
The function checks if the domain part of the username is an IP address and adjusts accordingly. It also handles different username formats and uses global variables if no credentials are provided.
#>
Function Get-LDAPUri
{
	param (
		[string[]]$Credential = $null
	)
	$domain = $env:USERDOMAIN

	if ($Credential) {
		$Credential = @() + $Credential
		$username = $Credential[0]# Format: domain\user | user@domain | domain\user@dc-ip
		$password = $Credential[1]


		# domain\user@dc-ip
		if( $username.Contains('\') -and $username.Contains('@') ){
			$tmp = $username.Split('@')
			$domain = $tmp[1]
			$username = $tmp[0]
		}elseif( $username.Contains('\') ){
			$tmp = $username.Split('\')
			$domain = $tmp[0]
		}elseif( $username.Contains('@') ){
			$tmp = $username.Split('@')
			$domain = $tmp[1]
			$username = $domain+'\'+$tmp[0]
		}
		# Check if $domain is an IP
		try{
			[int]($domain.Replace('.','')) | Out-Null
			# Is an IP
		}catch{
			# Is a domain
			if( $global:LambdaAccount -ne $null -and $global:LambdaAccount[0].Contains('@') -and $global:LambdaAccount[0].Contains('\') ){
				$domain = $global:LambdaAccount[0].split('@')[1]
			}
		}
		return "LDAP://$domain",$username,$password
	}

	if( $global:LambdaAccount -ne $null -and $global:LambdaAccount[0].Contains('@') -and $global:LambdaAccount[0].Contains('\') ){
		$tmp = $global:LambdaAccount[0].split('@')
		$domain = $tmp[1]
		$username = $tmp[0]
		$password = $global:LambdaAccount[1]
		return "LDAP://$domain",$username,$password
	}

	return "LDAP://$domain",$null,$null
}


<##################################################################################################
.SYNOPSIS
	Retrieves the transitive membership of an Active Directory object.

.DESCRIPTION
	The Get-ADSIMemberOfTransitive function takes a distinguished name of an Active Directory object and retrieves all groups that the object is a member of, including nested group memberships.

.PARAMETER DistenquishedName
	The distinguished name of the Active Directory object for which to retrieve the transitive membership.

.PARAMETER Credential
	Optional. An array of credentials to use for the Active Directory query. If not provided, the current user's credentials are used.

.EXAMPLE
	Get-ADSIMemberOfTransitive -DistenquishedName "CN=John Doe,OU=Users,DC=example,DC=com"
	Retrieves all groups that "John Doe" is a member of, including nested groups.

.EXAMPLE
	Get-ADSIMemberOfTransitive -DistenquishedName "CN=John Doe,OU=Users,DC=example,DC=com" -Credential @('domain\user', 'password')
	Retrieves all groups that "John Doe" is a member of, including nested groups, using the specified credentials.
#>
function Get-ADSIMemberOfTransitive
{
	param (
		[string]$DistenquishedName,
		[string[]]$Credential	 = $null
	)
	if( -not ($DistenquishedName -is [string]) ){
		throw "DistenquishedName is not a String type => $DistenquishedName"
	}
	if( $DistenquishedName -eq $null -or $DistenquishedName -eq "" ){
		throw "DistenquishedName is empty"
	}
	if( -not $DistenquishedName.StartsWith('CN=') ){
		throw "DistenquishedName is not a valid AD path (CN=xxx,OU=xxx,DC=xxx)"
	}
	$directoryEntry = $null
	$uri,$username,$password = Get-LDAPUri $Credential
	if( $username -ne $null ){
		$directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("$uri/$DistenquishedName", $username, $password)
	}else{
		$directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("$uri/$DistenquishedName")
	}

	$searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
	$searcher.PropertiesToLoad.Add("msds-memberOfTransitive") | Out-Null
	$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
	try {
		$ret = $searcher.FindOne()
		if( $ret -eq $null ){
			return $null
		}
		return $ret.Properties['msds-memberOfTransitive']
	}catch{
		MyLog "Erreur lors de la recherche de l'objet AD: $_" | Out-Null
		MyLog $($_ |Out-String) | Out-Null
		MyLog $($_ | Format-List * -Force | Out-String) | Out-Null
		return $null
	}
}


<##################################################################################################
.SYNOPSIS
Displays a form for Remote Desktop Protocol (RDP) credentials input.

.DESCRIPTION
The Show-RDPForm function creates and displays a graphical user interface (GUI) form 
that allows users to input their RDP credentials. This form can be used to securely 
collect and manage RDP login information.

.EXAMPLE
PS> Show-RDPForm
#>
function Show-RDPForm {
	# Créer le formulaire
	$form = New-Object System.Windows.Forms.Form
	$form.Text = "PowerCredzMan"
	$form.Size = New-Object System.Drawing.Size(350,200)
	$form.StartPosition = "CenterScreen"
	$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$form.MaximizeBox = $false

	# Ajouter une étiquette
	$label = New-Object System.Windows.Forms.Label
	$label.Text = "Computer Name :"
	$label.Location = New-Object System.Drawing.Point(10,20)
	$label.Size = New-Object System.Drawing.Size(120,20)
	$form.Controls.Add($label) | Out-Null

	# Ajouter une zone de texte
	$textbox = New-Object System.Windows.Forms.TextBox
	$textbox.Location = New-Object System.Drawing.Point(140,20)
	$textbox.Size = New-Object System.Drawing.Size(180,20)
	$textbox.Text = $global:LastComputer
	$form.Controls.Add($textbox) | Out-Null
	
	$lapsCheckbox = New-Object System.Windows.Forms.CheckBox
	$lapsCheckbox.Text = "Use LAPS if possible"
	$lapsCheckbox.Location = New-Object System.Drawing.Point(140,50)
	$lapsCheckbox.Size = New-Object System.Drawing.Size(150,20)
	$lapsCheckbox.Checked = $true
	$form.Controls.Add($lapsCheckbox) | Out-Null

	# Ajouter un bouton de validation
	$button = New-Object System.Windows.Forms.Button
	$button.Text = "Connect"
	$button.Location = New-Object System.Drawing.Point(130,90)
	$button.Size = New-Object System.Drawing.Size(80,30)
	$form.Controls.Add($button) | Out-Null

	# Événement clic sur le bouton
	$button.Add_Click({
		$computerName = $textbox.Text.Trim()
		$useLAPS = $lapsCheckbox.Checked
		if ($computerName -ne "") {
			$ret = Connect-RDP -ComputerName $computerName -UseLAPS $useLAPS
			if( $ret ){
				$form.Close()
				return
			}
			# Option 1 : Activer le formulaire
			$form.Activate()

			# Option 2 : Utiliser TopMost temporairement pour forcer l'apparition au premier plan
			$form.TopMost = $true
			Start-Sleep -Milliseconds 100
			$form.TopMost = $false
		}
		else {
			[System.Windows.Forms.MessageBox]::Show("Provide a valide computer name.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
		}
	}) | Out-Null

	# Gérer l'appui sur la touche Entrée dans la zone de texte
	$textbox.Add_KeyDown({
		param($sender, $e)
		if ($e.KeyCode -eq "Enter") {
			$button.PerformClick()
			$e.SuppressKeyPress = $true
		}
	}) | Out-Null
	
	$form.Add_Shown({
		# Option 1 : Activer le formulaire
		$form.Activate()

		# Option 2 : Utiliser TopMost temporairement pour forcer l'apparition au premier plan
		$form.TopMost = $true
		Start-Sleep -Milliseconds 100
		$form.TopMost = $false
	}) | Out-Null

	# Afficher le formulaire
	$form.ShowDialog()  | Out-Null
}


<##################################################################################################
.SYNOPSIS
Establishes a Remote Desktop Protocol (RDP) connection to a specified remote machine.

.DESCRIPTION
Connect-RDP is a function that establishes an RDP connection to a remote machine using the specified computer name or IP address and optionally the Local Administrator Password Solution (LAPS).
This function can be used to connect to remote machines securely and efficiently.

.PARAMETER ComputerName
Specifies the name or IP address of the remote computer to which you want to connect.

.PARAMETER UseLAPS
Specifies if the Local Administrator Password Solution (LAPS) should be used for the connection.

.EXAMPLE
PS C:\> Connect-RDP -ComputerName "192.168.1.10"

.EXAMPLE
PS C:\> Connect-RDP -ComputerName "server01" -UseLAPS $true
#>
function Connect-RDP {
	param(
		[string]$ComputerName,
		[bool]$UseLAPS = $false
	)

	try {
		# Vérifier si la machine existe dans le domaine
		$computer = $null
		try{
			$computer = Get-ADSIObject $ComputerName -ObjectClass Computer
		}catch{
			[System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
			return $false
		}
		if( $computer -eq $null ){
			[System.Windows.Forms.MessageBox]::Show("Computer '$ComputerName' not found.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
			return $false
		}

		$matchedGroupType = Get-TierMemberShip -AccountName $ComputerName 


		if ($matchedGroupType.Count -ne 1) {
			[System.Windows.Forms.MessageBox]::Show("No Tiering group found for '$ComputerName'.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
			return $false
		}

		$accountName = ''
		$accountPassword = ''
		
		$credz = Get-CachedCredzTiering -TierLevel $matchedGroupType
		if( $credz -ne $null -and $credz.Count -eq 2 ){
			$accountName = $credz[0]
			$accountPassword = $credz[1]
		}else{
			$vcredz = Get-ValidCredentials -UserName "$($global:DefaultDomainName)\${matchedGroupType}_$($env:USERNAME)" -Message "Please, provide password for account type $matchedGroupType" -TierLevel $matchedGroupType
			if( $vcredz -eq $null -or $vcredz.Count -ne 2 ){
				return $false
			}
			$accountName = $vcredz[0]
			$accountPassword = $vcredz[1]
		}

		# Check crez
		$computerViewWithAdmAccount = $null
		try {
			$computerViewWithAdmAccount = Get-ADSIObject -AccountName $ComputerName -ObjectClass Computer -Credential $accountName,$accountPassword
		}catch{
			[System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
			Remove-CachedCredzTiering -AccountName $accountName
			return Connect-RDP -ComputerName $ComputerName -UserLAPS $UseLAPS
		}
		
		if( $UseLAPS ){
			$via = "$($env:USERDNSDOMAIN)\$($env:USERNAME)"
			if( $global:LambdaAccount -ne $null ){
				$via = $global:LambdaAccount[0]
			}
			@('ms-Mcs-AdmPwd','ms-LAPS-Password','ms-LAPS-EncryptedPassword') | %{
				$attribute = $_
				try{
					$localPassword = $computer.Properties[$attribute]
					if( $localPassword.Count -eq 1 -and $localPassword[0] -ne $null -and $localPassword[0] -ne "" ){
						MyLog "Via $via, found LAPS ($attribute) usage on this server, using local administrator"
						Show-Notification -Title "PowerCredzMan" -Message "Via $via, found LAPS ($attribute) usage on this server, using local administrator"
						$localPassword = $localPassword[0]
					}else{
						$localPassword = $computerViewWithAdmAccount.Properties[$attribute]
						if( $localPassword.Count -eq 1 -and $localPassword[0] -ne $null -and $localPassword[0] -ne "" ){
							MyLog "Via $accountName, found LAPS ($attribute) usage on this server, using local administrator"
							Show-Notification -Title "PowerCredzMan" -Message "Via $accountName, found LAPS ($attribute) usage on this server, using local administrator"
							$localPassword = $localPassword[0]
						}else{
							$localPassword = $null
						}
					}
					
					if( $localPassword -ne $null -and $localPassword -ne "" ){					
						if( $attribute -eq 'ms-Mcs-AdmPwd' ){
							$accountName = '.\Administrator'
							$accountPassword = $localPassword
						}elseif( $attribute -eq 'ms-LAPS-Password' ){
							# {"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%eb!57be4a4B95Z43394ba956de69e5d8975#$8a6d)4f82da6ad500HGx"}
							try {
								$tmp = $localPassword | ConvertFrom-JSON
								$accountName = '.\'+$tmp.n
								$accountPassword = $tmp.p
							}catch{								
								throw "Invalid ms-LAPS-Password format ! => $localPassword"
							}
						}elseif( $attribute -eq 'ms-LAPS-EncryptedPassword' ){
							# To UnCrypt => https://blog.xpnsec.com/lapsv2-internals/
							# {"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%eb!57be4a4B95Z43394ba956de69e5d8975#$8a6d)4f82da6ad500HGx"}
							throw "ms-LAPS-EncryptedPassword Is used but is not supported ! => $localPassword"

							# try {
							# 	$tmp = $localPassword | ConvertFrom-JSON
							# 	$accountName = ".\"+$tmp.n
							# 	$accountPassword = $tmp.p
							# }catch{
							# 	[System.Windows.Forms.MessageBox]::Show("Invalid ms-LAPS-EncryptedPassword format ! => $localPassword", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
							# 	throw "Invalid ms-LAPS-EncryptedPassword format ! => $localPassword"
							# }
						}
					}
				}catch{
					MyLog $($_ |Out-String) | Out-Null
					MyLog $($_ | Format-List * -Force | Out-String) | Out-Null
					[System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
				}
			}
		}
		
		$global:LastComputer = $ComputerName

		# Ajouter les informations d'identification via cmdkey
		cmdkey /generic:"$ComputerName" /user:"$accountName" /password:"$accountPassword" | Out-Null

		# Lancer la session RDP
		Start-Process -WindowStyle Hidden "cmd.exe" "/c","mstsc /v:$ComputerName /span /admin & ping 127.0.0.1 -c 15 & cmdkey /delete:$ComputerName" | Out-Null
		
		return $true
	} catch {
		MyLog $($_ |Out-String) | Out-Null
		MyLog $($_ | Format-List * -Force | Out-String) | Out-Null
		[System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
		return $false
	}
}


#################################################################################################
#################################################################################################
# If Out Of Domain, ask for basic credentials

if( $env:LOGONSERVER -eq "\\$($env:USERDOMAIN)" ){
	$global:LambdaAccount = Get-ValidCredentials -UserName "domain\user@dc-ip" -Message "Your computer is out of any domain, please provide basic credentials for basic queries" -TierLevel $null
	if( $global:LambdaAccount -eq $null ){
		[System.Windows.Forms.MessageBox]::Show("Unable to join domain from an unjoin computer", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
		exit
	}
	if( $global:LambdaAccount[0].Contains('\') -and $global:LambdaAccount[0].Contains('@') ) {
		$global:DefaultDomainName = $global:LambdaAccount[0].Split('\')[0]
	}
}


#################################################################################################
#################################################################################################
# MAIN

try {
	$icon = [System.Drawing.Icon]::ExtractAssociatedIcon([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}catch {
	Write-Warning "Impossible d'extraire l'icône de l'exécutable. Utilisation d'une icône par défaut."
	# Utiliser une icône par défaut si l'extraction échoue
	$icon = [System.Drawing.SystemIcons]::Application
}

# Créer une nouvelle icône dans la barre des tâches
$global:NotifyIcon = New-Object System.Windows.Forms.NotifyIcon
$global:NotifyIcon.Icon = $icon
$global:NotifyIcon.Visible = $true
$global:NotifyIcon.Text = "PowerCredzMan"

# Créer un menu contextuel pour l'icône (optionnel)
$contextMenu = New-Object System.Windows.Forms.ContextMenu
$exitMenuItem = New-Object System.Windows.Forms.MenuItem "Quit"
$exitMenuItem.add_Click({
	$global:NotifyIcon.Visible = $false
	[System.Windows.Forms.Application]::Exit()
}) | Out-Null
$contextMenu.MenuItems.Add($exitMenuItem) | Out-Null
$global:NotifyIcon.ContextMenu = $contextMenu

# Définir le gestionnaire d'événements pour le clic sur l'icône
$global:NotifyIcon.add_Click({
	# Afficher le formulaire lors d'un clic ou d'un double-clic
	Show-RDPForm
}) | Out-Null


# Garder le script en cours d'exécution
[System.Windows.Forms.Application]::Run() | Out-Null