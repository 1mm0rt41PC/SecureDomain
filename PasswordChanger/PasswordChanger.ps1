function Set-PasswordRemotely
{
    [CmdletBinding(DefaultParameterSetName = 'Secure')]
    param(
        [Parameter(ParameterSetName = 'Secure', Mandatory)][string] $UserName,
        [Parameter(ParameterSetName = 'Secure', Mandatory)][securestring] $OldPassword,
        [Parameter(ParameterSetName = 'Secure', Mandatory)][securestring] $NewPassword,
        [Parameter(ParameterSetName = 'Secure', Mandatory)][securestring] $NewPasswordConfirm,
        [Parameter(ParameterSetName = 'Secure')][alias('DC', 'Server', 'ComputerName')][string] $DomainController=($env:LOGONSERVER).replace('\\',''),
        [Parameter(ParameterSetName = 'Secure')][bool] $modeGUI=$false
    )
    Begin {
        $DllImport = @'
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
public static extern bool NetUserChangePassword(string domain, string username, string oldpassword, string newpassword);
'@
        $NetApi32 = Add-Type -MemberDefinition $DllImport -Name 'NetApi32' -Namespace 'Win32' -PassThru

        if (-not $DomainController) {
            if ($env:computername -eq $env:userdomain) {
                # not joined to domain, lets prompt for DC
                $DomainController = Read-Host -Prompt 'Domain Controller DNS name or IP Address'
            } else {
                $Domain = $Env:USERDNSDOMAIN
                $Context = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $Domain)
                $DomainController = ([System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($Context)).Name
            }
        }
    }
    Process {
        if ($DomainController -and $OldPassword -and $NewPassword -and $UserName -and $NewPasswordConfirm) {
			$pwd1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword))
			$pwd2_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPasswordConfirm))
			if( $pwd1_text -ne $pwd2_text ){
				$msg = "Password change for account $UserName failed. NewPassword and NewPasswordConfirm are not equal"
				if( $modeGUI ){
					(New-Object -ComObject Wscript.Shell).Popup($msg,0,"Password Changer",0x0)
				}else{
					Write-Host -Object "Set-PasswordRemotely - $msg" -ForegroundColor Red
				}
				Return $null
			}
            $OldPasswordPlain = [System.Net.NetworkCredential]::new([string]::Empty, $OldPassword).Password
            $NewPasswordPlain = [System.Net.NetworkCredential]::new([string]::Empty, $NewPassword).Password

            $result = $NetApi32::NetUserChangePassword($DomainController, $UserName, $OldPasswordPlain, $NewPasswordPlain)
            if ($result) {
				$msg = "Password change for account $UserName failed on $DomainController. Error: $result Please try again."
				$foregroundColor='Red'
            } else {
                $msg = "Password change for account $UserName succeeded on $DomainController."
				$foregroundColor='Cyan'
            }
			if( $modeGUI ){
				(New-Object -ComObject Wscript.Shell).Popup($msg,0,"Password Changer",0x0)
			}else{
				Write-Host -Object "Set-PasswordRemotely - $msg" -ForegroundColor $foregroundColor
			}
        } else {
            $msg='Password change for account failed. All parameters are required.'
			if( $modeGUI ){
				(New-Object -ComObject Wscript.Shell).Popup($msg,0,"Password Changer",0x0)
			}else{
				Write-Host -Object "Set-PasswordRemotely - $msg" -ForegroundColor 'Red'
			}
        }
    }
}
Set-PasswordRemotely -modeGUI $true > $null