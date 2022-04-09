1) Install the module on the primary DC `Get-ADForest | Select-Object SchemaMaster`
```ps1
if( -not (get-command choco.exe -ErrorAction SilentlyContinue) ){
	try {
		iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
	} catch {
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
		iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
	}
	set-alias -name choco -Value 'C:\ProgramData\chocolatey\bin\choco.exe'
}
# Installation of LAPS & LAPS UI on the DC
choco install laps --params='/ALL' -y
# Update the schema of the AD
Import-module AdmPwd.PS
Update-AdmPwdADSchema
# Set ACLs to set passwords in ms-Mcs-AdmPwd by SELF (computers)
Set-AdmPwdComputerSelfPermission -Identity <Base OU with computers>
```

2) Create the GPO - Auto LAPS deployement
```ps1
try {
	iwr https://raw.githubusercontent.com/1mm0rt41PC/SecureDomain/main/Function_New-GPOSchTask.ps1 -UseBasicParsing | iex
} catch {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
	iwr https://raw.githubusercontent.com/1mm0rt41PC/SecureDomain/main/Function_New-GPOSchTask.ps1 -UseBasicParsing | iex
}
New-GPOChoco -GPOName "[SD][Choco] LAPS" -TaskName "[SD][Choco] LAPS" -TaskType ImmediateTask -Command "powershell.exe" -CommandArguments '-exec bypass -nop -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex; C:\ProgramData\chocolatey\bin\choco.exe install -y laps"'
Set-GPRegistryValue -Name "[SD][Choco] LAPS" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName "AdmPwdEnabled" -Value 1 -Type Dword
Set-GPRegistryValue -Name "[SD][Choco] LAPS" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName "PwdExpirationProtectionEnabled" -Value 1 -Type Dword
Set-GPRegistryValue -Name "[SD][Choco] LAPS" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName "PasswordComplexity" -Value 4 -Type Dword
Set-GPRegistryValue -Name "[SD][Choco] LAPS" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName "PasswordLength" -Value 16 -Type Dword
Set-GPRegistryValue -Name "[SD][Choco] LAPS" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName "PasswordAgeDays" -Value 30 -Type Dword
```

3) Creation of the link. Make a link to the OU where the target computers are located. It is possible to restrict via targeting.


4) Test part. Connect to the "test" computer and run:
```batch
C:\> gpupdate /force
```

To check the deployment of choco & laps:
```batch
C:\> dir C:\ProgramData\chocolatey\bin\
C:\> C:\ProgramData\chocolatey\bin\choco.exe list -local
```

5) Check the status of the password in the DC, in a powershell with **ADMIN UAC**:
```ps1
Get-AdmPwdPassword -Name <test-computer>
```

In case of problem, you have to run a new `gpupdate /force` and if it fails, on the test computer:
- `rsop.msc`
- `gpresult /r`
- `gpresult /h C:\gpo.html`
