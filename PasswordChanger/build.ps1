git clone https://github.com/MScholtes/PS2EXE $env:temp\PS2EXE
Import-Module $env:temp\PS2EXE\Module\ps2exe.ps1
rm -Force -Recurse $env:temp\PS2EXE
Invoke-ps2exe -inputFile .\PasswordChanger.ps1 -outputFile .\PasswordChanger.exe -x64 -UNICODEEncoding -iconFile .\logger.ico -title "PasswordChanger - SecureDomain" -company "SecureDomain - OpenSource Password Changer" -version 2024.07.22