git clone https://github.com/MScholtes/PS2EXE $env:temp\PS2EXE
Import-Module $env:temp\PS2EXE\Module\ps2exe.ps1
rm -Force -Recurse $env:temp\PS2EXE
Invoke-ps2exe -inputFile .\logger.ps1 -outputFile .\logger.exe -x64 -UNICODEEncoding -iconFile .\logger.ico -title "Logger - SecureDomain" -company "SecureDomain - OpenSource Logger" -version 2024.07.09 -requireAdmin