git clone https://github.com/MScholtes/PS2EXE $env:temp\PS2EXE
Import-Module $env:temp\PS2EXE\Module\ps2exe.ps1
rm -Force -Recurse $env:temp\PS2EXE
$data = cat .\PowerCredzMan.ps1
$data.Replace('EnableLog = $true','EnableLog = $false') | Out-File -Encoding UTF8 .\PowerCredzMan_toexe.ps1
Invoke-ps2exe -inputFile .\PowerCredzMan_toexe.ps1 -noConsole -outputFile .\PowerCredzMan.exe -x64 -UNICODEEncoding -iconFile .\logger.ico -title "PowerCredzMan - SecureDomain" -company "SecureDomain - OpenSource Credz Manager" -version 2024.10.15