1) View current LogonServer

```powershell
C:\> set lo
LOGONSERVER=\\DC01
```

2) Switch the domain controller computer used (cmd as local admin)

```powershell
C:\> nltest /SC_RESET:DomainName\DomainControllerName
```

3) Set Domain Controller Via Registry
In `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` in a String `SiteName` set `DC1.domain.com`
