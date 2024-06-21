# 1) Enable audit mode for auth
# - Connect to your SQL server from the SQL Server Management Studio.
# - Right click on your SQL server in the object explorer (left column) and choose properties.
# - Click on the Security tab
# - Change Login auditing from “failed logins only” to “Both failed and successful logins”
# - Restart the service

Get-WinEvent -FilterHashtable @{ LogName='Application';	Id=18456 }
