$data=@()
Get-ADObject -SearchBase "CN=DisplaySpecifiers,CN=Configuration,DC=earth,DC=lo" -Filter * -Properties adminContextMenu,contextMenu | select DistinguishedName,adminContextMenu,contextMenu | %{
	$ret = 1 | Select DistinguishedName,adminContextMenu,contextMenu
	$ret.DistinguishedName=$_.DistinguishedName
	$_.adminContextMenu | %{
		$tmp = $ret | Select DistinguishedName,adminContextMenu,contextMenu
		$tmp.adminContextMenu = $_
		$data += @($tmp)
	}
	$_.contextMenu | %{
		$tmp = $ret | Select DistinguishedName,adminContextMenu,contextMenu
		$tmp.contextMenu = $_
		$data += @($tmp)
	}
}
$data | ConvertTo-Csv -NoTypeInformation | Out-File -Encoding ASCII DisplaySpecifiers.csv
# From: https://sdmsoftware.com/active-directory/active-directory-security-abusing-display-specifiers/
# Injection like "2,Reset Password…,\\gpaa\packages\resetpw.bat"
