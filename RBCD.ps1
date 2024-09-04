Get-ADComputer -Filter * -Properties * | Format-List -Property *delegat*,msDS-AllowedToActOnBehalfOfOtherIdentity
