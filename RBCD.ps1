Get-ADComputer -Filter * -Properties * | Format-List -Property Name,*delegat*,msDS-AllowedToActOnBehalfOfOtherIdentity
