<#
# Description:
#    PowerShell function that tries to give a friendly translation of Get-Acl into human readable data. The function is designed exclusively for Active Directory, and requires the ActiveDirectory Module.
# From:
#    https://github.com/santisq/Get-EffectiveAccess
# Examples:
#    Get-ADOrganizationalUnit -Filter "Name -eq 'ExampleOU'" | Get-EffectiveAccess | Out-GridView
#    Get-EffectiveAccess -Identity 'OU=ExampleOU,DC=domainName,DC=com' | Out-GridView
#    Get-ADObject -Filter * | Get-EffectiveAccess | ft *
#>
function Get-EffectiveAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidatePattern('(?:(CN=([^,]*)),)?(?:((?:(?:CN|OU)=[^,]+,?)+),)?((?:DC=[^,]+,?)+)$')]
        [alias('DistinguishedName')]
        [string] $Identity,

        [parameter()]
        [alias('Domain')]
        [string] $Server
    )

    begin {
        $guid    = [guid]::Empty
        $GUIDMap = @{}

        if($PSBoundParameters.ContainsKey('Server')) {
            $domain = Get-ADRootDSE -Server $Server
        }
        else {
            $domain = Get-ADRootDSE
        }

        $params = @{
            SearchBase  = $domain.schemaNamingContext
            LDAPFilter  = '(schemaIDGUID=*)'
            Properties  = 'name', 'schemaIDGUID'
            ErrorAction = 'SilentlyContinue'
        }
        $adObjParams = @{
            Properties = 'nTSecurityDescriptor'
        }

        if($PSBoundParameters.ContainsKey('Server')) {
            $params['Server']  = $Server
            $adObjParams['Server'] = $Server
        }
        $schemaIDs = Get-ADObject @params

        $params['SearchBase'] = "CN=Extended-Rights,$($domain.configurationNamingContext)"
        $params['LDAPFilter'] = '(objectClass=controlAccessRight)'
        $params['Properties'] = 'name', 'rightsGUID'
        $extendedRigths = Get-ADObject @params

        foreach($i in $schemaIDs) {
            if(-not $GUIDMap.ContainsKey([guid] $i.schemaIDGUID)) {
                $GUIDMap.Add([guid] $i.schemaIDGUID, $i.name)
            }
        }
        foreach($i in $extendedRigths) {
            if(-not $GUIDMap.ContainsKey([guid] $i.rightsGUID)) {
                $GUIDMap.Add([guid] $i.rightsGUID, $i.name)
            }
        }
    }

    process {
        try {
            $adObjParams['Identity'] = $Identity
            $object = Get-ADObject @adObjParams

            foreach($acl in $object.nTSecurityDescriptor.Access) {
                if($guid.Equals($acl.ObjectType)) {
                    $objectType = 'All Objects (Full Control)'
                }
                elseif($GUIDMap.ContainsKey($acl.ObjectType)) {
                    $objectType = $GUIDMap[$acl.ObjectType]
                }
                else {
                    $objectType = $acl.ObjectType
                }

                if($guid.Equals($acl.InheritedObjectType)) {
                    $inheritedObjType = 'Applied to Any Inherited Object'
                }
                elseif($GUIDMap.ContainsKey($acl.InheritedObjectType)) {
                    $inheritedObjType = $GUIDMap[$acl.InheritedObjectType]
                }
                else {
                    $inheritedObjType = $acl.InheritedObjectType
                }

                [PSCustomObject]@{
                    DistinguishedName     = $Identity
                    Name                  = $object.Name
                    IdentityReference     = $acl.IdentityReference
                    AccessControlType     = $acl.AccessControlType
                    ActiveDirectoryRights = $acl.ActiveDirectoryRights
                    ObjectType            = $objectType
                    InheritedObjectType   = $inheritedObjType
                    InheritanceType       = $acl.InheritanceType
                    IsInherited           = $acl.IsInherited
                }
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}
