function Find-VulnerableManagedIdentities {
    <#
    .SYNOPSIS
    Identifies Azure Managed Identities with critical role assignments that could be used to escalate privileges.

    .DESCRIPTION
    This function connects to Microsoft Graph using an access token (can be created via AADinternals module), then:
      - Retrieves an access token and sets up necessary HTTP headers.
      - Defines a non-exhaustive list of critical roles (e.g. RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All, etc.) 
        and additional transitive roles (e.g. Global Administrator, Application Administrator) that are known to be exploitable for privilege escalation.
      - Queries Microsoft Graph to locate the Microsoft Graph service principal and retrieves its app roles.
      - Constructs a mapping of critical roles by matching the list against the available app roles.
      - Finds all Managed Identities (both User Assigned and System Assigned) in Azure Active Directory that are enabled.
      - Extracts crucial information regarding the Managed Identities.
      - Additionally, the function searches for Azure AD groups (sourced from on-premises sync) that might provide Azure Resource Manager (ARM) permissions by looking for specific keywords in group properties. 
        If found, it recursively traverses group memberships to flag potential escalation vectors.

    .PARAMETER AccessToken
    A [String] representing a valid Microsoft Graph API access token.

    .OUTPUTS
    A [PSCustomObject] with the following properties:
      - **ManagedIdentities**: An array of PSCustomObject representing potential Managed Identities to compromise. Each object includes properties such as:
          - *ManagedIdentityName*: The display name of the Managed Identity.
          - *ManagedIdentityId*: The unique identifier of the Managed Identity.
          - *ManagedIdentityType*: The type of Managed Identity (User Assigned (UAMI) or System Assigned (SAMI)).
          - *CriticalAssignedRoles*: The critical app roles directly assigned to the identity.
          - *CriticalTransitiveRoles*: The critical roles inherited transitively.
          - *SubscriptionId*: The subscription ID extracted from the identity's metadata.
          - *ResourceGroup*: The resource group name extracted from the identity's metadata.
      - **VulnerableGroups**: An array of group objects that are potentially vulnerable (i.e., synced from on-premises) and may have Azure Resource Manager (ARM) privileges.

    .EXAMPLE
    PS C:\> $AccessToken = Get-AADIntAccessTokenForMSGraph -Credentials $(Get-Credential)
    PS C:\> Find-VulnerableManagedIdentities -AccessToken $AccessToken

    .NOTES
    - Some iutput is written to the host using Write-Host.
    - Written by Omri Refaeli.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Provide a valid Microsoft Graph API access token.")]
        [string]$AccessToken
    )

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }
    $headersConsistency = @{
        "Authorization"   = "Bearer $accessToken"
        "Content-Type"    = "application/json"
        "ConsistencyLevel" = "eventual"    # Required for some queries (e.g., $count)
    }

    # Non-Exhaustive list of critical roles that can directly be used to escalate to Global Admin
    $criticalRoles = @("RoleManagement.ReadWrite.Directory","AppRoleAssignment.ReadWrite.All","Directory.ReadWrite.All","PrivilegedAccess.ReadWrite.AzureADGroup","Group.ReadWrite.All","User.ReadWrite.All","Application.ReadWrite.All")
    $criticalTransitiveRoles = @("Global Administrator", "Application Administrator") # TODO add more

    $msGraphFilter = "displayName eq 'Microsoft Graph'"
    $msGraphResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$msGraphFilter" -Headers $headers -Method GET
    $graphServicePrincipalId = $msGraphResponse.value[0].id

    $msGraphDetailsUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$graphServicePrincipalId"
    $msGraphDetails = Invoke-RestMethod -Uri $msGraphDetailsUri -Headers $headers -Method GET
    $graphAppRoles = $msGraphDetails.appRoles

    $criticalRolesDict = @{}
    $groupKeyWords = @{
    Owner = "GeneralKeyWord"
    Contrib = "GeneralKeyWord"
    Subscription = "GeneralKeyWord"
    ResourceGr = "GeneralKeyWord"
    'Resource Group' = "GeneralKeyWord"
    _RG = "GeneralKeyWord"
    }

    # Match critical roles with app roles and populate the dictionary
    foreach ($role in $criticalRoles) 
    { 
        $roleId = $graphAppRoles | Where-Object { $_.Value -eq $role } | select -ExpandProperty Id
        $criticalRolesDict[$roleId] = $role
    }

    # Finding all Managed Identities (an Azure resource, but can have Graph permissions in Entra)
    $managedIdentityUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=servicePrincipalType eq 'ManagedIdentity'"
    $managedIdentityResponse = Invoke-RestMethod -Uri $managedIdentityUri -Headers $headers -Method GET
    $spns = $managedIdentityResponse.value | Where-Object { $_.accountEnabled -eq $true }

    #$spns = Get-MgServicePrincipal -Filter "servicePrincipalType eq 'ManagedIdentity'" | Where-Object {$_.AccountEnabled -eq "True"}

    $potentialSpnsToCompromise = New-Object System.Collections.ArrayList
    $SpnPattern = "isExplicit=(?<isExplicit>\w+)[\s\S]*?/subscriptions/(?<subscription>[-\d\w]+)/resourcegroups/(?<resourcegroup>.+?)/"


    # AppRolesAssignments are not retrieved with Get-MgServicePrincipal for some reason, let's get them directly for each identity
    foreach ($spn in $spns)
    {
        $assignedCriticalRoles = @()
        $transitiveCriticalRoles = @()

        $appRoleAssignmentsUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($spn.id)/appRoleAssignments"
        $appRoleAssignmentsResponse = Invoke-RestMethod -Uri $appRoleAssignmentsUri -Headers $headers -Method GET
        $spnAppRoles = $appRoleAssignmentsResponse.value | Where-Object { $_.resourceId -eq $graphServicePrincipalId -and ($criticalRolesDict.Keys -contains $_.appRoleId) }
    
        $transitiveMemberOfUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($spn.id)/transitiveMemberOf"
        $transitiveMemberOfResponse = Invoke-RestMethod -Uri $transitiveMemberOfUri -Headers $headers -Method GET
        $transitiveMemberOf = $transitiveMemberOfResponse.value | Where-Object { $_.displayName -and ($criticalTransitiveRoles -contains $_.displayName) }

        if ($spnAppRoles)
        {
           # Get all critical app roles assigned to this SPN
            foreach ($roleAssignment in $spnAppRoles) {
                $criticalRoleDetails = $criticalRolesDict[$roleAssignment.AppRoleId]
                if ($criticalRoleDetails) {
                    $assignedCriticalRoles += $criticalRoleDetails
                }
            }

        }

        if ($transitiveMemberOf)
        {
            if ($transitiveMemberOf -is [PSCustomObject]) # Only one role ==> a PSCustomObject
            {
                $transitiveCriticalRoles += $transitiveMemberOf['displayName']
            }
            elseif ($transitiveMemberOf -is [System.Array]) # Multiple roles ==> Array
            {
              $transitiveMemberOf | ForEach-Object {$transitiveCriticalRoles += $_['displayName']}
            }
            else
            {
                write-host -ForegroundColor Red "Something was wrong with parsing the transitive membership of $($spn.DisplayName) - $transitiveMemberOf"
            }
        }

        if ($transitiveMemberOf -or $spnAppRoles) # Found Critical Managed Identity
        {
            $match = [regex]::Match($spn.AlternativeNames, $SpnPattern)
            if ($match.Success) {
                # Extract values using capture groups , should always be able to parse
                $isExplicit = $match.Groups[1].Value
                $subscriptionId = $match.Groups[2].Value
                $resourceGroup = $match.Groups[3].Value
            } else {
                Write-host -ForegroundColor Red "Coldn't parse AlternativeName for SPN $($spn.AppDisplayName)."
            }

            if ($isExplicit -eq "True") # Checks if UAMI or SAMI
            {
                 $spnType = "UAMI" # User Assigned Managed Identity
            }
            else 
            {
                $spnType = "SAMI" # System Assigned Managed Identity
            }

            $singleSpn = [PSCustomObject]@{
            ManagedIdentityName          = $spn.DisplayName
            ManagedIdentityId            = $spn.Id
            ManagedIdentityType          = $spnType
            CriticalAssignedRoles        = $assignedCriticalRoles
            CriticalTransitiveRoles      = $criticalTransitiveRoles
            SubscriptionId               = $subscriptionId
            ResourceGroup                = $resourceGroup
            }
        
            # Add to keyword search
            if ($groupKeyWords.Keys -contains $subscriptionId -and $groupKeyWords[$subscriptionId] -is [System.Array])
            {
                $groupKeyWords[$subscriptionId]   += $spn
            }
            else
            {
                $groupKeyWords[$subscriptionId] = @($spn)
            }

            if ($groupKeyWords.Keys -contains $resourceGroup -and $groupKeyWords[$resourceGroup] -is [System.Array])
            {
                $groupKeyWords[$resourceGroup]   += $spn
            }
            else
            {
                $groupKeyWords[$resourceGroup] = @($spn)
            }

            $potentialSpnsToCompromise.Add($singleSpn) | Out-Null
          }
    }


    $potentialSpnsToCompromise | ForEach-Object {
        # If these properties are arrays, join their elements into a comma-separated string
        $assignedRoles   = $_.CriticalAssignedRoles -join ', '
        $transitiveRoles = $_.CriticalTransitiveRoles -join ', '

        $output = @"
    Found potential Managed Identities to compromise:
      ManagedIdentityName:     $($_.ManagedIdentityName)
      ManagedIdentityId:       $($_.ManagedIdentityId)
      ManagedIdentityType:     $($_.ManagedIdentityType)
      CriticalAssignedRoles:   $assignedRoles
      CriticalTransitiveRoles: $transitiveRoles
      SubscriptionId:          $($_.SubscriptionId)
      ResourceGroup:           $($_.ResourceGroup)

"@

        Write-Host -ForegroundColor Green $output
    }

    Write-Host -ForegroundColor Yellow "Can't read ARM permissions with sync account, if we had Read permissions over a subscriptions it would have been easier..
    Instead we are looking for keywords in groups to find Azure Subscriptions\ResourceGroups related groups, since we are able to add ourselves to any synced group, we just have to find the right one"

    $groupsToCheck = [System.Collections.ArrayList]@() 
    $allGroups = @() 

    $groupsUrl = "https://graph.microsoft.com/v1.0/groups?`$filter=securityEnabled eq true&`$top=999"
    do {
        $response = Invoke-RestMethod -Uri $groupsUrl -Headers $headersConsistency -Method GET
        if ($response.value) {
            $allGroups += $response.value
        }
        $groupsUrl = $response.'@odata.nextLink'
    } while ($groupsUrl)


    # Find potential groups that have ARM privileges
    foreach ($group in $allGroups) {
        $displayName = $group.DisplayName
        $description = $group.Description

        # Loop through each keyword defined in your dictionary.
        foreach ($keyword in $groupKeyWords.Keys) {
            if ([string]::IsNullOrEmpty($keyword)) { continue }

            # Perform a case-insensitive check if the keyword is present
            # in either the DisplayName or Description.
            if ( ($displayName -and $displayName.ToLower().Contains($keyword.ToLower())) -or
                 ($description -and $description.ToLower().Contains($keyword.ToLower())) ) {
            
                # Add the group to $groupsToCheck if it hasn't been added already.
                if (-not $groupsToCheck.Contains($group)) {
                    $groupsToCheck.Add($group) | Out-Null
                }
                # Once a match is found for this group, move to the next group.
                break
            }
        }
    }

    $groupsIdsToCheck = [System.Collections.ArrayList]@() #IDs
    $CheckedGroupsIds = [System.Collections.ArrayList]@()
    $VulnerableGroups = [System.Collections.ArrayList]@()

    # Struct to enable looping recursively
    foreach ($group in $groupsToCheck)
    {
        $groupWithContext = [PSCustomObject]@{
            groupId = $group.Id
            rootGroupId = $group.Id
            rootGroupName = $group.DisplayName
            rootGroupDescription = $group.Description
        }
        $groupsIdsToCheck.Add($groupWithContext) | Out-Null
    }

    # Loop through all groups to find a synced group that is a candidate
    While ($groupsIdsToCheck.Count -gt 0)
    {
        $group = $groupsIdsToCheck[0]
        $groupId = $group.groupId
        $groupsIdsToCheck.RemoveAt(0)
        if ($CheckedGroupsIds -contains $groupId) # Just in case
        {
            continue
        }
        $CheckedGroupsIds.Add($groupId) | Out-Null
        $vulnGroup = $allGroups | where {$_.Id -eq $groupId}

        if ($vulnGroup.OnPremisesSyncEnabled -eq "True")
        {
            
            $vulnGroup | Add-Member -MemberType NoteProperty -Name rootGroupId -Value $group.rootGroupId
            $vulnGroup | Add-Member -MemberType NoteProperty -Name rootGroupName -Value $group.rootGroupName
            $vulnGroup | Add-Member -MemberType NoteProperty -Name rootGroupDescription -Value $group.rootGroupDescription
            $VulnerableGroups.Add($vulnGroup) | Out-Null
            Write-Host -ForegroundColor Green "Found potentially vulnerable synced group! Group: $($vulnGroup.DisplayName) ($($vulnGroup.Id)); A transitive member of the potentially ARM privileged group '$($group.rootGroupName)' ($($group.rootGroupId)), Description: $($group.rootGroupDescription)"
        }
        $members = @()
        $membersUrl = "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$top=999"

        do {
            $response = Invoke-RestMethod -Uri $membersUrl -Headers $headersConsistency -Method GET
            if ($response.value) {
                $members += $response.value
            }
            $membersUrl = $response.'@odata.nextLink'

        } while ($membersUrl)

        $members = $members | Where-Object {($_.'@odata.type' -eq '#microsoft.graph.group' -or $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group') -and $CheckedGroupsIds -notcontains $_.Id }
        foreach ($member in $members)
        {
             $groupWithContext = [PSCustomObject]@{
                groupId = $member.Id
                rootGroupId = $group.rootGroupId
                rootGroupName = $group.rootGroupName
                rootGroupDescription = $group.rootGroupDescription
            }
            $groupsIdsToCheck.Add($groupWithContext) | Out-Null
        }

    }
    return [PSCustomObject]@{
    ManagedIdentities = $potentialSpnsToCompromise
    VulnerableGroups  = $VulnerableGroups
    }
}

# Import the required AADinternals module
Import-Module AADinternals -RequiredVersion 0.9.7

$passwd = ConvertTo-SecureString 'bla' -AsPlainText -Force
$user = "bla@bla.onmicrosoft.com"
$creds = New-Object System.Management.Automation.PSCredential ($user, $passwd)
$at = Get-AADIntAccessTokenForMSGraph -Credentials $creds

Find-VulnerableManagedIdentities -AccessToken $at
