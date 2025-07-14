# Module: LeastPrivilegeIAMTools
function Invoke-LeastPrivilegeAudit {
    param (
        [string]$OutputPath = ".\OverprivilegedAppsAudit.txt"
    )

    Connect-MgGraph -Scopes "Application.Read.All", "AppRoleAssignment.Read.All", "DelegatedPermissionGrant.Read.All"
    "Audit Report - $(Get-Date)" | Out-File $OutputPath

    $apps = Get-MgApplication -All
    foreach ($app in $apps) {
        $appId = $app.AppId
        $displayName = $app.DisplayName
        $permissions = Get-MgServicePrincipalOauth2PermissionGrant -Filter "ClientId eq '$appId'" -ErrorAction SilentlyContinue

        if ($permissions) {
            foreach ($perm in $permissions) {
                $scope = $perm.Scope
                if ($scope -match "All" -or $scope -match "Write") {
                    "$displayName ($appId) has potentially overprivileged scope: $scope" | Out-File $OutputPath -Append
                }
            }
        }
    }
    Write-Host "Audit complete. Output saved to $OutputPath"
}

function Invoke-LeastPrivilegeReduction {
    param (
        [switch]$WhatIf
    )

    Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"

    $reductionMap = @{
        "User.ReadWrite.All"        = "User.Read.All"
        "Files.ReadWrite.All"       = "Files.Read.All"
        "Calendars.ReadWrite"       = "Calendars.Read"
        "Mail.ReadWrite"            = "Mail.Read"
        "Group.ReadWrite.All"       = "Group.Read.All"
        "Directory.ReadWrite.All"   = "Directory.Read.All"
        "Contacts.ReadWrite"        = "Contacts.Read"
        "Tasks.ReadWrite"           = "Tasks.Read"
        "Sites.ReadWrite.All"       = "Sites.Read.All"
        "Device.ReadWrite.All"      = "Device.Read.All"
    }

    $apps = Get-MgApplication -All
    foreach ($app in $apps) {
        $appId = $app.AppId
        $displayName = $app.DisplayName
        $grants = Get-MgServicePrincipalOauth2PermissionGrant -Filter "ClientId eq '$appId'" -ErrorAction SilentlyContinue

        foreach ($grant in $grants) {
            $currentScopes = $grant.Scope -split ' '
            $newScopes = @()
            $changed = $false

            foreach ($scope in $currentScopes) {
                if ($reductionMap.ContainsKey($scope)) {
                    $newScope = $reductionMap[$scope]
                    Write-Host "[$displayName] Reducing '$scope' → '$newScope'"
                    $newScopes += $newScope
                    $changed = $true
                } else {
                    $newScopes += $scope
                }
            }

            if ($changed -and ($newScopes -ne $currentScopes)) {
                if ($WhatIf) {
                    Write-Host "WHATIF: Would update $displayName ($appId) with scopes: $($newScopes -join ', ')"
                } else {
                    Set-MgServicePrincipalOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id -Scope ($newScopes -join ' ')
                    Write-Host "Updated $displayName with reduced scopes."
                }
            }
        }
    }

    Write-Host "Permission reduction process complete."
}
