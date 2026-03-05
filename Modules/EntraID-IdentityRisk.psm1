<#
EntraID-IdentityRisk.psm1
Phase 1 identity risk checks: stale apps, guest owners, privileged SP role assignments,
user consent grants, and stale service principals.
Part of LeastPrivilegeIAMTools v2.0
#>

function Invoke-EntraIdentityRiskAudit {
    [CmdletBinding()]
    param()

    $findings = @()
    $now = [DateTime]::UtcNow

    # ── CHECK 1: Service principals with privileged Entra role assignments ─────
    Write-Verbose '[EntraID-IdentityRisk] Checking privileged role assignments on service principals...'
    try {
        $criticalRoles = @(
            'Global Administrator', 'Privileged Role Administrator',
            'Application Administrator', 'Cloud Application Administrator',
            'Exchange Administrator', 'SharePoint Administrator',
            'Intune Administrator', 'Authentication Administrator',
            'Privileged Authentication Administrator', 'Security Administrator'
        )

        $allRoleDefs = Get-MgDirectoryRoleTemplate -All -ErrorAction SilentlyContinue
        $criticalRoleIds = $allRoleDefs | Where-Object { $_.DisplayName -in $criticalRoles } | Select-Object -ExpandProperty Id

        foreach ($roleId in $criticalRoleIds) {
            try {
                $members = Get-MgDirectoryRoleMemberAsServicePrincipal -DirectoryRoleId $roleId -All -ErrorAction SilentlyContinue
                foreach ($sp in $members) {
                    $roleName = ($allRoleDefs | Where-Object { $_.Id -eq $roleId }).DisplayName
                    $sev = if ($roleName -in @('Global Administrator','Privileged Role Administrator')) { 'Critical' } else { 'High' }
                    $findings += [pscustomobject]@{
                        Severity    = $sev
                        Category    = 'PrivilegedAccess'
                        Title       = "Service principal assigned privileged Entra role"
                        Subject     = "$($sp.DisplayName) ($($sp.AppId))"
                        Detail      = "Role: $roleName — Service principals with directory roles can act autonomously with elevated permissions, no MFA applies."
                        Remediation = "Review whether this SP genuinely requires $roleName. Prefer granular Graph API permissions over directory role assignments for service principals."
                        RawData     = @{ SpDisplayName = $sp.DisplayName; AppId = $sp.AppId; Role = $roleName }
                    }
                }
            } catch { Write-Verbose "Role $roleId member check skipped: $($_.Exception.Message)" }
        }
    } catch { Write-Verbose "Privileged role check error: $($_.Exception.Message)" }

    # ── CHECK 2: Stale app registrations (no sign-in activity in 90+ days) ────
    Write-Verbose '[EntraID-IdentityRisk] Checking for stale app registrations...'
    try {
        $spList = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,SignInActivity,CreatedDateTime,AccountEnabled |
                  Where-Object { $_.AppOwnerOrganizationId -eq (Get-MgOrganization | Select-Object -First 1 -ExpandProperty Id) }

        foreach ($sp in $spList) {
            if ($sp.SignInActivity -and $sp.SignInActivity.LastSignInDateTime) {
                $daysSince = ($now - $sp.SignInActivity.LastSignInDateTime).TotalDays
                if ($daysSince -gt 180) {
                    $findings += [pscustomobject]@{
                        Severity    = 'Medium'
                        Category    = 'Lifecycle'
                        Title       = "Stale service principal (no sign-in > 180 days)"
                        Subject     = "$($sp.DisplayName) ($($sp.AppId))"
                        Detail      = "Last sign-in: $($sp.SignInActivity.LastSignInDateTime.ToString('yyyy-MM-dd')) ($([int]$daysSince) days ago). Unused apps with active credentials expand the attack surface."
                        Remediation = "Confirm with app owner whether the service principal is still needed. If not, disable first, then delete after 30-day observation period."
                        RawData     = @{ SpDisplayName = $sp.DisplayName; AppId = $sp.AppId; LastSignIn = $sp.SignInActivity.LastSignInDateTime; DaysSince = [int]$daysSince }
                    }
                }
            } elseif ($sp.CreatedDateTime) {
                $agedays = ($now - $sp.CreatedDateTime).TotalDays
                if ($agedays -gt 90) {
                    $findings += [pscustomobject]@{
                        Severity    = 'Low'
                        Category    = 'Lifecycle'
                        Title       = "App registration with no recorded sign-in activity"
                        Subject     = "$($sp.DisplayName) ($($sp.AppId))"
                        Detail      = "Created $([int]$agedays) days ago with no sign-in activity recorded. May be unused or may have sign-in logging disabled."
                        Remediation = "Verify app is actively used. Enable sign-in logging if missing. Remove if unused."
                        RawData     = @{ SpDisplayName = $sp.DisplayName; AppId = $sp.AppId; CreatedDateTime = $sp.CreatedDateTime }
                    }
                }
            }
        }
    } catch { Write-Verbose "Stale SP check error: $($_.Exception.Message)" }

    # ── CHECK 3: Guest users as app owners ────────────────────────────────────
    Write-Verbose '[EntraID-IdentityRisk] Checking for guest owners on app registrations...'
    try {
        $allApps = Get-MgApplication -All -Property Id,DisplayName,AppId -ErrorAction SilentlyContinue
        foreach ($app in $allApps | Select-Object -First 200) {  # cap to avoid throttling
            try {
                $owners = Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction SilentlyContinue
                foreach ($owner in $owners) {
                    if ($owner.AdditionalProperties['userType'] -eq 'Guest') {
                        $findings += [pscustomobject]@{
                            Severity    = 'High'
                            Category    = 'AppOwnership'
                            Title       = "Guest user is an owner of an app registration"
                            Subject     = "$($app.DisplayName) ($($app.AppId))"
                            Detail      = "Owner: $($owner.AdditionalProperties['displayName'] ?? $owner.Id) (Guest) — Guest owners can modify app configurations and add credentials."
                            Remediation = "Remove guest owner. App ownership should be restricted to internal accounts. Assign an internal user or group as owner."
                            RawData     = @{ AppId = $app.AppId; GuestOwner = $owner.AdditionalProperties['displayName'] }
                        }
                    }
                }
            } catch { }
        }
    } catch { Write-Verbose "Guest owner check error: $($_.Exception.Message)" }

    # ── CHECK 4: User consent grants (delegated grants not admin-consented) ────
    Write-Verbose '[EntraID-IdentityRisk] Checking delegated permission grants...'
    try {
        $highRiskDelegatedScopes = @(
            'Mail.Read', 'Mail.ReadWrite', 'Mail.Send',
            'Files.ReadWrite.All', 'Calendars.ReadWrite',
            'Contacts.ReadWrite', 'User.ReadWrite.All',
            'Directory.ReadWrite.All', 'offline_access'
        )

        $grants = Get-MgOauth2PermissionGrant -All -ErrorAction SilentlyContinue
        foreach ($grant in $grants | Where-Object { $_.ConsentType -eq 'Principal' }) {
            $scopes = $grant.Scope -split ' '
            $riskyScopes = $scopes | Where-Object { $_ -in $highRiskDelegatedScopes }
            if ($riskyScopes) {
                $findings += [pscustomobject]@{
                    Severity    = 'Medium'
                    Category    = 'ConsentGrants'
                    Title       = "User-consented delegated grant includes high-risk scopes"
                    Subject     = "ClientId: $($grant.ClientId) | PrincipalId: $($grant.PrincipalId)"
                    Detail      = "User individually consented to: $($riskyScopes -join ', '). User consent bypasses admin review and can be exploited if the user account is compromised."
                    Remediation = "Review and revoke unnecessary user consent grants. Enable admin consent requirement for high-risk scopes in Entra ID Enterprise Apps > Consent and Permissions. Investigate whether consent was granted by phishing."
                    RawData     = @{ ClientId = $grant.ClientId; Scopes = $riskyScopes; PrincipalId = $grant.PrincipalId }
                }
            }
        }
    } catch { Write-Verbose "Consent grant check error: $($_.Exception.Message)" }

    # ── CHECK 5: Apps with no owners ─────────────────────────────────────────
    Write-Verbose '[EntraID-IdentityRisk] Checking for ownerless app registrations...'
    try {
        $allApps = Get-MgApplication -All -Property Id,DisplayName,AppId -ErrorAction SilentlyContinue
        foreach ($app in $allApps | Select-Object -First 200) {
            try {
                $owners = Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction SilentlyContinue
                if (($owners | Measure-Object).Count -eq 0) {
                    $findings += [pscustomobject]@{
                        Severity    = 'Low'
                        Category    = 'AppOwnership'
                        Title       = "App registration has no designated owner"
                        Subject     = "$($app.DisplayName) ($($app.AppId))"
                        Detail      = "No owner assigned. Ownerless apps lack accountability — no one is responsible for credential rotation or decommissioning."
                        Remediation = "Assign at least one internal user as owner for accountability. For service accounts, assign to a team distribution group or use a service account with a defined owner."
                        RawData     = @{ AppId = $app.AppId; DisplayName = $app.DisplayName }
                    }
                }
            } catch { }
        }
    } catch { Write-Verbose "App owner check error: $($_.Exception.Message)" }

    Write-Verbose "[EntraID-IdentityRisk] $($findings.Count) findings from identity risk audit."
    return $findings
}
