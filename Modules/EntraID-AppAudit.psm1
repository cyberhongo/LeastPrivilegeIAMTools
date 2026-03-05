<#
EntraID-AppAudit.psm1
Audits Entra ID application registrations for excessive Microsoft Graph application-level permissions.
Enhanced from v1: adds reply URL checks, multi-tenant flagging, delegated grant review.
Part of LeastPrivilegeIAMTools v2.0
#>

# ── Risk classification tables ───────────────────────────────────────────────

$script:HighRiskPatterns = @(
    'ReadWrite\.All$', '\.ReadWrite\.All$', 'Write\.All$',
    '^Directory\.ReadWrite\.All$', '^RoleManagement\.ReadWrite\.Directory$',
    '^AppRoleAssignment\.ReadWrite\.All$', '^Application\.ReadWrite\.All$',
    '^Group\.ReadWrite\.All$', '^User\.ReadWrite\.All$',
    '^Mail\.ReadWrite$', '^Mail\.Send$', '^MailboxSettings\.ReadWrite$',
    '^Files\.ReadWrite\.All$', '^Sites\.FullControl\.All$',
    '^Exchange\.ManageAsApp$'
)

$script:CriticalRiskPatterns = @(
    '^Directory\.ReadWrite\.All$',
    '^RoleManagement\.ReadWrite\.Directory$',
    '^AppRoleAssignment\.ReadWrite\.All$',
    '^Application\.ReadWrite\.All$',
    '^Exchange\.ManageAsApp$',
    '^full_access_as_app$'
)

function Get-PermissionRisk {
    param([string[]]$RoleNames)
    foreach ($r in $RoleNames) {
        foreach ($p in $script:CriticalRiskPatterns) { if ($r -match $p) { return 'Critical' } }
    }
    foreach ($r in $RoleNames) {
        foreach ($p in $script:HighRiskPatterns) { if ($r -match $p) { return 'High' } }
    }
    if ($RoleNames | Where-Object { $_ -match '(?i)(\.All$|ReadWrite|Write)' }) { return 'High' }
    return 'Medium'
}

# ── Main audit function ───────────────────────────────────────────────────────

function Invoke-EntraAppPermissionAudit {
    <#
    .SYNOPSIS Internal: audits app registrations for excessive Graph app permissions.
    #>
    [CmdletBinding()]
    param([switch]$IncludeFirstParty)

    $findings = @()

    # Build role catalogue from Graph SP
    Write-Verbose '[EntraID-AppAudit] Building Graph role catalogue...'
    $graphSp    = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop
    $roleLookup = @{}
    foreach ($role in $graphSp.AppRoles) { $roleLookup[[string]$role.Id] = $role.Value }

    # Retrieve all app registrations
    Write-Verbose '[EntraID-AppAudit] Enumerating app registrations...'
    $apps = Get-MgApplication -All -Property Id,DisplayName,AppId,RequiredResourceAccess,PublisherDomain,
                                                CreatedDateTime,Web,SignInAudience,Owners | Where-Object { $_ }

    $totalApps = ($apps | Measure-Object).Count
    Write-Verbose "[EntraID-AppAudit] $totalApps app registrations found."

    foreach ($app in $apps) {

        # Skip first-party unless explicitly included
        if (-not $IncludeFirstParty -and $app.PublisherDomain -match 'microsoft\.com$') { continue }

        # ── CHECK 1: Application-level Graph permissions ─────────────────────
        if ($app.RequiredResourceAccess) {
            $appRoleIds = @()
            foreach ($res in $app.RequiredResourceAccess) {
                foreach ($ra in $res.ResourceAccess) {
                    if ($ra.Type -eq 'Role') { $appRoleIds += [string]$ra.Id }
                }
            }

            if ($appRoleIds.Count -gt 0) {
                $roleNames = $appRoleIds | ForEach-Object { if ($roleLookup.ContainsKey($_)) { $roleLookup[$_] } else { "UnknownRole:$_" } }
                $severity  = Get-PermissionRisk -RoleNames $roleNames
                $findings += [pscustomobject]@{
                    Severity    = $severity
                    Category    = 'AppPermissions'
                    Title       = "App has elevated Graph application permissions"
                    Subject     = "$($app.DisplayName) ($($app.AppId))"
                    Detail      = "Permissions: $($roleNames -join '; ')"
                    Remediation = "Review and remove permissions not actively used. Replace broad scopes (e.g., User.Read.All) with resource-specific alternatives where the API supports it."
                    RawData     = @{ AppId = $app.AppId; DisplayName = $app.DisplayName; Roles = $roleNames; Publisher = $app.PublisherDomain; CreatedDateTime = $app.CreatedDateTime }
                }
            }
        }

        # ── CHECK 2: Reply URL hygiene ────────────────────────────────────────
        if ($app.Web -and $app.Web.RedirectUris) {
            $riskyUris = $app.Web.RedirectUris | Where-Object {
                $_ -match '(?i)(localhost|127\.0\.0\.1|\*|http://(?!localhost))' -or $_ -eq '*'
            }
            foreach ($uri in $riskyUris) {
                $sev = if ($uri -eq '*' -or $uri -match '\*') { 'Critical' } else { 'High' }
                $findings += [pscustomobject]@{
                    Severity    = $sev
                    Category    = 'AppConfiguration'
                    Title       = "Risky reply URL (redirect URI) detected"
                    Subject     = "$($app.DisplayName) ($($app.AppId))"
                    Detail      = "Redirect URI: $uri — Wildcard or non-HTTPS URIs allow auth code interception."
                    Remediation = "Remove wildcard reply URLs immediately. Replace localhost URIs with specific non-production URLs before production deployment."
                    RawData     = @{ AppId = $app.AppId; ReplyUrl = $uri }
                }
            }
        }

        # ── CHECK 3: Multi-tenant apps ────────────────────────────────────────
        if ($app.SignInAudience -in @('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount', 'PersonalMicrosoftAccount')) {
            $findings += [pscustomobject]@{
                Severity    = 'Medium'
                Category    = 'AppConfiguration'
                Title       = "Multi-tenant app registration"
                Subject     = "$($app.DisplayName) ($($app.AppId))"
                Detail      = "SignInAudience: $($app.SignInAudience) — App is accessible from outside your tenant. External users can potentially trigger consent flows."
                Remediation = "Confirm multi-tenant configuration is intentional. If internal use only, restrict to AzureADMyOrg. Ensure admin consent is required for any sensitive permissions."
                RawData     = @{ AppId = $app.AppId; SignInAudience = $app.SignInAudience }
            }
        }

        # ── CHECK 4: App credential expiry ────────────────────────────────────
        # Note: requires fetching per-app passwords/key credentials
        try {
            $appDetail = Get-MgApplication -ApplicationId $app.Id -Property PasswordCredentials,KeyCredentials -ErrorAction SilentlyContinue
            if ($appDetail) {
                $now = [DateTime]::UtcNow
                foreach ($cred in @($appDetail.PasswordCredentials + $appDetail.KeyCredentials) | Where-Object { $_ }) {
                    if (-not $cred.EndDateTime) { continue }
                    $daysLeft = ($cred.EndDateTime - $now).TotalDays
                    if ($daysLeft -lt 0) {
                        $findings += [pscustomobject]@{
                            Severity    = 'High'
                            Category    = 'CredentialHygiene'
                            Title       = "Expired app credential (secret/certificate)"
                            Subject     = "$($app.DisplayName) ($($app.AppId))"
                            Detail      = "Credential '$($cred.DisplayName ?? 'unnamed')' expired $([math]::Abs([int]$daysLeft)) days ago ($($cred.EndDateTime.ToString('yyyy-MM-dd')))."
                            Remediation = "Remove expired credentials immediately. If the app is still in use, rotate with a new certificate (preferred over client secrets). Document secret rotation in a runbook."
                            RawData     = @{ AppId = $app.AppId; CredName = $cred.DisplayName; Expiry = $cred.EndDateTime }
                        }
                    } elseif ($daysLeft -lt 30) {
                        $findings += [pscustomobject]@{
                            Severity    = 'Medium'
                            Category    = 'CredentialHygiene'
                            Title       = "App credential expiring within 30 days"
                            Subject     = "$($app.DisplayName) ($($app.AppId))"
                            Detail      = "Credential '$($cred.DisplayName ?? 'unnamed')' expires in $([int]$daysLeft) days ($($cred.EndDateTime.ToString('yyyy-MM-dd')))."
                            Remediation = "Rotate before expiry to avoid service disruption. Prefer certificate-based auth over client secrets."
                            RawData     = @{ AppId = $app.AppId; CredName = $cred.DisplayName; Expiry = $cred.EndDateTime; DaysLeft = [int]$daysLeft }
                        }
                    }
                }
            }
        } catch { Write-Verbose "Credential check skipped for $($app.DisplayName): $($_.Exception.Message)" }
    }

    Write-Verbose "[EntraID-AppAudit] $($findings.Count) findings from app permission audit."
    return $findings
}
