<#
.SYNOPSIS
    LeastPrivilegeIAMTools – Audit Azure AD / Entra ID app registrations for
    excessive Microsoft Graph **application** permissions and generate flexible
    reports (text, CSV).

.DESCRIPTION
    • Installs Microsoft Graph PowerShell SDK on‑demand (CurrentUser scope).
    • Supports either delegated (interactive) or application (client‑credential)
      authentication.
    • Flags any application registration that requests **application roles** –
      these are the high‑impact Microsoft Graph permissions that grant
      app‑only access to tenant data.
    • Generates both a human‑readable *text* report and a structured *CSV*
      report for spreadsheet / SIEM ingestion.
    • Creates the target folders automatically and disconnects from Graph
      when finished.

.PARAMETER OutputPath
    Path to the plain‑text report. A matching *.csv* file will be written next
    to it automatically.

.PARAMETER TenantId / ClientId / CertificateThumbprint / ClientSecret
    Optional parameters for app‑based (client‑credential) authentication.

.EXAMPLE
    # Interactive run, store reports under C:\Audit
    Invoke-LeastPrivilegeAudit -Verbose -OutputPath "C:\Audit\OverprivilegedApps.txt"

.EXAMPLE
    # Automation run with certificate‑based service principal
    Invoke-LeastPrivilegeAudit `
        -TenantId 'xxxxxxxx‑xxxx‑xxxx‑xxxx‑xxxxxxxxxxxx' `
        -ClientId 'yyyyyyyy‑yyyy‑yyyy‑yyyy‑yyyyyyyyyyyy' `
        -CertificateThumbprint 'ABCDEF1234567890ABCDEF1234567890ABCDEF12' `
        -OutputPath 'C:\Audit\OverprivilegedApps_sp.txt'

.NOTES
    Author  : Lucidity Consulting LLC  |  Ashton Mairura
    Updated : $(Get-Date -Format 'yyyy-MM-dd')
    License : MIT
#>

<#
LeastPrivilegeIAMTools.psm1
Audits Azure AD / Entra ID application registrations for excessive Microsoft Graph application‑level permissions. Outputs TXT, CSV, JSON, HTML, and optionally pushes to Log Analytics.
Author  : Lucidity Consulting LLC | Ashton Mairura
License : MIT
LastMod : 2025‑07‑15
#>

function Invoke-LeastPrivilegeAudit {
    [CmdletBinding()]
    param(
        [string]$OutputPath = "C:\Audit\OverprivilegedApps.txt",
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [string]$ClientSecret,
        [string]$WorkspaceId,
        [string]$SharedKey,
        [switch]$IncludeFirstParty
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # ─── Ensure Graph SDK ──────────────────────────────────────────────
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
    }
    Import-Module Microsoft.Graph -ErrorAction Stop

    # ─── Authenticate ─────────────────────────────────────────────────
    if ($PSBoundParameters.ContainsKey('ClientId')) {
        if (-not $TenantId) { throw 'TenantId is required for application authentication.' }
        $auth = @{ TenantId = $TenantId; ClientId = $ClientId }
        if ($CertificateThumbprint) { $auth.CertificateThumbprint = $CertificateThumbprint }
        elseif ($ClientSecret)      { $auth.ClientSecret          = $ClientSecret          }
        else { throw 'Provide CertificateThumbprint or ClientSecret.' }
        Connect-MgGraph @auth -Scopes '.default' -NoWelcome | Out-Null
    }
    else {
        $scopes = @('Application.Read.All','Directory.Read.All','RoleManagement.Read.Directory')
        Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
    }

    # ─── Prepare paths ────────────────────────────────────────────────
    $folder = Split-Path -Parent $OutputPath
    if ($folder -and -not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder | Out-Null }
    $csvPath  = [System.IO.Path]::ChangeExtension($OutputPath,'csv')
    $jsonPath = [System.IO.Path]::ChangeExtension($OutputPath,'json')
    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath,'html')

    "Audit Report - $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ssZ'))" | Out-File $OutputPath -Encoding utf8
    'DisplayName,AppId,RiskSeverity,Roles,Publisher,CreatedDateTime' | Out-File $csvPath -Encoding utf8

    $jsonBag  = @()
    $htmlRows = @()

    # ─── Build role catalogue ─────────────────────────────────────────
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    $roleLookup = @{}
    foreach ($role in $graphSp.AppRoles) { $roleLookup[[string]$role.Id] = $role.Value }

    # ─── Retrieve applications ───────────────────────────────────────
    $apps = Get-MgApplication -All
    foreach ($app in $apps) {
        if (-not $app.RequiredResourceAccess) { continue }
        if (-not $IncludeFirstParty -and $app.PublisherDomain -match 'microsoft\.com$') { continue }

        # Collect application role IDs robustly (always array)
        $roleIds = @()
        foreach ($res in $app.RequiredResourceAccess) {
            foreach ($ra in $res.ResourceAccess) {
                if ($ra.Type -eq 'Role') {
                    $roleIds += [string]$ra.Id
                }
            }
        }
        if (-not $roleIds) { continue }

        $roleNames = $roleIds | ForEach-Object { $roleLookup[$_] }
        $risk = (($roleNames | Where-Object { $_ -match '(?i)(Write|ReadWrite|\.All$)' }) | Measure-Object).Count -gt 0 ? 'High' : 'Medium'

        # TXT
        "[$risk] $($app.DisplayName) ($($app.AppId)) - $($roleNames -join '; ')" |
            Out-File $OutputPath -Append -Encoding utf8

        # CSV
        ('"{0}",{1},{2},"{3}","{4}",{5}' -f (
            $app.DisplayName.Replace('"','""'),
            $app.AppId,
            $risk,
            ($roleNames -join '; ').Replace('"','""'),
            ($app.PublisherDomain ?? ''),
            ($app.CreatedDateTime ?? '')) ) | Out-File $csvPath -Append -Encoding utf8

        # JSON collection
        $jsonBag += [pscustomobject]@{
            DisplayName     = $app.DisplayName
            AppId           = $app.AppId
            RiskSeverity    = $risk
            Roles           = $roleNames
            Publisher       = $app.PublisherDomain
            CreatedDateTime = $app.CreatedDateTime
        }

        # HTML row
        $htmlRows += "<tr><td>$($app.DisplayName)</td><td>$($app.AppId)</td><td>$risk</td><td>$([string]::Join('<br/>',$roleNames))</td><td>$($app.PublisherDomain)</td><td>$($app.CreatedDateTime)</td></tr>"
    }

    # ─── Write JSON & HTML ───────────────────────────────────────────
    $jsonBag | ConvertTo-Json -Depth 4 | Out-File $jsonPath -Encoding utf8

    $htmlTop = @(
        '<!doctype html><html><head><meta charset="utf-8"><title>Least Privilege Audit</title>',
        '<style>body{font-family:Segoe UI,Arial;max-width:1200px;margin:auto;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;}th{background:#f2f2f2;}</style>',
        '</head><body>',
        "<h1>Least Privilege Audit - $(Get-Date)</h1>",
        '<table><thead><tr><th>Display Name</th><th>AppId</th><th>Risk</th><th>Roles</th><th>Publisher</th><th>Created</th></tr></thead><tbody>'
    )
    $htmlTop + $htmlRows + '</tbody></table></body></html>' | Out-File $htmlPath -Encoding utf8

    # ─── Optional Log Analytics push ─────────────────────────────────
    if ($WorkspaceId -and $SharedKey) {
        try {
            $body = $jsonBag | ConvertTo-Json -Depth 4
            $dateRfc = [DateTime]::UtcNow.ToString('r')
            $contentType = 'application/json'
            $stringToSign = "POST`n$($body.Length)`n$contentType`nx-ms-date:$dateRfc`n/api/logs"
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($stringToSign)
            $key   = [Convert]::FromBase64String($SharedKey)
            $hmac  = [System.Security.Cryptography.HMACSHA256]::new($key)
            $sig   = [Convert]::ToBase64String($hmac.ComputeHash($bytes))
            $headers = @{ Authorization = "SharedKey ${WorkspaceId}:$sig"; 'Log-Type' = 'LeastPrivilegeApp'; 'x-ms-date' = $dateRfc }
            $uri = "https://${WorkspaceId}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ContentType $contentType
        } catch { Write-Warning "Log Analytics upload failed: $($_.Exception.Message)" }
    }

    Disconnect-MgGraph
    Write-Host "Audit complete. TXT: $OutputPath | CSV: $csvPath | JSON: $jsonPath | HTML: $htmlPath"
    Write-Host "Audit complete. TXT: $OutputPath | CSV: $csvPath | JSON: $jsonPath | HTML: $htmlPath"
}

Export-ModuleMember -Function Invoke-LeastPrivilegeAudit


