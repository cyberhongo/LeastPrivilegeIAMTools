<#
.SYNOPSIS
    LeastPrivilegeIAMTools - Entra ID + on-prem Active Directory IAM security auditor.

.DESCRIPTION
    Modular security audit tool for MSP use against client environments.
    Covers Entra ID application permissions, identity risk, on-prem AD security hygiene,
    and hybrid identity posture. Produces scored reports in TXT / CSV / JSON / HTML.

    Sub-modules loaded automatically from .\Modules\:
        EntraID-AppAudit.psm1      - App registration permission audit
        EntraID-IdentityRisk.psm1  - Stale apps, expiring secrets, guest owners, role assignments
        AD-SecurityAudit.psm1      - On-prem AD: Kerberos, DCSync, trusts, privileged accounts
        Scoring-Engine.psm1        - Weighted risk scoring + domain health score

.AUTHOR   Lucidity Consulting LLC | Ashton Mairura
.LICENSE  MIT
.VERSION  2.0.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ─── Load Sub-Modules ──────────────────────────────────────────────────

$moduleRoot = $PSScriptRoot
$subModules  = @(
    'Modules\EntraID-AppAudit.psm1',
    'Modules\EntraID-IdentityRisk.psm1',
    'Modules\AD-SecurityAudit.psm1',
    'Modules\Scoring-Engine.psm1'
)
foreach ($sm in $subModules) {
    $fullPath = Join-Path $moduleRoot $sm
    if (Test-Path $fullPath) {
        Import-Module $fullPath -Force -Global
    } else {
        Write-Warning "Sub-module not found: $fullPath - related functions will be unavailable."
    }
}

#endregion

#region ─── Authentication Helpers ───────────────────────────────────────────

function Connect-GraphForAudit {
    <#
    .SYNOPSIS Internal helper. Connects to Microsoft Graph with appropriate scopes.
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [string]$ClientSecret
    )

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host '[+] Installing Microsoft.Graph SDK (CurrentUser)...'
        Install-Module Microsoft.Graph -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    if ($ClientId) {
        if (-not $TenantId) { throw 'TenantId required for app-based auth.' }
        $auth = @{ TenantId = $TenantId; ClientId = $ClientId }
        if ($CertificateThumbprint)  { $auth.CertificateThumbprint = $CertificateThumbprint }
        elseif ($ClientSecret)       { $auth.ClientSecret          = (ConvertTo-SecureString $ClientSecret -AsPlainText -Force) }
        else { throw 'Supply CertificateThumbprint or ClientSecret for app auth.' }
        Connect-MgGraph @auth -NoWelcome | Out-Null
        Write-Verbose '[Graph] Connected via service principal.'
    } else {
        $scopes = @(
            'Application.Read.All',
            'Directory.Read.All',
            'RoleManagement.Read.Directory',
            'DelegatedPermissionGrant.Read.All',
            'AuditLog.Read.All',
            'Policy.Read.All'
        )
        Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
        Write-Verbose '[Graph] Connected via delegated auth.'
    }
}

#endregion

#region ─── Main Entry Points ─────────────────────────────────────────────────

function Invoke-LeastPrivilegeAudit {
    <#
    .SYNOPSIS
        Audits Entra ID for app permission violations and identity risk findings.

    .PARAMETER OutputPath
        Base path for reports. Extensions (.csv, .json, .html) auto-appended.

    .PARAMETER TenantId / ClientId / CertificateThumbprint / ClientSecret
        Optional service principal auth. If omitted, interactive delegated auth used.

    .PARAMETER WorkspaceId / SharedKey
        Optional: push JSON results to Azure Log Analytics / Microsoft Sentinel.

    .PARAMETER IncludeFirstParty
        Include Microsoft first-party apps in the audit (skipped by default).

    .PARAMETER SkipAppAudit
        Skip application permission checks (useful when running identity-only pass).

    .PARAMETER SkipIdentityRisk
        Skip identity risk checks (stale apps, expiring secrets, etc.).

    .EXAMPLE
        Invoke-LeastPrivilegeAudit -OutputPath 'C:\Audit\Client1\EntraAudit.txt' -Verbose
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath           = 'C:\Audit\EntraAudit.txt',
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [string]$ClientSecret,
        [string]$WorkspaceId,
        [string]$SharedKey,
        [switch]$IncludeFirstParty,
        [switch]$SkipAppAudit,
        [switch]$SkipIdentityRisk
    )

    $startTime = Get-Date
    Write-Host "`n[LeastPrivilegeIAMTools v2.0] Entra ID Audit - $($startTime.ToString('yyyy-MM-dd HH:mm')) UTC" -ForegroundColor Cyan

    Connect-GraphForAudit -TenantId $TenantId -ClientId $ClientId `
        -CertificateThumbprint $CertificateThumbprint -ClientSecret $ClientSecret

    # Prepare output folder
    $folder = Split-Path -Parent $OutputPath
    if ($folder -and -not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }

    $allFindings = @()

    if (-not $SkipAppAudit) {
        Write-Host '[*] Running app permission audit...'
        $allFindings += Invoke-EntraAppPermissionAudit -IncludeFirstParty:$IncludeFirstParty
    }

    if (-not $SkipIdentityRisk) {
        Write-Host '[*] Running identity risk checks...'
        $allFindings += Invoke-EntraIdentityRiskAudit
    }

    # Score findings
    $scoreResult = Get-AuditScore -Findings $allFindings -AuditScope 'EntraID'

    # Write outputs
    Write-AuditReports -Findings $allFindings -Score $scoreResult -OutputPath $OutputPath `
        -WorkspaceId $WorkspaceId -SharedKey $SharedKey -AuditType 'Entra ID'

    Disconnect-MgGraph | Out-Null
    $elapsed = (Get-Date) - $startTime
    Write-Host "`n[✓] Audit complete in $([int]$elapsed.TotalSeconds)s - Score: $($scoreResult.DomainScore)/100 ($($scoreResult.RiskRating))" -ForegroundColor Green
    Write-Host "    Reports: $folder"
    return $scoreResult
}

function Invoke-ADSecurityAudit {
    <#
    .SYNOPSIS
        Audits on-premises Active Directory for security hygiene issues.

    .PARAMETER OutputPath
        Base path for reports.

    .PARAMETER DomainController
        Optional: target DC FQDN. Uses default DC discovery if not specified.

    .PARAMETER Credential
        Optional PSCredential for remote execution (service account with read access).

    .EXAMPLE
        Invoke-ADSecurityAudit -OutputPath 'C:\Audit\Client1\ADAudit.txt' -Verbose

    .EXAMPLE
        $cred = Get-Credential
        Invoke-ADSecurityAudit -OutputPath 'C:\Audit\ADAudit.txt' -DomainController 'DC01.corp.local' -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath       = 'C:\Audit\ADAudit.txt',
        [string]$DomainController,
        [PSCredential]$Credential
    )

    $startTime = Get-Date
    Write-Host "`n[LeastPrivilegeIAMTools v2.0] On-Prem AD Audit - $($startTime.ToString('yyyy-MM-dd HH:mm')) UTC" -ForegroundColor Cyan

    # Verify RSAT is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'ActiveDirectory module not found. Install RSAT: Install-WindowsFeature RSAT-AD-PowerShell (Server) or Get-WindowsCapability -Name Rsat.ActiveDirectory* | Add-WindowsCapability (Win10/11).'
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    $folder = Split-Path -Parent $OutputPath
    if ($folder -and -not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }

    # Build AD cmdlet common parameters
    $adParams = @{}
    if ($DomainController) { $adParams.Server = $DomainController }
    if ($Credential)       { $adParams.Credential = $Credential }

    Write-Host '[*] Running on-prem AD security checks...'
    $allFindings = Invoke-ADSecurityChecks @adParams

    $scoreResult = Get-AuditScore -Findings $allFindings -AuditScope 'OnPremAD'
    Write-AuditReports -Findings $allFindings -Score $scoreResult -OutputPath $OutputPath -AuditType 'On-Prem AD'

    $elapsed = (Get-Date) - $startTime
    Write-Host "`n[✓] AD Audit complete in $([int]$elapsed.TotalSeconds)s - Score: $($scoreResult.DomainScore)/100 ($($scoreResult.RiskRating))" -ForegroundColor Green
    Write-Host "    Reports: $folder"
    return $scoreResult
}

function Invoke-FullIAMAudit {
    <#
    .SYNOPSIS
        Runs both Entra ID and on-prem AD audits, producing a combined report.

    .EXAMPLE
        Invoke-FullIAMAudit -OutputBasePath 'C:\Audit\Client1' -TenantId 'xxx' -ClientId 'yyy' -CertificateThumbprint 'zzz'
    #>
    [CmdletBinding()]
    param(
        [string]$OutputBasePath = 'C:\Audit',
        [string]$ClientName     = 'Client',
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [string]$ClientSecret,
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$DomainController,
        [PSCredential]$Credential,
        [switch]$IncludeFirstParty,
        [switch]$SkipEntraAudit,
        [switch]$SkipADAudit
    )

    $ts     = Get-Date -Format 'yyyyMMdd-HHmm'
    $outDir = Join-Path $OutputBasePath "$ClientName-$ts"
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null

    $results = @{}

    if (-not $SkipEntraAudit) {
        $results.Entra = Invoke-LeastPrivilegeAudit `
            -OutputPath     (Join-Path $outDir 'EntraAudit.txt') `
            -TenantId       $TenantId `
            -ClientId       $ClientId `
            -CertificateThumbprint $CertificateThumbprint `
            -ClientSecret   $ClientSecret `
            -WorkspaceId    $WorkspaceId `
            -SharedKey      $SharedKey `
            -IncludeFirstParty:$IncludeFirstParty
    }

    if (-not $SkipADAudit) {
        $results.AD = Invoke-ADSecurityAudit `
            -OutputPath       (Join-Path $outDir 'ADAudit.txt') `
            -DomainController $DomainController `
            -Credential       $Credential
    }

    # Combined summary
    $combinedScore = 'N/A'
    if ($results.Entra -and $results.AD) {
        $combinedScore = [math]::Round(($results.Entra.DomainScore + $results.AD.DomainScore) / 2)
    } elseif ($results.Entra) { $combinedScore = $results.Entra.DomainScore }
    elseif ($results.AD)      { $combinedScore = $results.AD.DomainScore }

    Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host   "║       FULL IAM AUDIT SUMMARY         ║" -ForegroundColor Cyan
    Write-Host   "╚══════════════════════════════════════╝" -ForegroundColor Cyan
    if ($results.Entra) { Write-Host "  Entra ID Score : $($results.Entra.DomainScore)/100  ($($results.Entra.RiskRating))" }
    if ($results.AD)    { Write-Host "  AD Score       : $($results.AD.DomainScore)/100  ($($results.AD.RiskRating))" }
    Write-Host          "  Combined Score : $combinedScore/100"
    Write-Host          "  Output folder  : $outDir"
    Write-Host ""
    return $results
}

#endregion

#region ─── Report Writer ─────────────────────────────────────────────────────

function Write-AuditReports {
    [CmdletBinding()]
    param(
        [array]$Findings,
        [hashtable]$Score,
        [string]$OutputPath,
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$AuditType = 'IAM'
    )

    $folder   = Split-Path -Parent $OutputPath
    $csvPath  = [IO.Path]::ChangeExtension($OutputPath, 'csv')
    $jsonPath = [IO.Path]::ChangeExtension($OutputPath, 'json')
    $htmlPath = [IO.Path]::ChangeExtension($OutputPath, 'html')

    # TXT
    $txtLines = @("# LeastPrivilegeIAMTools - $AuditType Audit Report")
    $txtLines += "# Generated : $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    $txtLines += "# Score     : $($Score.DomainScore)/100 ($($Score.RiskRating))"
    $txtLines += "# Findings  : $($Findings.Count) ($($Score.CriticalCount) Critical, $($Score.HighCount) High, $($Score.MediumCount) Medium, $($Score.LowCount) Low)"
    $txtLines += ""
    foreach ($f in ($Findings | Sort-Object { switch($_.Severity){'Critical'{0}'High'{1}'Medium'{2}'Low'{3}default{4}} })) {
        $txtLines += "[$($f.Severity.ToUpper())] [$($f.Category)] $($f.Title)"
        $txtLines += "    Subject  : $($f.Subject)"
        $txtLines += "    Detail   : $($f.Detail)"
        $txtLines += "    Remediate: $($f.Remediation)"
        $txtLines += ""
    }
    $txtLines | Out-File $OutputPath -Encoding utf8

    # CSV
    $Findings | Select-Object Severity, Category, Title, Subject, Detail, Remediation |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8

    # JSON
    @{
        AuditType   = $AuditType
        GeneratedAt = [DateTime]::UtcNow.ToString('o')
        Score       = $Score
        Findings    = $Findings
    } | ConvertTo-Json -Depth 6 | Out-File $jsonPath -Encoding utf8

    # HTML
    $htmlContent = New-HtmlAuditReport -Findings $Findings -Score $Score -AuditType $AuditType
    $htmlContent | Out-File $htmlPath -Encoding utf8

    # Optional: Log Analytics push
    if ($WorkspaceId -and $SharedKey) {
        try {
            Push-ToLogAnalytics -JsonPayload ($Findings | ConvertTo-Json -Depth 6) `
                -WorkspaceId $WorkspaceId -SharedKey $SharedKey -LogType "LPIAMAudit_${AuditType -replace '\s',''}"
            Write-Host "[+] Findings pushed to Log Analytics workspace."
        } catch {
            Write-Warning "Log Analytics push failed: $($_.Exception.Message)"
        }
    }

    Write-Verbose "Reports written: TXT / CSV / JSON / HTML under $folder"
}

#endregion

#region ─── Log Analytics Push ────────────────────────────────────────────────

function Push-ToLogAnalytics {
    [CmdletBinding()]
    param(
        [string]$JsonPayload,
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$LogType = 'LPIAMAudit'
    )
    $dateRfc     = [DateTime]::UtcNow.ToString('r')
    $bodyBytes   = [Text.Encoding]::UTF8.GetBytes($JsonPayload)
    $sigString   = "POST`n$($bodyBytes.Length)`napplication/json`nx-ms-date:$dateRfc`n/api/logs"
    $hmac        = [Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($SharedKey))
    $sig         = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($sigString)))
    $uri         = "https://${WorkspaceId}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    $headers     = @{
        Authorization = "SharedKey ${WorkspaceId}:$sig"
        'Log-Type'    = $LogType
        'x-ms-date'   = $dateRfc
    }
    Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $JsonPayload -ContentType 'application/json'
}

#endregion

Export-ModuleMember -Function Invoke-LeastPrivilegeAudit, Invoke-ADSecurityAudit, Invoke-FullIAMAudit
