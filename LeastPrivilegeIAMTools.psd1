@{
    RootModule        = 'LeastPrivilegeIAMTools.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = 'a7c3d2e1-4f5b-48a9-9c0d-1e2f3a4b5c6d'
    Author            = 'Lucidity Consulting LLC | Ashton Mairura'
    CompanyName       = 'Lucidity Consulting LLC'
    Copyright         = '(c) 2025 Lucidity Consulting LLC. MIT License.'
    Description       = 'Entra ID + on-prem AD IAM security auditor for MSP use. Covers app permissions, identity risk, Kerberos attack surface, DCSync, and privileged account hygiene.'
    PowerShellVersion = '7.0'
    RequiredModules   = @()   # Microsoft.Graph loaded on-demand; ActiveDirectory loaded on-demand
    FunctionsToExport = @(
        'Invoke-LeastPrivilegeAudit',
        'Invoke-ADSecurityAudit',
        'Invoke-FullIAMAudit'
    )
    PrivateData = @{
        PSData = @{
            Tags         = @('ActiveDirectory','EntraID','Security','IAM','MSP','Audit','LeastPrivilege','Kerberos')
            ProjectUri   = 'https://github.com/LucidSecOps/LeastPrivilegeIAMTools'
            LicenseUri   = 'https://github.com/LucidSecOps/LeastPrivilegeIAMTools/blob/main/LICENSE'
            ReleaseNotes = @'
v2.0.0
- Added on-prem AD security audit (Invoke-ADSecurityAudit): Kerberoast, AS-REP Roast,
  DCSync ACL check, KRBTGT age, stale DA accounts, domain trusts, reversible encryption,
  Protected Users gap, lockout policy.
- Added Entra ID identity risk module: stale SPs, expiring secrets, guest owners,
  user consent grants, privileged SP role assignments, ownerless apps.
- Enhanced app permission audit: Critical severity tier, reply URL hygiene,
  multi-tenant app detection.
- New weighted scoring engine: 0-100 domain health score with risk rating.
- Rich HTML dashboard with filtering, color-coded badges, executive summary.
- Added Invoke-FullIAMAudit orchestrator for combined Entra + AD reporting.
- Modular architecture: sub-modules in .\Modules\ for maintainability.
'@
        }
    }
}
