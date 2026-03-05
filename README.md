# 🛡️ LeastPrivilegeIAMTools

**Author:** Lucidity Consulting LLC | Ashton Mairura  
**Version:** 2.0.0  
**License:** MIT  
[![MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> **LeastPrivilegeIAMTools** audits Entra ID and on-premises Active Directory for security gaps,
> generating scored reports with actionable remediation guidance. Built for MSP use against client environments.

---

## 📑 Table of Contents

1. [What's New in v2.0](#whats-new)
2. [Architecture](#architecture)
3. [Checks Performed](#checks-performed)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Report Outputs](#report-outputs)
7. [Scoring Model](#scoring-model)
8. [Required Permissions](#required-permissions)
9. [Security Notes](#security-notes)

---

## 🆕 What's New in v2.0

| Area | New Capabilities |
|---|---|
| **On-Prem AD** | Kerberoast, AS-REP Roast, DCSync ACL, KRBTGT age, stale DA accounts, domain trusts, reversible encryption, Protected Users gap, lockout policy |
| **Entra ID Risk** | Stale service principals, expiring secrets/certs, guest app owners, user consent grants, privileged SP role assignments, ownerless apps |
| **App Permissions** | Critical severity tier, reply URL hygiene, multi-tenant app detection |
| **Scoring** | Weighted 0–100 domain health score with risk rating label |
| **HTML Dashboard** | Filter by severity, color-coded badges, executive summary section |
| **Architecture** | Modular sub-modules, combined `Invoke-FullIAMAudit` orchestrator |

---

## 🏗️ Architecture

```
LeastPrivilegeIAMTools/
├── LeastPrivilegeIAMTools.psm1          # Main orchestrator + auth + report writer
├── LeastPrivilegeIAMTools.psd1          # Module manifest
├── Modules/
│   ├── EntraID-AppAudit.psm1            # App registration permission checks
│   ├── EntraID-IdentityRisk.psm1        # Identity risk: stale SPs, secrets, consent
│   ├── AD-SecurityAudit.psm1            # On-prem AD: Kerberos, DCSync, trusts, hygiene
│   └── Scoring-Engine.psm1             # Weighted scoring + HTML dashboard generator
├── Sign-ModuleWithSelfSignedCert.ps1    # Lab signing helper
└── README.md
```

---

## 🔍 Checks Performed

### Entra ID — App Permissions (`EntraID-AppAudit.psm1`)
| Check | Severity |
|---|---|
| App with Critical Graph permissions (e.g., `RoleManagement.ReadWrite.Directory`) | Critical |
| App with High-risk permissions (e.g., `Mail.Send`, `User.ReadWrite.All`) | High |
| App with Medium-risk permissions (broad `.All` read scopes) | Medium |
| Wildcard or non-HTTPS reply URLs | Critical/High |
| Multi-tenant app registrations | Medium |
| Expired app secret or certificate | High |
| App credential expiring within 30 days | Medium |

### Entra ID — Identity Risk (`EntraID-IdentityRisk.psm1`)
| Check | Severity |
|---|---|
| Service principal with Global Admin or privileged directory role | Critical/High |
| Service principal with no sign-in in 180+ days | Medium |
| App registration with no recorded sign-in activity | Low |
| Guest user as app registration owner | High |
| User-consented delegated grant with high-risk scopes | Medium |
| App registration with no designated owner | Low |

### On-Prem AD (`AD-SecurityAudit.psm1`)
| Check | Severity |
|---|---|
| Privileged account Kerberoastable (SPN on user) | Critical/High |
| AS-REP Roastable account (no Kerberos pre-auth) | High |
| Non-DC principal with DCSync rights (Replicating Directory Changes All) | Critical |
| KRBTGT password not rotated in 180+ days | Medium/High |
| Domain Admin account inactive > 90 days | High |
| Domain trust with SID filtering concerns | High/Medium |
| Account with PasswordNeverExpires (especially privileged) | High/Medium |
| Account with reversible encryption enabled | High |
| Domain Admin not in Protected Users group | Medium |
| Minimum password length < 12 | Medium |
| Account lockout threshold disabled | High |

---

## 📦 Installation

```powershell
# Clone
git clone https://github.com/LucidSecOps/LeastPrivilegeIAMTools.git
cd LeastPrivilegeIAMTools

# Install Microsoft Graph SDK (required for Entra audits)
Install-Module Microsoft.Graph -Scope CurrentUser

# For on-prem AD audits: RSAT must be installed on the machine
# Windows Server:
Install-WindowsFeature RSAT-AD-PowerShell
# Windows 10/11:
Get-WindowsCapability -Name Rsat.ActiveDirectory* -Online | Add-WindowsCapability -Online

# Import
Import-Module .\LeastPrivilegeIAMTools.psm1 -Force
```

---

## 🚀 Usage

### Entra ID Only (Interactive Auth)
```powershell
Invoke-LeastPrivilegeAudit -OutputPath 'C:\Audit\Client1\EntraAudit.txt' -Verbose
```

### Entra ID with Service Principal Auth
```powershell
Invoke-LeastPrivilegeAudit `
    -TenantId              'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -ClientId              'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy' `
    -CertificateThumbprint 'ABCDEF1234567890ABCDEF1234567890ABCDEF12' `
    -OutputPath            'C:\Audit\Client1\EntraAudit.txt'
```

### On-Prem AD Audit
```powershell
# Run on a domain-joined machine with RSAT
Invoke-ADSecurityAudit -OutputPath 'C:\Audit\Client1\ADAudit.txt' -Verbose

# Run remotely with alternate credentials
$cred = Get-Credential
Invoke-ADSecurityAudit -OutputPath 'C:\Audit\ADAudit.txt' `
    -DomainController 'DC01.corp.local' -Credential $cred
```

### Full IAM Audit (Entra + AD Combined)
```powershell
Invoke-FullIAMAudit `
    -OutputBasePath        'C:\Audit' `
    -ClientName            'Acme Corp' `
    -TenantId              'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -ClientId              'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy' `
    -CertificateThumbprint 'ABCDEF...' `
    -DomainController      'DC01.acme.local'
```

### Push to Microsoft Sentinel
```powershell
Invoke-LeastPrivilegeAudit `
    -OutputPath  'C:\Audit\EntraAudit.txt' `
    -WorkspaceId '<Log Analytics Workspace ID>' `
    -SharedKey   '<Primary Key>'
```

---

## 📊 Report Outputs

Each audit produces four files:

| File | Content |
|---|---|
| `.txt` | Human-readable findings sorted by severity with remediation steps |
| `.csv` | Structured data for Excel / SIEM ingestion |
| `.json` | Full structured output including raw data and score metadata |
| `.html` | Interactive dashboard with severity filtering and executive summary |

---

## 🎯 Scoring Model

The domain health score (0–100) starts at 100 and deducts based on findings:

| Severity | Deduction Per Finding |
|---|---|
| Critical | 25 points |
| High     | 10 points |
| Medium   |  3 points |
| Low      |  1 point  |

| Score Range | Risk Rating |
|---|---|
| 90–100 | Low Risk |
| 70–89  | Medium Risk |
| 50–69  | High Risk |
| 0–49   | Critical Risk |

---

## 🔑 Required Permissions

### Entra ID (Microsoft Graph)
| Scope | Purpose |
|---|---|
| `Application.Read.All` | Enumerate app registrations and service principals |
| `Directory.Read.All` | Read directory objects and assignments |
| `RoleManagement.Read.Directory` | Read directory role assignments |
| `DelegatedPermissionGrant.Read.All` | Review user and admin consent grants |
| `AuditLog.Read.All` | Read sign-in activity for staleness checks |
| `Policy.Read.All` | Read authorization policy settings |

### On-Prem AD
- Domain user with **read access to AD objects and ACLs**
- `AD:` PowerShell drive access for DCSync ACL check (requires Domain Admin or delegated ACL read)
- RSAT ActiveDirectory module installed

---

## 🔒 Security Notes

- **Dry-run first:** `Invoke-LeastPrivilegeReduction` (if used) supports `-WhatIf`.
- **No secrets stored:** Auth via `Connect-MgGraph` or service principal certificate.
- **Cert over secret:** Certificate-based SP auth is strongly preferred over client secrets for automation.
- **Scope the SP:** For production scheduled audits, create a dedicated read-only service principal — do NOT reuse an admin account.
- **Credential parameter:** The `-Credential` parameter for AD audits is handled in-memory only and not persisted.
- **Signed module:** Ships with test self-sign cert — re-sign with your organization's code-signing cert for production deployment.

---

## 📄 License

MIT License — © 2025 Lucidity Consulting LLC.  
Internal use and use as part of client engagements is permitted. Commercial redistribution of the tool itself requires separate arrangement.
