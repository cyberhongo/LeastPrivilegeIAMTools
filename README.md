# 🛡️ LeastPrivilegeIAMTools PowerShell Module

**Author:** Ashton Mairura • **Version:** 1.0.3 • **License:** MIT
![PowerShell Gallery](https://img.shields.io/badge/PowerShellGallery-v1.0.3-blue?logo=powershell) ![MIT](https://img.shields.io/badge/License-MIT-green)

> **LeastPrivilegeIAMTools** helps you **discover** and **remediate** over‑privileged Microsoft Graph permissions in Azure AD / Entra ID app registrations.

---

## 📑 Table of Contents

1. [Features](#features)
2. [Functions](#functions)
3. [Installation](#installation)
4. [Examples](#examples)
5. [Requirements](#requirements)
6. [Required Graph Permissions](#required-graph-permissions)
7. [Security Notes](#security-notes)
8. [Repository Structure](#repository-structure)
9. [Contributing](#contributing)
10. [License](#license)

---

## ✨ Features

| Feature                  | Description                                                                                     |
| ------------------------ | ----------------------------------------------------------------------------------------------- |
| **Audit**                | Identify Graph *application* permissions (AppRoles) that breach least‑privilege guidelines.     |
| **Risk Scoring**         | Flags apps as **High** or **Medium** based on permission names (`Write`, `ReadWrite`, `*.All`). |
| **Multi‑format Reports** | Generates **TXT**, **CSV**, **JSON**, and **HTML** dashboards.                                  |
| **Reduction (optional)** | Replace high‑impact scopes with safer alternatives (`Invoke‑LeastPrivilegeReduction`).          |
| **Sentinel Upload**      | Push JSON results to **Azure Log Analytics / Sentinel** for SOC visibility.                     |
| **Signed Module**        | Ship with a self‑signed cert for lab use (re‑sign with your own cert for prod).                 |

---

## 🔧 Functions

### `Invoke‑LeastPrivilegeAudit`

Audits app registrations and writes reports.

```powershell
# Import the module
Import-Module .\LeastPrivilegeIAMTools.psm1

# Delegated (interactive) run
Invoke-LeastPrivilegeAudit -OutputPath "C:\Audit\OverPriv.txt" -Verbose

# Service‑principal (app) auth + Sentinel push
Invoke-LeastPrivilegeAudit -TenantId "<TenantId>" -ClientId "<ClientId>" \
    -CertificateThumbprint "<Thumbprint>" -WorkspaceId "<WSID>" \
    -SharedKey "<PrimaryKey>" -OutputPath "C:\Audit\OverPriv.txt"
```

### `Invoke‑LeastPrivilegeReduction`

*(optional)* Automatically swaps risky Graph permissions for reduced ones. Always supports **‑WhatIf**.

```powershell
# Preview changes
Invoke-LeastPrivilegeReduction -WhatIf

# Apply changes (after review)
Invoke-LeastPrivilegeReduction
```

---

## 📦 Installation

```powershell
# Clone the repo
git clone https://github.com/cyberhongo/LeastPrivilegeIAMTools.git
cd LeastPrivilegeIAMTools

# Ensure Microsoft Graph SDK
Install-Module Microsoft.Graph -Scope CurrentUser

# Import
Import-Module .\LeastPrivilegeIAMTools.psm1 -Force
```

---

## 🚀 Examples

| Scenario                               | Command                                                           |
| -------------------------------------- | ----------------------------------------------------------------- |
| **Basic audit (delegated)**            | `Invoke-LeastPrivilegeAudit -OutputPath 'C:\Audit\LeastPriv.txt'` |
| **Include Microsoft first‑party apps** | `Invoke-LeastPrivilegeAudit -IncludeFirstParty`                   |
| **Upload to Sentinel**                 | `Invoke-LeastPrivilegeAudit -WorkspaceId <id> -SharedKey <key>`   |
| **Dry‑run reduction**                  | `Invoke-LeastPrivilegeReduction -WhatIf`                          |

---

## 📝 Requirements

* PowerShell **7.0** or newer
* **Microsoft.Graph** PowerShell SDK
  `Install-Module Microsoft.Graph -Scope CurrentUser`

---

## 🔑 Required Graph Permissions

| Scope                               | Reason                                       |
| ----------------------------------- | -------------------------------------------- |
| `Application.Read.All`              | Enumerate applications & service principals  |
| `Directory.Read.All`                | Read directory objects & AppRole assignments |
| `RoleManagement.Read.Directory`     | Inspect directory roles                      |
| `AppRoleAssignment.Read.All`        | *(App‑based auth)* Read app role assignments |
| `DelegatedPermissionGrant.Read.All` | Review delegated grants                      |
| `Application.ReadWrite.All`         | *(Reduction)* Modify application permissions |

> **Tip:** Run `Connect‑MgGraph -Scopes <comma‑separated scopes>` once as Global Admin and consent on behalf of your tenant.

---

## 🔒 Security Notes

* **Dry‑run first:** Every modifying cmdlet supports `‑WhatIf`.
* **No secrets stored:** Auth via `Connect‑MgGraph` or service‑principal certificate.
* **Signed:** Module ships with a test cert—replace with your own for production.

---

## 📂 Repository Structure

```
LeastPrivilegeIAMTools/
├── LeastPrivilegeIAMTools.psm1       # Module code
├── LeastPrivilegeIAMTools.psd1       # Manifest
├── README.md                         # This file
├── Signature.txt                     # Signing thumbprint & hash
├── Sign-ModuleWithSelfSignedCert.ps1 # Helper to (re)sign
└── Examples/
    └── ExampleUsage.ps1
```

---

## 🙌 Contributing

Pull requests are welcome! If you spot scope mappings or risk logic that need improvement, open an issue or PR.

---

## 📄 License

This project is licensed under the **MIT License**.
© 2025 Lucidity Consulting LLC. All rights reserved.
