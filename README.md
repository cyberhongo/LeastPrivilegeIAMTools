<p align="center">
  <img src="https://lucidityconsult.net/wp-content/uploads/2024/08/unnamed.png" alt="Lucidity Consulting LLC Logo" width="150"/>
</p>

# 🛡️ LeastPrivilegeIAMTools PS Helper Script  
**Author:** Ashton Mairura  
**Version:** 1.0.3  

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Empower your Microsoft Graph environment with `LeastPrivilegeIAMTools`  
> Audit and reduce app permissions using **least privilege** principles.

---

## 📚 Table of Contents

- [🚀 Functions](#-functions)
  - [🔍 Invoke-LeastPrivilegeAudit](#-invoke-leastprivilegeaudit)
  - [✂️ Invoke-LeastPrivilegeReduction](#-invoke-leastprivilegereduction)
- [🧪 Example Usages](#-example-usages)
- [📝 Requirements](#-requirements)
- [🔑 Required Microsoft Graph Permissions](#-required-microsoft-graph-permissions)
- [🔒 Security Notes](#-security-notes)
- [📂 Repository Structure (Optional)](#-repository-structure-optional)
- [🙌 Contributions](#-contributions)
- [📄 License](#-license)

---

## 🚀 Functions

### 🔍 `Invoke-LeastPrivilegeAudit`  
Scans **Azure AD app registrations** for **overprivileged Microsoft Graph scopes**.  
Helps you identify unnecessary permissions.

### ✂️ `Invoke-LeastPrivilegeReduction`  
Replaces high-privilege Graph scopes with least-privileged alternatives.  
Helps right-size app permissions securely.

---

## 🧪 Example Usages

### 🔹 Interactive Delegated Login (default)
```powershell
# Import the module
Import-Module .\LeastPrivilegeIAMTools.psm1

# Run audit with delegated login
Invoke-LeastPrivilegeAudit -OutputPath "C:\Audit\delegated.txt"
🔹 App-Based Auth (Client Credentials)
Invoke-LeastPrivilegeAudit -OutputPath "C:\Audit\appauth.txt" `
    -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -TenantId "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
    -ClientSecret "yourAppSecretHere"

📝 Requirements
PowerShell 7.0+

Microsoft Graph PowerShell SDK
Install it via:
Install-Module Microsoft.Graph -Scope CurrentUser

🔑 Required Microsoft Graph Permissions
For full functionality, the following Microsoft Graph permissions are required:
| Scope                               | Purpose                                                   |
| ----------------------------------- | --------------------------------------------------------- |
| `Application.Read.All`              | Enumerate applications and service principals             |
| `Directory.Read.All`                | Read directory objects                                    |
| `RoleManagement.Read.Directory`     | Inspect directory roles                                   |
| `AppRoleAssignment.Read.All`        | *(App-based only)* Read app role assignments              |
| `DelegatedPermissionGrant.Read.All` | Review delegated grants                                   |
| `Application.ReadWrite.All`         | Modify application permissions *(required for reduction)* |
---------------------------------------------------------------------------------------------------

🔒 Security Notes
✅ Dry Run Safety: -WhatIf is supported for safe testing before making changes.
🔏 Self-Signed Module: This module is signed with a test/lab certificate.
🚫 No Secrets Stored: No hardcoded credentials or tokens are stored.

📂 Repository Structure
/
├── LeastPrivilegeIAMTools.psm1
├── LeastPrivilegeIAMTools.psd1
├── README.md
├── Signature.txt
├── Sign-ModuleWithSelfSignedCert.ps1
└── Examples/
    ├── OverprivilegedApps.txt
    └── ExampleUsage.ps1

🙌 Contributions
Pull requests are welcome!
If you spot permission misconfigurations or scope mappings that need tuning—open an issue or PR.

📄 License
This project is licensed under the MIT License.
© 2025 Lucidity Consulting LLC. All rights reserved.

✅ Lucidity Consulting LLC ✅
🔁 GitHub Owner: Lucidity Consulting LLC
🔗 Repository URL: https://github.com/cyberhongo/LeastPrivilegeIAMTools

<p align="center">
  <img src="https://lucidityconsult.net/wp-content/uploads/2024/08/unnamed.png" alt="Lucidity Consulting LLC Logo" width="150"/>
</p>
