
LeastPrivilegeIAMTools PowerShell Module
========================================

Author: Ashton Mairura
Version: 1.0.0
Purpose: Audit and reduce Microsoft Graph app permissions using the principle of least privilege.

---

Functions Included:
-------------------

1. Invoke-LeastPrivilegeAudit
   - Description: Audits all app registrations for overprivileged scopes.
   - Usage:
       Import-Module .\LeastPrivilegeIAMTools.psm1 ## Full path of where the script resides
       Invoke-LeastPrivilegeAudit -Verbose -OutputPath "C:\Audit\LeastPriv.txt"

2. Invoke-LeastPrivilegeReduction
   - Description: Replaces high-privilege Graph scopes with least-privileged alternatives.
   - Usage:
       Invoke-LeastPrivilegeReduction -WhatIf   # Safe dry run
       Invoke-LeastPrivilegeReduction           # Live run (after review)

---

Requirements:
-------------
- PowerShell 7+
- Microsoft.Graph PowerShell SDK
- Permissions:
    - Application.Read.All
    - AppRoleAssignment.Read.All
    - DelegatedPermissionGrant.Read.All
    - Application.ReadWrite.All (for reduction)

---

Security Notes:
---------------
- All changes are gated behind -WhatIf by default.
- Module is signed with a self-signed certificate for lab use.
- No secrets or hardcoded credentials are used.

=======
# 🛡️ LeastPrivilegeIAMTools PowerShell Module  
**Author:** Ashton Mairura  
**Version:** 1.0.0  

[![PowerShell Gallery Version](https://img.shields.io/badge/PowerShellGallery-v1.0.0-blue.svg?logo=powershell)](https://www.powershellgallery.com/)  
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)  
[![GitHub Stars](https://img.shields.io/github/stars/cyberhongo/LeastPrivilegeIAMTools?style=social)](https://github.com/cyberhongo/LeastPrivilegeIAMTools/stargazers)
> Empower your Microsoft Graph environment with `LeastPrivilegeIAMTools`  
> Audit and reduce app permissions using **least privilege** principles.

---

## 📚 Table of Contents

- [🚀 Functions](#-functions)
  - [🔍 Invoke-LeastPrivilegeAudit](#-invoke-leastprivilegeaudit)
  - [✂️ Invoke-LeastPrivilegeReduction](#-invoke-leastprivilegereduction)
- [📝 Requirements](#-requirements)
- [🔑 Required Microsoft Graph Permissions](#-required-microsoft-graph-permissions)
- [🔒 Security Notes](#-security-notes)
- [📂 Repository Structure (Optional)](#-repository-structure-optional)

---

## 🚀 Functions

### 🔍 `Invoke-LeastPrivilegeAudit`  
Scans **Azure AD app registrations** for **overprivileged Microsoft Graph scopes**.  
Helps you identify unnecessary permissions.

#### 🧪 Usage
```powershell
# Import the module
Import-Module .\LeastPrivilegeIAMTools.psm1

# Run the audit
Invoke-LeastPrivilegeAudit -OutputPath "C:\Audit\OverprivilegedApps.txt"

## ✂️ Invoke-LeastPrivilegeReduction
Replaces high-privilege Graph scopes with least-privileged alternatives.
Helps right-size app permissions securely.
# Preview changes (safe dry run)
Invoke-LeastPrivilegeReduction -WhatIf

# Apply changes (after careful review)
Invoke-LeastPrivilegeReduction

📝 Requirements
PowerShell 7.0+

Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph -Scope CurrentUser

🔑 Required Microsoft Graph Permissions
For full functionality, the following Microsoft Graph permissions are required:
| Scope                               | Purpose                                                   |
| ----------------------------------- | --------------------------------------------------------- |
| `Application.Read.All`              | Enumerate applications and service principals             |
| `AppRoleAssignment.Read.All`        | Read app role assignments                                 |
| `DelegatedPermissionGrant.Read.All` | Review delegated grants                                   |
| `Application.ReadWrite.All`         | Modify application permissions *(required for reduction)* |

🔒 Security Notes
✅ Dry Run Safety: -WhatIf is supported for safe testing before making changes.

🔏 Self-Signed Module: This module is signed with a test/lab certificate.

🚫 No Secrets Stored: No hardcoded credentials or tokens.

📂 Repository Structure
/
├── LeastPrivilegeIAMTools.psm1
├── README.md
└── Examples/
    ├── OverprivilegedApps.txt
    └── ExampleUsage.ps1

🙌 Contributions
Pull requests are welcome!
If you spot permission misconfigurations or scope mappings that need tuning—open an issue or PR.

## 📄 License
This project is licensed under the [MIT License](LICENSE).  
© 2025 Lucidity Consulting LLC. All rights reserved.

## ✅ Lucidity Consulting LLC ✅ ##

- 🔁 **GitHub Owner**: cyberhongo

- 🔗 **Repository URL**: `https://github.com/cyberhongo/LeastPrivilegeIAMTools`

>>>>>>> 387353bdb53909d065b8897a56b3650d8950f24d
=======
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
