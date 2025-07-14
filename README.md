<<<<<<< HEAD
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
       Import-Module .\LeastPrivilegeIAMTools.psm1
       Invoke-LeastPrivilegeAudit -OutputPath "C:\Audit\OverprivilegedApps.txt"

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
