# 🛡️ LeastPrivilegeIAMTools PowerShell Module  
**Author:** Ashton Mairura  
**Version:** 1.0.0  

[![PowerShell Gallery Version](https://img.shields.io/badge/PowerShellGallery-v1.0.0-blue.svg?logo=powershell)](https://www.powershellgallery.com/)  
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)  
[![GitHub Stars](https://img.shields.io/github/stars/YOUR_USERNAME/LeastPrivilegeIAMTools?style=social)](https://github.com/YOUR_USERNAME/LeastPrivilegeIAMTools/stargazers)  
[![Issues](https://img.shields.io/github/issues/YOUR_USERNAME/LeastPrivilegeIAMTools.svg)](https://github.com/YOUR_USERNAME/LeastPrivilegeIAMTools/issues)  
[![CI Status](https://github.com/YOUR_USERNAME/LeastPrivilegeIAMTools/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/LeastPrivilegeIAMTools/actions)

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

