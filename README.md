LeastPrivilegeIAMTools PowerShell Module 🛡️

Author: Ashton Mairura

Version: 1.0.0

Empower your Microsoft Graph environment with the LeastPrivilegeIAMTools PowerShell Module! This tool helps you audit and reduce app permissions, ensuring your applications adhere strictly to the principle of least privilege.

🚀 Functions
🔍 Invoke-LeastPrivilegeAudit
Audits all Azure AD app registrations for overprivileged Microsoft Graph scopes. Identify where your apps have more permissions than they need.

Usage:

PowerShell

Import-Module .\LeastPrivilegeIAMTools.psm1
Invoke-LeastPrivilegeAudit -OutputPath "C:\Audit\OverprivilegedApps.txt"
✂️ Invoke-LeastPrivilegeReduction
Automatically replaces high-privilege Microsoft Graph scopes with their least-privileged alternatives. Secure your environment by right-sizing permissions.

Usage:

PowerShell

Invoke-LeastPrivilegeReduction -WhatIf # ✅ Always run a safe dry run first!
Invoke-LeastPrivilegeReduction         # ⚠️ Execute live changes (after careful review)
📝 Requirements
PowerShell 7+

Microsoft.Graph PowerShell SDK (Install-Module Microsoft.Graph)

🔑 Permissions Needed
The module requires the following Microsoft Graph permissions for the executing identity:

Application.Read.All

AppRoleAssignment.Read.All

DelegatedPermissionGrant.Read.All

Application.ReadWrite.All (for Invoke-LeastPrivilegeReduction only)

🔒 Security Notes
Safety First: All modification functions are protected by the -WhatIf parameter by default, allowing you to preview changes before they are applied.

Module Signing: The module is signed with a self-signed certificate, intended for lab and testing environments.

No Hardcoded Secrets: This module does not use any hardcoded credentials or secrets.
