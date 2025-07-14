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

