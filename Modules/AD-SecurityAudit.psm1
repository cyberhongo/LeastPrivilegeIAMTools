<#
AD-SecurityAudit.psm1
On-premises Active Directory security hygiene checks.
Targets: Kerberos attack surface, privileged account hygiene, DCSync exposure,
         domain trusts, password policy hygiene, and high-risk configurations.
Requires: ActiveDirectory PowerShell module (RSAT)
Part of LeastPrivilegeIAMTools v2.0
#>

function Invoke-ADSecurityChecks {
    <#
    .SYNOPSIS Internal: runs all on-prem AD security checks.
    .PARAMETER Server       Optional target DC FQDN.
    .PARAMETER Credential   Optional PSCredential.
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $adParams = @{}
    if ($Server)     { $adParams.Server     = $Server     }
    if ($Credential) { $adParams.Credential = $Credential }

    $findings = @()
    $now = Get-Date

    # ── CHECK 1: Accounts with PasswordNeverExpires ───────────────────────────
    Write-Verbose '[AD-SecurityAudit] Checking PasswordNeverExpires accounts...'
    try {
        $pneAccounts = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
            -Properties PasswordNeverExpires, DistinguishedName, LastLogonDate, MemberOf @adParams
        foreach ($acct in $pneAccounts) {
            $isPriv = $acct.MemberOf | Where-Object { $_ -match '(Domain Admins|Enterprise Admins|Schema Admins|Administrators)' }
            $sev = if ($isPriv) { 'High' } else { 'Medium' }
            $findings += [pscustomobject]@{
                Severity    = $sev
                Category    = 'PasswordPolicy'
                Title       = "Account with PasswordNeverExpires enabled"
                Subject     = $acct.SamAccountName
                Detail      = "DN: $($acct.DistinguishedName). Last logon: $($acct.LastLogonDate). $(if ($isPriv) { 'PRIVILEGED GROUP MEMBER.' })"
                Remediation = "Enforce password expiry per policy (NIST SP 800-63B recommends expiry on breach detection; CIS recommends 60-365 days). For service accounts, migrate to gMSA (Group Managed Service Account) to eliminate password management entirely."
                RawData     = @{ SamAccountName = $acct.SamAccountName; DN = $acct.DistinguishedName; IsPrivileged = [bool]$isPriv }
            }
        }
    } catch { Write-Warning "PasswordNeverExpires check failed: $($_.Exception.Message)" }

    # ── CHECK 2: Kerberoastable accounts (SPNs on user accounts) ─────────────
    Write-Verbose '[AD-SecurityAudit] Checking Kerberoastable accounts...'
    try {
        $kerbAccounts = Get-ADUser -Filter { ServicePrincipalName -like '*' -and Enabled -eq $true } `
            -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate, MemberOf @adParams
        foreach ($acct in $kerbAccounts) {
            $isPriv = $acct.MemberOf | Where-Object { $_ -match '(Domain Admins|Enterprise Admins|Schema Admins|Administrators)' }
            $sev = if ($isPriv) { 'Critical' } else { 'High' }
            $findings += [pscustomobject]@{
                Severity    = $sev
                Category    = 'KerberosAttackSurface'
                Title       = "Kerberoastable account (user with SPN)"
                Subject     = $acct.SamAccountName
                Detail      = "SPNs: $($acct.ServicePrincipalName -join '; '). Password last set: $($acct.PasswordLastSet). $(if ($isPriv) { 'PRIVILEGED — Critical Kerberoast target.' })"
                Remediation = "Migrate services to gMSA (group managed service accounts) — they auto-rotate passwords and are not Kerberoastable. If gMSA is not feasible, ensure the service account has a strong random password (>25 chars) and enforce regular rotation. Prioritize privileged accounts."
                RawData     = @{ SamAccountName = $acct.SamAccountName; SPNs = $acct.ServicePrincipalName; IsPrivileged = [bool]$isPriv }
            }
        }
    } catch { Write-Warning "Kerberoast check failed: $($_.Exception.Message)" }

    # ── CHECK 3: AS-REP Roastable accounts (no pre-auth required) ────────────
    Write-Verbose '[AD-SecurityAudit] Checking AS-REP Roastable accounts...'
    try {
        $DONT_REQUIRE_PREAUTH = 0x400000
        $asrepAccounts = Get-ADUser -Filter { Enabled -eq $true } `
            -Properties UserAccountControl, PasswordLastSet @adParams |
            Where-Object { ($_.UserAccountControl -band $DONT_REQUIRE_PREAUTH) -ne 0 }
        foreach ($acct in $asrepAccounts) {
            $findings += [pscustomobject]@{
                Severity    = 'High'
                Category    = 'KerberosAttackSurface'
                Title       = "AS-REP Roastable account (Kerberos pre-auth disabled)"
                Subject     = $acct.SamAccountName
                Detail      = "Account does not require Kerberos pre-authentication. An attacker can request an AS-REP hash offline without credentials. Password last set: $($acct.PasswordLastSet)."
                Remediation = "Enable Kerberos pre-authentication (clear 'Do not require Kerberos preauthentication' in account settings). This flag is rarely needed in modern environments — confirm with app team before removing."
                RawData     = @{ SamAccountName = $acct.SamAccountName; UAC = $acct.UserAccountControl }
            }
        }
    } catch { Write-Warning "AS-REP Roast check failed: $($_.Exception.Message)" }

    # ── CHECK 4: DCSync-capable non-DC accounts ───────────────────────────────
    Write-Verbose '[AD-SecurityAudit] Checking DCSync exposure (Replicating Directory Changes All)...'
    try {
        $domain = Get-ADDomain @adParams
        $domainDN = $domain.DistinguishedName
        $dcGroup  = (Get-ADGroup 'Domain Controllers' @adParams).SID.Value
        $roGroup  = (Get-ADGroup 'Read-only Domain Controllers' @adParams -ErrorAction SilentlyContinue)?.SID.Value

        # Get ACL on domain object
        $acl = Get-ACL -Path "AD:\$domainDN" -ErrorAction SilentlyContinue
        if ($acl) {
            $dcsyncGuids = @(
                '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
                '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes-All (DCSync)
            )
            $dcsyncAces = $acl.Access | Where-Object {
                $_.ObjectType -in $dcsyncGuids -and $_.AccessControlType -eq 'Allow'
            }
            foreach ($ace in $dcsyncAces) {
                $identRef = $ace.IdentityReference.ToString()
                # Skip legitimate DCs and replication groups
                if ($identRef -match '(Domain Controllers|Enterprise Domain Controllers|SYSTEM|Administrators|NT AUTHORITY)') { continue }
                if ($dcGroup -and $identRef -match $dcGroup) { continue }

                $findings += [pscustomobject]@{
                    Severity    = 'Critical'
                    Category    = 'PrivilegedAccess'
                    Title       = "Non-DC principal has DCSync rights (Replicating Directory Changes All)"
                    Subject     = $identRef
                    Detail      = "ACE grants Replicating Directory Changes (All) on $domainDN. This enables mimikatz dcsync — dump of all domain password hashes without any alert on most SIEMs."
                    Remediation = "Remove this ACE immediately unless it belongs to a legitimate replication account (e.g., Azure AD Connect sync account). Investigate how this ACE was added. Review with: (Get-ACL 'AD:\\$domainDN').Access"
                    RawData     = @{ Identity = $identRef; ObjectType = $ace.ObjectType; DomainDN = $domainDN }
                }
            }
        }
    } catch { Write-Warning "DCSync check failed (requires AD: drive): $($_.Exception.Message)" }

    # ── CHECK 5: KRBTGT password age ──────────────────────────────────────────
    Write-Verbose '[AD-SecurityAudit] Checking KRBTGT password age...'
    try {
        $krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet @adParams
        $daysSince = ($now - $krbtgt.PasswordLastSet).TotalDays
        if ($daysSince -gt 180) {
            $sev = if ($daysSince -gt 365) { 'High' } else { 'Medium' }
            $findings += [pscustomobject]@{
                Severity    = $sev
                Category    = 'KerberosAttackSurface'
                Title       = "KRBTGT password has not been rotated in $([int]$daysSince) days"
                Subject     = 'krbtgt'
                Detail      = "Password last changed: $($krbtgt.PasswordLastSet). A stale KRBTGT enables long-lived Golden Tickets. Microsoft recommends rotation at least every 180 days, or immediately after any suspected compromise."
                Remediation = "Rotate KRBTGT password twice (30-minute interval between rotations) to invalidate all existing Kerberos tickets. Use Microsoft's New-KrbtgtKeys script. WARNING: Test in non-prod first and coordinate with all DCs. See: https://github.com/microsoft/New-KrbtgtKeys.ps1"
                RawData     = @{ PasswordLastSet = $krbtgt.PasswordLastSet; DaysSince = [int]$daysSince }
            }
        }
    } catch { Write-Warning "KRBTGT check failed: $($_.Exception.Message)" }

    # ── CHECK 6: Domain Admin accounts not used in 90+ days ──────────────────
    Write-Verbose '[AD-SecurityAudit] Checking stale Domain Admin accounts...'
    try {
        $daMembers = Get-ADGroupMember -Identity 'Domain Admins' -Recursive @adParams |
                     Where-Object { $_.objectClass -eq 'user' }
        foreach ($member in $daMembers) {
            $user = Get-ADUser -Identity $member.SamAccountName -Properties LastLogonDate, Enabled, PasswordLastSet @adParams
            if ($user.Enabled -and $user.LastLogonDate -and ($now - $user.LastLogonDate).TotalDays -gt 90) {
                $findings += [pscustomobject]@{
                    Severity    = 'High'
                    Category    = 'PrivilegedAccess'
                    Title       = "Domain Admin account inactive > 90 days"
                    Subject     = $user.SamAccountName
                    Detail      = "Last logon: $($user.LastLogonDate) ($([int]($now - $user.LastLogonDate).TotalDays) days ago). Enabled DA accounts that are not actively used are credential theft targets."
                    Remediation = "Disable or remove stale DA accounts. Enforce a just-in-time privileged access model — domain admin access should be time-limited, not persistent. Consider Microsoft PAM (Privileged Access Management) tier model."
                    RawData     = @{ SamAccountName = $user.SamAccountName; LastLogon = $user.LastLogonDate }
                }
            }
        }
    } catch { Write-Warning "Domain Admin stale check failed: $($_.Exception.Message)" }

    # ── CHECK 7: Domain trusts ────────────────────────────────────────────────
    Write-Verbose '[AD-SecurityAudit] Enumerating domain trusts...'
    try {
        $trusts = Get-ADTrust -Filter * @adParams
        foreach ($trust in $trusts) {
            $sev = 'Low'
            $detail = "Trust to: $($trust.Target) | Direction: $($trust.Direction) | Type: $($trust.TrustType)"
            if ($trust.TrustType -eq 'External') {
                $sev = 'Medium'
                $detail += " — External trusts bypass SID filtering if not enforced."
            }
            if (-not $trust.SIDFilteringForestAware -and $trust.Direction -in @('Bidirectional','Inbound')) {
                $sev = 'High'
                $detail += " — SID filtering may not be fully enforced (bidirectional/inbound risk)."
            }
            $findings += [pscustomobject]@{
                Severity    = $sev
                Category    = 'DomainTrust'
                Title       = "Domain trust: $($trust.Target)"
                Subject     = $trust.Name
                Detail      = $detail
                Remediation = "Review all trusts for business necessity. Ensure SID filtering is enabled on all external trusts. Disable inbound trust from untrusted domains if no longer needed. Document trust justification."
                RawData     = @{ TrustTarget = $trust.Target; Direction = $trust.Direction; TrustType = $trust.TrustType }
            }
        }
    } catch { Write-Warning "Domain trust check failed: $($_.Exception.Message)" }

    # ── CHECK 8: Accounts with reversible encryption enabled ─────────────────
    Write-Verbose '[AD-SecurityAudit] Checking reversible encryption accounts...'
    try {
        $ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
        $revEncAccts = Get-ADUser -Filter { Enabled -eq $true } -Properties UserAccountControl @adParams |
                       Where-Object { ($_.UserAccountControl -band $ENCRYPTED_TEXT_PWD_ALLOWED) -ne 0 }
        foreach ($acct in $revEncAccts) {
            $findings += [pscustomobject]@{
                Severity    = 'High'
                Category    = 'PasswordPolicy'
                Title       = "Account has 'Store password using reversible encryption' enabled"
                Subject     = $acct.SamAccountName
                Detail      = "Reversible encryption stores passwords in a recoverable form — functionally equivalent to cleartext. An attacker with NTDS.dit access can recover the plaintext password."
                Remediation = "Disable 'Store password using reversible encryption' for this account. Force a password reset after disabling. This setting should NEVER be enabled unless required by a legacy protocol (e.g., CHAP) — in that case, isolate the account."
                RawData     = @{ SamAccountName = $acct.SamAccountName; UAC = $acct.UserAccountControl }
            }
        }
    } catch { Write-Warning "Reversible encryption check failed: $($_.Exception.Message)" }

    # ── CHECK 9: Protected Users group membership (absence check) ────────────
    Write-Verbose '[AD-SecurityAudit] Checking Protected Users group membership for DA/EA...'
    try {
        $protectedUsers  = (Get-ADGroupMember -Identity 'Protected Users' -Recursive @adParams -ErrorAction SilentlyContinue) |
                            ForEach-Object { $_.SamAccountName }
        $daMembers       = (Get-ADGroupMember -Identity 'Domain Admins' -Recursive @adParams) |
                            Where-Object { $_.objectClass -eq 'user' }
        $notProtected    = $daMembers | Where-Object { $_.SamAccountName -notin $protectedUsers }

        foreach ($member in $notProtected) {
            $findings += [pscustomobject]@{
                Severity    = 'Medium'
                Category    = 'PrivilegedAccess'
                Title       = "Domain Admin not in Protected Users security group"
                Subject     = $member.SamAccountName
                Detail      = "Protected Users prevents credential caching, NTLM auth, DES/RC4 Kerberos, and unconstrained delegation — significantly raising the bar for pass-the-hash and pass-the-ticket attacks."
                Remediation = "Add all Domain Admin (and higher) accounts to the 'Protected Users' group. Test first with a non-production admin account — Protected Users restrictions may break legacy application dependencies."
                RawData     = @{ SamAccountName = $member.SamAccountName }
            }
        }
    } catch { Write-Warning "Protected Users check failed: $($_.Exception.Message)" }

    # ── CHECK 10: Default domain password policy ──────────────────────────────
    Write-Verbose '[AD-SecurityAudit] Checking default domain password policy...'
    try {
        $policy = Get-ADDefaultDomainPasswordPolicy @adParams
        if ($policy.MinPasswordLength -lt 12) {
            $findings += [pscustomobject]@{
                Severity    = 'Medium'
                Category    = 'PasswordPolicy'
                Title       = "Minimum password length below recommended threshold (< 12)"
                Subject     = "Default Domain Password Policy"
                Detail      = "Current minimum length: $($policy.MinPasswordLength). CIS Benchmark Level 1 recommends ≥ 14. NIST SP 800-63B recommends ≥ 8 but higher for shared/privileged accounts."
                Remediation = "Set minimum password length to at least 14 characters in Default Domain Policy. Consider implementing Microsoft Entra ID Password Protection to block common passwords and custom banned word lists on-prem."
                RawData     = @{ MinPasswordLength = $policy.MinPasswordLength }
            }
        }
        if ($policy.LockoutThreshold -eq 0) {
            $findings += [pscustomobject]@{
                Severity    = 'High'
                Category    = 'PasswordPolicy'
                Title       = "Account lockout threshold is disabled (0)"
                Subject     = "Default Domain Password Policy"
                Detail      = "No lockout threshold = unlimited password spray attempts. This is a critical misconfiguration for any internet-facing or password-spray-targeted environment."
                Remediation = "Set lockout threshold to 5-10 failed attempts (CIS: ≤5). Set lockout duration to ≥15 minutes. Set observation window to ≥15 minutes."
                RawData     = @{ LockoutThreshold = $policy.LockoutThreshold }
            }
        }
    } catch { Write-Warning "Password policy check failed: $($_.Exception.Message)" }

    Write-Verbose "[AD-SecurityAudit] $($findings.Count) findings from on-prem AD audit."
    return $findings
}
