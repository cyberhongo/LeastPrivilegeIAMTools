function Invoke-LeastPrivilegeAudit {
    <#
    .SYNOPSIS
        Performs a least-privilege audit of Azure AD / Entra ID application registrations.

    .DESCRIPTION
        - Installs Microsoft Graph SDK if not present.
        - Supports both delegated login (interactive) and application login (client credentials).
        - Flags apps that request application roles (app-level permissions).
        - Outputs a timestamped audit report to a specified file.
        - Disconnects from Graph when complete.

    .PARAMETER OutputPath
        Path where the audit report will be saved.

    .PARAMETER ClientId
        (Optional) Application (client) ID for app-based authentication.

    .PARAMETER TenantId
        (Optional) Directory (tenant) ID for app-based authentication.

    .PARAMETER ClientSecret
        (Optional) Client secret for app-based authentication.
    #>

    [CmdletBinding()]
    param(
        [string]$OutputPath = "C:\Audit\OverprivilegedApps-$((Get-Date).ToString('yyyyMMdd-HHmmss')).txt",
        [string]$ClientId,
        [string]$TenantId,
        [string]$ClientSecret
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Ensure Microsoft Graph SDK is installed
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Verbose "Installing Microsoft.Graph SDK..."
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -AllowClobber -Force
    }

    Import-Module Microsoft.Graph -ErrorAction Stop

    # Connect to Microsoft Graph
    if ($ClientId -and $TenantId -and $ClientSecret) {
        Write-Host "Using application-based authentication..."
        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -ClientSecret $ClientSecret -Scopes "https://graph.microsoft.com/.default"
    } else {
        Write-Host "Using delegated (interactive) authentication..."
        $delegatedScopes = @(
            'Application.Read.All'
            'Directory.Read.All'
            'RoleManagement.Read.Directory'
        )
        Connect-MgGraph -Scopes $delegatedScopes -NoWelcome
    }

    # Validate connection
    try {
        $null = Get-MgContext
    } catch {
        throw "Failed to connect to Microsoft Graph. Check credentials and permissions."
    }

    # Ensure output directory exists
    $folder = Split-Path -Parent $OutputPath
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder | Out-Null
    }

    # Begin audit
    "Least Privilege Audit Report - $(Get-Date -Format 'u')" | Out-File -FilePath $OutputPath -Encoding utf8

    try {
        $apps = Get-MgApplication -All
    } catch {
        throw "Failed to retrieve applications. Ensure the app has Application.Read.All and Directory.Read.All permissions with admin consent."
    }

    foreach ($app in $apps) {
        $privilegedRoles = $app.RequiredResourceAccess.ResourceAccess |
            Where-Object { $_.Type -eq 'Role' }

        if ($privilegedRoles) {
            "Over-privileged app: $($app.DisplayName) ($($app.AppId))" | Out-File -FilePath $OutputPath -Append -Encoding utf8
            foreach ($role in $privilegedRoles) {
                "  - Role ID: $($role.Id)" | Out-File -FilePath $OutputPath -Append -Encoding utf8
            }
        }
    }

    Disconnect-MgGraph
    Write-Host "Audit complete. Output saved to: $OutputPath"
}

Export-ModuleMember -Function Invoke-LeastPrivilegeAudit
