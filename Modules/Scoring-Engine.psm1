<#
Scoring-Engine.psm1
Weighted risk scoring engine and HTML report generator for LeastPrivilegeIAMTools.
Produces a 0-100 domain health score (higher = better) and an HTML dashboard.
Part of LeastPrivilegeIAMTools v2.0
#>

# ── Severity weight table (deduction points) ─────────────────────────────────
$script:SeverityWeights = @{
    Critical = 25
    High     = 10
    Medium   =  3
    Low      =  1
}

$script:MaxScore      = 100
$script:ScorePenaltyCap = 100  # Can't score below 0

function Get-AuditScore {
    <#
    .SYNOPSIS  Calculates a weighted domain health score (0-100) from a findings array.
    .PARAMETER Findings   Array of finding objects with a .Severity property.
    .PARAMETER AuditScope Label for reporting (EntraID / OnPremAD / Full).
    .OUTPUTS   Hashtable: DomainScore, RiskRating, CriticalCount, HighCount, MediumCount, LowCount, TotalFindings
    #>
    [CmdletBinding()]
    param(
        [array]  $Findings,
        [string] $AuditScope = 'IAM'
    )

    $critical = ($Findings | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object).Count
    $high     = ($Findings | Where-Object { $_.Severity -eq 'High'     } | Measure-Object).Count
    $medium   = ($Findings | Where-Object { $_.Severity -eq 'Medium'   } | Measure-Object).Count
    $low      = ($Findings | Where-Object { $_.Severity -eq 'Low'      } | Measure-Object).Count

    $deduction = ($critical * $script:SeverityWeights.Critical) +
                 ($high     * $script:SeverityWeights.High)     +
                 ($medium   * $script:SeverityWeights.Medium)   +
                 ($low      * $script:SeverityWeights.Low)

    $score     = [math]::Max(0, $script:MaxScore - $deduction)
    $rating    = switch ($score) {
        { $_ -ge 90 } { 'Low Risk'       ; break }
        { $_ -ge 70 } { 'Medium Risk'    ; break }
        { $_ -ge 50 } { 'High Risk'      ; break }
        default       { 'Critical Risk'           }
    }

    return @{
        DomainScore    = $score
        RiskRating     = $rating
        AuditScope     = $AuditScope
        CriticalCount  = $critical
        HighCount      = $high
        MediumCount    = $medium
        LowCount       = $low
        TotalFindings  = $Findings.Count
        Deduction      = $deduction
    }
}

# ── HTML Report Generator ─────────────────────────────────────────────────────

function New-HtmlAuditReport {
    <#
    .SYNOPSIS  Generates a full HTML audit dashboard report.
    #>
    [CmdletBinding()]
    param(
        [array]    $Findings,
        [hashtable]$Score,
        [string]   $AuditType = 'IAM'
    )

    $genDate    = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $scoreColor = switch ($Score.DomainScore) {
        { $_ -ge 90 } { '#27ae60' ; break }
        { $_ -ge 70 } { '#f39c12' ; break }
        { $_ -ge 50 } { '#e67e22' ; break }
        default       { '#e74c3c'           }
    }

    # Build findings rows sorted by severity
    $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $sortedFindings = $Findings | Sort-Object { $severityOrder[$_.Severity] }

    $rows = $sortedFindings | ForEach-Object {
        $badgeColor = switch ($_.Severity) {
            'Critical' { '#e74c3c' }
            'High'     { '#e67e22' }
            'Medium'   { '#f39c12' }
            'Low'      { '#3498db' }
            default    { '#95a5a6' }
        }
        @"
        <tr>
            <td><span class="badge" style="background:$badgeColor">$($_.Severity)</span></td>
            <td>$($_.Category)</td>
            <td><strong>$([System.Web.HttpUtility]::HtmlEncode($_.Title))</strong></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($_.Subject))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($_.Detail))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($_.Remediation))</td>
        </tr>
"@
    }

    # Category breakdown for summary
    $catSummary = $Findings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
        "<li><strong>$($_.Name)</strong>: $($_.Count) finding(s)</li>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LeastPrivilegeIAMTools – $AuditType Audit Report</title>
<style>
  :root {
    --bg: #f8f9fa; --card: #ffffff; --border: #dee2e6;
    --text: #212529; --muted: #6c757d;
    --critical: #e74c3c; --high: #e67e22; --medium: #f39c12; --low: #3498db;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, Arial, sans-serif; background: var(--bg); color: var(--text); padding: 24px; }
  .header { background: #1a1a2e; color: white; padding: 28px 32px; border-radius: 8px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }
  .header h1 { font-size: 1.6rem; font-weight: 600; }
  .header .meta { font-size: 0.85rem; color: #adb5bd; margin-top: 4px; }
  .score-badge { text-align: center; }
  .score-number { font-size: 3.5rem; font-weight: 700; color: $scoreColor; line-height: 1; }
  .score-label  { font-size: 0.9rem; color: #adb5bd; margin-top: 4px; }
  .score-rating { font-size: 1rem; font-weight: 600; color: $scoreColor; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
  .card .count { font-size: 2.2rem; font-weight: 700; }
  .card .label { font-size: 0.8rem; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .card.critical .count { color: var(--critical); }
  .card.high     .count { color: var(--high);     }
  .card.medium   .count { color: var(--medium);   }
  .card.low      .count { color: var(--low);       }
  .section { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 24px; margin-bottom: 24px; }
  .section h2 { font-size: 1.1rem; margin-bottom: 16px; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 10px; }
  .section ul { padding-left: 20px; font-size: 0.9rem; line-height: 1.8; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  thead th { background: #f1f3f5; text-align: left; padding: 10px 12px; font-weight: 600; border-bottom: 2px solid var(--border); white-space: nowrap; }
  tbody td { padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:hover { background: #f8f9fa; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; color: white; font-size: 0.75rem; font-weight: 600; white-space: nowrap; }
  .filter-bar { margin-bottom: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
  .filter-btn { padding: 5px 14px; border: 1px solid var(--border); border-radius: 20px; cursor: pointer; font-size: 0.8rem; background: white; }
  .filter-btn.active, .filter-btn:hover { background: #1a1a2e; color: white; border-color: #1a1a2e; }
  .footer { text-align: center; font-size: 0.8rem; color: var(--muted); margin-top: 24px; }
  @media print { body { padding: 0; } .filter-bar { display: none; } }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>🛡️ LeastPrivilegeIAMTools — $AuditType Security Audit</h1>
    <div class="meta">Generated: $genDate &nbsp;|&nbsp; Lucidity Consulting LLC</div>
  </div>
  <div class="score-badge">
    <div class="score-number">$($Score.DomainScore)</div>
    <div class="score-label">/ 100</div>
    <div class="score-rating">$($Score.RiskRating)</div>
  </div>
</div>

<div class="cards">
  <div class="card critical"><div class="count">$($Score.CriticalCount)</div><div class="label">Critical</div></div>
  <div class="card high">    <div class="count">$($Score.HighCount)</div>    <div class="label">High</div></div>
  <div class="card medium">  <div class="count">$($Score.MediumCount)</div>  <div class="label">Medium</div></div>
  <div class="card low">     <div class="count">$($Score.LowCount)</div>     <div class="label">Low</div></div>
  <div class="card">         <div class="count">$($Score.TotalFindings)</div><div class="label">Total Findings</div></div>
</div>

<div class="section">
  <h2>📋 Executive Summary</h2>
  <p style="margin-bottom:12px; font-size:0.9rem; line-height:1.7;">
    This audit identified <strong>$($Score.TotalFindings) findings</strong> across the $AuditType environment,
    resulting in a domain health score of <strong style="color:$scoreColor">$($Score.DomainScore)/100 ($($Score.RiskRating))</strong>.
    $(if ($Score.CriticalCount -gt 0) { "<strong>$($Score.CriticalCount) critical finding(s) require immediate attention.</strong>" })
  </p>
  <ul>
    $($catSummary -join "`n    ")
  </ul>
</div>

<div class="section">
  <h2>🔍 Detailed Findings</h2>
  <div class="filter-bar" id="filterBar">
    <button class="filter-btn active" onclick="filterTable('All')">All ($($Score.TotalFindings))</button>
    <button class="filter-btn" onclick="filterTable('Critical')" style="border-color:#e74c3c;color:#e74c3c">Critical ($($Score.CriticalCount))</button>
    <button class="filter-btn" onclick="filterTable('High')"     style="border-color:#e67e22;color:#e67e22">High ($($Score.HighCount))</button>
    <button class="filter-btn" onclick="filterTable('Medium')"   style="border-color:#f39c12;color:#f39c12">Medium ($($Score.MediumCount))</button>
    <button class="filter-btn" onclick="filterTable('Low')"      style="border-color:#3498db;color:#3498db">Low ($($Score.LowCount))</button>
  </div>
  <div style="overflow-x:auto">
  <table id="findingsTable">
    <thead>
      <tr>
        <th>Severity</th><th>Category</th><th>Finding</th>
        <th>Subject</th><th>Detail</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      $($rows -join "`n")
    </tbody>
  </table>
  </div>
</div>

<div class="footer">
  LeastPrivilegeIAMTools v2.0 &nbsp;|&nbsp; Lucidity Consulting LLC &nbsp;|&nbsp;
  Score: $($Score.DomainScore)/100 (lower penalties = higher score = healthier posture) &nbsp;|&nbsp;
  Report generated $genDate
</div>

<script>
function filterTable(severity) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#findingsTable tbody tr').forEach(row => {
    if (severity === 'All') { row.style.display = ''; return; }
    const badge = row.querySelector('.badge');
    row.style.display = (badge && badge.textContent.trim() === severity) ? '' : 'none';
  });
}
</script>

</body>
</html>
"@
    return $html
}
