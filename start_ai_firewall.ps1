#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

$profiles = Get-NetFirewallProfile -Profile Domain, Private, Public
foreach ($profile in $profiles) {
    if (-not $profile.Enabled -or -not $profile.LogBlocked -or $profile.LogAllowed) {
        throw "Run install_windows.ps1 as Administrator first; the firewall policy is not configured for $($profile.Name)."
    }
}

$auditSubcategoryGuid = '{0CCE9226-69AE-11D9-BED3-505054503030}'
$auditOutput = & auditpol.exe /get /subcategory:$auditSubcategoryGuid /r
if ($LASTEXITCODE -ne 0) {
    throw 'Could not verify Filtering Platform Connection success auditing.'
}
$auditRow = $auditOutput | ConvertFrom-Csv |
    Where-Object { ($_.'Subcategory GUID' -replace '[{}]', '') -eq $auditSubcategoryGuid } |
    Select-Object -First 1
if (-not $auditRow -or ([string]$auditRow.'Inclusion Setting') -notmatch 'Success') {
    throw 'Run install_windows.ps1 as Administrator first; connection success auditing is not enabled.'
}

$python = Get-Command python -ErrorAction Stop
$monitorPath = Join-Path $PSScriptRoot 'firewall_core.py'
& $python.Source $monitorPath monitor
if ($LASTEXITCODE -ne 0) {
    throw "The AI firewall monitor exited with code $LASTEXITCODE."
}
