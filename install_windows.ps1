#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

$profileNames = @('Domain', 'Private', 'Public')
$backupDirectory = Join-Path $env:ProgramData 'AI_Firewall_Project'
$backupPath = Join-Path $backupDirectory 'firewall-profile-backup.json'
$loggingBackupPath = Join-Path $backupDirectory 'firewall-logging-backup.json'
$auditBackupPath = Join-Path $backupDirectory 'connection-audit-backup.json'
$auditSubcategoryGuid = '{0CCE9226-69AE-11D9-BED3-505054503030}'

function Get-ConnectionAuditState {
    $output = & auditpol.exe /get /subcategory:$auditSubcategoryGuid /r
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not read the Filtering Platform Connection audit policy.'
    }

    $row = $output | ConvertFrom-Csv |
        Where-Object { ($_.'Subcategory GUID' -replace '[{}]', '') -eq $auditSubcategoryGuid } |
        Select-Object -First 1
    if (-not $row) {
        throw 'Could not identify the Filtering Platform Connection audit policy row.'
    }

    $setting = ([string]$row.'Inclusion Setting').Trim()
    switch -Exact ($setting) {
        'No Auditing' { return [PSCustomObject]@{ Success = $false; Failure = $false } }
        'Success' { return [PSCustomObject]@{ Success = $true; Failure = $false } }
        'Failure' { return [PSCustomObject]@{ Success = $false; Failure = $true } }
        'Success and Failure' { return [PSCustomObject]@{ Success = $true; Failure = $true } }
        default { throw "Unrecognized audit policy setting '$setting'; refusing to change it." }
    }
}

function Set-ConnectionAuditState($success, $failure) {
    $successSetting = if ($success) { 'enable' } else { 'disable' }
    $failureSetting = if ($failure) { 'enable' } else { 'disable' }
    & auditpol.exe /set /subcategory:$auditSubcategoryGuid `
        /success:$successSetting /failure:$failureSetting | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not update the Filtering Platform Connection audit policy.'
    }
}

foreach ($profileName in $profileNames) {
    $profile = Get-NetFirewallProfile -Profile $profileName
    if ($profile.PolicyStoreSourceType -eq 'GroupPolicy') {
        throw "The $profileName profile is managed by Group Policy. No settings were changed."
    }
}

if (-not (Test-Path -LiteralPath $backupPath)) {
    New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
    $snapshot = foreach ($profileName in $profileNames) {
        $profile = Get-NetFirewallProfile -Profile $profileName
        [PSCustomObject]@{
            Name                  = $profile.Name
            Enabled               = [bool]$profile.Enabled
            DefaultInboundAction  = [string]$profile.DefaultInboundAction
            DefaultOutboundAction = [string]$profile.DefaultOutboundAction
        }
    }
    $snapshot | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $backupPath -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $loggingBackupPath)) {
    $loggingSnapshot = foreach ($profileName in $profileNames) {
        $profile = Get-NetFirewallProfile -Profile $profileName
        [PSCustomObject]@{
            Name       = $profile.Name
            LogBlocked = [bool]$profile.LogBlocked
            LogAllowed = [bool]$profile.LogAllowed
        }
    }
    $loggingSnapshot | ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath $loggingBackupPath -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $auditBackupPath)) {
    $auditSnapshot = Get-ConnectionAuditState
    $auditSnapshot | ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath $auditBackupPath -Encoding UTF8
}

$expectedProfiles = @($profileNames | Sort-Object)
$savedProfiles = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
$savedProfileNames = @($savedProfiles | ForEach-Object { $_.Name } | Sort-Object)
$savedLogging = Get-Content -LiteralPath $loggingBackupPath -Raw | ConvertFrom-Json
$savedLoggingNames = @($savedLogging | ForEach-Object { $_.Name } | Sort-Object)
$savedAudit = Get-Content -LiteralPath $auditBackupPath -Raw | ConvertFrom-Json
if (($savedProfileNames -join ',') -ne ($expectedProfiles -join ',') -or
    ($savedLoggingNames -join ',') -ne ($expectedProfiles -join ',') -or
    @($savedLogging | Where-Object { $null -eq $_.LogBlocked -or $null -eq $_.LogAllowed }).Count -gt 0 -or
    $null -eq $savedAudit.Success -or $null -eq $savedAudit.Failure) {
    throw "The saved firewall, logging, or audit settings are incomplete or invalid. No settings were changed."
}

try {
    Set-NetFirewallProfile `
        -Profile $profileNames `
        -Enabled True `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -LogBlocked True `
        -LogAllowed False

    $currentAudit = Get-ConnectionAuditState
    Set-ConnectionAuditState -success $true -failure $currentAudit.Failure

    foreach ($profileName in $profileNames) {
        $profile = Get-NetFirewallProfile -Profile $profileName
        if (-not $profile.Enabled -or
            $profile.DefaultInboundAction -ne 'Block' -or
            $profile.DefaultOutboundAction -ne 'Allow' -or
            -not $profile.LogBlocked -or
            $profile.LogAllowed) {
            throw "Firewall policy verification failed for the $profileName profile."
        }
    }
    if (-not (Get-ConnectionAuditState).Success) {
        throw 'Filtering Platform Connection success auditing could not be verified.'
    }
}
catch {
    $applyError = $_
    try {
        $savedProfiles = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        foreach ($savedProfile in $savedProfiles) {
            Set-NetFirewallProfile `
                -Profile $savedProfile.Name `
                -Enabled ([bool]$savedProfile.Enabled) `
                -DefaultInboundAction ([string]$savedProfile.DefaultInboundAction) `
                -DefaultOutboundAction ([string]$savedProfile.DefaultOutboundAction)
        }
        $savedLogging = Get-Content -LiteralPath $loggingBackupPath -Raw | ConvertFrom-Json
        foreach ($savedProfile in $savedLogging) {
            Set-NetFirewallProfile `
                -Profile $savedProfile.Name `
                -LogBlocked ([bool]$savedProfile.LogBlocked) `
                -LogAllowed ([bool]$savedProfile.LogAllowed)
        }
        $savedAudit = Get-Content -LiteralPath $auditBackupPath -Raw | ConvertFrom-Json
        Set-ConnectionAuditState `
            -success ([bool]$savedAudit.Success) `
            -failure ([bool]$savedAudit.Failure)
    }
    catch {
        throw "Applying firewall policy failed: $applyError Rollback also failed: $_. Backups retained in $backupDirectory."
    }

    throw "Applying firewall policy failed and the previous firewall, logging, and audit settings were restored: $applyError"
}

Write-Host 'Windows Defender Firewall is enabled for Domain, Private, and Public.'
Write-Host 'Default inbound action: Block. Default outbound action: Allow.'
Write-Host 'Dropped-connection logging and Filtering Platform Connection success auditing are enabled.'
Write-Host 'Existing firewall rules were preserved.'
Write-Host "Previous settings are backed up in: $backupDirectory"
