#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

$backupDirectory = Join-Path $env:ProgramData 'AI_Firewall_Project'
$backupPath = Join-Path $backupDirectory 'firewall-profile-backup.json'
$loggingBackupPath = Join-Path $backupDirectory 'firewall-logging-backup.json'
$auditBackupPath = Join-Path $backupDirectory 'connection-audit-backup.json'
$auditSubcategoryGuid = '{0CCE9226-69AE-11D9-BED3-505054503030}'
if (-not (Test-Path -LiteralPath $backupPath)) {
    throw "No saved firewall profile settings were found at $backupPath. No settings were changed."
}

function Set-ConnectionAuditState($success, $failure) {
    $successSetting = if ($success) { 'enable' } else { 'disable' }
    $failureSetting = if ($failure) { 'enable' } else { 'disable' }
    & auditpol.exe /set /subcategory:$auditSubcategoryGuid `
        /success:$successSetting /failure:$failureSetting | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not restore the Filtering Platform Connection audit policy.'
    }
}

function Get-ConnectionAuditState {
    $output = & auditpol.exe /get /subcategory:$auditSubcategoryGuid /r
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not verify the Filtering Platform Connection audit policy.'
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
        default { throw "Unrecognized audit policy setting '$setting'." }
    }
}

$savedProfiles = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
$expectedProfiles = @('Domain', 'Private', 'Public')
$savedNames = @($savedProfiles | ForEach-Object { $_.Name } | Sort-Object)
$expectedNames = @($expectedProfiles | Sort-Object)
if (($savedNames -join ',') -ne ($expectedNames -join ',')) {
    throw "The saved firewall profile settings are incomplete or invalid. No settings were changed."
}

if (Test-Path -LiteralPath $loggingBackupPath) {
    $savedLogging = Get-Content -LiteralPath $loggingBackupPath -Raw | ConvertFrom-Json
    $savedLoggingNames = @($savedLogging | ForEach-Object { $_.Name } | Sort-Object)
    if (($savedLoggingNames -join ',') -ne ($expectedNames -join ',') -or
        @($savedLogging | Where-Object { $null -eq $_.LogBlocked -or $null -eq $_.LogAllowed }).Count -gt 0) {
        throw "The saved firewall logging settings are incomplete or invalid. No settings were changed."
    }
}
if (Test-Path -LiteralPath $auditBackupPath) {
    $savedAudit = Get-Content -LiteralPath $auditBackupPath -Raw | ConvertFrom-Json
    if ($null -eq $savedAudit.Success -or $null -eq $savedAudit.Failure) {
        throw "The saved connection-audit settings are incomplete or invalid. No settings were changed."
    }
}

foreach ($savedProfile in $savedProfiles) {
    Set-NetFirewallProfile `
        -Profile $savedProfile.Name `
        -Enabled ([bool]$savedProfile.Enabled) `
        -DefaultInboundAction ([string]$savedProfile.DefaultInboundAction) `
        -DefaultOutboundAction ([string]$savedProfile.DefaultOutboundAction)
}

if (Test-Path -LiteralPath $loggingBackupPath) {
    foreach ($savedProfile in $savedLogging) {
        Set-NetFirewallProfile `
            -Profile $savedProfile.Name `
            -LogBlocked ([bool]$savedProfile.LogBlocked) `
            -LogAllowed ([bool]$savedProfile.LogAllowed)
    }
}

if (Test-Path -LiteralPath $auditBackupPath) {
    Set-ConnectionAuditState `
        -success ([bool]$savedAudit.Success) `
        -failure ([bool]$savedAudit.Failure)
    $restoredAudit = Get-ConnectionAuditState
    if ($restoredAudit.Success -ne [bool]$savedAudit.Success -or
        $restoredAudit.Failure -ne [bool]$savedAudit.Failure) {
        throw "Filtering Platform Connection audit restoration could not be verified. Backups retained in $backupDirectory."
    }
}

foreach ($savedProfile in $savedProfiles) {
    $profile = Get-NetFirewallProfile -Profile $savedProfile.Name
    if ($profile.Enabled -ne [bool]$savedProfile.Enabled -or
        $profile.DefaultInboundAction -ne [string]$savedProfile.DefaultInboundAction -or
        $profile.DefaultOutboundAction -ne [string]$savedProfile.DefaultOutboundAction) {
        throw "Firewall policy restoration could not be verified for the $($savedProfile.Name) profile. Backup retained at $backupPath."
    }
}

if (Test-Path -LiteralPath $loggingBackupPath) {
    foreach ($savedProfile in $savedLogging) {
        $profile = Get-NetFirewallProfile -Profile $savedProfile.Name
        if ($profile.LogBlocked -ne [bool]$savedProfile.LogBlocked -or
            $profile.LogAllowed -ne [bool]$savedProfile.LogAllowed) {
            throw "Firewall logging restoration could not be verified for the $($savedProfile.Name) profile. Backups retained in $backupDirectory."
        }
    }
}

Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -like 'AI_Firewall_Expire_*' } |
    Unregister-ScheduledTask -Confirm:$false
Get-NetFirewallRule -Group 'AI Firewall Project' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule

Remove-Item -LiteralPath $backupPath
if (Test-Path -LiteralPath $loggingBackupPath) {
    Remove-Item -LiteralPath $loggingBackupPath
}
if (Test-Path -LiteralPath $auditBackupPath) {
    Remove-Item -LiteralPath $auditBackupPath
}
if (-not (Get-ChildItem -LiteralPath $backupDirectory -Force)) {
    Remove-Item -LiteralPath $backupDirectory
}

Write-Host 'Previous Windows Defender Firewall profile settings were restored.'
Write-Host 'AI Firewall Project rules and their scheduled expiry tasks were removed.'
