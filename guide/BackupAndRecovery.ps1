<#
.SYNOPSIS
    Backup and Recovery Helper Script for Windows

.DESCRIPTION
    Automates several backup and recovery steps:
    - Checks for File History drive and enables it
    - Creates a system restore point
    - (Optional) Starts a full system image backup using wbadmin

.NOTES
    Run this script as Administrator
    Author: [Your Name]
    Date:   [Date]
#>

# =============================
# 1. Check for File History Drive and Enable
# =============================
Write-Host "[*] Checking for File History target drive..." -ForegroundColor Cyan
$drives = Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -or $_.DriveType -eq 'Fixed' -and $_.DriveLetter -ne $null -and $_.DriveLetter -ne 'C' }

if ($drives) {
    Write-Host "[+] Found drive(s): $($drives.DriveLetter -join ', ')" -ForegroundColor Green
    try {
        Write-Host "[*] Attempting to enable File History..."
        Start-Process "control.exe" "/name Microsoft.FileHistory" -Verb RunAs
        Write-Host "[!] File History settings opened — please enable and select a backup drive manually if not already configured." -ForegroundColor Yellow
    } catch {
        Write-Host "[!] Failed to open File History settings: $_" -ForegroundColor Red
    }
} else {
    Write-Host "[!] No suitable backup drive detected. Please connect one and re-run this step." -ForegroundColor Red
}

# =============================
# 2. Create a Restore Point
# =============================
Write-Host "[*] Creating a system restore point..." -ForegroundColor Cyan
Checkpoint-Computer -Description "Pre-Backup Hardening" -RestorePointType "MODIFY_SETTINGS"
Write-Host "[+] Restore point created." -ForegroundColor Green

# =============================
# 3. (Optional) Start System Image Backup
# =============================
# Note: wbadmin requires a destination drive/UNC path. Uncomment and edit as needed.
# Example: D: drive for backups
# $backupDest = "D:"
# Write-Host "[*] Starting system image backup to $backupDest ..." -ForegroundColor Cyan
# wbadmin start backup -backupTarget:$backupDest -include:C: -allCritical -quiet
# Write-Host "[+] System image backup complete." -ForegroundColor Green

Write-Host "[*] Backup and recovery configuration complete." -ForegroundColor Cyan
