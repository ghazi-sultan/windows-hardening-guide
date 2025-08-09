<#
.SYNOPSIS
    Application & Software Security Helper Script

.DESCRIPTION
    Automates key hardening actions from the "Application and Software Security" section:
    - Enables Windows SmartScreen
    - Disables SMBv1 protocol
    - Updates all applications via Windows Package Manager (winget)
    - Optionally lists and uninstalls legacy or unwanted software

.NOTES
    Author: Your Name
    Requires: Windows 10/11, PowerShell 5.1+, winget installed
    Test in a lab environment before deploying in production.
#>

# -------------------------------
# Function: Enable SmartScreen
# -------------------------------
Write-Host "[*] Enabling Windows SmartScreen..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
                     -Name "SmartScreenEnabled" -Value "RequireAdmin" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" `
                     -Name "EnableWebContentEvaluation" -Value 1 -Force
    Write-Host "[+] SmartScreen has been enabled." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to enable SmartScreen: $_" -ForegroundColor Red
}

# -------------------------------
# Function: Disable SMBv1 Protocol
# -------------------------------
Write-Host "[*] Disabling SMBv1 protocol..." -ForegroundColor Cyan
try {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
    Write-Host "[+] SMBv1 has been disabled." -ForegroundColor Green
} catch {
    Write-Host "[!] SMBv1 disable command failed (it may already be disabled): $_" -ForegroundColor Yellow
}

# -------------------------------
# Function: Update Apps with Winget
# -------------------------------
Write-Host "[*] Updating installed applications via winget..." -ForegroundColor Cyan
if (Get-Command winget -ErrorAction SilentlyContinue) {
    try {
        winget upgrade --all --accept-source-agreements --accept-package-agreements
        Write-Host "[+] Application updates completed." -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to update some or all applications: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] winget is not installed. Skipping app updates." -ForegroundColor Yellow
}

# -------------------------------
# Optional: List & Uninstall Legacy Software
# -------------------------------
$choice = Read-Host "Do you want to list installed apps for review/uninstall? (y/n)"
if ($choice -match '^[Yy]$') {
    Write-Host "[*] Gathering installed applications..." -ForegroundColor Cyan
    $apps = Get-WmiObject -Class Win32_Product | Sort-Object Name
    $apps | Format-Table Name, Version, Vendor -AutoSize

    $removeChoice = Read-Host "Do you want to uninstall any application now? (y/n)"
    if ($removeChoice -match '^[Yy]$') {
        $appName = Read-Host "Enter the exact name of the application to uninstall"
        $targetApp = $apps | Where-Object { $_.Name -eq $appName }
        if ($targetApp) {
            Write-Host "[*] Uninstalling $appName ..." -ForegroundColor Cyan
            $targetApp.Uninstall() | Out-Null
            Write-Host "[+] $appName has been uninstalled." -ForegroundColor Green
        } else {
            Write-Host "[!] Application not found. Check spelling and try again." -ForegroundColor Yellow
        }
    }
}

Write-Host "`n[✔] Application & Software Security tasks completed." -ForegroundColor Green
