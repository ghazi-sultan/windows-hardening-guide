<#
.SYNOPSIS
    User Account Security Hardening Script for Windows 11
.DESCRIPTION
    Implements key account security measures:
    - Disables Guest account
    - Removes unused local accounts (optional, requires confirmation)
    - Renames built-in Administrator account
    - Configures account lockout policies
    - Enforces strong password requirements
.NOTES
    Run this script in an elevated PowerShell session (Run as Administrator).
#>

# -------------------------------
# 1. Disable the Guest Account
# -------------------------------
Write-Host "Disabling Guest account..." -ForegroundColor Cyan
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

# -------------------------------
# 2. Rename the Built-in Administrator Account
# -------------------------------
$newAdminName = "SysAdmin_Secure"  # <-- Change this to your preferred name
Write-Host "Renaming built-in Administrator account to '$newAdminName'..." -ForegroundColor Cyan
Rename-LocalUser -Name "Administrator" -NewName $newAdminName -ErrorAction SilentlyContinue

# -------------------------------
# 3. Optional: Remove Unused Local Accounts
# -------------------------------
Write-Host "Checking for unused local accounts..." -ForegroundColor Cyan
$accounts = Get-LocalUser | Where-Object { $_.Name -notin @($newAdminName, "Guest", "$env:UserName") }

foreach ($acc in $accounts) {
    $confirm = Read-Host "Do you want to remove the account '$($acc.Name)'? (y/n)"
    if ($confirm -eq "y") {
        Remove-LocalUser -Name $acc.Name
        Write-Host "Removed account: $($acc.Name)" -ForegroundColor Yellow
    }
}

# -------------------------------
# 4. Configure Account Lockout Policies
# -------------------------------
Write-Host "Configuring account lockout policy..." -ForegroundColor Cyan
# Lock account after 5 failed attempts
net accounts /lockoutthreshold:5
# Lockout duration: 15 minutes
net accounts /lockoutduration:15
# Reset account lockout counter after 15 minutes
net accounts /lockoutwindow:15

# -------------------------------
# 5. Enforce Strong Password Requirements
# -------------------------------
Write-Host "Enforcing strong password requirements..." -ForegroundColor Cyan
# Minimum password length: 12
net accounts /minpwlen:12
# Maximum password age: 90 days
net accounts /maxpwage:90
# Minimum password age: 1 day
net accounts /minpwage:1

# Enable password complexity (via Local Security Policy)
Write-Host "Enabling password complexity requirements..." -ForegroundColor Cyan
secedit /export /cfg "$env:TEMP\secpol.cfg"
(Get-Content "$env:TEMP\secpol.cfg") -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1' | Set-Content "$env:TEMP\secpol.cfg"
secedit /configure /db "$env:windir\security\local.sdb" /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY
Remove-Item "$env:TEMP\secpol.cfg" -Force

Write-Host "User Account Security hardening complete." -ForegroundColor Green
