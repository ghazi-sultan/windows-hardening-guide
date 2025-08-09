<#
.SYNOPSIS
    Device & Peripheral Security Hardening Script for Windows 11
.DESCRIPTION
    Automates common device and peripheral security measures:
    - Disable Bluetooth adapters
    - Optionally disable USB storage devices
    - Check Device Guard / Credential Guard status
    - Optionally disable specific peripherals (printers, webcams, etc.)
.NOTES
    Run this script in an elevated PowerShell session (Run as Administrator).
#>

# -------------------------------
# 1. Disable Bluetooth Adapters
# -------------------------------
Write-Host "Checking for Bluetooth adapters..." -ForegroundColor Cyan
$btAdapters = Get-NetAdapter | Where-Object { $_.Name -like "*Bluetooth*" }
if ($btAdapters) {
    foreach ($adapter in $btAdapters) {
        $confirmBT = Read-Host "Disable Bluetooth adapter '$($adapter.Name)'? (y/n)"
        if ($confirmBT -eq "y") {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false
            Write-Host "Bluetooth adapter '$($adapter.Name)' disabled." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "No Bluetooth adapters found." -ForegroundColor DarkGray
}

# -------------------------------
# 2. Optional: Disable USB Storage Devices
# -------------------------------
$disableUSB = Read-Host "Do you want to disable ALL USB storage devices? (y/n)"
if ($disableUSB -eq "y") {
    Write-Host "Disabling USB storage devices..." -ForegroundColor Cyan
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
    Write-Host "USB storage devices disabled. This requires a restart to take full effect." -ForegroundColor Yellow
}

# -------------------------------
# 3. Check Device Guard & Credential Guard Status
# -------------------------------
Write-Host "Checking Device Guard / Credential Guard status..." -ForegroundColor Cyan
$dgStatus = Get-CimInstance -ClassName Win32_DeviceGuard
$dgStatus | Format-List *

# -------------------------------
# 4. Optional: Disable Specific Peripherals
# -------------------------------
$disablePeripheral = Read-Host "Do you want to list and optionally disable other peripherals (printers, webcams, etc.)? (y/n)"
if ($disablePeripheral -eq "y") {
    Write-Host "Listing peripherals..." -ForegroundColor Cyan
    $devices = Get-PnpDevice | Where-Object { $_.Status -eq "OK" -and $_.Class -in @("Printer","Image","SmartCardReader") }
    if ($devices) {
        $devices | Format-Table -AutoSize
        foreach ($device in $devices) {
            $confirmDevice = Read-Host "Disable device '$($device.FriendlyName)'? (y/n)"
            if ($confirmDevice -eq "y") {
                Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false
                Write-Host "Device '$($device.FriendlyName)' disabled." -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "No matching peripherals found." -ForegroundColor DarkGray
    }
}

Write-Host "Device and Peripheral Security hardening complete." -ForegroundColor Green
