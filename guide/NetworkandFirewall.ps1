<#
.SYNOPSIS
    Network and Firewall Security Hardening Script for Windows 11
.DESCRIPTION
    Automates network-related security configurations:
    - Sets current network to Public
    - Optionally disables IPv6
    - Disables Remote Desktop, Remote Assistance, and SMBv1
    - Ensures Windows Defender Firewall is enabled and blocks inbound connections by default
    - Enables logging for dropped packets
.NOTES
    Run in elevated PowerShell (Run as Administrator).
#>

# -------------------------------
# 1. Set Current Network to Public
# -------------------------------
Write-Host "Setting current network profile to Public..." -ForegroundColor Cyan
Get-NetConnectionProfile | ForEach-Object {
    Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Public
}

# -------------------------------
# 2. Optional: Disable IPv6
# -------------------------------
$disableIPv6 = Read-Host "Do you want to disable IPv6 on all network adapters? (y/n)"
if ($disableIPv6 -eq "y") {
    Write-Host "Disabling IPv6 on all adapters..." -ForegroundColor Cyan
    Get-NetAdapterBinding -ComponentID ms_tcpip6 | ForEach-Object {
        Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6
    }
}

# -------------------------------
# 3. Disable Remote Desktop & Remote Assistance
# -------------------------------
Write-Host "Disabling Remote Desktop..." -ForegroundColor Cyan
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1

Write-Host "Disabling Remote Assistance..." -ForegroundColor Cyan
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name "fAllowToGetHelp" -Value 0

# -------------------------------
# 4. Disable SMBv1
# -------------------------------
Write-Host "Disabling SMBv1 protocol..." -ForegroundColor Cyan
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# -------------------------------
# 5. Configure Windows Defender Firewall
# -------------------------------
Write-Host "Enabling Windows Firewall for all profiles..." -ForegroundColor Cyan
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

Write-Host "Blocking inbound connections by default..." -ForegroundColor Cyan
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# -------------------------------
# 6. Enable Firewall Logging for Dropped Packets
# -------------------------------
Write-Host "Enabling dropped packet logging..." -ForegroundColor Cyan
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed False -LogBlocked True -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384

Write-Host "Network and Firewall Security hardening complete." -ForegroundColor Green
