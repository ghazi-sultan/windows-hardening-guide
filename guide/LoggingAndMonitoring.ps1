<#
.SYNOPSIS
    Logging & Monitoring Hardening Script

.DESCRIPTION
    Implements key actions from the "Logging and Monitoring" section:
    - Enables advanced security auditing
    - Increases log sizes and retention
    - Configures PowerShell script block logging & transcription
    - Creates a custom Event Viewer view for security events

.NOTES
    Author: Your Name
    Requires: PowerShell 5.1+, Local Admin rights
    Test before deployment in production.
#>

# -------------------------------
# Enable Advanced Audit Policy Categories
# -------------------------------
Write-Host "[*] Enabling advanced auditing policies..." -ForegroundColor Cyan
$categories = @(
    "Logon/Logoff",
    "Object Access",
    "Privilege Use",
    "Policy Change",
    "Account Management"
)

foreach ($cat in $categories) {
    auditpol /set /subcategory:"$cat" /success:enable /failure:enable | Out-Null
}
Write-Host "[+] Advanced audit policies enabled." -ForegroundColor Green

# -------------------------------
# Increase Event Log Sizes & Retention
# -------------------------------
Write-Host "[*] Increasing event log sizes and retention..." -ForegroundColor Cyan
$logs = @("Security", "System", "Application")
foreach ($log in $logs) {
    wevtutil sl $log /ms:104857600  # 100 MB per log
    wevtutil sl $log /rt:true       # Retain logs; do not overwrite automatically
}
Write-Host "[+] Log sizes increased to 100MB and retention enabled." -ForegroundColor Green

# -------------------------------
# Enable PowerShell Script Block Logging & Transcription
# -------------------------------
Write-Host "[*] Enabling PowerShell script block logging & transcription..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                     -Name "EnableScriptBlockLogging" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
                     -Name "EnableTranscripting" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
                     -Name "OutputDirectory" -Value "C:\PowerShell_Logs" -Force
    New-Item -Path "C:\PowerShell_Logs" -ItemType Directory -Force | Out-Null
    Write-Host "[+] PowerShell logging enabled. Logs will be stored in C:\PowerShell_Logs" -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to enable PowerShell logging: $_" -ForegroundColor Red
}

# -------------------------------
# Create Custom Event Viewer View (Security-focused)
# -------------------------------
Write-Host "[*] Creating custom Event Viewer view for critical security events..." -ForegroundColor Cyan
$customViewXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4720 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4725 or EventID=4726)]]</Select>
  </Query>
</QueryList>
"@

$viewPath = "$env:ProgramData\Microsoft\Event Viewer\Views\Security_Monitor.xml"
$customViewXml | Out-File -Encoding UTF8 -FilePath $viewPath
Write-Host "[+] Custom Event Viewer security view created at: $viewPath" -ForegroundColor Green

# -------------------------------
# Final Output
# -------------------------------
Write-Host "`n[✔] Logging & Monitoring configuration completed." -ForegroundColor Green
Write-Host "Tip: Configure Windows Event Forwarding or SIEM integration for centralized monitoring." -ForegroundColor Yellow
