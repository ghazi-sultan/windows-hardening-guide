# Windows Hardening Guide

A practical and beginner-friendly checklist for hardening a Windows system, created for IT professionals, home users, and cybersecurity beginners. This guide focuses on actionable steps with built-in tools, no third-party software required.

---
## 1. Overview
---
## 🔒 Basic Hardening Steps (Beginner Friendly)

1. **Keep Windows Updated** – Regularly install Windows Updates and security patches via Windows Update or WSUS.
2. **Use Strong Passwords** – Create long, complex passwords. Consider using a passphrase (e.g. `CoffeeBeansGrowFast!2025`).
3. **Enable Account Lockout Policies** – Prevent brute-force attacks by limiting login attempts:
   - `secpol.msc` → Account Policies → Account Lockout Policy
4. **Disable Unused User Accounts** – Remove or disable guest/default accounts that aren’t needed.
5. **Use a Standard User Account for Daily Use** – Avoid using the Administrator account unless necessary.
6. **Enable Windows Defender & Configure It** – Real-time protection, cloud-delivered protection, and automatic sample submission should be ON.
7. **Enable SmartScreen Filter** – Helps block malicious sites and downloads.
8. **Use BitLocker Drive Encryption** – Encrypt the system drive (`C:`) to prevent unauthorized access to data.
9. **Enable Firewall (Windows Defender Firewall)** – Ensure it’s active and logging:
   - `wf.msc` → Properties → Logging tab → Customize → Log dropped packets and successful connections
10. **Disable Remote Desktop if Not Used** – Only enable RDP if needed and use strong authentication methods (MFA or VPN).

---

## 🛠️ Intermediate Security Tweaks

11. **Set UAC (User Account Control) to Always Notify**
12. **Audit Logon Events and Failed Access Attempts**
13. **Disable Autorun for External Drives** – Prevent malware via USB.
14. **Remove Bloatware or Preinstalled Apps** – Use `winget` or `PowerShell`.
15. **Limit Windows Telemetry** – Go to Settings → Privacy → Diagnostics & feedback.
16. **Check for Open Ports Regularly** – Use `netstat -ano` or tools like TCPView.
17. **Use NTFS Permissions to Restrict File Access**
18. **Disable SMBv1 Protocol** – Legacy protocol often targeted by ransomware.
19. **Disable Windows Script Host (if not needed)** – Prevent `.vbs` and `.js` abuse.
20. **Enable Secure Boot in BIOS**

---
## 2. User account security
---
A major part of system hardening involves restricting user access to only what is necessary. This helps limit the potential impact of malware or unauthorized users.

1. **Use Standard Accounts for Daily Tasks:** Admin privileges should only be used when needed. For normal use, operate from a non-admin account.
2. **Disable Unused or Default Accounts:** Remove old user profiles and ensure the Guest account is disabled.
3. **Rename the Built-in Administrator Account:** Attackers often target this account by name. Renaming it adds an extra layer of obscurity.
4. **Implement Account Lockout Policies:** Configure Windows to lock user accounts temporarily after a set number of failed login attempts to prevent brute-force attacks.
5. **Set Strong Password Requirements:** Enforce complexity rules and minimum lengths through Local Group Policy or domain policy.
6. **Use Two-Factor Authentication (2FA):** If using a Microsoft account or connected domain environment, enable 2FA wherever supported.

---

## 3. Network and Firewall Security

Windows comes with a built-in firewall and networking stack that needs tuning for better protection — especially on laptops and desktops directly connected to the internet.

### 🔌 Recommended Network Settings:

- **Set your network as “Public”** unless you're in a trusted environment.
  - Go to *Settings → Network & Internet → Properties* and set the network profile to `Public`.
  - This disables network discovery and file/printer sharing by default.

- **Disable IPv6** if not in use.
  - Use `ncpa.cpl` → Right-click adapter → Properties → Uncheck *Internet Protocol Version 6 (TCP/IPv6)*.

- **Turn off network discovery and file/printer sharing** unless you specifically need it.
  - Control Panel → Network and Sharing Center → Advanced sharing settings.

- **Disable unnecessary services** like:
  - *Remote Desktop* (unless needed).
  - *Remote Assistance*.
  - *SMBv1 protocol* (deprecated and insecure).
    - Run: `dism /online /norestart /disable-feature /featurename:SMB1Protocol`

---

### 🧱 Windows Defender Firewall Settings

- ✅ Ensure the firewall is **enabled for all profiles**: Domain, Private, and Public.
  - Open *Windows Security → Firewall & network protection* and verify all profiles are active.

- ✅ **Block all inbound connections by default** (especially on Public profile).
  - Go to *Advanced Settings* → Right-click on Public Profile → Properties → Inbound connections → Block (default).

- ✅ **Only allow required apps** through the firewall.
  - *Control Panel → Windows Defender Firewall → Allow an app or feature through Windows Firewall*.

- ✅ Use **Windows Defender Firewall with Advanced Security** (`wf.msc`) to:
  - Create **explicit allow rules** for apps that need inbound access.
  - Block **specific outbound connections** if necessary (e.g. telemetry, games, etc.).
  - **Log dropped packets**:
    - In `wf.msc` → Right-click *Windows Defender Firewall with Advanced Security on Local Computer* → Properties → Logging → Customize → Enable logging.

---

### 🧪 Testing Your Configuration

- Use `ping`, `tracert`, and `netstat -abno` to check network paths and open ports.
- Run `Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction` in PowerShell to quickly review firewall posture.
- Use port scanners like [Nmap](https://nmap.org) from another device on the same network to validate closed ports.

## 4. Device and peripheral security

Properly managing hardware interfaces is a key step in preventing unauthorized data exfiltration and physical attacks on a system.

#### 🔒 Disable Unused Hardware

If certain hardware like Bluetooth, infrared, or FireWire (IEEE 1394) isn’t in use, disable them from the BIOS/UEFI or Device Manager to reduce your attack surface.

```powershell
# Disable Bluetooth (example)
Disable-NetAdapter -Name "Bluetooth Network Connection" -Confirm:$false
```

#### 🔌 USB Port Control

USB drives can be used to inject malware or steal data. Consider disabling USB storage via Group Policy or Registry settings.

```reg
; Disable USB Storage Devices
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR]
"Start"=dword:00000004
```

> ⚠️ **Warning:** This disables USB storage completely, including legitimate drives. Use with caution on production systems.

#### 🛡️ Device Guard and Credential Guard (Enterprise Editions)

Enable **Device Guard** and **Credential Guard** if using Windows 10/11 Enterprise. These features use virtualization-based security (VBS) to isolate critical processes and credentials from threats.

```powershell
# Check VBS status
Get-CimInstance -ClassName Win32_DeviceGuard
```

> 📌 Note: These features require UEFI, Secure Boot, and Virtualization to be enabled in BIOS.

#### 🖨️ Restrict Peripheral Devices

Disable or restrict use of printers, webcams, and smart card readers if they’re not essential to your system operations.

- Go to **Device Manager**, locate the peripheral, right-click, and choose **Disable**.
- Use **Group Policy** to prevent installation of new device drivers.

## 4. Application and Software Security

Proper application control is essential to reducing the attack surface on a Windows machine. By limiting what gets installed and ensuring all software is trusted and up to date, you reduce the risk of malware and zero-day exploits.

- **Use Only Trusted Software**
  - Install applications only from reputable vendors or official stores.
  - Avoid pirated software and keygens which are often laced with malware.

- **Enable SmartScreen**
  - Windows SmartScreen helps protect against phishing and malware by warning users before running unrecognized apps or visiting malicious websites.
  - Enable it via *Windows Security > App & browser control*.

- **Configure AppLocker or Windows Defender Application Control (WDAC)**
  - AppLocker (Pro/Enterprise editions) allows you to define rules for which users can run what apps.
  - WDAC is more advanced and policy-driven; best for enterprise scenarios.

- **Keep Software Up to Date**
  - Use tools like Windows Update and Windows Package Manager (`winget`) to automate updates.
  - Uninstall or patch unsupported or legacy software.

- **Disable Unnecessary Features**
  - Turn off Windows features like Internet Explorer, SMBv1, and legacy components unless absolutely needed.
  - Go to *Control Panel > Programs > Turn Windows features on or off*.

- **Use Browser Hardening Techniques**
  - Enable pop-up blockers, disable autofill, and use extensions like uBlock Origin or NoScript.
  - Prefer privacy-respecting browsers like Firefox with hardened settings.

## 5. Logging and Monitoring

Monitoring user activity and system changes is essential for early detection of threats and quick incident response. Windows provides built-in tools like Event Viewer and third-party solutions for enhanced visibility.

### 🔧 Action Steps

- **Enable Auditing Policies**
  - Go to `Local Security Policy` > `Advanced Audit Policy Configuration`.
  - Enable auditing for:
    - Logon events
    - Object access
    - Privilege use
    - Policy changes
    - Account management

- **Configure Windows Event Viewer**
  - Open Event Viewer and set up custom views for critical security logs.
  - Regularly review logs under:
    - `Windows Logs > Security`
    - `Windows Logs > System`
    - `Applications and Services Logs`

- **Enable PowerShell Logging**
  - Use Group Policy Editor:
    - Navigate to `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`.
    - Enable script block logging and transcription.

- **Set Up Log Retention Policies**
  - Ensure that logs are not overwritten too quickly by increasing log size and retention duration.
  - Use `wevtutil` or Group Policy to set log limits.

- **Forward Logs to Central Location (Optional)**
  - Use Windows Event Forwarding (WEF) or a third-party SIEM for centralized log monitoring and analysis.

> ✅ **Tip:** Regularly reviewing logs helps in identifying unauthorized access attempts, misconfigurations, or malware activity.

## 6. Backup and Recovery

A solid backup and recovery plan protects your system against data loss due to ransomware, hardware failure, or system corruption.

### 🔧 Action Steps

- **Set Up File History (Personal Files Backup)**
  - Go to `Settings > Update & Security > Backup`.
  - Add a drive and turn on **File History** to back up Documents, Pictures, Videos, etc.

- **Create a System Image**
  - Open **Control Panel > Backup and Restore (Windows 7)**.
  - Click on **Create a system image** and select a location (external drive or network location).
  - This creates a full backup of your OS, drivers, installed programs, and system settings.

- **Set Up System Restore**
  - Right-click `This PC` > `Properties` > `System Protection`.
  - Enable protection for your system drive (usually C:).
  - Create a **restore point** after major changes or security hardening steps.

- **Schedule Regular Backups**
  - Use Task Scheduler to automate backups (for advanced users).
  - Or configure File History to back up files hourly/daily.

- **Test Your Backups**
  - Periodically test restoring files or system images to ensure backups work correctly.
  - Don’t wait for disaster to discover a backup failure.

- **Use 3-2-1 Backup Strategy (Recommended)**
  - 3 total copies of your data
  - 2 stored on different devices
  - 1 stored offsite or in the cloud

> ✅ **Tip:** Always disconnect external drives after backups to protect them from ransomware.

## 7. Physical Security

Even with secure configurations, a Windows system is vulnerable if an attacker can gain physical access. This section covers physical security measures relevant to protecting Windows devices from tampering or bypass.

### ✅ BIOS/UEFI Protection
- **Set a BIOS/UEFI password** to prevent unauthorized changes to boot settings.
- **Disable booting from external devices** (USB/DVD) unless required.
- **Enable Secure Boot** to prevent unsigned bootloaders or OS from loading.

### ✅ BitLocker Drive Encryption
- Enable **BitLocker with TPM + PIN** for pre-boot authentication.
- This ensures full disk encryption even if the hard drive is removed and accessed elsewhere.
- Optional: Use a USB startup key for added security.

### ✅ Lock Screen & Idle Lockout
- Set short timeout for screen lock (e.g., 5-10 mins).
- Require password on wake from sleep or screen saver.
  - `Settings > Accounts > Sign-in options > Require sign-in`

### ✅ Prevent Unauthorized USB Access
- Disable unused physical ports via BIOS or Device Manager.
- Group Policy (Pro/Enterprise):
  - `Computer Configuration > Administrative Templates > System > Removable Storage Access`
  - Deny read/write access to all removable drives.

### ✅ Disable Boot to Other OSes
- Ensure Windows Boot Manager is the only allowed bootloader.
- Check and lock down boot order in BIOS settings.

### ✅ Hardware Tracking and Recovery (Optional)
- Enable **Find My Device** in Windows Settings.
  - `Settings > Privacy & security > Find my device`
- Install endpoint protection with tamper detection or geolocation if stolen.

---

**📝 Notes:**  
- Combine these with building-level physical controls for a holistic defense-in-depth strategy.
- BitLocker is your strongest line of defense if physical theft occurs.

## 8. Secure Configuration and Bloatware Removal

Proper system configuration and removing unnecessary software helps reduce the attack surface of a Windows system. Most new PCs come with preinstalled applications (bloatware) that not only waste system resources but can also introduce security vulnerabilities.

### 📌 Key Actions:

- **Remove Bloatware and Unused Applications**  
  Use `winget`, `PowerShell`, or the Control Panel to remove preinstalled software, manufacturer utilities, and trialware that are not essential.

- **Use Minimal Software Installations**  
  Install only what is needed for productivity or essential tasks. Avoid cluttering the system with unnecessary tools or duplicate programs.

- **Disable Unused Windows Features**  
  Navigate to **Control Panel > Programs > Turn Windows features on or off** and disable unneeded features like Internet Explorer, SMBv1, XPS Services, etc.

- **Use PowerShell to Harden Settings**  
  Configure settings such as script execution policy, remote access, and telemetry using PowerShell to ensure consistency and automation.

- **Disable Cortana and Web Search Integration**  
  Reduce privacy risks and system load by disabling Cortana and web search from the Start menu using Group Policy or registry edits.

- **Turn Off Consumer Experience Improvements**  
  Disable Microsoft consumer experiences via Group Policy to avoid automatic app installations and ads.

- **Review Startup Programs**  
  Check and disable unnecessary startup applications using **Task Manager > Startup** or via `msconfig`.

- **Configure Privacy Settings**  
  Go to **Settings > Privacy & Security** and review permissions for apps (camera, microphone, location, etc.). Disable what’s not required.

### 🛠 Tools You Can Use:
- `winget uninstall <package>` – Windows Package Manager for removing apps
- `Get-AppxPackage` and `Remove-AppxPackage` in PowerShell for UWP apps
- Group Policy Editor (`gpedit.msc`)
- `Autoruns` from Sysinternals to inspect startup items

### ✅ Outcome:
Removing bloatware and applying secure configurations helps streamline the system, improves performance, and significantly reduces unnecessary exposure to potential vulnerabilities.

## 9. Security Baselines & Benchmarking

Security baselines and benchmarks provide a standardized set of recommended configurations to harden systems based on best practices from trusted organizations like CIS (Center for Internet Security) or Microsoft.

### 📌 Key Actions:

- **Apply CIS Benchmarks**  
  Download and follow the [CIS Microsoft Windows 10/11 Benchmark](https://www.cisecurity.org/cis-benchmarks) guide for secure configuration practices. Tools like CIS-CAT (for paid members) can assess compliance.

- **Use Microsoft Security Baselines**  
  Microsoft provides official baselines via the [Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10). These include GPO backups and spreadsheets with recommendations.

- **Leverage Security Configuration Frameworks**  
  Use frameworks such as NIST 800-53 or NIST Cybersecurity Framework (CSF) to align your system's configuration to broader security goals, particularly useful in enterprise environments.

- **Audit System Configuration**  
  Tools like `LGPO.exe`, `secedit`, and `gpresult` can be used to apply and validate Group Policy Object (GPO) settings and other local security policies.

- **Automate Benchmarking with Scripts**  
  PowerShell scripts and community tools like `Baseliner`, `AuditPol`, or custom scripts can help automate configuration checking and comparison.

### 🛠 Tools You Can Use:
- [CIS-CAT Lite](https://www.cisecurity.org/cis-cat-lite) for local benchmark auditing
- Microsoft Security Compliance Toolkit
- `gpresult /h report.html` for GPO summary
- `secedit /analyze` to compare current settings with a template
- PowerShell for custom checks

### ✅ Outcome:
Implementing and maintaining system configurations based on trusted benchmarks ensures that your Windows system adheres to recognized security standards and reduces the likelihood of misconfigurations that could be exploited.

## 10. Update & Patch Management

Regularly updating Windows and installed software is critical to mitigating vulnerabilities and ensuring your system is protected against known threats.

### 📌 Key Actions:

- **Enable Automatic Windows Updates**  
  Keep Windows Update enabled to receive the latest security patches and stability improvements.

- **Manually Check for Updates**  
  Periodically check for updates by navigating to:
  `Settings → Windows Update → Check for updates`

- **Enable Update for Other Microsoft Products**  
  In Windows Update settings, enable the option to receive updates for Office and other Microsoft products.

- **Use Windows Server Update Services (WSUS)** *(for enterprise)*  
  Organizations can manage updates centrally using WSUS to test and approve patches before deployment.

- **Patch Third-Party Software**  
  Use tools like:
  - [Patch My PC](https://patchmypc.com/home-updater)
  - [Ninite](https://ninite.com/)
  - [SUMo](https://www.kcsoftwares.com/?sumo) *(note: SUMo has been discontinued)*  
  to automatically keep non-Microsoft applications updated.

- **Unattended or Scheduled Updates**  
  Use Task Scheduler or Group Policy to define when updates are installed (e.g., during off-hours).

### 🛠 Tools You Can Use:
- Windows Update
- `sconfig` (on Windows Server or headless systems)
- Task Scheduler for scripted patch checks
- PowerShell: `Get-WindowsUpdate`, `Install-WindowsUpdate` via PSWindowsUpdate module

### ✅ Outcome:
Effective patch management ensures known vulnerabilities are mitigated in a timely manner, significantly reducing your exposure to exploits and malware.

## 11. Secure Remote Access Configuration

Remote access features like Remote Desktop Protocol (RDP) and PowerShell Remoting can be powerful tools, but they pose serious risks if not secured properly.

### 📌 Key Actions:

- **Disable RDP if Not Needed**  
  If you don’t need Remote Desktop, disable it entirely:
  `System Properties → Remote → Uncheck "Allow remote connections to this computer"`

- **Use VPN for Remote Access**  
  Never expose RDP or other remote management ports directly to the internet. Instead, use a secure VPN tunnel (e.g., WireGuard or OpenVPN) to connect to your internal network first.

- **Change Default RDP Port**  
  Change the default TCP port (3389) to a non-standard port to reduce automated attack attempts. *(Note: this is security through obscurity, not a substitute for real protection.)*

- **Enable Network Level Authentication (NLA)**  
  This adds a layer of authentication before a remote desktop session is established:
  `System Properties → Remote → Check "Allow connections only from computers running NLA"`

- **Use Strong Passwords and 2FA**  
  Apply strong password policies and enable two-factor authentication (2FA) if using remote management tools.

- **Restrict RDP Access via Firewall**  
  Use the Windows Defender Firewall to only allow RDP from specific IP addresses or subnets.

- **Enable Logging and Alerts for Remote Connections**  
  Audit successful and failed login attempts using Event Viewer and set up email alerts if suspicious activity is detected.

### 🛠 Tools You Can Use:
- Windows Defender Firewall
- Group Policy Editor (`gpedit.msc`)
- Event Viewer
- VPN software (WireGuard, OpenVPN)
- PowerShell for managing WinRM

### ✅ Outcome:
Properly securing remote access drastically reduces the risk of brute-force attacks, lateral movement, and unauthorized access.

## 12. Final Checklist & Verification

Once you've completed all the hardening steps, it's critical to verify that your configurations are in place and functioning as intended.

### ✅ Post-Hardening Checklist:

- [ ] All unnecessary services are disabled  
- [ ] All user accounts follow least privilege principles  
- [ ] Local Administrator account is renamed or disabled  
- [ ] BitLocker is enabled on all drives  
- [ ] Firewall is active with proper rules  
- [ ] Remote Desktop is disabled or protected by VPN & NLA  
- [ ] Windows Defender or third-party antivirus is running  
- [ ] All updates are installed and automatic updates are enabled  
- [ ] Secure BIOS/UEFI settings applied and password protected  
- [ ] Logging is enabled and being monitored  
- [ ] Backups are set up, tested, and stored securely  
- [ ] System is benchmarked using tools like CIS-CAT or Microsoft Baseline Security Analyzer (MBSA)

### 🧪 Verification Methods:

- **Run Security Scans**  
  Use tools like [Microsoft Defender Offline Scan](https://support.microsoft.com/en-us/windows/help-protect-my-pc-with-microsoft-defender-offline-9306d528-9f17-9b6d-2f2c-9846f2fdfa85), [MBSA](https://www.microsoft.com/en-us/download/details.aspx?id=7558), or **CIS-CAT** to evaluate your system security posture.

- **Review Group Policy Settings**  
  Open `gpedit.msc` and ensure all key policies are enforced.

- **Audit System Logs**  
  Open **Event Viewer** and review logs for failed login attempts, unexpected reboots, or permission errors.

- **Conduct a Reboot Test**  
  Restart your system and verify that all critical services, security tools, and firewalls come back online properly.

- **Simulate a Threat** *(Optional for Advanced Users)*  
  Use tools like Kali Linux (in a safe lab environment) to test your hardened system for known vulnerabilities or open ports.

### 🧠 Pro Tip:
Document any deviations from the recommended settings and the reasoning behind them — this is a best practice for audits and team-based environments.

---

✅ **Congratulations!**  
You've now built a hardened Windows system that’s more resilient to malware, unauthorized access, and misconfigurations. Remember: hardening is not a one-time task — regularly revisit this guide to adapt to evolving threats and system changes.

