# Windows Hardening Guide

A practical and beginner-friendly checklist for hardening a Windows system, created for IT professionals, home users, and cybersecurity beginners. This guide focuses on actionable steps with built-in tools, no third-party software required.

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

## 📄 To Do Next
- Include screenshots for each step in a subfolder called `/screenshots`.
- Add PowerShell scripts in a `/scripts` directory for automating selected steps.
- Eventually include a section on Group Policy for domain environments.
