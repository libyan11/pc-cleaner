# Fixing fake virus pop-ups and spam notifications: step by step

A manual guide for a Windows 10/11 PC that shows "McAfee/Norton: your PC is infected", "Virus found!" or spam notifications that open dodgy websites. You can do all of it by hand, or let [PC Cleaner](README.md) do most of it (option 1 in `START HERE.bat`).

Commands go in **PowerShell as administrator**: right-click Start > **Terminal (Admin)** or **Windows PowerShell (Admin)**, then click **Yes**. Type or paste one line at a time and press Enter.

## Before you start

- **Don't sign in to anything new on that PC** (email, bank, Claude, password manager) until it's clean.
- **Never call a phone number shown in a pop-up**, and never let anyone "connect remotely" to fix it. Microsoft, McAfee and Norton don't show phone numbers in pop-ups.
- Do all of this while signed in to **that PC's normal user account**. Notifications and extensions belong to the account, not the PC.

## 1. What kind of pop-up is it?

| What you see | What it is | Go to |
|---|---|---|
| A box in the bottom-right corner with a **Chrome or Edge logo** that says "virus found" or similar | A website you once allowed to send notifications | Step 2 |
| A **full-screen page** with alarms, "your PC is locked" and a phone number | A scam web page. Nothing is installed | Close it: press **Ctrl+Shift+Esc**, select the browser and click **End task**. Reopen the browser and **don't** restore the tabs |
| A **McAfee or Norton window** outside the browser saying your subscription expired | A real, pre-installed trial trying to sell you a subscription | Step 5 |
| Searches go to an odd search site, or the browser opens strange pages by itself | A hijacker extension, policy or shortcut | Steps 3, 4, 7, 8 |

## 2. Stop notification spam (the most common cause)

**Chrome:** go to `chrome://settings/content/notifications`. Under **Allowed to send notifications**, click the three dots next to each site you don't know (or all of them) and choose **Block** or **Remove**. Also turn on **Use quieter messaging**.

**Edge:** go to `edge://settings/content/notifications` and do the same. Also check that **Scareware blocker** is on: Settings > Privacy, search, and services > Security.

**Firefox:** Settings > Privacy & Security > Permissions > Notifications > **Settings...**. Remove the sites, then tick **Block new requests asking to allow notifications**.

**Windows:** Settings > System > **Notifications**. Switch off any app you don't recognise.

**Chrome bonus:** Settings > Privacy and security > **Safety Check** shows sites Chrome has already blocked for abusive notifications.

## 3. Remove bad extensions, then reset the browser

1. Go to `chrome://extensions` (or `edge://extensions`, or `about:addons` in Firefox).
2. Click **Remove** on anything you don't recognise. Be especially wary of anything with "search", "PDF converter", "coupon", "weather", "new tab" or "WebAdvisor" in the name.
3. Reset the browser settings. This restores the search engine, home page and start-up pages and switches extensions off, but keeps bookmarks, history and passwords:
   - Chrome: `chrome://settings/reset` > **Restore settings to their original defaults**
   - Edge: `edge://settings/reset` > **Restore settings to their default values**
   - Firefox: `about:support` > **Refresh Firefox**

If an extension comes back after you remove it, a program is reinstalling it. Do step 5, then repeat this step.

## 4. Remove fake "security" web apps

Fake security-check sites can install themselves as web apps and keep sending alerts after the browser is closed.
- Chrome: go to `chrome://apps`, right-click anything you didn't install > **Remove from Chrome**.
- Edge: go to `edge://apps` and remove the same way.

## 5. Uninstall junk programs and expired security trials

Settings > Apps > **Installed apps**, sort by **Install date**, and uninstall anything you don't recognise. Uninstall in particular:
- McAfee, Norton, Avast or AVG trials you don't pay for (Microsoft Defender already protects you), and **WebAdvisor**
- Fake optimisers and "driver updaters", toolbars, **OneLaunch**, **Wave Browser**, anything called "PC ... Cleaner/Speed up/Optimizer"

To list programs by install date:

```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName | Sort-Object InstallDate -Descending | Select-Object -First 40 DisplayName, Publisher, InstallDate | Format-Table -AutoSize
```

## 6. Virus scan with Microsoft Defender

Update the virus definitions:

```powershell
Update-MpSignature
```

Full scan (takes 1-2 hours):

```powershell
Start-MpScan -ScanType FullScan
```

See what it found:

```powershell
Get-MpThreat | Select-Object ThreatName, IsActive, Resources | Format-List
```

Remove what it found:

```powershell
Remove-MpThreat
```

Turn on blocking of potentially unwanted apps (adware and bundled junk). Microsoft recommends it, and it is often only in "watch" mode on home PCs:

```powershell
Set-MpPreference -PUAProtection Enabled
```

If a threat keeps coming back, run an **offline scan**. It restarts the PC straight away and scans before Windows starts (about 15 minutes), so save your work first:

```powershell
Start-MpWDOScan
```

## 7. Check what starts with Windows

Task Manager (**Ctrl+Shift+Esc**) > **Start-up apps**: disable anything unknown.

List start-up programs:

```powershell
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | Format-List
```

List non-Microsoft scheduled tasks (adware often adds one that opens a website):

```powershell
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { [pscustomobject]@{ Task = $_.TaskPath + $_.TaskName; State = $_.State; Runs = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ' } } | Format-List
```

If a task runs a browser with a web address, or something from `AppData` you don't recognise, delete it in **Task Scheduler**, after uninstalling the program it belongs to.

## 8. "Managed by your organization" on a home PC

If the browser says this, but it's not a work or school PC, a program has set browser policies to force an extension or search engine. To see them, go to `chrome://policy` or `edge://policy`.

To remove them, PC Cleaner does it safely (with a backup). To do it by hand, **save a backup first** (it lands on your Desktop), then delete the key. Do the same for `HKCU\...`, and use `Microsoft\Edge` in place of `Google\Chrome` for Edge:

```powershell
reg export "HKLM\SOFTWARE\Policies\Google\Chrome" "$env:USERPROFILE\Desktop\chrome-policy-backup.reg"
```

```powershell
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /f
```

Parental-control software also uses policies. If you set that up, leave them.

## 9. Check the browser shortcuts

Right-click the browser icon on the Desktop and choose **Properties**. In the **Target** box, the path should end with `chrome.exe"` or `msedge.exe"`, with no web address after it. If there's a web address or `--load-extension`, delete the shortcut, then pin the browser again from the Start menu. Check the taskbar icon too (right-click it, then right-click the browser name > Properties).

## 10. Clean the junk

Settings > System > Storage > **Temporary files**: tick everything except **Downloads** and **Recycle Bin** (unless you've checked those), then click **Remove files**. Or run PC Cleaner option 3.

## When to reset Windows instead

Cleaning is enough for normal pop-up and adware problems. **Reset** if any of these are true:
- Defender finds something with **Trojan**, **PWS** (password stealer), **Backdoor**, **Ransom** or **RAT** in its name.
- The pop-ups come back after you've done every step above.
- Programs you removed keep reappearing, or the PC is unusably slow.
- You just want a clean start.

How:
1. **Scan before backing up** (step 6), so you don't back up infected files. Back up only your own documents and photos (OneDrive or a USB drive), not programs or installers.
2. Have your Microsoft account password and, if the PC is encrypted, the BitLocker recovery key (aka.ms/myrecoverykey).
3. Open **Settings > System > Recovery > Reset PC** (Windows 10: Settings > Update & Security > Recovery > Reset this PC).
4. Choose **Remove everything**, then **Cloud download** (a fresh copy of Windows from Microsoft).
5. Afterwards: run Windows Update until nothing is left, install your browser and programs from their official sites, and run PC Cleaner once.

You don't need to clean before a reset: "Remove everything" wipes it all anyway. PC Cleaner option 7 saves a list of your programs first, so you know what to reinstall.

## Your Microsoft account and other devices

- **A reset only affects that one PC.** Your other devices and your account are not touched.
- **Notification spam and adware don't normally steal passwords.** If Defender found a password stealer, trojan or backdoor, assume anything typed on that PC may be known. In that case, do this **from a clean device**:
  1. Change your Microsoft account password, then your email and banking passwords.
  2. At account.microsoft.com/security, check **Recent activity**, turn on **two-step verification**, and remove devices you don't recognise.
- **Browser sync can carry a bad extension to your other devices.** If Chrome or Edge on that PC is signed in with sync on, check `chrome://extensions` or `edge://extensions` on your other devices too after cleaning.
- **Signing in to Windows after a reset is safe.** If setup offers to restore from a backup, that's fine: it restores settings and Store apps, not adware. Check the browser's extensions after it syncs.

## Asking Claude for help with that PC

You don't need to sign Claude in on that PC. The safest way is to run PC Cleaner there, copy its `PCCleaner\Reports\<date>` folder (`report.html` and `log.txt`) to a USB stick or OneDrive, and give it to Claude on your own PC.

If you do want Claude working on that PC directly, wait until a scan shows it's clean. Install the Claude desktop app from claude.ai/download and sign in through the browser window it opens. Keep Claude asking before it makes changes; don't switch on any "allow everything" mode on a PC you don't fully trust. Never type passwords into the chat.
