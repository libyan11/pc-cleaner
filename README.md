# PC Cleaner

A portable virus scan, pop-up fix and clean-up tool for **Windows 10 / 11**, a companion to [Laptop Check](https://github.com/libyan11/laptopchecker). Double-click one file, answer a few questions, and it:
- scans for viruses
- gets rid of fake "virus found / McAfee / Norton" pop-ups and spam notifications
- finds adware and browser hijackers
- checks your security settings
- cleans junk files

At the end you get a colour-coded report of what it found, fixed and freed.

It uses only what is built into Windows: Microsoft Defender, Microsoft's Malicious Software Removal Tool, DISM and Disk Clean-up. Nothing is downloaded or installed.

**Prefer to do it by hand?** [FIX-POPUPS-GUIDE.md](FIX-POPUPS-GUIDE.md) is a step-by-step guide with the exact clicks and commands. It also covers when to reset Windows instead, and what to do about your Microsoft account and other devices.

## Quick start

1. **Download it:** on GitHub click **Code > Download ZIP** (or `git clone` this repo).
2. **Unblock the ZIP:** right-click the ZIP, choose **Properties**, tick **Unblock** if you see it, and click **OK**. Without this, Windows (especially with Smart App Control on) may block the files.
3. **Extract it:** right-click the ZIP > **Extract All...**. Don't run anything from inside the ZIP.
4. Open the `PCCleaner` folder and double-click **`START HERE.bat`**.
5. Pick an option, then click **Yes** when Windows asks for administrator permission. A new window opens.
6. **Answer the questions at the start** (press Enter to accept the suggested answer). After that it runs by itself, so you can leave it.
7. The report opens in your browser at the end. Every report is kept in `PCCleaner\Reports\<date>\` (`report.html`, plus `log.txt` with everything that was shown on screen).

> Don't double-click `PCCleaner.ps1`. Windows deliberately shows "Open with" for `.ps1` files so scripts can't run by accident. `START HERE.bat` runs it for you.

## Menu options

| Option | What it does | Time |
|---|---|---|
| **1 Scan + fix + clean** (recommended) | Security check, quick virus scan, second-opinion scan, pop-up/notification/hijacker fix, adware check, then the normal clean-up | ~10 min |
| **2 Full virus scan only** | Everything in the scan and fix part, with a full Defender scan of every file | 1-2 hours |
| **3 Deep clean only** | The normal clean-up plus Windows Update leftovers, setup/upgrade leftovers, crash dumps, shader and thumbnail caches, and an offer to remove `Windows.old` | 5-30 min |
| **4 Everything** | Full virus scan + fix + deep clean | 1-2+ hours |
| **5 Offline virus scan** | The scan part, then offers a Microsoft Defender Offline scan, which **restarts the PC** and scans before Windows starts. Use it when a threat keeps coming back | ~15 min after restart |
| **6 Recent downloads and programs** | Asks how many weeks back to look, lists everything downloaded and every program installed in that time, and lets you remove what you don't want. Files go to the **Recycle Bin**, so they can be recovered | a few minutes |
| **7 Fresh start** | Explains how to reset Windows to like-new, saves a list of your installed programs first, and opens Settings > Recovery | - |

## Fake virus pop-ups and spam notifications

Pop-ups saying "McAfee: your PC is infected", "Norton subscription expired" or "Virus found! Click here" are almost never from McAfee or Norton, and usually not a real virus. They come from one of these places, and PC Cleaner checks every one of them:

| Where they come from | What PC Cleaner does |
|---|---|
| **A website you once clicked "Allow notifications" on.** It then sends fake alerts that open scam pages. This is the most common cause. | Lists every site allowed to send notifications in Chrome, Edge, Brave, Vivaldi and Opera, and **blocks them** (it asks first, and the browser must be closed; it offers to close it). A backup of the browser setting is kept. For Firefox it tells you exactly where to remove them. |
| **An expired security trial** (McAfee and Norton come pre-installed on many laptops). It shows real "your PC is at risk" pop-ups to sell a subscription. | Finds security programs that are installed but switched off and **offers to open their uninstaller**. Microsoft Defender already protects you. |
| **A browser hijacker extension** that changes your search engine or home page so searches go to ad sites. | Flags extensions that take over the search engine, home page or start-up pages and says where they send you. It also flags extensions a program keeps re-adding through the registry, plus adware-type extensions. At the end it opens the browser's Extensions page so you can click **Remove**. |
| **Browser policies** that force an extension or search engine (the browser says "Managed by your organization"). | On a home PC (not company/school), **offers to remove them**, saving a backup you can double-click to restore. |
| **Adware programs** (fake optimisers, driver updaters, toolbars, OneLaunch, Wave Browser...). | Flags them and **offers to open their uninstaller**. |
| **A fake "security check" installed as a web app.** It keeps sending alerts even when the browser is closed. | Lists installed web apps and flags ones with security-sounding names, with the steps to remove them (`chrome://apps` / `edge://apps`). |
| **Doctored shortcuts** on the Desktop, Start menu or taskbar that make the browser open a scam site or load a hidden extension. | Checks every browser shortcut for a web address or `--load-extension` and says which ones to delete and re-pin. |
| **Extensions loaded from outside the browser** (how ChromeLoader-type malware works). | Flags any extension loaded from a folder outside the browser, and extension developer mode. |
| **Start-up entries or scheduled tasks** that open a website when the PC starts. | Flags any start-up program or scheduled task that opens a web address in a browser or belongs to known adware (OneLaunch, Wave Browser and similar). |

PC Cleaner also offers to turn on Defender's **blocking of potentially unwanted apps** (PUA). Microsoft recommends it, but on home PCs it is often only in "watching" mode, which lets adware install.

Two more places worth checking by hand afterwards:
- **Chrome:** Settings > Privacy and security > **Safety Check** lists sites Chrome has already taken notification permission away from.
- **Windows:** Settings > System > **Notifications** lists every app allowed to show notifications. Switch off any you don't recognise.

If a full-screen page says your PC is locked and gives a phone number to call, it's a **scam page, not a virus**. Don't call the number. Press **Ctrl+Shift+Esc**, end the browser in Task Manager, and when you reopen the browser, don't restore the previous tabs.

## What else it checks (scan)

- **Security settings:** which antivirus is on and up to date, firewall on all network types, User Account Control, Smart App Control, last Windows Update and pending restarts.
- **Microsoft Defender:** real-time and tamper protection, updates the virus definitions, **exclusions** (malware adds these to hide), runs a Quick or Full scan, lists active threats and **removes them** (asked at the start), and lists earlier detections Defender already handled.
- **Second opinion:** Microsoft's Malicious Software Removal Tool (`MRT.exe`, built into Windows) in quick mode.
- **Start-up programs, scheduled tasks, services and running programs:** each one is checked for a valid digital signature. It's flagged if it runs from a temp/download/public folder without a signature, launches hidden scripts or download commands, opens a website, belongs to known adware, or points to a file that no longer exists.
- **Hidden start-up hooks (WMI):** a place malware uses to restart itself after removal. These are reported, never removed automatically.
- **Installed programs:** known unwanted or bundled programs, and anything installed in the last 14 days.
- **Network settings:** the `hosts` file (malware redirects or blocks well-known sites there), proxy settings and DNS servers.

Items marked **REVIEW** aren't automatically bad. They're things a person should look at. Real malware is detected and removed by Defender and MRT.

## What it cleans

**Normal clean-up** (options 1, 3, 4):
- Your temp folder and the Windows temp folder. Files from the last 24 hours are kept so running programs and installers don't break.
- Browser caches for Chrome, Edge, Brave, Vivaldi, Firefox and Opera (all profiles), plus Discord and Steam web caches.
- Windows error reports and the Delivery Optimization cache (copies of updates shared with other PCs).
- The Recycle Bin (only if you say yes).

**Deep clean adds** (options 3, 4):
- Crash dumps, graphics shader caches (games rebuild them; first launch may stutter briefly) and the thumbnail cache.
- Old copies of updated Windows files via DISM `/StartComponentCleanup`. Windows would do this itself after 30 days. It never uses `/ResetBase`, so installed updates can still be uninstalled.
- The Windows Update download cache: optional, off unless you say yes, and only worth it if Windows Update is stuck. Skipped while Windows Update is busy.
- Setup and upgrade leftovers, via Windows' own Disk Clean-up.
- `Windows.old`, your previous Windows installation (only if you say yes; afterwards you can't go back to that version).

At the end it shows how much space was freed and the free space on drive C: before and after.

## What it never touches

Your documents, photos, music, videos and desktop, saved passwords, cookies and logins, browsing history and bookmarks, game saves, and the Windows install files that "Reset this PC" needs. The **Downloads** folder is only touched in option 6, only for items you pick, and they go to the Recycle Bin.

Other safety rules built into the code:
- It refuses to empty any folder that resolves to a drive root, Windows, Program Files, ProgramData or your profile folder, whatever an environment variable says.
- It never follows links or junctions out of a folder it is cleaning.
- It never uninstalls anything by itself. It opens the program's own uninstaller, and only for programs you said yes to.
- It never turns any security feature off.
- Browser settings are only changed while the browser is closed, and a backup is kept (`Preferences.pccleaner-backup` in the browser profile folder).

## Fresh start (reset Windows)

When a PC is full of junk, or pop-ups keep coming back after everything else, the cleanest fix is Windows' built-in reset. Option 7 explains it step by step and saves a list of your programs first. In short:

1. Back up your files (OneDrive or a USB drive), and sign in to your browser so bookmarks and passwords sync.
2. Plug in the charger, and have your Microsoft account password and, if the PC is encrypted, your BitLocker recovery key (aka.ms/myrecoverykey).
3. **Windows 11:** Settings > System > Recovery > **Reset PC**. **Windows 10:** Settings > Update & Security > Recovery > Reset this PC > Get started.
4. Choose **Keep my files** (removes apps and settings) or **Remove everything** (wipes the PC; best for a bad infection or before selling it), then **Cloud download** (a fresh copy of Windows from Microsoft).

If Windows won't start, hold **Shift** while clicking **Restart**, then go to Troubleshoot > Reset this PC.

## Ask Claude to look at a PC

**Easiest: send Claude the results.** Run PC Cleaner on that PC, then copy its `PCCleaner\Reports\<date>` folder (`report.html` and `log.txt`) to a USB stick or OneDrive. Open it on a PC where you use Claude and ask: *"Here is the PC Cleaner log from another PC - what should I fix?"*

**Or let Claude work on that PC directly.** Only do this with the PC owner's permission, because Claude will be able to see files there.
1. On that PC, install the Claude desktop app from claude.ai/download and **sign in with your Claude account**. Signing in happens in the browser window it opens; you never type a password into a terminal.
2. Open the **Code** tab and choose the extracted `PCCleaner` folder as the project folder.
3. Ask something like: *"Run PC Cleaner and explain the report, then help me get rid of the pop-ups."* Claude asks before running anything that changes the PC.

## Troubleshooting

| What you see | What to do |
|---|---|
| **"Open with"** when you click `PCCleaner.ps1` | Normal: Windows doesn't run `.ps1` files on double-click. Double-click `START HERE.bat` instead. |
| **"PCCleaner.ps1 was not found"** | You ran it from inside the ZIP. Extract the ZIP first (Quick start steps 2-3). |
| **"Windows protected your PC"** | Click **More info**, then **Run anyway**. Or unblock the ZIP before extracting (step 2) and it won't appear. |
| **"Smart App Control blocked..."** | Delete the extracted folder, unblock the ZIP (step 2), and extract it again. **Don't switch Smart App Control off**: once it's off, Windows can't turn it back on without a reinstall. |
| **"running scripts is disabled" / "not digitally signed"** and it mentions Group Policy | A company or school manages this PC. Ask its IT department. |
| The PC's user has a **standard account** and you typed an administrator's password | That's fine: PC Cleaner checks the account that is signed in, not the administrator's. It says so at the top of the window. Remove flagged extensions and empty the Recycle Bin from that user's own account. |
| You clicked **No** on the administrator prompt | It runs in limited mode: MRT, threat removal, system temp files, browser policy removal and the deep clean are skipped. Run it again and click **Yes**. |
| Notifications still pop up | Make sure the browser was closed when PC Cleaner fixed them (it says so in the report). If not, run option 1 again and let it close the browser, or follow the steps in the report. |
| A threat won't go away | Use option 5 (Offline virus scan), or open Windows Security > Virus & threat protection > Protection history. |

## Advanced: command line

```powershell
powershell -ExecutionPolicy Bypass -File .\PCCleaner\PCCleaner.ps1 -Action Both -ScanType Full -Deep
```

| Option | Meaning |
|---|---|
| `-Action Scan\|Clean\|Both` | Scan and fix, clean, or both (default `Both`) |
| `-Action Recent -Weeks 2` | Review downloads and programs from the last N weeks |
| `-Action FreshStart` | Fresh start guide |
| `-ScanType Quick\|Full` | Defender scan depth (default `Quick`) |
| `-Deep` | Add the deep clean |
| `-OfflineScan` | At the end, offer a Defender Offline scan (always asks, because it restarts the PC) |
| `-NoPrompt` | Answer yes to the routine questions. It still never empties the Recycle Bin, deletes Windows.old, removes browser policies, closes browsers, uninstalls programs or moves your files |
| `-NoElevate` | Don't ask for admin rights (limited mode) |
| `-NoOpen` | Don't open the report at the end |
| `-OutRoot <folder>` | Save reports somewhere else |

## Privacy

Nothing is uploaded by PC Cleaner. Microsoft's own tools work as they always do: Defender may send samples if you have sample submission on, and MRT sends Microsoft its usual anonymous result report. Reports and logs list program names, file names and paths from the PC they ran on, so they are excluded from git by `.gitignore`. Only share them with people you trust.

## Removing it

Nothing is installed outside the folder: no scheduled tasks or services are added, and the temporary Disk Clean-up settings it uses are removed again. To remove it, delete the `PCCleaner` folder. If it blocked notification sites, the original browser setting is kept as `Preferences.pccleaner-backup` in the browser's profile folder.
